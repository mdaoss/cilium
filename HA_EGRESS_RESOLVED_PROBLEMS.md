# Resolved Problems — Egress Gateway HA

This file contains problems with implemented fixes.
Section numbers are preserved from the original combined tracker for traceability.

## 1. Empty Egress Policy Map with Virtual Egress IP

**Symptom:** `cilium_egress_gw_policy_v4` BPF map is empty on all nodes despite a
valid `CiliumEgressGatewayPolicy` being applied. Cilium agent logs show:

```
level=error msg="Failed to derive policy gateway configuration"
  error="failed to retrieve interface with egress IP: no interface with 100.64.0.200 IPv4 assigned to"
```

**Root cause:** The original `deriveFromPolicyGatewayConfig()` in
`pkg/egressgateway/policy.go` assumed the `egressIP` from the policy spec is
assigned to a local network interface on the gateway node. It called
`netdevice.GetIfaceWithIPv4Address(egressIP)` to find that interface, and when
the IP was not found (because it is a virtual/floating IP announced via
BGP or MetalLB), it returned an error. This error prevented
`localNodeConfiguredAsGateway` from being set to `true`, so the reconciler
never wrote any entries to the egress policy BPF map.

**Fix (commit `495d26267f`):** When `GetIfaceWithIPv4Address` fails, fall back to
the interface with the IPv4 default route (`route.NodeDeviceWithDefaultRoute`)
instead of returning an error. The egress IP from the policy spec is always
kept as the SNAT address — only the egress interface name needs a fallback.
This supports the shared-VIP model where both gateways SNAT to the same
virtual IP and packets physically egress via each node's default-route
interface.

---

## 3. BPF Compilation Failures Block Endpoint Regeneration

**Symptom:** Endpoints stuck in `waiting-to-regenerate` state. The egress
gateway BPF defines (`ENABLE_EGRESS_GATEWAY`, etc.) are present in
`node_config.h` but absent from individual endpoint `ep_config.h` files.
Cilium agent logs show BPF compilation errors.

**Known compilation issues and fixes:**

### 3a. C89 Declaration-After-Statement (commit `27dbe67c88`)

BPF programs are compiled with `-Werror -Wdeclaration-after-statement`. Any
variable declaration after a statement in the same scope causes a hard error:

```
error: ISO C90 forbids mixed declarations and code
```

All variable declarations must be at the top of their enclosing block, before
any executable statements.

### 3b. `__throw_build_bug` / memset Errors (commit `c5adaf2677`)

The BPF toolchain intercepts `__builtin_memset` via macro and redirects it to
`__throw_build_bug()`, causing linker errors. This is triggered by:

- Direct calls to `__builtin_memset()` or `memset()`
- Partial designated initializers (`struct foo x = { .field = val }`) — the
  compiler generates an implicit memset to zero uninitialized fields
- Empty initializers (`= {}`) that the compiler doesn't optimize away
- Struct sizes that grow due to padding (e.g. `ipv4_nat_target` growing from
  20 to 24 bytes), making the compiler unable to inline the zeroing

**Fix:** Use field-by-field assignment instead of aggregate initializers. Zero
padding fields manually (`key.pad[0] = 0; key.pad[1] = 0; ...`). Keep struct
field order optimized to minimize padding.


---

## 5. Non-Gateway Nodes Need Egress IP for Reverse Map

**Symptom:** After enabling `egress-gateway-ha-redirect`, non-gateway worker
nodes have an empty `cilium_egress_gw_reverse4` map. HA redirect does not work
— replies arriving at the worker pass through unintercepted.

**Root cause:** `deriveFromPolicyGatewayConfig()` is only called on gateway
nodes (where `node.IsLocal()` matches the policy's `nodeSelector`). On
non-gateway nodes, `gwc.egressIP` stays at `0.0.0.0`, and
`reconcileReverseMap()` skips entries with invalid egress IPs.

**Fix:** In `regenerateGatewayConfig()` (`pkg/egressgateway/policy.go`), after
the gateway node loop, propagate the egress IP from the policy spec to
non-gateway nodes:

```go
if !gwc.egressIP.IsValid() || gwc.egressIP == EgressIPNotFoundIPv4 {
    if policyGwc.egressIP.IsValid() {
        gwc.egressIP = policyGwc.egressIP
    }
}
```

This ensures `reconcileReverseMap()` has the egress IP on every node.

---

## 7. Gateway Node Failure Does Not Update Policy Map

**Status: RESOLVED — gateway health prober handles failover**

**Symptom:** When a gateway node is hard-killed (VM shutdown, power loss, kernel
panic), the egress gateway policy map (`cilium_egress_gw_policy_v4`) on surviving
nodes continues to list the dead gateway. ~50% of new connections fail because
the worker tunnels them to the unreachable gateway.

**Original root cause:** The egress gateway manager reconciled only when a
CiliumNode CR was deleted. The CiliumNode CR lifecycle depends on the K8s Node
object, which persists indefinitely even when `NotReady`. No Delete event was
ever fired, so the policy map was never updated.

**Fix (commit `31c0936ace`):** The gateway health prober actively probes each
gateway's health port (4240) at 1-second intervals. After 3 consecutive
failures (~3s), the gateway is marked unhealthy and excluded from
`regenerateGatewayConfig()` via `manager.unhealthyGateways`. The policy map
is reconciled to single-gateway mode automatically.

Key code:
- `pkg/egressgateway/gateway_prober.go` — TCP probe loop, failure/recovery
  thresholds, health event channel
- `pkg/egressgateway/manager.go:120` — `unhealthyGateways` skip in
  `regenerateGatewayConfig()`

**Detection timeline:**
- Failure detection: ~3s (3 probes × 1s interval)
- Recovery: ~40s (40 consecutive successful probes, covers full BPF recompilation)

**Production requirements remain:**
- BGP health-checking is still needed to withdraw the dead nexthop from ECMP
  (reply path fix — separate from forward path)
- HA K8s API server recommended for agent connectivity during gateway failures

**Test results (c028):** During single-gateway mode with pre-changed routes,
0 failures. Gateway removed from policy map within 3s of failure detection.

---

## 10. Post-Recovery Stale NAT/Steering Entries (Short-Lived Connections)

**Status: RESOLVED — BPF port-range steering + recovery threshold**

**Symptom:** After a gateway node crashes and recovers, ~5% of new connections
fail when the recovered gateway is re-added to the policy map. Failure rate
gradually decreases over time as stale state expires. No BPF drops visible
(`cilium monitor --type drop` is empty).

**Root cause (two layers):**

1. **Stale NAT/steering entries on surviving gateway (reply path):** During
   single-gateway mode, GW0 uses the full SNAT port range (32768–65535),
   including GW1's half. After recovery, stale steering entries on GW0 claim
   ownership of ports in GW1's range, causing incorrect revSNAT for new GW1
   connections — packets delivered with wrong client port.

2. **Recovered gateway BPF not ready (forward path):** After VM boot, the
   health port (4240) comes up ~13s before overlay BPF is fully loaded.
   A "devices changed" event triggers BPF recompilation (~18s), with the
   final overlay program not attached until ~35s after the health port.

**Fix (commit `31c0936ace`):**

- **BPF port-range validation in `egress_gw_reply_steer()`:** In both the
  `!steer` branch (LRU eviction) and the stale-entry branch, a reverse map
  lookup determines the true port-range owner. If the port is in GW1's range
  (≥ `EGRESS_GW_PORT_MIN_1`) but GW0 claims ownership, the reply is
  redirected to GW1 via tunnel. Code: `bpf/lib/egress_gateway.h` lines ~459–514.

- **Recovery threshold of 40 probes:** The gateway prober requires 40
  consecutive successful probes (40s at 1s interval) before restoring a
  recovered gateway. This covers the full BPF lifecycle: health port up →
  initial BPF load → "devices changed" recompilation → program reload.
  Config: `egress-gateway-probe-recovery-threshold` flag.

**Test results (c028):** 131 failures out of 30,000 (0.4%), matching the
CT flush baseline (c024: 124 failures). This is the irreducible minimum from
connections in-flight during the transition.

---

## 9. HA Test Client Panics with `-report=0s`

**Symptom:** Running the HA egress test client with `-report=0s` crashes
immediately with:

```
panic: non-positive interval for NewTicker
```

**Root cause:** The progress reporter goroutine unconditionally called
`time.NewTicker(*reportInterval)` in `ha_egress_gw_test/cmd/client/main.go`.
Go's ticker requires a strictly positive duration; `0s` panics.

**Fix:** Guard the progress reporter goroutine with `if *reportInterval > 0`.
When `-report=0s` is passed, the reporter is simply not started and no
periodic progress is printed. The final summary line is still printed.


---

## 8. Gateway Can Stay Blacklisted After Probe Target Churn

**Symptom:** A gateway could remain excluded from egress policy selection even
after it was healthy and re-selected by policy. This happened after target
churn (node delete/recreate, relabeling, or policy updates that temporarily
removed and re-added the same gateway).

**Root cause:** `gatewayProber.setTargets()` removed stale entries from its
local `p.unhealthy` set when a node left probe targets, but this cleanup was
not propagated to `manager.unhealthyGateways`. The manager only updated that
set on gateway health events. When the node was later re-added as a probe
target, prober state started as `wasUnhealthy=false`, so no recovery event was
emitted and the stale manager entry remained — keeping the gateway blacklisted
indefinitely.

**Fix:** `updateProberTargets()` (`pkg/egressgateway/manager.go`) now prunes
`manager.unhealthyGateways` entries for nodes that are no longer active gateway
targets. When stale entries are removed, the steering map is flushed and a
follow-up reconciliation is triggered so `regenerateGatewayConfig()` re-includes
the gateway.
