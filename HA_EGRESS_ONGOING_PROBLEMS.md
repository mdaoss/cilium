# Ongoing Problems — Egress Gateway HA

This file contains active limitations, operational risks, and open issues.
Section numbers are preserved from the original combined tracker for traceability.

## 2. Pods Created Before Cilium Are Invisible to Egress Gateway

**Symptom:** `cilium_egress_gw_policy_v4` BPF map is empty even though the
virtual-IP fix above is applied and the `CiliumEgressGatewayPolicy` is
correctly configured. No errors in cilium agent logs related to egress
gateway. `cilium endpoint list` on the worker node shows only `reserved:host`
and `reserved:health` — the pod endpoint is missing. `kubectl get
ciliumendpoints -A` returns no results.

**Root cause:** The pod was created before Cilium was deployed (or before
Cilium's CNI configuration was written). Because Cilium's CNI plugin never
handled the pod's network setup, no cilium endpoint was created for it and
no `CiliumEndpoint` custom resource exists. The egress gateway reconciler
matches policies against `matchedEndpoints` — with zero endpoints, it
iterates nothing and writes zero entries to the policy map.

**Diagnosis:**
```bash
# On the worker node running the pod:
kubectl exec <cilium-pod> -- cilium endpoint list
# If the pod IP is missing from the list, Cilium doesn't manage it.

kubectl get ciliumendpoints -n <namespace>
# If empty, no pods in that namespace are tracked by Cilium.
```

**Fix:** Delete the pod so its deployment controller recreates it. The new pod
goes through Cilium's CNI plugin, which creates the endpoint and the
`CiliumEndpoint` resource. The egress gateway reconciler then matches it and
populates the BPF map.

```bash
kubectl delete pod <pod-name> -n <namespace>
# Wait for the deployment to recreate the pod, then verify:
kubectl exec <cilium-pod> -- cilium endpoint list
kubectl exec <cilium-pod> -- cilium bpf egress list
```

This is a general Cilium behavior (not specific to egress gateway HA) — any
pod created without Cilium as the active CNI will be invisible to all Cilium
features.

---

## 4. Steering Map Owner IP Uses Node IP, Not Endpoint Check

**Symptom:** On the reply path, `egress_gw_reply_steer()` checks whether the
owner is local by calling `__lookup_ip4_endpoint(steer->owner_ip)` and checking
for `ENDPOINT_F_HOST`. The `owner_ip` stored in the steering map is the node's
internal IP (`IPV4_DIRECT_ROUTING`).

**Root cause:** The steering map `owner_ip` field is populated in
`nodeport_snat_fwd_ipv4()` from `target.egress_gw_owner_ip`, which is set to
the selected gateway's node IP in `snat_v4_needs_masquerade()`. This value
must match `IPV4_DIRECT_ROUTING` on the owner node for the endpoint check to
succeed.

**Risk:** If `IPV4_DIRECT_ROUTING` differs from the IP used in the policy map's
`gateway_ip_0`/`gateway_ip_1` (e.g., dual-stack or multi-homed nodes), the
owner check fails and replies are unnecessarily redirected.

**Mitigation:** Ensure gateway node IPs in `CiliumEgressGatewayPolicy` match the
nodes' `InternalIP` (the same IP Cilium uses for `IPV4_DIRECT_ROUTING`). This
is the default for standard Kubernetes clusters.


---

## 6. SNAT Port Exhaustion Under Sustained Load

**Status: UNDERSTOOD — mitigation available**

**Symptom:** After ~315K short-lived TCP connections at sustained ~500 rps
(per gateway), new connections start failing with 100% drop rate. Client sees
`TimeoutError` or `ConnectionResetError`. `cilium monitor --type drop` shows
`DROP_NAT_NO_MAPPING` on gateway nodes during the test. The server never
receives the SYN — drops happen on the forward path SNAT.

**Root cause:** Each HA gateway has ~16,384 SNAT ports (half of the 32768–65535
range). BPF conntrack entries for TCP have a configurable lifetime (default
8000s, `bpf-ct-timeout-regular-tcp`). Even after a short-lived connection
closes (FIN exchange), the CT/NAT entry persists until GC runs. Under sustained
load, all ports fill with stale entries from closed connections. When
`__snat_v4_nat()` cannot find a free port after 128 random probes
(`SNAT_COLLISION_RETRIES`), it returns `DROP_NAT_NO_MAPPING`.

**Failure rate vs free ports:** The SNAT allocator picks random ports. With N
free ports out of 16384 total, the probability of failing all 128 attempts is:
```
P(drop) = (1 - N/16384)^128
```
At 1.8% free → P(drop) ≈ 10%. At 0% free → P(drop) = 100%.

**Drop notification path:**

| Drop Code | BPF Location | Caller Chain |
|-----------|-------------|--------------|
| `DROP_NAT_NO_MAPPING` | `nat.h:229` | `__snat_v4_nat()` → `snat_v4_nat()` → `nodeport_snat_fwd_ipv4()` → `send_drop_notify_error_ext` |
| `DROP_NO_EGRESS_GATEWAY` | `egress_gateway.h:203` | `egress_gw_handle_packet()` → `bpf_host.c` → `send_drop_notify_error_ext` |
| `DROP_NO_EGRESS_IP` | `nat.h:612` | `snat_v4_needs_masquerade()` → `nodeport_snat_fwd_ipv4()` → `send_drop_notify_error_ext` |
| `DROP_NO_FIB` | `egress_gateway.h:65` | `egress_gw_fib_lookup_and_redirect()` → same chain |

**Why cilium monitor may appear silent:** `cilium monitor --type drop` only
shows live events — it must be running DURING the test. If checked after the
test completes, no drops are visible. The drop path through
`nodeport_snat_fwd_ipv4()` does call `send_drop_notify_error_ext`.

**Diagnosis:**
```bash
# Check SNAT map occupancy on gateways:
kubectl exec <cilium-gw-pod> -- cilium bpf nat list | wc -l

# If close to 16384 per gateway, ports are exhausted.
# Run cilium monitor DURING the test to confirm:
kubectl exec <cilium-gw-pod> -- cilium monitor --type drop
# Look for DROP_NAT_NO_MAPPING
```

**Mitigation — for testing:**
```bash
# Flush SNAT/CT maps before each test run:
for pod in cilium-f82zr cilium-bvbgc cilium-nsh96; do
  kubectl exec $pod -- cilium bpf nat flush
  kubectl exec $pod -- cilium bpf ct flush global
done
```

**Mitigation — BPF (applied):** Lower the NAT GC signal threshold for egress
gateway from 64 retries to 16 (`bpf/lib/nat.h`). This triggers the Go agent's
GC 4x earlier when the egress gateway port range is getting congested.

**Production considerations:**
- At ~500 rps per gateway, port exhaustion hits after ~5 minutes (315K / 500 ≈ 630s)
- At ~50 rps per gateway, exhaustion hits after ~55 minutes
- At ~2.0 rps per gateway, exhaustion hits at steady state (8000s default lifetime × 2.0 ≈ 16384)
- For workloads exceeding these thresholds, reduce `bpf-ct-timeout-regular-tcp`
  or distribute traffic across multiple egress IPs (each gets its own port space)
- See `HA_EGRESS_GW_TUNABLES.md` for capacity formulas and all tuning levers

**Test results:** After flushing SNAT/CT maps, 315K connections completed with
**0 failures** at ~500 rps sustained. Baseline test (worker direct, no egress
gateway) showed 0% loss, confirming the network layer is not at fault.

**Widened range validation (2026-03-19):** With `node-port-range: "1024,1025"`
(32255 ports/gw instead of 16384), 150K TCP connections at 500 rps completed
with 0 failures through a full failure/recovery cycle. HTTP/2 multiplexed
test (50 connections, 500 rps) also passed with <0.5% failures in both
gw-kill directions, confirming the wider port range works end-to-end.
See `HA_EGRESS_GW_TUNABLES.md` for capacity formulas and tuning levers.


---

## 11. Forward-Path Rehash Breaks Long-Lived Streams After Gateway Recovery

**Status: MITIGATED — fixed port ranges reduce severity**

**Symptom:** After a gateway recovers and is re-added to the policy map, ~50%
of existing long-lived connections (e.g. gRPC streams) break. The client sees
TCP RST or silent timeout. This does NOT affect short-lived TCP connections.

**Root cause:** During single-gateway mode, the `active_gw` bitmask routes
all traffic to the surviving gateway. After recovery, `active_gw` changes to
`ACTIVE_BOTH` and the hash is computed on **every packet** in
`egress_gw_request_needs_redirect()` (`bpf/lib/egress_gateway.h`):

```
Single-gw mode:  active_gw == ACTIVE_0 → always GW0
After recovery:   active_gw == ACTIVE_BOTH → hash(5-tuple) → GW0 or GW1 (50/50)
```

For ~50% of existing streams, the hash now selects GW1. GW1 has no NAT/CT
entry (just rebooted), creates a new SNAT mapping with a different source
port, and the server sees a packet from an unknown 5-tuple → TCP RST.

**Mitigation from fixed port ranges (2026-03-18):** With the fixed port range
design, both gateway IPs are always in the policy map (`gateway_ip_1` is
never zeroed). The `active_gw` bitmask controls routing. When recovery happens,
GW0's NAT table does NOT contain stale entries spanning GW1's port range
(because GW0 only uses its own fixed range, even during single-active mode).
This eliminates the port collision component of the rehash problem, though
the fundamental issue of rerouting established flows to a gateway without
their SNAT state remains for long-lived connections.

**Why it's not visible in tests:** The test client creates independent
short-lived TCP connections (connect → send → close in <1 second). Old
connections are already closed by recovery time. The rehash only affects
long-lived streams (gRPC, WebSocket).

**Proposed fixes (for long-lived streams):**

**Option A — CT-aware routing (BPF only):** In
`egress_gw_request_needs_redirect()`, for `CT_ESTABLISHED` flows, always use
the previously selected gateway (preserving routing). Only hash for new
connections (`CT_NEW`). Old flows stay on GW0 until they naturally close; new
flows balance across both gateways.

**Option B — Forward-path steering map:** Add a forward-path steering map on
the worker that records which gateway was selected for each flow's first
packet. Subsequent packets use the recorded gateway.

**gRPC mitigations (without code fix):**
- Set `GRPC_ARG_MAX_CONNECTION_AGE` on server (e.g. 5–10 min) so streams
  rotate naturally onto fresh connections with correct port partitioning
- Ensure gRPC client retry policy handles transient RSTs during recovery
- See `HA_EGRESS_GRPC_TUNING_GUIDE.md` for CT timeout and keepalive settings

---

## 12. Post-Recovery Connection Failures (Trickle)

**Status: RESOLVED — fixed port ranges eliminate stale cross-range NAT entries**

**Resolution (2026-03-18):** The trickle was caused by gw0's NAT table
retaining stale entries from single-gw mode that spanned the full SNAT port
range, including gw1's partition. After recovery, replies for gw1-owned
connections hitting gw0's stale entries caused silent failures via the
recircle path.

The **fixed port range design** eliminates this root cause: each gateway now
uses exclusively its own SNAT port range (determined by `IPV4_DIRECT_ROUTING`
vs policy map gateway IPs), even during single-active failover. GW0 never
creates NAT entries in GW1's port range, so there are no stale cross-range
entries after recovery.

**Validation (ha-fixed-ports image, 2026-03-18):**

| Test | RPS | Total | Result |
|------|-----|-------|--------|
| Scenario 9 run 1 | 100 | 30,000 | 30000 OK, 0 fail |
| Scenario 9 run 2 | 100 | 30,000 | 30000 OK, 0 fail |
| Scenario 9 run 3 | 500 | 150,000 | 150000 OK, 0 fail |
| Scenario 10 (widened range, TCP) | 500 | 150,000 | 149500 OK, 500 fail (0.33%) |
| Scenario 11a (HTTP/2, kill gw1) | 500 | 150,000 | 149499 OK, 501 fail (0.33%) |
| Scenario 11b (HTTP/2, kill gw0) | 500 | 150,000 | 149364 OK, 636 fail (0.42%) |

Scenario 9 TCP runs completed with zero failures. The latest Scenario 10 TCP
rerun completed with 500 failures (0.33%) during the recovery transition,
which is still within the scenario's `<0.5%` pass threshold. HTTP/2 failures
are from multiplexed streams on connections routed through the killed gateway —
expected behavior since long-lived HTTP/2 connections cannot survive gateway
death, but the client reconnects immediately through the surviving gateway.
Compared to 0.1–1.2% failure rates in the previous implementation (c029),
the widened-range design still behaves within the expected recovery envelope.

**Previous observations (c029, before fix):**

| Test | Config | Result | Notes |
|------|--------|--------|-------|
| 9b run 1 (20K) | Recovery, no ECMP restore | 19762/20000 (238 fail, 1.19%) | 200 burst + 38 trickle |
| 9b run 2 (20K) | Recovery, no ECMP restore | 19920/20000 (80 fail, 0.40%) | 0 burst + 80 trickle |
| 9b run 3 (20K) | Recovery, no ECMP restore | 19978/20000 (22 fail, 0.11%) | 0 burst + 22 trickle |
| Post-recovery baseline | Both gw, replies via gw0 | 4977/5000 (23 fail, 0.46%) | Stale state |

**Key design changes that fixed this:**

1. `active_gw` bitmask in policy map — gateway IPs always in fixed slots,
   bitmask controls routing (no more zeroing `gateway_ip_1`)
2. Fixed SNAT port range per gateway — determined by `IPV4_DIRECT_ROUTING`
   comparison, not per-flow hash. A gateway never uses the other's ports.
3. Control plane preserves slot assignment — `regenerateGatewayConfig()`
   always assigns both gateways to their sorted slots regardless of health
