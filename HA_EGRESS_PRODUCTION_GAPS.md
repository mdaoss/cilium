# Egress Gateway HA — Production Readiness Gaps

Status: **Validated on real cluster. Some gaps remain before production.**

Phases 1–4 implement the full data-plane logic (forward path hashing, port
partitioning, steering map population, reply steering, fallback). The HA
redirect feature adds non-gateway node reply interception. All paths have been
validated on a real multi-node cluster with 10K+ connections and rotating
routes. Several gaps remain before deploying to production.

---

## Critical Gaps

### ~~1. No Datapath Testing~~ — RESOLVED

All BPF paths have been validated on a real 3-node cluster (2 gateways + 1
worker) with Geneve + DSR mode:

- Forward path: hash selects correct gateway, SNAT uses fixed per-gateway port range
- Steering map: entries written with correct reply-direction key after SNAT
- Reply at owner: steering lookup finds local owner, rev SNAT succeeds
- Reply at non-owner: steering lookup redirects via tunnel to owner
- Fallback: cross-gateway redirect on NAT miss via overlay handler
- HA redirect: non-gateway worker intercepts and forwards replies
- Multi-policy: two egress IPs tested simultaneously
- 10K connection stress test with rotating routes: 0 failures
- 150K TCP connection failure/recovery cycle at 500 rps: 0 failures (widened port range)
- 150K HTTP/2 multiplexed failure/recovery at 500 rps: <0.5% failures (both gw kill directions)

### ~~2. No Integration / Connectivity Tests~~ — RESOLVED

The full asymmetric-reply scenario has been validated end-to-end:

```
Pod A → tunnel to GW0 → SNAT (port from partition 0) → external server
Reply → arrives at GW1 (ECMP) → steering lookup → tunnel to GW0
GW0 → rev SNAT → tunnel to pod's node → Pod A receives reply
```

Additionally tested: replies via non-gateway worker (HA redirect), live failover
with route rotation across all nodes, and multi-policy pairs.

See [HA_EGRESS_TEST_SCENARIOS.md](HA_EGRESS_TEST_SCENARIOS.md) for reproducible
test procedures.

### 3. SNAT Port Range Is Narrow

The implementation partitions `NODEPORT_PORT_MIN_NAT–NODEPORT_PORT_MAX_NAT`
(typically 32768–43835), giving ~5,500 ports per gateway.

The design doc proposed 1024–65535 (~32,000 ports per gateway). The current
range may cause SNAT port exhaustion under high-connection workloads.

**Decision needed:** use the wider range (requires verifying no conflict with
NodePort, kube-proxy, and other SNAT users) or accept the narrower range with
documented limits.

### ~~4. Virtual IP Interface Fallback~~ — RESOLVED

Implemented in `deriveFromPolicyGatewayConfig()` (`pkg/egressgateway/policy.go`).
When `GetIfaceWithIPv4Address(egressIP)` fails (because the egress IP is a
virtual/floating IP not assigned to any local interface), the code falls back to
`route.NodeDeviceWithDefaultRoute()`. The egress IP from the policy spec is
kept as the SNAT address; only the egress interface name uses the fallback.

This supports the shared-VIP model where both gateways SNAT to the same virtual
IP and packets physically egress via each node's default-route interface.

### 5. Upgrade Path Untested

The policy map value size changed from 8 bytes (single gateway) to 16 bytes
(two gateways + pad). This is a breaking change:

- Old agents cannot read new map entries.
- New agents cannot read old map entries.
- Rolling upgrades with mixed agent versions will cause policy map corruption.

**Needed:** either a migration path (detect old format, upgrade in place) or
documented requirement for coordinated restart of all Cilium agents.

---

## Important (Non-Blocking) Gaps

### 6. No Trace Reason Codes

`TRACE_REASON_EGRESS_GW_OWNER_0` / `TRACE_REASON_EGRESS_GW_OWNER_1` are not
implemented. Without these, `cilium monitor` cannot show which gateway was
selected for a given flow, making production debugging harder.

### 7. No BPF-Level Unit Tests

The design doc (section 7.2) proposed BPF unit tests for:

- Hash determinism: same 5-tuple always produces same owner.
- Hash distribution: roughly 50/50 across 1000 different source ports.
- Port partition boundaries: `EGRESS_GW_PORT_MAX_0 < EGRESS_GW_PORT_MIN_1`.

These exist only as design doc sketches, not as runnable tests.

### 8. No Load / Stress Testing

The 64K-entry LRU steering map eviction behavior under real workloads is
unknown. Questions:

- At what connection rate do evictions start?
- Does the fallback mechanism (redirect to other gateway) add measurable
  latency?
- Are there pathological hash distributions that overload one gateway?

### 9. No Graceful Gateway Drain

When a gateway node is removed (e.g., node drain, crash):

- The control plane removes it from `manager.nodes` and reconciles the policy
  map.
- In-flight flows whose SNAT entries lived on the removed gateway are silently
  dropped — the remaining gateway has no SNAT mapping for those flows.
- No mechanism exists to proactively migrate or signal these flows.

This is acceptable for crash scenarios but could be improved for planned drains
(e.g., pre-drain SNAT entry replication or connection tracking notification).

### 10. Gateway Node Failure Does Not Update Policy Map

When a gateway node is hard-killed, the policy map on surviving nodes continues
to list the dead gateway. ~50% of new connections fail because the worker
tunnels them to the unreachable node. The egress gateway manager only reacts to
CiliumNode CR deletion, not Node `NotReady` status — and CiliumNode CRs persist
as long as the K8s Node object exists.

**Tested (2026-03-12):** 5000 connections at 50 rps, GW1 killed mid-test.
Result: 3523 ok, 1477 fail (29.5%). Policy map was never updated during the
~6 minute test. See [HA_EGRESS_ONGOING_PROBLEMS.md](HA_EGRESS_ONGOING_PROBLEMS.md) §7
for full analysis, test data, and production requirements.

**Fix options:**
1. Subscribe to Node `Ready` condition → remove `NotReady` nodes from
   `manager.nodes` → reconcile (~40s failover)
2. Add a heartbeat/liveness check between Cilium agents on gateway nodes
   (~seconds failover, more complex)

---

## Recommended Next Steps

1. ~~Set up multi-node test environment~~ — Done (3-node RKE cluster).
2. ~~Validate BPF programs load~~ — Done (Geneve + DSR, kernel 5.10+).
3. ~~Implement virtual IP fallback~~ — Done.
4. **Decide on port range** — benchmark current range under expected connection
   load. Consider widening to 1024–65535 for high-connection workloads.
5. **Document upgrade procedure** — coordinated agent restart requirement.
6. **Add trace reason codes** for owner selection events.
7. **Write automated CI tests** (Kind-based) for the core HA scenarios.
