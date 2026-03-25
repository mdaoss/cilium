# HA Egress Gateway — Tunables Reference

All configuration options, constants, thresholds, and limits related to
the HA active/active egress gateway feature.

---

## Runtime Configuration (Cilium Agent Flags / ConfigMap)

| Flag / ConfigMap Key | Type | Default | Effect |
|----------------------|------|---------|--------|
| `egress-gateway-ha-redirect` | bool | `false` | Enable reply-traffic interception on non-gateway (worker) nodes. Emits `ENABLE_EGRESS_GATEWAY_HA_REDIRECT` BPF define. Without this, replies must reach a gateway directly (via ECMP or single route). |
| `egress-gateway-policy-map-max` | int | 16384 | Max entries in `cilium_egress_gw_policy_v4` LPM trie. Propagated as `EGRESS_POLICY_MAP_SIZE` BPF define. |
| `egress-gateway-reconciliation-trigger-interval` | duration | `1s` | Min interval between egress gateway policy reconciliation runs. Controls batching of policy/node change events. |
| `egress-gateway-probe-interval` | duration | `1s` | Interval between TCP health probes to remote gateway nodes. Set to `0` to disable probing entirely. Lower values detect failures faster but increase network overhead. |
| `egress-gateway-probe-timeout` | duration | `1s` | TCP connect timeout for each health probe attempt. Must be ≤ probe interval to avoid overlapping probes. |
| `egress-gateway-probe-recovery-threshold` | int | `40` | Consecutive successful probes before restoring a recovered gateway. Must cover the full BPF lifecycle: health port up → initial load → recompilation (~18s) → overlay reload. |
| `egress-gateway-probe-recovery-hold-time` | duration | `0` | Additional grace period after a gateway is marked recovered. During this hold, the gateway is skipped for policy selection, keeping single-gateway mode until reply-path convergence stabilizes. |
| `node-port-range` | string | `30000-32767` | NodePort service range. The SNAT port range starts at `NodePortMax + 1`. Narrowing this range (e.g. `1024,1025`) lowers `NODEPORT_PORT_MIN_NAT` and widens per-gateway SNAT capacity. |

### Where defined

- `pkg/option/config.go:371` — `EnableEgressGatewayHARedirect`
- `pkg/maps/egressmap/policy.go:54,58` — `EgressGatewayPolicyMapMax`
- `pkg/egressgateway/manager.go:78,82,86` — `EgressGatewayReconciliationTriggerInterval`
- `pkg/egressgateway/manager.go` — `EgressGatewayProbeInterval`, `EgressGatewayProbeTimeout`, `EgressGatewayProbeRecoveryThreshold`, `EgressGatewayProbeRecoveryHoldTime`
- `pkg/option/config.go:1293-1296` — `NodePortMinDefault`, `NodePortMaxDefault`

---

## BPF Map Sizes

| Map | BPF Name | Type | Size | Configurable | Purpose |
|-----|----------|------|------|--------------|---------|
| Policy | `cilium_egress_gw_policy_v4` | LPM trie | 16384 (default) | Yes (`egress-gateway-policy-map-max`) | `(src_ip, dst_cidr)` → `(egress_ip, gw0, gw1)` |
| Steering | `cilium_egress_gw_steer4` | LRU hash | 65536 | Compile-time only (`EGRESS_GW_STEER_MAP_SIZE`) | Per-flow owner persistence: `{reply 5-tuple}` → `{owner_ip, owner_idx}` |
| Reverse | `cilium_egress_gw_reverse4` | hash | 64 | Compile-time only (hardcoded) | `{egress_ip}` → `{gw0, gw1}` for cross-gateway reply forwarding |

### Where defined

- `bpf/lib/egress_gateway.h:106-107` — `EGRESS_GW_STEER_MAP_SIZE` (guard: `#ifndef`, overridable)
- `bpf/lib/egress_gateway.h:127` — reverse map `max_entries` (hardcoded 64)
- `pkg/maps/egressmap/policy.go:88` — `EGRESS_POLICY_MAP_SIZE` emitted from Go

### Steering map LRU behavior

The steering map uses LRU eviction. When full, the oldest entry is evicted.
If a reply arrives for an evicted flow, `egress_gw_reply_steer_fallback()`
uses the reverse map to find the gateway pair and re-hashes to determine
the owner. This is a slower path but prevents connection drops.

---

## SNAT Port Partitioning

Each HA gateway gets half the SNAT port range. The range is
`[NODEPORT_PORT_MIN_NAT, NODEPORT_PORT_MAX_NAT]`, derived from the
`node-port-range` config. To widen per-gateway capacity, narrow the
NodePort range so that `NODEPORT_PORT_MIN_NAT` drops lower.

**Default** (node-port-range 30000-32767):

| Gateway | Min Port | Max Port | Ports |
|---------|----------|----------|-------|
| GW 0 (lower name) | `NODEPORT_PORT_MIN_NAT` (32768) | `EGRESS_GW_PORT_MID - 1` (49151) | 16384 |
| GW 1 (higher name) | `EGRESS_GW_PORT_MID` (49152) | `NODEPORT_PORT_MAX_NAT` (65535) | 16384 |

**With `node-port-range: "1024,1025"`** (wider SNAT range):

| Gateway | Min Port | Max Port | Ports |
|---------|----------|----------|-------|
| GW 0 (lower name) | 1026 | 33280 | 32255 |
| GW 1 (higher name) | 33281 | 65535 | 32255 |

The midpoint is computed as: `NODEPORT_PORT_MIN_NAT + (NODEPORT_PORT_MAX_NAT - NODEPORT_PORT_MIN_NAT + 1) / 2`

### Where defined

- `bpf/lib/egress_gateway.h` — port range macros (derived from `NODEPORT_PORT_MIN/MAX_NAT`)
- `bpf/lib/nat.h` — port range assignment in `snat_v4_needs_masquerade()`
- `pkg/datapath/linux/config/config.go` — emits `NODEPORT_PORT_MIN_NAT` and `NODEPORT_PORT_MAX_NAT`

### Interaction with NodePort range

If `node-port-range` is customized (e.g., `30000-40000`), then:
- `NODEPORT_PORT_MIN_NAT` = 40001
- `NODEPORT_PORT_MAX_NAT` = 65535
- Total SNAT ports = 25535, each gateway gets ~12767

Wider NodePort ranges reduce available SNAT ports per gateway.

---

## NAT GC Signal Thresholds

When SNAT port allocation struggles to find a free port, BPF signals the
Go agent to trigger garbage collection of expired CT/NAT entries.

| Constant | Value | Effect |
|----------|-------|--------|
| `SNAT_COLLISION_RETRIES` | 128 | Max random-port attempts before giving up (returns `DROP_NAT_NO_MAPPING`) |
| `SNAT_SIGNAL_THRES` | 64 | Non-EGW: signal GC after 64 retries |
| `SNAT_SIGNAL_THRES / 4` | 16 | **EGW HA**: signal GC after 16 retries (earlier, because per-gateway range is halved) |

### Where defined

- `bpf/lib/nat.h:38-39` — constants
- `bpf/lib/nat.h:254-258` — EGW-specific early signal logic

---

## CT/NAT Timeouts

These control how long NAT entries persist, affecting port reuse. NAT entries
are deleted by the Go agent's CT garbage collector — when a CT entry expires
and is removed, its associated NAT entry is removed with it.

| Flag / ConfigMap Key | BPF Define | Default | Effect |
|----------------------|------------|---------|--------|
| `bpf-ct-timeout-regular-tcp` | `CT_CONNECTION_LIFETIME_TCP` | 8000s | Lifetime for established TCP CT entries |
| `bpf-ct-timeout-regular-tcp-fin` | `CT_CLOSE_TIMEOUT` | 10s | Lifetime after both FINs (or RST) seen |
| `bpf-ct-timeout-regular-tcp-syn` | `CT_SYN_TIMEOUT` | 60s | Lifetime for half-open (SYN-only) entries |
| `bpf-ct-timeout-regular-any` | `CT_CONNECTION_LIFETIME_NONTCP` | 60s | Non-TCP (UDP, ICMP) entry lifetime |
| `bpf-ct-timeout-service-tcp` | `CT_SERVICE_LIFETIME_TCP` | 8000s | Service (ClusterIP/NodePort) TCP entries |
| `conntrack-gc-interval` | — | adaptive (10s–12h) | GC scan interval (overrides auto-tuning) |
| `conntrack-gc-max-interval` | — | — | Upper bound for auto-tuned GC interval |

### CT entry lifecycle in BPF

1. **SYN only** → timeout set to `CT_SYN_TIMEOUT` (60s)
2. **SYN+ACK seen** → timeout promoted to `CT_CONNECTION_LIFETIME_TCP` (8000s)
3. **Both FINs seen** (or RST) → `rx_closing` + `tx_closing` set → timeout
   shortened to `CT_CLOSE_TIMEOUT` (10s)
4. **GC runs** → expired entry + associated NAT entry deleted → SNAT port freed

### GC auto-tuning

When `conntrack-gc-interval` is not set, the agent auto-tunes based on the
fraction of entries deleted each scan:

- **>25% deleted** → interval shortened (down to min 10s)
- **<5% deleted** → interval lengthened (up to max 12h for LRU maps)
- **Starting interval**: 5 minutes
- **BPF signal override**: when BPF sends `SignalNatFillUp` (after 16 retries
  for EGW), GC runs immediately regardless of interval

### Where defined

- `daemon/cmd/daemon_main.go:762-781` — flag definitions and defaults
- `pkg/datapath/linux/config/config.go:223-226` — emits BPF defines from Go config
- `bpf/node_config.h:77-83` — template defaults
- `bpf/lib/conntrack.h:182,302,361` — lifetime assignment in CT lookup
- `pkg/maps/ctmap/gc/gc.go` — GC loop, auto-tuning, signal handling
- `pkg/defaults/defaults.go:364-372` — GC interval bounds

---

## Hash and Gateway Selection

| Parameter | Value | Effect |
|-----------|-------|--------|
| Hash function | `jhash_3words()` | Deterministic 5-tuple hash for gateway selection |
| Hash seed | `HASH_INIT4_SEED` (0xcafe) | Seed for `jhash` — consistent across all nodes |
| Selection | `hash & 1` | Bit 0 selects gateway 0 or 1 (statistical 50/50 split) |
| Max gateways per policy | 2 | Hardcoded limit in `regenerateGatewayConfig()` |
| Gateway ordering | Sorted by node name | Ensures all nodes agree on which is gw0 vs gw1 |

### Where defined

- `bpf/lib/egress_gateway.h:86-94` — `egress_gw_select_owner()`
- `bpf/node_config.h:93` — `HASH_INIT4_SEED`
- `pkg/egressgateway/policy.go:143` — `if gatewayCount >= 2 { break }`

---

## BPF Feature Defines

| Define | Controlled By | Effect |
|--------|--------------|--------|
| `ENABLE_EGRESS_GATEWAY` | `EnableIPv4EgressGateway` (agent flag) | Master gate for all egress gateway BPF code |
| `ENABLE_EGRESS_GATEWAY_COMMON` | Auto-defined when `ENABLE_EGRESS_GATEWAY` is set | Scoped gate for code needed in `nat.h` (compiled before `egress_gateway.h`) |
| `ENABLE_EGRESS_GATEWAY_HA_REDIRECT` | `egress-gateway-ha-redirect` flag | Enables worker-node reply interception via `bpf_host.c` |
| `IPV4_DIRECT_ROUTING` | Per-node (agent emits node's K8s IP) | Used in HA redirect to determine if current node is a gateway |

### Where defined

- `bpf/lib/common.h:52` — `ENABLE_EGRESS_GATEWAY_COMMON`
- `pkg/egressgateway/manager.go:207` — emits `ENABLE_EGRESS_GATEWAY_HA_REDIRECT`
- `bpf/node_config.h:250-251` — `IPV4_DIRECT_ROUTING` template

---

## Gateway Health Probing

The gateway prober detects unreachable gateway nodes and triggers policy map
reconciliation to remove them. This prevents ~50% connection black-holing when
a gateway VM crashes.

| Parameter | Default | Configurable | Effect |
|-----------|---------|--------------|--------|
| Probe timeout | 1s | Yes (`egress-gateway-probe-timeout`) | TCP connect timeout per probe attempt |
| Failure threshold | 3 | No (compile-time) | Consecutive failures before marking unhealthy |
| Health port | 4240 | No (compile-time) | Target port — Cilium agent health API |
| Probe interval | 1s | Yes (`egress-gateway-probe-interval`) | Time between probe rounds |
| Recovery threshold | 40 | Yes (`egress-gateway-probe-recovery-threshold`) | Consecutive successes before restoring a recovered gateway |
| Recovery hold time | 0s | Yes (`egress-gateway-probe-recovery-hold-time`) | Extra delay after recovery before gateway is eligible for policy selection |

### Detection timeline

```
Gateway crashes at T=0
  T=1s  — probe 1 fails (timeout after 1s)
  T=2s  — probe 2 fails
  T=3s  — probe 3 fails → threshold reached
           → unhealthyGateways updated
           → reconcileLocked() → policy map updated to single-gateway
```

Worst case: `probe_interval × failure_threshold + probe_timeout` = 1×3 + 1 = 4s.
Best case: if the probe fires just as the node dies, detection is ~3s.

### Recovery timeline

```
Gateway recovers at T=0
  T=1s   — recovery probe 1/40
  T=2s   — recovery probe 2/40
  ...
  T=40s  — recovery probe 40/40 → threshold reached
           → unhealthyGateways cleared
           → if hold-time > 0, gateway enters hold window
           → reconcileLocked() keeps single-gateway until hold expires
           → hold timer fires → reconcileLocked() restores dual-gateway
```

Recovery requires 40 consecutive successful probes (40s at default interval).
This delay gives the recovered Cilium agent time to finish loading BPF programs
and populating tail call maps before traffic is directed to it.

### Disabling the prober

Set `egress-gateway-probe-interval: "0"` in the cilium ConfigMap. When disabled,
the prober goroutine is not started and `updateProberTargets()` is a no-op.
Gateway failures will only be detected if the `CiliumNode` CR is manually
deleted (e.g., via node auto-deletion controller or `kubectl delete ciliumnode`).

### Where defined

- `pkg/egressgateway/gateway_prober.go:17-33` — constants
- `pkg/egressgateway/manager.go` — `EgressGatewayProbeInterval`, `EgressGatewayProbeTimeout`, `EgressGatewayProbeRecoveryThreshold`, `EgressGatewayProbeRecoveryHoldTime` config fields, prober lifecycle

---

## Special Sentinel Values

| Constant | Value | Meaning |
|----------|-------|---------|
| `EGRESS_GATEWAY_NO_GATEWAY` | `0x00000000` | No gateway found → drop packet |
| `EGRESS_GATEWAY_EXCLUDED_CIDR` | `0x00000001` | Destination in excluded CIDR → pass through |
| `EGRESS_GATEWAY_NO_EGRESS_IP` | `0x00000000` | No egress IP configured |
| `gateway_ip_1 == 0` | `0x00000000` | Single-gateway mode (no HA) |

### Where defined

- `bpf/lib/egress_gateway.h:27-31`

---

## Capacity Planning

With default settings and 2 gateways:

| Resource | Per Gateway | Total | Limit Source |
|----------|-----------|-------|-------------|
| SNAT ports | 16384 (default); 32255 with `node-port-range: "1024,1025"` | 32768 (default) | `(NODEPORT_PORT_MAX_NAT - NODEPORT_PORT_MIN_NAT + 1) / 2` |
| Steering entries | 65536 (shared LRU) | 65536 | `EGRESS_GW_STEER_MAP_SIZE` |
| Reverse entries | 64 (shared) | 64 | Hardcoded |
| Policy entries | 16384 (shared) | 16384 | `egress-gateway-policy-map-max` |

**Tested (default 16384 ports/gw)**: 315K connections at ~500 rps sustained
with 0 failures before port space filled. After exhaustion, 100% of new
connections fail with `DROP_NAT_NO_MAPPING`. Flushing SNAT/CT maps immediately
restores operation.

**Tested (widened 32255 ports/gw)**: 150K TCP connections at 500 rps with full
failure/recovery cycle: 0 failures. 150K HTTP/2 multiplexed requests (50
connections, 500 rps) with failure/recovery: <0.5% failures in both gw-kill
directions (failures are from in-flight streams on connections routed through
the killed gateway).

See the SNAT Port Capacity Tuning Guide below for formulas and tuning levers.

---

## SNAT Port Capacity Tuning Guide

### Variables

| Symbol | Parameter | Default | ConfigMap Key |
|--------|-----------|---------|---------------|
| `NP_MAX` | NodePort range upper bound | 32767 | `node-port-range` |
| `NAT_MAX` | Upper SNAT port bound | 65535 | hardcoded |
| `T_tcp` | TCP established CT lifetime | 8000s | `bpf-ct-timeout-regular-tcp` |
| `T_fin` | CT lifetime after both FINs/RST | 10s | `bpf-ct-timeout-regular-tcp-fin` |
| `T_syn` | CT lifetime for half-open | 60s | `bpf-ct-timeout-regular-tcp-syn` |
| `GC_int` | GC scan interval | adaptive | `conntrack-gc-interval` |
| `N_eip` | Distinct egress IPs | 1 | number of policies with different `egressIP` |
| `N_gw` | Gateways per policy | 2 | hardcoded |

### Formula 1: Ports per gateway

```
PORTS_PER_GW = (NAT_MAX - NP_MAX) / N_gw
             = (65535 - NP_MAX) / 2
```

Default: `(65535 - 32767) / 2 = 16384`

| `node-port-range` | `NP_MAX` | `SNAT_TOTAL` | `PORTS_PER_GW` |
|--------------------|----------|--------------|----------------|
| 30000-32767 (default) | 32767 | 32768 | 16384 |
| 1024,1025 (minimal) | 1025 | 64510 | 32255 |
| 30000-30000 (⚠ rejected) | — | — | — |
| 30000-30001 (narrow) | 30001 | 35534 | 17767 |

### Formula 2: Effective port hold time

A port is occupied from connection creation until GC removes the expired
CT+NAT entry. The effective hold time depends on connection behavior:

```
Short-lived (FIN exchange):  T_effective = T_fin + GC_int
Half-open (SYN timeout):     T_effective = T_syn + GC_int
Long-lived (stays open):     T_effective = T_tcp
RST closed:                  T_effective = T_fin + GC_int
```

For short-lived HTTP/API-style connections (the common egress workload), the
port hold time is `T_fin + GC_int`, **not** `T_tcp`. The established timeout
only applies to connections that remain open without closing.

### Formula 3: Maximum sustained connection rate

At steady state, new port allocations must not exceed port reclamation:

```
MAX_RPS_PER_GW = PORTS_PER_GW / T_effective
MAX_RPS_TOTAL  = MAX_RPS_PER_GW × N_gw × N_eip
```

Examples (default 16384 ports/GW, 2 GW, 1 egress IP):

| Connection type | T_effective | Max RPS/GW | Max RPS total |
|----------------|-------------|------------|---------------|
| Short-lived, GC=10s | 20s | 819 | 1638 |
| Short-lived, GC=30s | 40s | 409 | 819 |
| Short-lived, GC=5min | 310s | 52 | 105 |
| Long-lived, T_tcp=8000s | 8000s | 2.0 | 4.1 |
| Long-lived, T_tcp=3600s | 3600s | 4.5 | 9.1 |
| Long-lived, T_tcp=900s | 900s | 18.2 | 36.4 |

### Formula 4: Time to exhaustion

Before GC reclaims any ports (cold start or burst):

```
TIME_TO_EXHAUST = PORTS_PER_GW / ACTUAL_RPS
```

Default: `16384 / 500 = ~33s`. After this initial fill, GC must keep up or
ports exhaust. If `ACTUAL_RPS < MAX_RPS_PER_GW`, steady state is sustainable.

### Formula 5: Scaling with multiple egress IPs

Each distinct egress IP gets its own NAT 5-tuple namespace. N policies with
N different egress IPs multiply total capacity linearly:

```
TOTAL_PORT_CAPACITY = PORTS_PER_GW × N_gw × N_eip
```

Split workloads across policies via pod label selectors:

```yaml
# Policy A: egressIP 100.64.0.200, matchLabels: {app: web}
# Policy B: egressIP 100.64.0.201, matchLabels: {app: api}
# Each gets 16384 × 2 = 32768 ports → total 65536
```

### Tuning levers (priority order)

**For short-lived connections (HTTP, API calls):**

| Priority | Lever | ConfigMap | Impact | Risk |
|----------|-------|-----------|--------|------|
| 1 | Force fast GC | `conntrack-gc-interval: "10s"` | ~4x throughput vs default adaptive | Higher CPU from frequent scans |
| 2 | Multiple egress IPs | N/A (add policies) | Linear scaling | More policies/IPs to manage |
| 3 | Lower TCP timeout | `bpf-ct-timeout-regular-tcp: "1800s"` | Safety net for leaked connections | Active long connections may get GC'd |
| 4 | Shrink NodePort range | `node-port-range: "30000-30000"` | +8% ports per GW | Cannot use NodePort services |
| 5 | Lower FIN timeout | `bpf-ct-timeout-regular-tcp-fin: "5s"` | Marginal (saves 5s/port) | Minimal |

**For long-lived connections (DB, WebSocket, gRPC):**

| Priority | Lever | ConfigMap | Impact | Risk |
|----------|-------|-----------|--------|------|
| 1 | Multiple egress IPs | N/A (add policies) | Linear scaling | More policies to manage |
| 2 | Lower TCP timeout | `bpf-ct-timeout-regular-tcp: "900s"` | ~9x throughput | Must exceed longest connection lifetime |
| 3 | Force faster GC | `conntrack-gc-interval: "30s"` | Faster reclaim after close | CPU overhead |
| 4 | Shrink NodePort range | `node-port-range: "30000-30000"` | +8% ports per GW | Cannot use NodePort services |

### ConfigMap template

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-config
  namespace: kube-system
data:
  # --- SNAT port capacity tuning ---
  bpf-ct-timeout-regular-tcp: "3600s"        # default 8000s
  bpf-ct-timeout-regular-tcp-fin: "10s"      # default 10s (already optimal)
  bpf-ct-timeout-regular-tcp-syn: "30s"      # default 60s
  conntrack-gc-interval: "15s"               # default adaptive (10s-12h)
  node-port-range: "30000-30001"             # default 30000-32767
```

Restart cilium agents after changes:
`kubectl rollout restart ds/cilium -n kube-system`
