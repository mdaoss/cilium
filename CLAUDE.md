# Project Rules

- Do not mention any AI usage anywhere
- Git commits must have well-explained messages: a concise subject line summarizing the change, followed by a body that explains what was changed, why it was changed, and any relevant context (root cause, test results, trade-offs)
- Never run sudo commands on the local machine (100.64.0.129) — all local sudo operations (route changes, etc.) are performed by the user manually. Ask the user and wait.
- VM shutdown/power-on for gateway failure tests is always done by the user via the hypervisor — never attempt to stop/kill cilium containers or VMs programmatically

# Project Overview

This is a fork of Cilium v1.16.10 with an **IPv4 Active/Active High-Availability Egress Gateway** feature.

- Base tag: `v1.16.10`
- Main branch: `v1.16.10-ha`
- Working branch: `1.16.10-ha-claude-01`
- Scope: IPv4 only, exactly 2 active gateways per policy, active/active (not primary/secondary)

## What Vanilla Egress Gateway Does

Each `CiliumEgressGatewayPolicy` maps to a **single active gateway node**:
1. Policy map (`cilium_egress_gw_policy_v4`, LPM trie): `(src_ip, dst_cidr)` -> `(egress_ip, gateway_ip)`
2. Forward path (`from_container` / `to-netdev`): matches policy, SNATs to egress_ip on the gateway
3. Reply path (`to-netdev`): `egress_gw_reply_matches_policy()` matches reverse tuple, tunnels reply to pod's node

Key files (vanilla):
- `bpf/lib/egress_gateway.h` — BPF policy lookup, redirect, SNAT hooks
- `bpf/lib/nodeport.h` — `nodeport_snat_fwd_ipv4()` (SNAT), `tail_nodeport_nat_ingress_ipv4()` (rev SNAT)
- `bpf/lib/nat.h` — `snat_v4_needs_masquerade()`, `snat_v4_nat()`, `snat_v4_rev_nat()`
- `bpf/bpf_overlay.c` — overlay SNAT hook
- `pkg/egressgateway/manager.go` — control plane reconciliation
- `pkg/egressgateway/policy.go` — `regenerateGatewayConfig()`, `deriveFromPolicyGatewayConfig()`
- `pkg/maps/egressmap/policy.go` — Go mirror of policy map

## What HA Adds

### BPF Maps (3 new/modified)

| Map | Type | Purpose |
|-----|------|---------|
| `cilium_egress_gw_policy_v4` | LPM trie | **Modified**: value extended from 8->16 bytes: `{egress_ip, gateway_ip_0, gateway_ip_1, active_gw}`. Both gateway IPs always in fixed slots; `active_gw` bitmask (1=gw0, 2=gw1, 3=both) indicates which are reachable. |
| `cilium_egress_gw_steer4` | LRU hash, 64K | **New**: per-flow owner persistence `{reply 5-tuple} -> {owner_ip, owner_idx}` |
| `cilium_egress_gw_reverse4` | hash, 64 | **New**: reverse lookup `{egress_ip} -> {gateway_ip_0, gateway_ip_1}` |

### Forward Path Changes

- `egress_gw_select_owner()` — jhash of 5-tuple, returns 0 or 1
- `egress_gw_request_needs_redirect()` — uses `active_gw` bitmask: hash when both active, route to active one when only one
- `snat_v4_needs_masquerade()` — determines own fixed port range via `IPV4_DIRECT_ROUTING` vs gateway IPs (gw0: lower half, gw1: upper half); never uses the other gateway's ports
- `nodeport_snat_fwd_ipv4()` — populates steering map after SNAT with reply-direction key

### Reply Path Changes

- `egress_gw_reply_steer()` — pre-steering before rev SNAT, redirects non-owner replies via tunnel
- `egress_gw_reply_steer_fallback()` — post-failure fallback when steering entry was LRU-evicted
- `tail_handle_egw_overlay_revsnat()` — overlay handler with cross-gateway redirect on NAT miss

### HA Redirect Feature (optional)

- Config: `egress-gateway-ha-redirect: "true"` in cilium configmap
- BPF define: `ENABLE_EGRESS_GATEWAY_HA_REDIRECT`
- `bpf/bpf_host.c` `handle_ipv4_cont()` — non-gateway nodes intercept reply traffic and tunnel to a gateway
- Uses `IPV4_DIRECT_ROUTING` to check if current node is a gateway
- Uses `cilium_egress_gw_reverse4` for egress IP -> gateway pair lookup

### Control Plane Changes

- `regenerateGatewayConfig()` — collects up to 2 gateway nodes sorted by name, always assigns IPs to fixed slots, sets `activeGW` bitmask based on health/hold state
- `deriveFromPolicyGatewayConfig()` — virtual IP fallback via `route.NodeDeviceWithDefaultRoute()`
- `reconcileReverseMap()` — populates reverse map on every reconciliation
- Egress IP propagation to non-gateway nodes for reverse map population
- `pkg/option/config.go` — `EnableEgressGatewayHARedirect` config option
- `pkg/egressgateway/manager.go` — emits `ENABLE_EGRESS_GATEWAY_HA_REDIRECT` BPF define

## Key BPF Files Changed

| File | HA Changes |
|------|------------|
| `bpf/lib/common.h` | Extended `egress_gw_policy_entry` with `active_gw` bitmask, added steer + reverse structs |
| `bpf/lib/egress_gateway.h` | `active_gw`-based selection, port macros, steer map + update, reply steer + fallback, reverse map |
| `bpf/lib/nat.h` | `ipv4_nat_target` HA fields, fixed port range via `IPV4_DIRECT_ROUTING` in `snat_v4_needs_masquerade()` |
| `bpf/lib/nodeport.h` | Steering map population, reply steer calls |
| `bpf/bpf_overlay.c` | `tail_handle_egw_overlay_revsnat()` with cross-gw redirect |
| `bpf/bpf_host.c` | HA redirect interception for non-gateway nodes |

## Key Go Files Changed

| File | HA Changes |
|------|------------|
| `pkg/maps/egressmap/policy.go` | Two-gateway value struct with `ActiveGW` bitmask |
| `pkg/maps/egressmap/steer.go` | New: steering map types + interface |
| `pkg/maps/egressmap/reverse.go` | New: reverse map types + interface |
| `pkg/egressgateway/policy.go` | Fixed-slot gateway assignment with `activeGW` bitmask, egress IP propagation |
| `pkg/egressgateway/manager.go` | Policy map with `activeGW`, reverse map reconciliation (active-only), HA redirect define |
| `pkg/option/config.go` | `EnableEgressGatewayHARedirect` option |
| `cilium-dbg/cmd/bpf_egress_steer.go` | New: `cilium bpf egress steer` command |
| `cilium-dbg/cmd/bpf_egress_steer_list.go` | New: `cilium bpf egress steer list` |

## BPF Gotchas

- Variables must be declared at top of scope (C89 `-Wdeclaration-after-statement`)
- No `memset()` / `__builtin_memset()` — use field-by-field assignment
- No partial designated initializers — compiler generates implicit memset
- `ENABLE_EGRESS_GATEWAY_COMMON` scope for things needed in `nat.h` (not `ENABLE_EGRESS_GATEWAY`)
- Tunnel-arrived packets skip `egress_gw_handle_packet()` via `ctx_egw_done` — hash must be computed in `snat_v4_needs_masquerade()` not earlier
- `IPV4_DIRECT_ROUTING` is per-node BPF define equal to node's K8s internal IP

## Documentation

| File | Content |
|------|---------|
| `HA_EGRESS_GW_DESIGN.md` | Full architecture, algorithms, map schemas, file change list |
| `HA_EGRESS_RESOLVED_PROBLEMS.md` | Fixed issues and implemented resolutions |
| `HA_EGRESS_ONGOING_PROBLEMS.md` | Active limitations, risks, and open issues |
| `HA_EGRESS_PRODUCTION_GAPS.md` | Production readiness status |
| `HA_EGRESS_TEST_SCENARIOS.md` | Reproducible test procedures |
| `HA_EGRESS_PERFORMANCE_ANALYSIS.md` | Overhead analysis vs vanilla |
| `HA_EGRESS_DEMO.md` | Step-by-step live demo script |
| `HA_EGRESS_TROUBLESHOOTING_GUIDE.md` | Testing and troubleshooting guide |
| `HA_EGRESS_GW_TUNABLES.md` | Configuration parameters, map sizes, port ranges, capacity tuning |
| `HA_EGRESS_GRPC_TUNING_GUIDE.md` | gRPC-specific tuning: CT timeouts, keepalive, failover |

## Resolved: Hash Inconsistency Bug (VERIFIED)

The ~1.5% persistent failure rate at 5000+ connections was caused by **swapped port arguments** in `egress_gw_request_needs_redirect()` (`bpf/lib/egress_gateway.h` line ~219). The worker's hash didn't match the gateway's hash, breaking port partitioning — both gateways used both port ranges, causing SNAT port collisions.

**Fix:** swap `rtuple->dport, rtuple->sport` → `rtuple->sport, rtuple->dport` in the `egress_gw_select_owner()` call.

**Verified:** 0% failure at 5K, 10K, and 60K connections (was 1.5%, 2.9%, 16.1%).

## Test Cluster

- 3-node RKE cluster: 2 gateway nodes + 1 worker
- External server: 100.64.0.129 (this is the LOCAL machine where claude runs, not a remote node — no SSH needed)
- SSH credentials for cluster nodes: rke/rke
- Container runtime: Docker (use `docker inspect --format '{{.State.Pid}}' <container_id>` to get PID for nsenter)
- To find pod container IDs: `ssh rke@<node> "sudo docker ps --format '{{.Names}} {{.ID}}' | grep <pod-name>"`
- Use the pause container (k8s_POD_*) PID for `nsenter --net` since it owns the network namespace
- **Always use nsenter via SSH to access cilium/pod network namespaces** — never use `kubectl exec` for BPF map operations or network debugging. Use `sshpass -p rke ssh rke@<node> "sudo nsenter --net -t <PID> <command>"` for pods, and find the cilium agent PID via `docker inspect` on the cilium container for cilium operations (e.g. `bpftool map dump`)
- Tunnel mode: Geneve, LB mode: DSR
- Docker image: `docker.io/valexz/cilium-ha-egw:<tag>`
- Image deployment: save locally with `docker save`, copy to each node via `scp`, load with `docker load`:
  ```
  docker save docker.io/valexz/cilium-ha-egw:<tag> | gzip > /tmp/cilium-ha-egw-<tag>.tar.gz
  for node in <gw0> <gw1> <worker>; do scp /tmp/cilium-ha-egw-<tag>.tar.gz rke@$node:/tmp/ && ssh rke@$node "sudo docker load < /tmp/cilium-ha-egw-<tag>.tar.gz"; done
  ```
- Test tools: Go TCP client/server (`cmd/client`, `cmd/server`) and HTTP/2 client/server (`cmd/h2client`, `cmd/h2server`) in `ha_egress_gw_test/` (see `HA_EGRESS_TEST_SCENARIOS.md`)
- Validated: 60K concurrent connections, rotating routes, multi-policy, 0 failures; 150K HTTP/2 failure/recovery at 500 rps
