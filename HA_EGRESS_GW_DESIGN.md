# IPv4 Active/Active High Availability Egress Gateway — Implementation Design

**Target:** Cilium v1.16.10
**Scope:** IPv4 only, exactly 2 active gateways per policy, active/active (not primary/secondary)
**Status:** Prototype complete. See [HA_EGRESS_PRODUCTION_GAPS.md](HA_EGRESS_PRODUCTION_GAPS.md) for remaining work.

---

## 1. Architecture Summary

### Current Architecture (Single Gateway)

Today each `CiliumEgressGatewayPolicy` maps to a single active gateway node. The flow:

1. **Policy map** (`cilium_egress_gw_policy_v4`, LPM trie) maps `(src_ip, dst_cidr)` → `(egress_ip, gateway_ip)`.
2. **Forward path** (`from_container` / `to-netdev`): packet matches policy → if local node is gateway, SNAT locally; otherwise tunnel-encap to gateway node.
3. **SNAT** on gateway: `snat_v4_nat()` with `ipv4_nat_target{.addr=egress_ip, .min_port=NODEPORT_PORT_MIN_NAT, .max_port=NODEPORT_PORT_MAX_NAT}`.
4. **Reply path** (`to-netdev`): `egress_gw_reply_matches_policy()` matches reverse tuple → tunnel-encap reply to source pod's node. Gateway also does `snat_v4_rev_nat()` to undo SNAT.

### Active/Active Architecture

```
                    ┌─────────────────────────────────┐
                    │  CiliumEgressGatewayPolicy       │
                    │  nodeSelector matches 2 nodes    │
                    │  egressIP: 10.0.100.50           │
                    └──────────┬──────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                                 ▼
     ┌─────────────────┐              ┌─────────────────┐
     │  Gateway 0       │              │  Gateway 1       │
     │  Node IP: 1.1.1.1│              │  Node IP: 2.2.2.2│
     │  SNAT ports:     │              │  SNAT ports:     │
     │  32768–38301     │              │  38302–43835     │
     └─────────────────┘              └─────────────────┘
              │                                 │
              │    Same EgressIP (10.0.100.50)  │
              │    Announced via BGP/MetalLB    │
              └────────────┬────────────────────┘
                           ▼
                    External Network
```

**Key changes:**
- Policy map value carries **two** gateway IPs and a single egress IP
- **5-tuple hash** on forward path selects gateway 0 or gateway 1
- **SNAT port partitioning**: gateway 0 uses lower half, gateway 1 uses upper half of `NODEPORT_PORT_MIN_NAT–NODEPORT_PORT_MAX_NAT`
- **Steering map** persists `(reply-tuple → owner)` for asymmetric return routing
- **Reply path**: look up steering map → redirect to owner gateway → reverse SNAT
- **Fallback**: if steering entry evicted, redirect to other gateway after rev SNAT failure
- **Reverse map** (`cilium_egress_gw_reverse4`) maps `egress_ip → (gw0, gw1)` for overlay cross-gateway redirect
- **Overlay reverse SNAT** handler: tail call from overlay for reply traffic reverse SNAT on the gateway
- **HA redirect** (optional): non-gateway nodes intercept reply traffic and tunnel to a gateway
- **Gateway health probing**: TCP probes to remote gateway nodes detect failures and update policy maps

---

## 2. Map Schema Changes

### 2.1 Policy Map Value: Two Active Gateways

**BPF struct** (`bpf/lib/common.h`):

```c
struct egress_gw_policy_entry {
	__u32 egress_ip;      /*  0: SNAT IP (same for both gateways) */
	__u32 gateway_ip_0;   /*  4: active gateway 0 node internal IP */
	__u32 gateway_ip_1;   /*  8: active gateway 1 node internal IP */
	__u32 pad;            /* 12: alignment padding to 16 bytes */
};
```

**Go mirror struct** (`pkg/maps/egressmap/policy.go`):

```go
type EgressPolicyVal4 struct {
	EgressIP   types.IPv4 `align:"egress_ip"`
	GatewayIP0 types.IPv4 `align:"gateway_ip_0"`
	GatewayIP1 types.IPv4 `align:"gateway_ip_1"`
	Pad        uint32     `align:"pad"`
}
```

### 2.2 Steering Map (New)

A new LRU hash map to persist the per-flow owner for asymmetric reply steering.

**BPF structs** (`bpf/lib/common.h`):

```c
struct egress_gw_steer_key {
	__u32 saddr;     /* reply src = server IP */
	__u32 daddr;     /* reply dst = egress IP */
	__u16 sport;     /* reply sport = server port */
	__u16 dport;     /* reply dport = SNAT port */
	__u8  nexthdr;   /* protocol */
	__u8  pad[3];    /* alignment to 16 bytes */
};

struct egress_gw_steer_val {
	__u32 owner_ip;  /* node internal IP of the owner gateway */
	__u8  owner_idx; /* 0 or 1 — which gateway owns this flow */
	__u8  pad[3];
};
```

**BPF map definition** (`bpf/lib/egress_gateway.h`):

```c
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct egress_gw_steer_key);
	__type(value, struct egress_gw_steer_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_GW_STEER_MAP_SIZE);  /* 65536 */
} cilium_egress_gw_steer4 __section_maps_btf;
```

**Go mirror** (`pkg/maps/egressmap/steer.go`):

```go
type EgressSteerKey4 struct {
	SAddr   types.IPv4 `align:"saddr"`
	DAddr   types.IPv4 `align:"daddr"`
	SPort   uint16     `align:"sport"`
	DPort   uint16     `align:"dport"`
	NextHdr uint8      `align:"nexthdr"`
	Pad     [3]uint8   `align:"pad"`
}

type EgressSteerVal4 struct {
	OwnerIP  types.IPv4 `align:"owner_ip"`
	OwnerIdx uint8      `align:"owner_idx"`
	Pad      [3]uint8   `align:"pad"`
}
```

**Why this key works:** On the reply path, BEFORE reverse SNAT, the packet has
`src=server_ip, dst=egress_ip, sport=server_port, dport=snat_port`. This
5-tuple is exactly the steering key, written during forward-path SNAT by
swapping src↔dst from the post-SNAT packet.

### 2.3 Reverse Map (New)

A small hash map mapping each egress IP to the pair of gateways that serve it.
Used by the overlay reverse SNAT handler to cross-redirect when a reply arrives
at the wrong gateway, and by the HA redirect feature on non-gateway nodes.

**BPF structs** (`bpf/lib/common.h`):

```c
struct egress_gw_reverse_key {
	__be32 egress_ip;
};

struct egress_gw_reverse_val {
	__be32 gateway_ip_0;
	__be32 gateway_ip_1;
};
```

**BPF map definition** (`bpf/lib/egress_gateway.h`):

```c
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct egress_gw_reverse_key);
	__type(value, struct egress_gw_reverse_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_egress_gw_reverse4 __section_maps_btf;
```

**Go mirror** (`pkg/maps/egressmap/reverse.go`):

```go
type EgressReverseKey4 struct {
	EgressIP types.IPv4 `align:"egress_ip"`
}

type EgressReverseVal4 struct {
	GatewayIP0 types.IPv4 `align:"gateway_ip_0"`
	GatewayIP1 types.IPv4 `align:"gateway_ip_1"`
}
```

Populated by `reconcileReverseMap()` in `pkg/egressgateway/manager.go` during
each reconciliation cycle. Max 64 entries (one per unique egress IP).

---

## 3. Datapath Algorithm — Step by Step

### 3.1 Forward Path

```
Pod → from_container → to-netdev (or overlay)

1. egress_gw_handle_packet() is called
   - Calls egress_gw_request_needs_redirect_hook() → egress_gw_request_needs_redirect()
   - Looks up policy for (saddr, daddr)

2. egress_gw_request_needs_redirect(): active_gw-based gateway selection
   - If gateway_ip_1 != 0 (HA policy, both IPs always in fixed slots):
     - Check active_gw bitmask (EGRESS_GW_ACTIVE_0/1/BOTH):
       - ACTIVE_BOTH: hash = egress_gw_select_owner(5-tuple)
         gateway_ip = (hash & 1 == 0) ? gateway_ip_0 : gateway_ip_1
       - ACTIVE_1 only: gateway_ip = gateway_ip_1
       - ACTIVE_0 only: gateway_ip = gateway_ip_0
   - If gateway_ip_1 == 0 (non-HA single gateway):
     - gateway_ip = gateway_ip_0

3. If gateway_ip is this node → let packet through for local SNAT
   Else → tunnel-encap to gateway_ip

4. On the gateway node, nodeport_snat_fwd_ipv4() is called:
   - snat_v4_needs_masquerade() → egress_gw_snat_needed_hook()
     Returns egress_ip as target.addr, plus gw_ip0 and gw_ip1
   - If gw_ip1 != 0: determine own fixed port range by comparing
     IPV4_DIRECT_ROUTING against gw_ip0/gw_ip1 (no hash needed):
     - IPV4_DIRECT_ROUTING == gw_ip0 → port range 0
     - IPV4_DIRECT_ROUTING == gw_ip1 → port range 1
   - Each gateway ALWAYS uses its own fixed port range, even in
     single-active mode. This prevents port collisions during
     failover/recovery — a gateway never uses ports reserved for
     the other.
   - Store owner_idx and owner_ip (=IPV4_DIRECT_ROUTING) in
     ipv4_nat_target struct
   - snat_v4_nat() allocates port from the fixed range

5. After SNAT succeeds, populate steering map (nodeport_snat_fwd_ipv4):
   - Re-read post-SNAT packet to get allocated SNAT port
   - egress_gw_steer_update(ip4->saddr, ip4->daddr,
                             ports[0], ports[1], ip4->protocol,
                             IPV4_DIRECT_ROUTING,
                             target.egress_gw_owner_idx)
   - The function swaps src↔dst to form the reply-direction key
```

### 3.2 Reply Path

```
External → gateway node (either one, due to ECMP/BGP)

1. tail_nodeport_nat_ingress_ipv4() is called

2. BEFORE snat_v4_rev_nat(): egress_gw_reply_steer(ctx, ip4, &ext_err)
   - egress_gw_reply_matches_policy(ip4) — confirms this is an EGW reply
   - Only TCP/UDP (ICMP has no port-based steering)
   - Extract L4 ports via ctx_load_bytes()
   - Build steering key from reply 5-tuple:
     { saddr=ip4->saddr, daddr=ip4->daddr, sport=ports[0],
       dport=ports[1], nexthdr=ip4->protocol }
   - map_lookup_elem(&cilium_egress_gw_steer4, &key)
     - No entry: return CTX_ACT_OK (try local rev SNAT)
     - Entry found, owner is local (__lookup_ip4_endpoint + ENDPOINT_F_HOST):
       return CTX_ACT_OK (do local rev SNAT)
     - Entry found, owner is remote:
       __encap_and_redirect_with_nodeid() to owner → DONE

3. snat_v4_rev_nat() runs:
   - SUCCESS: existing path (de-SNAT → tunnel to pod's node)
   - DROP_NAT_NO_MAPPING:
     - egress_gw_reply_steer_fallback(ctx, &ext_err)
       - Re-parse packet, verify EGW reply
       - lookup_ip4_egress_gw_policy() to get both gateway IPs
       - If gateway_ip_1 == 0: no fallback (single gateway)
       - Determine "other" gateway via ENDPOINT_F_HOST check
       - __encap_and_redirect_with_nodeid() to other GW → DONE
     - If fallback returns CTX_ACT_OK: recircle (existing behavior)
```

### 3.3 Overlay Reverse SNAT Path

When a reply is redirected via tunnel (either from steering or from HA redirect),
it arrives at the gateway's overlay interface. A dedicated tail call handles
reverse SNAT on the overlay:

```
Reply arrives via overlay tunnel on gateway
  → tail_handle_egw_overlay_revsnat() [CILIUM_CALL_IPV4_EGW_OVERLAY_REVSNAT]
    → snat_v4_rev_nat()
      → SUCCESS: ipv4_local_delivery() to pod
      → DROP_NAT_NO_MAPPING:
        → Reverse map lookup: find the OTHER gateway
        → __encap_and_redirect_with_nodeid() to peer gateway → DONE
        (Cross-gateway redirect handles the case where HA redirect
         or steering sent the reply to the wrong gateway of the pair)
```

**Code:** `bpf/bpf_overlay.c` — `tail_handle_egw_overlay_revsnat()` is
registered as tail call ID 50 (`CILIUM_CALL_IPV4_EGW_OVERLAY_REVSNAT`).

The cross-gateway redirect on `DROP_NAT_NO_MAPPING` uses `cilium_egress_gw_reverse4`
to determine the peer: if `gateway_ip_0 == IPV4_DIRECT_ROUTING` (this node),
redirect to `gateway_ip_1`, and vice versa.

### 3.4 HA Redirect Path (Non-Gateway Nodes)

When `egress-gateway-ha-redirect: "true"` is set in cilium config, non-gateway
nodes can intercept incoming reply traffic destined for an egress IP and
redirect it to a gateway via tunnel. This provides `externalTrafficPolicy:
Cluster`-like behavior for egress gateway replies.

```
Reply arrives at non-gateway worker node → from-netdev
  → handle_ipv4_cont()
    → Reverse map lookup: rkey.egress_ip = ip4->daddr
    → If match AND node is NOT a gateway (neither gw0 nor gw1):
      → __encap_and_redirect_with_nodeid() to gateway_ip_0 → DONE
    → If node IS a gateway: fall through to normal egress GW processing
    → If no match: fall through (not an egress reply)
```

**Code:** `bpf/bpf_host.c` in `handle_ipv4_cont()`, guarded by
`#ifdef ENABLE_EGRESS_GATEWAY_HA_REDIRECT`. The node identity check uses
`IPV4_DIRECT_ROUTING` (the per-node BPF define equal to the node's K8s
internal IP) compared against both `rval->gateway_ip_0` and `rval->gateway_ip_1`.

**Config:** Enabled via `egress-gateway-ha-redirect: "true"` in the cilium
configmap. Emits `ENABLE_EGRESS_GATEWAY_HA_REDIRECT` BPF define.

### 3.5 Gateway Health Probing

When a gateway node fails (e.g., VM crash, hard shutdown), the Kubernetes Node
object transitions to `NotReady` but the `CiliumNode` CR persists. Since the
egress gateway manager only reacts to `CiliumNode` deletions, the dead gateway
remains in the policy map, causing ~50% of new connections to black-hole.

The gateway prober solves this by periodically TCP-connecting to port 4240
(Cilium agent health API) on each remote gateway node:

```
Gateway Prober (goroutine per agent)
  │
  │  every probe-interval (default 1s)
  ├──► TCP connect to gw0:4240 (1s timeout)
  ├──► TCP connect to gw1:4240 (1s timeout)
  │
  │  3 consecutive failures (~3s)
  ├──► gatewayHealthEvent{nodeName, healthy: false}
  │       │
  │       ▼
  │    Manager.processEvents()
  │       │
  │       ├── unhealthyGateways[nodeName] = struct{}{}
  │       └── reconcileLocked()
  │             │
  │             ├── regenerateGatewayConfig() skips unhealthy nodes
  │             ├── Policy map updated: single-gateway mode
  │             └── updateProberTargets() refreshes probe list
  │
  │  40 consecutive successes after recovery (~40s)
  └──► gatewayHealthEvent{nodeName, healthy: true}
          │
          ▼
       delete(unhealthyGateways, nodeName)
       if recovery-hold-time > 0:
         mark gateway held until now+hold
         reconcileLocked() keeps single-gateway mode
         timer triggers reconcile on hold expiry
       else:
         reconcileLocked() restores dual-gateway mode
```

**Detection timeline:** With default settings (1s interval, 3 failures, 1s
timeout), a dead gateway is removed from the policy map in ~3–4s. This is
faster than Kubernetes marking the Node `NotReady` (~40s).

**Recovery hold (optional):** `egress-gateway-probe-recovery-hold-time` can
delay gateway re-selection after probe recovery. This is useful when external
ECMP/BGP convergence may lag behind local Cilium readiness.

**Deadlock prevention:** `handleProbeResult()` determines the event to send
while holding `p.mu`, then releases the lock before sending on the channel.
This avoids a three-way deadlock: prober holds `p.mu` → blocks on full channel
→ `processEvents` blocked by manager `Mutex` → trigger goroutine holds manager
`Mutex` → calls `setTargets` → blocks on `p.mu`.

**Code:** `pkg/egressgateway/gateway_prober.go`

### 3.6 Port Partitioning

```c
/* bpf/lib/egress_gateway.h — inside ENABLE_EGRESS_GATEWAY_COMMON */
#define EGRESS_GW_PORT_RANGE_SIZE (NODEPORT_PORT_MAX_NAT - NODEPORT_PORT_MIN_NAT + 1)
#define EGRESS_GW_PORT_MID        (NODEPORT_PORT_MIN_NAT + EGRESS_GW_PORT_RANGE_SIZE / 2)
#define EGRESS_GW_PORT_MIN_0      NODEPORT_PORT_MIN_NAT       /* typically 32768 */
#define EGRESS_GW_PORT_MAX_0      (EGRESS_GW_PORT_MID - 1)    /* typically 38301 */
#define EGRESS_GW_PORT_MIN_1      EGRESS_GW_PORT_MID          /* typically 38302 */
#define EGRESS_GW_PORT_MAX_1      NODEPORT_PORT_MAX_NAT       /* typically 43835 */
```

Each gateway allocates SNAT ports exclusively from its **fixed** partition,
eliminating port collisions when both gateways share the same egress IP.
The port range is determined by the gateway's slot assignment (comparing
`IPV4_DIRECT_ROUTING` against `gateway_ip_0`/`gateway_ip_1` in the policy
map), NOT by the per-flow hash. A gateway never uses ports reserved for
the other gateway, even during single-active failover mode.

**Note:** The port range is derived from `NODEPORT_PORT_MIN_NAT` /
`NODEPORT_PORT_MAX_NAT` (typically 32768–43835), yielding ~5,500 ports per
gateway. See [HA_EGRESS_PRODUCTION_GAPS.md](HA_EGRESS_PRODUCTION_GAPS.md) §3 for discussion of
using a wider range.

---

## 4. Implementation Phases (Aligned with Commits)

### Phase 1–2: Struct/Map Schema + Control Plane + Forward Path
**Commit:** `3c383a20ca` — `egress-gateway: implement active/active HA phases 1-2`

**BPF changes:**
| File | Changes |
|------|---------|
| `bpf/lib/common.h` | Extended `egress_gw_policy_entry` (8→16 bytes) with `gateway_ip_0`, `gateway_ip_1`, `active_gw` (bitmask). Added `EGRESS_GW_ACTIVE_0/1/BOTH` constants. Added `egress_gw_steer_key`, `egress_gw_steer_val` structs. |
| `bpf/lib/egress_gateway.h` | Added `#include "lib/jhash.h"`. Port partition macros (`EGRESS_GW_PORT_*`) and `egress_gw_select_owner()` inside `ENABLE_EGRESS_GATEWAY_COMMON`. Steering map definition and `egress_gw_steer_update()` inside `ENABLE_EGRESS_GATEWAY`. Modified `egress_gw_request_needs_redirect()` to use `active_gw` bitmask for gateway selection: hash only when both active, otherwise route to the active one. Extended `egress_gw_snat_needed()` / `egress_gw_snat_needed_hook()` signatures with `gw_ip0`/`gw_ip1` output params. |
| `bpf/lib/nat.h` | Removed `const` from `ipv4_nat_target.min_port`/`max_port`. Added `egress_gw_owner_idx` and `egress_gw_owner_ip` fields. Added HA block in `snat_v4_needs_masquerade()`: determines gateway's own fixed port range by comparing `IPV4_DIRECT_ROUTING` against `gw_ip0`/`gw_ip1` (no hash needed on SNAT path). |
| `bpf/lib/nodeport.h` | Added steering map population in `nodeport_snat_fwd_ipv4()` after `snat_v4_nat()`: re-reads post-SNAT packet, calls `egress_gw_steer_update()` for TCP/UDP flows. |
| `bpf/bpf_overlay.c` | Updated `egress_gw_snat_needed_hook()` call site with new `gw_ip0`, `gw_ip1` params. |
| `bpf/bpf_alignchecker.c` | Added `egress_gw_steer_key`, `egress_gw_steer_val` for alignment checking. |
| `bpf/tests/lib/egressgw_policy.h` | Updated test helper for new struct layout. |

**Go changes:**
| File | Changes |
|------|---------|
| `pkg/maps/egressmap/policy.go` | `EgressPolicyVal4` with `GatewayIP0`, `GatewayIP1`, `Pad`. `Update()` takes 5 args. `GetGatewayAddr0()`/`GetGatewayAddr1()` replace `GetGatewayAddr()`. `Match()` checks both gateways. |
| `pkg/maps/egressmap/steer.go` | **New file.** `EgressSteerKey4`, `EgressSteerVal4`, `SteerMap` interface, `steerMap` implementation with LRU hash. `CreatePrivateSteerMap()` for tests. |
| `pkg/maps/egressmap/egress.go` | Added `createSteerMapFromDaemonConfig` Cell provider with `EGRESS_GW_STEER_MAP_SIZE` node define. |
| `pkg/egressgateway/policy.go` | Added `gatewayIP1` to `gatewayConfig`. `regenerateGatewayConfig()` collects up to 2 nodes sorted by name. |
| `pkg/egressgateway/manager.go` | `addMissingEgressRules()` and `removeUnusedEgressRules()` thread both gateway IPs through policy map operations. |
| `pkg/datapath/alignchecker/alignchecker.go` | Added `EgressSteerKey4`, `EgressSteerVal4` alignment checks. |
| `cilium-dbg/cmd/bpf_egress_list.go` | Shows `Gateway IP 0` and `Gateway IP 1` columns. |
| `pkg/maps/egressmap/policy_test.go` | Updated for two-gateway `Update()`/`Lookup()` calls. |
| `pkg/egressgateway/manager_privileged_test.go` | Updated `egressRule`/`parsedEgressRule` structs and helpers for `gatewayIP1`. |

**Key design decisions:**

1. **Hash computed in `snat_v4_needs_masquerade()`, not via CB slot.** The
   design doc originally proposed storing `owner_idx` in `CB_EGRESS_GW_OWNER_IDX`
   from `egress_gw_handle_packet()`. However, tunnel-arrived packets skip
   `egress_gw_handle_packet()` (via `ctx_egw_done` mark), so the CB would not be
   set. Computing the hash in `snat_v4_needs_masquerade()` handles both local
   and tunnel-arrival paths uniformly.

2. **L4 ports re-extracted from packet headers.** In `snat_v4_needs_masquerade()`,
   `tuple->dport` and `tuple->sport` are cleared to 0 before the egress gateway
   section. Rather than changing that invariant, the HA block reads the 4-byte L4
   header directly from the packet via `ctx_load_bytes(ctx, l4_off, ...)`.

3. **Port macros and `egress_gw_select_owner()` in `ENABLE_EGRESS_GATEWAY_COMMON`
   scope** (not `ENABLE_EGRESS_GATEWAY`) so they are available in `nat.h`, which
   uses `ENABLE_EGRESS_GATEWAY_COMMON`.

---

### Phase 3: Reply Path — Steering Map Lookup & Inter-Gateway Redirect
**Commit:** `06dafabdd6` — `egress-gateway: add reply-path steering for active/active HA (phase 3)`

**BPF changes only (2 files):**

| File | Changes |
|------|---------|
| `bpf/lib/egress_gateway.h` | Added `egress_gw_reply_steer()` — pre-steering before rev SNAT. Added `egress_gw_reply_steer_fallback()` — post-failure fallback after `DROP_NAT_NO_MAPPING`. Both guarded by `ENABLE_EGRESS_GATEWAY && !IS_BPF_OVERLAY`. |
| `bpf/lib/nodeport.h` | In `tail_nodeport_nat_ingress_ipv4()`: (1) Before `snat_v4_rev_nat()`: calls `egress_gw_reply_steer()`, returns redirect or drop immediately. (2) After `DROP_NAT_NO_MAPPING`: calls `egress_gw_reply_steer_fallback()`, returns redirect if successful. |

**`egress_gw_reply_needs_redirect_hook()` is unchanged.** It continues to
handle the owner-gateway case after successful rev SNAT: `ip4->daddr` is the
pod IP at that point, so `lookup_ip4_remote_endpoint()` finds the pod's node
and tunnels the reply there.

---

### Phase 4: Debug Tooling & Unit Tests
**Commit:** `5e29082548` — `egress-gateway: add steering map CLI and unit tests (phase 4)`

**Go changes only (4 files):**

| File | Changes |
|------|---------|
| `pkg/maps/egressmap/steer.go` | Added `Update()` method to `SteerMap` interface. Added `OpenPinnedSteerMap()` for CLI access. |
| `cilium-dbg/cmd/bpf_egress_steer.go` | **New file.** Parent `cilium bpf egress steer` command. |
| `cilium-dbg/cmd/bpf_egress_steer_list.go` | **New file.** `cilium bpf egress steer list [-o json]` dumps steering map entries. |
| `pkg/maps/egressmap/steer_test.go` | **New file.** Privileged unit test for steering map CRUD (Update, Lookup, Delete, IterateWithCallback). |

---

## 5. Decision Matrix

| Scenario | Steering entry? | Rev SNAT? | Action |
|----------|----------------|-----------|--------|
| Reply at owner | Found, local | Succeeds | Normal path: de-SNAT → tunnel to pod |
| Reply at non-owner | Found, remote | Skipped | `egress_gw_reply_steer` → tunnel to owner |
| Reply at owner, LRU evicted | Not found | Succeeds | Normal path (steering miss is harmless) |
| Reply at non-owner, LRU evicted | Not found | Fails | `egress_gw_reply_steer_fallback` → tunnel to other GW |
| Reply, single gateway | Not found | Succeeds | Normal path (no HA active) |
| Reply at non-gateway worker (HA redirect) | N/A | N/A | Reverse map hit → tunnel to gw0 → overlay rev SNAT |
| Reply at wrong gw via overlay | N/A | Fails | Cross-gw redirect via reverse map → tunnel to peer |
| Non-EGW reply | N/A | N/A | Passes through unchanged |

---

## 6. Hash Consistency

A critical invariant: the redirect path and the SNAT path produce the **same**
owner index for a given flow. Both use `egress_gw_select_owner()` with the
forward-direction 5-tuple:

| Path | Source of 5-tuple fields |
|------|--------------------------|
| `egress_gw_request_needs_redirect()` | Reversed CT tuple: `(rtuple->daddr, rtuple->saddr, rtuple->dport, rtuple->sport, rtuple->nexthdr)` |
| `snat_v4_needs_masquerade()` | Forward tuple + packet L4: `(tuple->saddr, tuple->daddr, l4_ports[0], l4_ports[1], tuple->nexthdr)` |

Both resolve to `(pod_ip, server_ip, pod_port, server_port, protocol)`.

The hash function:

```c
static __always_inline __u8
egress_gw_select_owner(__be32 saddr, __be32 daddr,
                       __be16 sport, __be16 dport, __u8 nexthdr)
{
	__u32 hash = jhash_3words((__u32)saddr, (__u32)daddr,
	                          ((__u32)sport << 16) | (__u32)dport,
	                          (__u32)nexthdr);
	return hash & 1;
}
```

---

## 7. Answering Key Questions

### Where does current egress gateway choose the gateway/node today?

1. **Control plane**: `PolicyConfig.regenerateGatewayConfig()` in `pkg/egressgateway/policy.go` iterates `manager.nodes` and picks matching nodes. Now picks up to 2 (sorted by name for determinism).
2. **BPF forward path**: `egress_gw_request_needs_redirect()` reads the policy map. With HA, hashes the 5-tuple to select between `gateway_ip_0` and `gateway_ip_1`.
3. **BPF SNAT path**: `snat_v4_needs_masquerade()` reads egress IP and both gateway IPs, computes hash, sets partitioned port range.

### Whether owner is recomputed, persisted, or both?

**Both.** On the forward path, it's computed from the 5-tuple. The result is
persisted in the steering map keyed by the reply-path tuple. On the reply path,
the steering map is authoritative because the reply packet does not carry enough
info to reconstruct the original 5-tuple before reverse SNAT.

### What tuple information exists on reply path before reverse SNAT?

- `src = server_ip` (original destination)
- `dst = egress_ip` (post-SNAT source, NOT the original pod IP)
- `sport = server_port` (original destination port)
- `dport = snat_port` (allocated SNAT port, NOT original source port)

We do NOT have the original pod IP or original source port, so we cannot
recompute the original 5-tuple hash. The steering map is the only mechanism
for reply-path owner identification.

### How replies are redirected between active gateways?

Via VxLAN/Geneve tunnel encapsulation using `__encap_and_redirect_with_nodeid()`.
The reply arrives at a gateway, the steering map identifies the owner, and if
the current node is not the owner, it tunnel-encaps to the owner's node IP.

### Behavior if steering entry is missing?

1. Try `snat_v4_rev_nat()` locally — maybe this node IS the owner and the LRU evicted the steering entry but the SNAT entry still exists.
2. If local rev_nat fails, `egress_gw_reply_steer_fallback()` looks up the policy map to find both gateways, then redirects to the OTHER gateway via tunnel.
3. If that gateway also fails, the packet is dropped.

### Where SNAT port selection happens and how partitioning is injected?

SNAT port selection happens in `snat_v4_new_mapping()` at `bpf/lib/nat.h`.
The `target->min_port` and `target->max_port` are the gateway's **fixed**
port range, determined in `snat_v4_needs_masquerade()` by comparing
`IPV4_DIRECT_ROUTING` against the two gateway IPs in the policy map
(no per-flow hash needed on the SNAT path). Each gateway always uses
its own half of the port range regardless of whether the other gateway
is active. The `ipv4_nat_target` struct carries these values (along with
`egress_gw_owner_idx` and `egress_gw_owner_ip`) through to the post-SNAT
steering map insertion.

---

## 8. Files Changed (Complete List)

### BPF Side

| File | Commit | Changes |
|------|--------|---------|
| `bpf/lib/common.h` | Phase 1–2 | Extended `egress_gw_policy_entry` with `active_gw` bitmask, added steer structs |
| `bpf/lib/egress_gateway.h` | Phase 1–2, 3 | Hash, port macros, steer map + update, `active_gw`-based redirect selection, reply steer + fallback |
| `bpf/lib/nat.h` | Phase 1–2 | `ipv4_nat_target` HA fields, fixed port range via `IPV4_DIRECT_ROUTING` in `snat_v4_needs_masquerade()` |
| `bpf/lib/nodeport.h` | Phase 1–2, 3 | Steering map population after SNAT, reply steer before rev SNAT, fallback after failure |
| `bpf/bpf_overlay.c` | Phase 1–2, 3+ | Updated `egress_gw_snat_needed_hook()` call; `tail_handle_egw_overlay_revsnat()` with cross-gw redirect |
| `bpf/bpf_host.c` | HA redirect | `handle_ipv4_cont()` reverse map intercept for non-gateway nodes |
| `bpf/bpf_alignchecker.c` | Phase 1–2 | Added steer and reverse struct types |
| `bpf/tests/lib/egressgw_policy.h` | Phase 1–2 | Updated test helper for new struct |

### Go Side

| File | Commit | Changes |
|------|--------|---------|
| `pkg/maps/egressmap/policy.go` | Phase 1–2 | Two-gateway value struct, updated interfaces |
| `pkg/maps/egressmap/steer.go` | Phase 1–2, 4 | New: steering map types, interface, Cell provider, `OpenPinnedSteerMap()`, `Update()` |
| `pkg/maps/egressmap/egress.go` | Phase 1–2 | Steering map Cell provider |
| `pkg/egressgateway/policy.go` | Phase 1–2, HA redirect, prober | `gatewayIP1`, `regenerateGatewayConfig` picks 2 nodes (skips unhealthy), egress IP propagation to non-gateway nodes |
| `pkg/option/config.go` | HA redirect | `EnableEgressGatewayHARedirect` config option |
| `pkg/egressgateway/gateway_prober.go` | Prober | **New file.** TCP health probing of remote gateway nodes, deadlock-safe event dispatch |
| `pkg/egressgateway/manager.go` | Phase 1–2, HA redirect, prober | Two-gateway policy map population, `reconcileReverseMap()`, `ENABLE_EGRESS_GATEWAY_HA_REDIRECT` define, gateway prober lifecycle + health event handling, `unhealthyGateways` set, `updateProberTargets()` |
| `pkg/datapath/alignchecker/alignchecker.go` | Phase 1–2 | Steer struct alignment checks |
| `cilium-dbg/cmd/bpf_egress_list.go` | Phase 1–2 | Two-gateway column display |
| `cilium-dbg/cmd/bpf_egress_steer.go` | Phase 4 | New: parent steer command |
| `cilium-dbg/cmd/bpf_egress_steer_list.go` | Phase 4 | New: steering map list command |
| `pkg/maps/egressmap/policy_test.go` | Phase 1–2 | Updated for two-gateway tests |
| `pkg/maps/egressmap/steer_test.go` | Phase 4 | New: steering map CRUD tests |
| `pkg/egressgateway/manager_privileged_test.go` | Phase 1–2 | Updated for `gatewayIP1` |

---

## 9. Known Risks and Caveats

### 9.1 Port Range

With `NODEPORT_PORT_MIN_NAT=32768` and `NODEPORT_PORT_MAX_NAT=43835`, each
gateway gets ~5,500 ports. This may be insufficient for high-connection
workloads. A wider range (e.g., 1024–65535) would give ~32K ports per gateway
but requires verifying no conflict with NodePort and other SNAT users.

### 9.2 Map Size Change

Policy map value changed from 8→16 bytes. Rolling upgrade with mixed agent
versions is not supported — all agents must be restarted together.

### 9.3 LRU Eviction

The 64K-entry steering map uses LRU eviction. Under high connection rates,
active flows may be evicted. The fallback mechanism adds one extra tunnel hop
but correctly delivers the packet.

### 9.4 No CB Slot Used

The implementation computes the hash in `snat_v4_needs_masquerade()` rather
than passing `owner_idx` via a CB metadata slot from `egress_gw_handle_packet()`.
This is because tunnel-arrived packets skip `egress_gw_handle_packet()` entirely
(via `ctx_egw_done`), so a CB slot would not be set on those paths.

### 9.5 Debugging

- `cilium bpf egress list`: shows both gateway IPs per policy entry.
- `cilium bpf egress steer list`: dumps all steering map entries with owner info.
- `cilium monitor --type drop`: shows `DROP_NAT_NO_MAPPING` for failed rev SNAT.
- **Port inspection**: SNAT port in range [32768, 38301] → gateway 0; [38302, 43835] → gateway 1.

---

## 10. Production Readiness

See [HA_EGRESS_PRODUCTION_GAPS.md](HA_EGRESS_PRODUCTION_GAPS.md) for the remaining gaps. Key items
already validated on a real cluster:

- Forward path hashing, fixed per-gateway SNAT port ranges, steering map population
- Asymmetric reply steering (both directions)
- Live failover with route changes mid-traffic
- HA redirect from non-gateway worker nodes
- Cross-gateway overlay redirect on NAT miss
- Multi-policy pairs with different egress IPs
- 10K connection stress test with rotating routes (0 failures)
- 150K TCP connection failure/recovery cycle at 500 rps (0 failures, widened port range)
- 150K HTTP/2 multiplexed failure/recovery cycle at 500 rps (<0.5% failures, both gw kill directions)
- Virtual IP interface fallback (implemented in `deriveFromPolicyGatewayConfig`)
- Gateway health probing with automatic policy map failover (implemented)
- Fixed port ranges: each gateway uses its own SNAT port range even during
  single-active failover, eliminating post-recovery trickle failures
- `active_gw` bitmask: policy map always preserves gateway slot assignments,
  bitmask controls routing — backward compatible with legacy entries

Remaining gaps:
- Narrow SNAT port range (~5,500 per gateway)
- Upgrade path (coordinated restart required)
- No BPF-level unit tests
- No graceful gateway drain
