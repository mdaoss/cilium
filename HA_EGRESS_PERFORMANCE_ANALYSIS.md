# HA Egress Gateway — Performance Overhead Analysis

Comparison of active/active HA egress gateway vs vanilla Cilium v1.16.10
single-gateway egress implementation.

---

## Outbound Path (Pod → External)

| Step | Vanilla | HA | Overhead |
|------|---------|-----|----------|
| Policy map lookup (LPM trie) | 1 lookup | 1 lookup | None |
| SNAT (`snat_v4_nat()`) | Yes | Yes | None |
| Steering map write | — | `map_update_elem()` on LRU hash | +1 BPF map write |
| L4 header read for steering | — | `ctx_load_bytes()` (4 bytes) | +1 packet read |

**Estimated overhead:** ~50–100ns per packet (one LRU hash update + one L4
header read). The LRU hash is preallocated — no allocation, no lock contention
on per-CPU paths.

**Code:** `bpf/lib/nodeport.h:1756-1783` — conditional on
`target.egress_gateway && target.egress_gw_owner_ip != 0`, TCP/UDP only.

---

## Reply Path — Normal Case (Reply Arrives at Owner Gateway)

| Step | Vanilla | HA | Overhead |
|------|---------|-----|----------|
| L4 header read | — | `ctx_load_bytes()` (4 bytes) | +1 packet read |
| Steering map lookup | — | `map_lookup_elem()` on LRU hash | +1 BPF map read |
| Endpoint check | — | `__lookup_ip4_endpoint()` (confirms local) | +1 endpoint lookup |
| Reverse SNAT | Yes | Yes | None |
| Local delivery | Yes | Yes | None |

**Estimated overhead:** ~30–80ns per packet. The steering map lookup hits,
confirms local ownership, and falls through to normal `snat_v4_rev_nat()`.
This is the common case (~50% of replies with 2-way ECMP).

**Code:** `bpf/lib/egress_gateway.h:398-475` (`egress_gw_reply_steer()`).

---

## Reply Path — Asymmetric (Reply Arrives at Wrong Gateway)

| Step | Vanilla | HA | Overhead |
|------|---------|-----|----------|
| Steering map lookup | — | Hit → owner is remote | +1 map read |
| Tunnel encap + redirect | N/A | `__encap_and_redirect_with_nodeid()` | Full tunnel hop |
| Overlay receive on owner | — | `tail_handle_egw_overlay_revsnat()` | +1 tail call |
| Reverse SNAT on owner | — | `snat_v4_rev_nat()` | Same as vanilla |
| Local delivery on owner | — | `ipv4_local_delivery()` | Same as vanilla |

**Estimated overhead:** ~5–15us — dominated by tunnel encap/decap (one extra
network hop within the cluster). This case does not exist in vanilla (single
gateway = no asymmetry). With 2-way ECMP, ~50% of replies take this path.

**Code:** `bpf/lib/egress_gateway.h:398-475` (redirect branch),
`bpf/bpf_overlay.c:491-562` (overlay handler).

---

## Reply Path — Worker Redirect (HA Redirect Feature)

Requires `egress-gateway-ha-redirect: "true"` in cilium config. Allows any
node (not just gateways) to accept reply traffic for egress connections.

| Step | Vanilla | HA Redirect | Overhead |
|------|---------|-------------|----------|
| Reverse map lookup on worker | N/A | `map_lookup_elem()` (4-byte key) | +1 map read |
| Tunnel encap to gateway | N/A | `__encap_and_redirect_with_nodeid()` | Full tunnel hop |
| Overlay receive on gateway | N/A | Reverse map check + tail call | +1 map read + tail call |
| Reverse SNAT on gateway | N/A | `snat_v4_rev_nat()` | Same cost |
| Cross-gateway redirect (50%) | N/A | Second tunnel hop | +1 more tunnel hop |

**Estimated overhead:** ~10–30us — 1 or 2 tunnel hops. This path does not
exist in vanilla at all. Worst case is 2 hops: worker → wrong gateway →
correct gateway.

**Code:** `bpf/bpf_host.c:731-758` (from-netdev intercept),
`bpf/bpf_overlay.c:509-535` (cross-gateway redirect on NAT miss).

---

## Memory Overhead

| Map | Type | Max Entries | Entry Size | Total |
|-----|------|-------------|------------|-------|
| `cilium_egress_gw_steer4` | LRU Hash | 65,536 | 28 bytes (key 20 + val 8) | ~1.8 MB per node |
| `cilium_egress_gw_reverse4` | Hash (NO_PREALLOC) | 64 | 12 bytes (key 4 + val 8) | ~768 bytes per node |

Vanilla has neither map. **Total memory overhead: ~1.8 MB per node.**

The steering map size is configurable via `egress-gateway-steer-map-max` in
the cilium configmap (default 65536).

---

## Instruction Count Overhead

| Path | Vanilla | HA Additional |
|------|---------|---------------|
| Outbound (after SNAT) | 0 | ~30 (conditional + key build + map write) |
| Reply (owner, common case) | 0 | ~40 (key build + map read + endpoint check) |
| Reply (non-owner) | N/A | ~60 + tunnel encap |
| Worker redirect | N/A | ~20 (map read) + tunnel encap |

---

## Summary

| Metric | Impact | When |
|--------|--------|------|
| Outbound latency | +50–100ns | Every egress TCP/UDP packet |
| Reply latency (owner) | +30–80ns | Replies at correct gateway (~50% with ECMP) |
| Reply latency (non-owner) | +5–15us | Replies at wrong gateway (~50% with ECMP) |
| Reply latency (worker redirect) | +10–30us | Only with `egress-gateway-ha-redirect` |
| Memory | +1.8 MB | Per node, constant |
| Tail call slots | +1 | ID 50 (`CILIUM_CALL_IPV4_EGW_OVERLAY_REVSNAT`) |

---

## Key Observations

1. **Zero overhead when disabled.** All HA code is behind `#ifdef
   ENABLE_EGRESS_GATEWAY` guards. If egress gateway is disabled, no maps are
   created and no instructions execute.

2. **Negligible overhead on the hot path.** The outbound steering map write
   (~100ns) and reply steering map read (~80ns) are single BPF hash
   operations — comparable to one conntrack lookup that already happens on
   every packet.

3. **Tunnel hops only on asymmetric replies.** The expensive path (tunnel
   encap/decap at ~5–15us) only fires when a reply arrives at the wrong node.
   With 2-way ECMP this is ~50% of replies. Without ECMP (single gateway
   receiving all replies), it is 0%.

4. **LRU eviction is free.** The steering map uses `BPF_MAP_TYPE_LRU_HASH`,
   so stale entries are automatically evicted with no GC overhead or periodic
   cleanup.

5. **No extra kernel lock contention.** LRU hash maps use per-CPU buckets
   internally, so concurrent writes from different CPUs do not contend.

6. **Worker redirect adds one config-gated hop.** The
   `egress-gateway-ha-redirect` feature adds a reverse map lookup (~20ns) in
   the from-netdev path on every incoming packet whose daddr matches an egress
   IP. The tunnel hop is the dominant cost, not the map lookup.

7. **Compared to alternatives.** The overhead of one BPF map lookup + one
   tunnel hop per asymmetric reply is comparable to what `kube-proxy` iptables
   does for `externalTrafficPolicy: Cluster` (DNAT + conntrack + forward),
   but entirely in eBPF with no iptables rules.
