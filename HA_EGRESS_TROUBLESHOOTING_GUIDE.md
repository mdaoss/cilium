# HA Egress Gateway — Testing & Troubleshooting Guide

**Applies to:** Cilium v1.16.10 with active/active HA egress gateway (2 gateways, shared virtual egress IP)

---

## 1. Architecture Overview

```
             Pod (10.0.0.60)
             Node: 100.64.0.131 (worker)
                    │
         ┌─────────┴──────────┐  (tunnel, hash-based)
         ▼                    ▼
  Gateway 0               Gateway 1
  100.64.0.128            100.64.0.130
  SNAT ports: 32768–49151 SNAT ports: 49152–65535
         │                    │
         └────────┬───────────┘
                  ▼
         Egress IP: 100.64.0.200 (virtual, BGP/MetalLB)
                  │
         External Server (100.64.0.129)
```

**Key BPF maps:**

| Map | Type | Purpose |
|-----|------|---------|
| `cilium_egress_gw_policy_v4` | LPM trie | Policy: `(src, dst_cidr)` → `(egress_ip, gw0, gw1)` |
| `cilium_egress_gw_steer4` | LRU hash (64K) | Steering: `(reply 5-tuple)` → `(owner_ip, owner_idx)` |
| `cilium_egress_gw_reverse4` | Hash (64) | Reverse: `(egress_ip)` → `(gw0, gw1)` |

**Packet flow — forward path:**
1. Pod sends packet → BPF on worker hashes 5-tuple → tunnels to selected gateway
2. Gateway does SNAT (partitioned port range) → writes steering entry → sends to external server

**Packet flow — reply path (symmetric, reply arrives at SNAT gateway):**
1. Reply arrives at gateway's external interface → `bpf_host` TC
2. `egress_gw_reply_steer()` looks up steering map → owner is local → CTX_ACT_OK
3. `snat_v4_rev_nat()` undoes SNAT → tunnels de-SNAT'd packet to worker → pod receives it

**Packet flow — reply path (asymmetric, reply arrives at OTHER gateway):**
1. Reply arrives at non-owner gateway via ECMP
2. `egress_gw_reply_steer()` → no steering entry (per-node map) → CTX_ACT_OK
3. `snat_v4_rev_nat()` fails with `DROP_NAT_NO_MAPPING` (no local conntrack)
4. `egress_gw_reply_steer_fallback()` → reverse map lookup → tunnels to other gateway
5. Packet arrives on `cilium_vxlan` of the owner gateway → `bpf_overlay.c`
6. Reverse map lookup → tail call `tail_handle_egw_overlay_revsnat`
7. `snat_v4_rev_nat()` succeeds (local conntrack) → `ipv4_local_delivery()` to pod

---

## 2. Verifying the Setup

### 2.1 Check Cilium Pods

```bash
kubectl get pods -A -l k8s-app=cilium -o wide
```

All cilium pods must be Running and Ready. Note which pod runs on which node.

### 2.2 Check Policy Map

On each gateway node:

```bash
# Substitute the cilium pod name for each gateway
kubectl exec -n <ns> <cilium-pod-gw0> -- cilium bpf egress list
```

Expected: entries showing `(src_cidr, dst_cidr)` → `(egress_ip, gateway_ip_0, gateway_ip_1)`.

If empty, see [Troubleshooting: Empty Policy Map](#41-empty-policy-map).

### 2.3 Check Reverse Map

```bash
kubectl exec -n <ns> <cilium-pod> -- bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_reverse4
```

Expected: one entry per egress IP. Key = egress IP, value = (gw0_ip, gw1_ip).

Example (hex, network byte order):
```
key: 64 40 00 c8              # 100.64.0.200
value: 64 40 00 80 64 40 00 82  # gw0=100.64.0.128, gw1=100.64.0.130
```

If empty, see [Troubleshooting: Empty Reverse Map](#42-empty-reverse-map).

### 2.4 Check Steering Map

```bash
kubectl exec -n <ns> <cilium-pod> -- cilium bpf egress steer list
# Or raw dump:
kubectl exec -n <ns> <cilium-pod> -- bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4
```

Entries appear after traffic flows through the gateway. Each entry maps a reply 5-tuple to the owner gateway.

**Critical check:** On gateway X, ALL steering entries must have `owner_ip` = gateway X's node IP. If you see entries pointing to the other gateway, the `IPV4_DIRECT_ROUTING` fix is not deployed — see [Troubleshooting: Wrong Owner in Steering Map](#44-wrong-owner-ip-in-steering-entries).

### 2.5 Check Endpoints

The pod must be managed by Cilium:

```bash
kubectl exec -n <ns> <cilium-pod-on-worker> -- cilium endpoint list
```

The pod's IP must appear in the list. If not, see [ONGOING_PROBLEMS.md §2](HA_EGRESS_ONGOING_PROBLEMS.md).

---

## 3. Testing

### 3.1 Basic Connectivity Test

Start a TCP listener on the external server, then connect from the pod:

```bash
# On external server (e.g., 100.64.0.129):
echo "reply" | nc -l -p 9000 -w 10 &

# From the pod:
kubectl exec -n <ns> <pod> -- sh -c "echo hello | nc -w 5 100.64.0.129 9000"
```

Expected output: `reply`

### 3.2 Verify Egress IP

On the external server, capture the source IP:

```bash
# Server side:
nc -l -p 9000 -w 10 &
tcpdump -i <iface> -n port 9000 -c 2
```

The SYN should show `src=<egress_ip>` (e.g., 100.64.0.200), not the pod or node IP.

### 3.3 Bulk Test (Go Client/Server)

The Go test tools in `ha_egress_gw_test/` provide high-concurrency testing:

```bash
# Build
cd ha_egress_gw_test && go build -o server ./cmd/server && go build -o client ./cmd/client

# Start server on external machine (100.64.0.129)
./server   # listens on :9999, prints total on Ctrl+C

# Copy client to worker (one-time)
scp client rke@100.64.0.131:/tmp/

# Run 200 connections at 100 concurrency from pod's network namespace
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -total 200 -parallel 100"
```

Client flags: `-server` (default 100.64.0.129:9999), `-total` (default 200),
`-parallel` (default 100), `-timeout` (default 5s), `-rps` (rate limit, 0=unlimited),
`-duration` (e.g. 15m, requires `-rps`), `-report` (progress interval, default 5s).

**Important:** Flush SNAT/CT maps before bulk tests to avoid false failures from
stale port exhaustion (see [§4.6](#46-snat-port-exhaustion-100-failure-after-sustained-load)).

Expected: `DONE: 200 ok, 0 fail out of 200`. Any failures indicate a datapath issue.

### 3.4 Sustained Rate Test

Test sustained throughput over a longer period:

```bash
# Flush maps first!
for pod in <cilium-gw0> <cilium-gw1> <cilium-worker>; do
  kubectl exec $pod -- cilium bpf nat flush
  kubectl exec $pod -- cilium bpf ct flush global
done

# Run 15 minutes at 500 rps from each pod (1000 rps total)
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client \
   -rps 500 -duration 15m -parallel 200 -report 10s"
```

**Validated:** 315K connections at ~500 rps with 0 failures (clean maps).
Port exhaustion begins at ~315K connections per gateway (~16K port limit).

### 3.5 Port Range Verification

After running traffic, check which SNAT ports are used. On the external server:

```bash
tcpdump -i <iface> -n src host <egress_ip> and tcp
```

Source ports in 32768–49151 → gateway index 0. Source ports in 49152–65535 → gateway index 1. Both ranges should appear, confirming both gateways are active.

### 3.5 Asymmetric Failover Test

Force all replies through one gateway by removing an ECMP nexthop:

```bash
# On external server, remove one gateway from the ECMP route:
sudo ip route del <egress_ip>/32
sudo ip route add <egress_ip>/32 via <gateway_0_ip>

# Run the Go client — all replies now go through gw0.
# Connections SNAT'd by gw1 must be redirected from gw0 → gw1 via tunnel.

# Restore ECMP when done:
sudo ip route del <egress_ip>/32
sudo ip route add <egress_ip>/32 nexthop via <gw0_ip> nexthop via <gw1_ip>
```

### 3.6 Steering Map Flush Test

Simulates LRU eviction. Flush the steering map and verify fallback works:

```bash
# Flush all entries on both gateways:
kubectl exec -n <ns> <cilium-pod-gw> -- sh -c '
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 2>/dev/null | \
    grep "^key:" | while read -r line; do
      key_hex=$(echo "$line" | sed "s/key: //;s/  value:.*//")
      bpftool map delete pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 key hex $key_hex
    done
'

# Run Go client again — should still pass using the fallback path.
```

---

## 4. Troubleshooting

### 4.1 Empty Policy Map

**Symptom:** `cilium bpf egress list` returns no entries.

**Possible causes:**

1. **Virtual egress IP not on any interface:**
   Check cilium agent logs for `"failed to retrieve interface with egress IP"`.
   Fix: commit `495d26267f` adds fallback to the default-route interface.

2. **Pod not managed by Cilium:**
   If the pod was created before Cilium, it has no CiliumEndpoint. Delete and recreate the pod.

3. **Policy not matching:**
   Verify `kubectl get cegp` shows the policy, and the pod labels match the policy selector.

### 4.2 Empty Reverse Map

**Symptom:** `bpftool map dump` of `cilium_egress_gw_reverse4` shows 0 elements.

**Possible causes:**

1. **BPF_F_NO_PREALLOC flag mismatch:**
   Check cilium agent logs for `"Unpinning map with incompatible properties"` mentioning `cilium_egress_gw_reverse4` with `Flags:1` vs `Flags:0`.

   The Go-side `bpf.NewMap` with `ebpf.Hash` automatically adds `BPF_F_NO_PREALLOC` (flag=1). The BPF-side map definition must include `__uint(map_flags, BPF_F_NO_PREALLOC)` to match. If they don't match, the Go agent unpins the BPF-created map and creates a new one — leaving the BPF programs referencing the old (deleted) map FD.

   After fixing the BPF header, a cilium agent restart is required.

2. **Policy map empty:**
   The reverse map is populated by the Go control plane from policy configs. If no policies exist, the reverse map will be empty.

### 4.3 Connection Failures (~20% Failure Rate)

**Symptom:** Bulk test shows ~80% success, ~20% failure. Failures are random.

**Diagnosis flow:**

1. **Check steering map entries** on both gateways. On gateway X, ALL entries must have `owner_ip` equal to gateway X's node IP. If entries on gw-A point to gw-B, the steering map owner bug is present.

2. **Check for stale steering entries.** After a Cilium restart, the steering map is pinned and old entries persist. Flush the maps (see §3.6) and retest.

3. **Use tcpdump** on the failing gateway's `cilium_vxlan` interface:
   ```bash
   kubectl exec -n <ns> <cilium-pod> -- tcpdump -i cilium_vxlan -n -c 20
   ```
   Look for reply packets arriving with `dst=<egress_ip>` — these are redirected replies that need overlay reverse SNAT.

4. **Check cilium monitor for drops:**
   ```bash
   kubectl exec -n <ns> <cilium-pod> -- cilium monitor --type drop
   ```
   `DROP_NAT_NO_MAPPING` on a gateway receiving redirected traffic means the overlay reverse SNAT path is not working.

### 4.4 Wrong Owner IP in Steering Entries

**Symptom:** On gateway 128, steering entries have `owner_ip=130` (or vice versa).

**Root cause:** The BPF code is using `target.egress_gw_owner_ip` (the hash-selected gateway) instead of `IPV4_DIRECT_ROUTING` (the local node IP). Both gateways SNAT traffic, so the steering entry must point to the node that actually holds the conntrack state.

**Verify the fix is deployed:**
```bash
# Check IPV4_DIRECT_ROUTING on each gateway:
kubectl exec -n <ns> <cilium-pod> -- \
  cat /var/run/cilium/state/globals/node_config.h | grep IPV4_DIRECT_ROUTING
```

The `IPV4_DIRECT_ROUTING` value (in host byte order) should match the node's K8s IP. All steering entries on that node must use this IP as `owner_ip`.

**Fix:** Ensure `bpf/lib/nodeport.h` uses `IPV4_DIRECT_ROUTING` in the `egress_gw_steer_update()` call, not `target.egress_gw_owner_ip`. Rebuild and redeploy the image, then flush stale steering entries.

### 4.5 Reply Packets Dropped After Tunnel Redirect

**Symptom:** tcpdump on `cilium_vxlan` shows SYN-ACK arriving with `dst=<egress_ip>`, but the packet never reaches the pod. It goes `cilium_vxlan → cilium_net → cilium_host` and is dropped.

**Root cause:** `bpf_overlay.c` has no handler for egress gateway reply packets arriving via tunnel. The packet falls through to `ipv4_host_delivery()` and the kernel drops it (no local route for the virtual egress IP).

**Fix:** The overlay reverse SNAT path must be present in `bpf_overlay.c`:
- Reverse map lookup (`cilium_egress_gw_reverse4`) in `handle_ipv4()`
- Tail call to `tail_handle_egw_overlay_revsnat` (ID 50)
- The tail call function performs `snat_v4_rev_nat()` and delivers to the pod

### 4.6 SNAT Port Exhaustion (100% Failure After Sustained Load)

**Symptom:** Connections work initially, then after several minutes of sustained
load (~500+ rps per gateway), ALL new connections start failing. Client shows
`TimeoutError` or `ConnectionResetError`. Server never receives the SYN.
`cilium monitor --type drop` on gateways shows `DROP_NAT_NO_MAPPING`.

**Root cause:** Each HA gateway has ~16,384 SNAT ports. BPF CT entries persist
until GC clears them (default TCP timeout: 8000s via `bpf-ct-timeout-regular-tcp`).
Closed connections still hold port reservations until GC runs. Under sustained
load, all ports fill up.

**Important:** `cilium monitor --type drop` only shows **live events** — it must
be running DURING the test. If checked after the test, no drops are visible.

**Quick fix — flush maps:**
```bash
for pod in <cilium-gw0-pod> <cilium-gw1-pod> <cilium-worker-pod>; do
  kubectl exec $pod -- cilium bpf nat flush
  kubectl exec $pod -- cilium bpf ct flush global
done
```

**Verify port pressure:**
```bash
# Count SNAT entries (max ~16384 per gateway in HA mode):
kubectl exec <cilium-gw-pod> -- cilium bpf nat list | wc -l
```

**Long-term:** See [ONGOING_PROBLEMS.md §6](HA_EGRESS_ONGOING_PROBLEMS.md) for
production-scale mitigations and `HA_EGRESS_GW_TUNABLES.md` for capacity
formulas (CT lifetime, GC interval, multiple egress IPs, port range tuning).

### 4.7 BPF Compilation Errors

See [RESOLVED_PROBLEMS.md §3](HA_EGRESS_RESOLVED_PROBLEMS.md) for common BPF compilation issues:
- C89 declaration-after-statement errors
- `__throw_build_bug` / memset errors from struct initializers

**Quick check:**
```bash
kubectl exec -n <ns> <cilium-pod> -- cilium endpoint list
```

If endpoints are stuck in `waiting-to-regenerate`, check agent logs for BPF compilation errors.

---

## 5. Useful Commands Reference

### BPF Map Inspection

```bash
# Policy map (both gateways shown):
kubectl exec -n <ns> <cilium-pod> -- cilium bpf egress list

# Steering map (per-flow owner):
kubectl exec -n <ns> <cilium-pod> -- cilium bpf egress steer list

# Reverse map (raw):
kubectl exec -n <ns> <cilium-pod> -- \
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_reverse4

# Count steering entries:
kubectl exec -n <ns> <cilium-pod> -- \
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 | grep "Found"
```

### Monitoring & Debugging

```bash
# Drop notifications:
kubectl exec -n <ns> <cilium-pod> -- cilium monitor --type drop

# All traffic (verbose):
kubectl exec -n <ns> <cilium-pod> -- cilium monitor -v

# Tcpdump on VxLAN tunnel:
kubectl exec -n <ns> <cilium-pod> -- tcpdump -i cilium_vxlan -n

# Tcpdump on external interface:
kubectl exec -n <ns> <cilium-pod> -- tcpdump -i eth0 -n host <egress_ip>
```

### BPF Config Verification

```bash
# Check node-level BPF defines:
kubectl exec -n <ns> <cilium-pod> -- \
  cat /var/run/cilium/state/globals/node_config.h | grep -E "EGRESS|DIRECT_ROUTING"

# Check ENABLE_EGRESS_GATEWAY is set:
kubectl exec -n <ns> <cilium-pod> -- \
  cat /var/run/cilium/state/globals/node_config.h | grep ENABLE_EGRESS_GATEWAY
```

### Steering Map Flush

```bash
kubectl exec -n <ns> <cilium-pod> -- sh -c '
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 2>/dev/null | \
    grep "^key:" | while read -r line; do
      key_hex=$(echo "$line" | sed "s/key: //;s/  value:.*//")
      bpftool map delete pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 key hex $key_hex
    done
  echo "flushed"
'
```

---

## 6. Interpreting Hex Dumps

BPF map dumps show values in network byte order (big-endian). Common IP conversions:

| Hex | IP |
|-----|----|
| `64 40 00 80` | 100.64.0.128 |
| `64 40 00 82` | 100.64.0.130 |
| `64 40 00 83` | 100.64.0.131 |
| `64 40 00 c8` | 100.64.0.200 |
| `64 40 00 81` | 100.64.0.129 |

**Steering map entry format:**
```
key: <saddr 4B> <daddr 4B>  <sport 2B> <dport 2B> <proto 1B> <pad 3B>
value: <owner_ip 4B> <owner_idx 1B> <pad 3B>
```

**Reverse map entry format:**
```
key: <egress_ip 4B>
value: <gateway_ip_0 4B> <gateway_ip_1 4B>
```

**Quick python conversion:**
```python
# Convert hex bytes to IP:
bytes = "64 40 00 c8"
print(".".join(str(int(b, 16)) for b in bytes.split()))
# → 100.64.0.200

# Convert port (2 bytes, big-endian):
port_hex = "00 50"
print(int(port_hex.replace(" ", ""), 16))
# → 80
```
