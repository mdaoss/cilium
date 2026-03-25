# HA Egress Gateway — Live Demo Script

Step-by-step demo for active/active HA egress gateway with Cilium.
Copy-paste each block in order.

---

## Current Cluster State

| Role | Node IP | Cilium Pod |
|------|---------|------------|
| Gateway 0 | 100.64.0.128 | cilium-btg8k |
| Gateway 1 | 100.64.0.130 | cilium-6hr2x |
| Worker | 100.64.0.131 | cilium-69pj6 |

- **Mode:** Geneve + DSR
- **Test pod:** `toolbox-8558745d46-gkqsj` in namespace `actor` (on worker 131)
- **Egress IP:** 100.64.0.200 (virtual, ECMP across both gateways)
- **External server:** 100.64.0.129

> Update pod names above after any cilium restart with:
> ```bash
> kubectl get pods -n default -l k8s-app=cilium -o wide
> ```

---

## Step 1 — Show the Setup

```bash
# Cluster nodes
kubectl get nodes -o wide

# Cilium agents
kubectl get pods -n default -l k8s-app=cilium -o wide

# Test pod on the worker node (NOT on a gateway)
kubectl get pods -n actor -o wide
```

**Say:** *"We have 2 gateway nodes (128 and 130) and a worker node (131). The test pod runs on the worker."*

---

## Step 2 — Show the Egress Gateway Policy

```bash
kubectl get cegp 100.64.0.200 -o yaml
```

**Say:** *"This policy selects pods in namespace `actor` and assigns virtual egress IP 100.64.0.200. Both gateway nodes match the nodeSelector — this gives us active/active HA."*

---

## Step 3 — Show BPF Maps

```bash
# Policy map — which pods get egress treatment
kubectl exec -n default cilium-btg8k -- cilium bpf egress list

# Reverse map — maps egress IP to gateway pair (for reply steering)
kubectl exec -n default cilium-btg8k -- \
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_reverse4
```

**Say:** *"The BPF policy map matches pod traffic to egress IPs. The reverse map lets any gateway identify reply packets belonging to HA egress connections."*

---

## Step 4 — Single Connection Test

**Terminal 1** (external server 100.64.0.129):

```bash
# Start the Go test server (from ha_egress_gw_test/)
./server   # listens on :9999
```

**Terminal 2** (your laptop):

```bash
# Run a single connection from the pod via nsenter
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -total 1 -parallel 1"
```

**Say:** *"The pod connects to the external server. Traffic exits through one of the two gateways, SNAT'd to the virtual egress IP 100.64.0.200."*

---

## Step 5 — ECMP Load Balancing (20 Connections)

### 5a. Verify ECMP route

On the external server:

```bash
ip route show 100.64.0.200
# Expected: nexthop via 100.64.0.128  nexthop via 100.64.0.130
```

### 5b. Flush steering maps

```bash
kubectl exec -n default cilium-btg8k -- sh -c '
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 2>/dev/null | \
  grep "^key:" | while read -r line; do
    key_hex=$(echo "$line" | sed "s/key: //;s/  value:.*//")
    bpftool map delete pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 key hex $key_hex
  done; echo "flushed gw0"'

kubectl exec -n default cilium-6hr2x -- sh -c '
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 2>/dev/null | \
  grep "^key:" | while read -r line; do
    key_hex=$(echo "$line" | sed "s/key: //;s/  value:.*//")
    bpftool map delete pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 key hex $key_hex
  done; echo "flushed gw1"'
```

### 5c. Run 200 connections

With the Go server running on 100.64.0.129:

```bash
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -total 200 -parallel 100"
```

### 5d. Show steering map split

```bash
echo "=== Gateway 0 (128) ==="
kubectl exec -n default cilium-btg8k -- \
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 | tail -1

echo "=== Gateway 1 (130) ==="
kubectl exec -n default cilium-6hr2x -- \
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 | tail -1
```

**Say:** *"200/200 passed. The steering map shows connections split across both gateways — active/active load balancing is working."*

---

## Step 6 — Asymmetric Failover (The Money Shot)

**Say:** *"Now the key test — what happens when ALL replies come through only ONE gateway, but connections were SNAT'd by BOTH? This simulates a real failover."*

### 6a. Flush steering maps

Repeat the flush commands from step 5b.

### 6b. Force all replies through gateway 1 only

On the external server:

```bash
sudo ip route replace 100.64.0.200/32 via 100.64.0.130

ip route show 100.64.0.200
# Shows: 100.64.0.200 via 100.64.0.130
```

### 6c. Run 200 connections

With the Go server running on 100.64.0.129:

```bash
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -total 200 -parallel 100"
```

### 6d. Show proof of cross-gateway tunneling

```bash
echo "=== Gateway 0 — got entries via tunnel (no direct replies!) ==="
kubectl exec -n default cilium-btg8k -- \
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 | tail -1

echo "=== Gateway 1 — handled all incoming replies ==="
kubectl exec -n default cilium-6hr2x -- \
  bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 | tail -1
```

**Say:** *"200/200! Even though ALL replies came through gateway 1, the connections SNAT'd by gateway 0 still worked. Gateway 1 detected those replies using the reverse map, tunneled them to gateway 0 for reverse SNAT, and the pod got the response. Gateway 0 has steering entries even though zero replies were routed to it directly — proof that the tunnel path works."*

---

## Step 7 — Live Failover (Zero Downtime)

**Say:** *"Can we change routes while traffic is flowing without dropping a single connection?"*

### 7a. Restore ECMP

On the external server:

```bash
sudo ip route replace 100.64.0.200/32 \
  nexthop via 100.64.0.128 nexthop via 100.64.0.130
```

### 7b. Start 500 connections (Terminal 1)

With the Go server running on 100.64.0.129:

```bash
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -total 500 -parallel 20 -timeout 10s"
```

### 7c. Change routes during test (Terminal 2)

While the test runs, cycle through these on the external server:

```bash
# ~10s after test starts: force all replies via gw1
sudo ip route replace 100.64.0.200/32 via 100.64.0.130

# ~10s later: force all replies via gw0
sudo ip route replace 100.64.0.200/32 via 100.64.0.128

# ~10s later: restore ECMP
sudo ip route replace 100.64.0.200/32 \
  nexthop via 100.64.0.128 nexthop via 100.64.0.130
```

**Say:** *"500/500 — zero dropped connections while we flipped routes between ECMP, gw0-only, gw1-only, and back. This is zero-downtime failover."*

---

## Key Talking Points

| Point | Detail |
|-------|--------|
| **Active/Active** | Both gateways handle traffic simultaneously — no wasted capacity |
| **Virtual Egress IP** | 100.64.0.200 is not tied to any single node, survives node failure |
| **BPF Steering Map** | Each gateway records which connections it SNAT'd, enabling cross-gateway reply forwarding |
| **Reverse Map** | Lets any gateway recognize HA egress reply traffic and tunnel it to the SNAT owner |
| **Zero Downtime** | Route changes (simulating BGP failover) cause no connection drops |

---

## Cleanup / Reset

```bash
# Restore ECMP route on external server
sudo ip route replace 100.64.0.200/32 \
  nexthop via 100.64.0.128 nexthop via 100.64.0.130

# Flush steering maps (both gateways)
for pod in cilium-btg8k cilium-6hr2x; do
  kubectl exec -n default $pod -- sh -c '
    bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 2>/dev/null | \
    grep "^key:" | while read -r line; do
      key_hex=$(echo "$line" | sed "s/key: //;s/  value:.*//")
      bpftool map delete pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 key hex $key_hex
    done; echo "flushed"'
done
```
