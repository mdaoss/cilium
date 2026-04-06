# HA Egress Gateway — Test Scenarios

Manual test procedures for validating active/active HA egress gateway across
tunnel protocol and load-balancer mode combinations.

---

## Prerequisites

### Cluster Layout

| Role | Node IP | Description |
|------|---------|-------------|
| Gateway 0 | 100.64.0.128 | Egress gateway, fixed SNAT port range: lower half |
| Gateway 1 | 100.64.0.130 | Egress gateway, fixed SNAT port range: upper half |
| Worker | 100.64.0.131 | Runs the test pod |
| External server | 100.64.0.129 | Target outside the cluster, runs Go test server |

### Resources

- **Egress IP:** 100.64.0.200 (virtual, announced via BGP/MetalLB)
- **ECMP route** on external server: `ip route add 100.64.0.200/32 nexthop via 100.64.0.128 nexthop via 100.64.0.130`
- **Test pod:** `toolbox` deployment in namespace `actor` on the worker node
- **CiliumEgressGatewayPolicy** selecting the test pod, matching both gateway nodes
- **Test tools:** Go client/server in `ha_egress_gw_test/` (build: `cd ha_egress_gw_test && go build -o server ./cmd/server && go build -o client ./cmd/client`)

### Access Pattern

All commands use SSH to cluster nodes. Cilium operations use `docker exec` into
the cilium-agent container; pod network operations use `nsenter --net`.

**Helper: find cilium-agent container ID on a node:**
```bash
sshpass -p rke ssh rke@<NODE_IP> "sudo docker ps -q --filter name=cilium-agent"
```

Shorthand used throughout this document — run on a given node via docker exec
into the cilium-agent container:
```bash
# Generic pattern (replace <NODE_IP> and <command>):
sshpass -p rke ssh rke@<NODE_IP> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) <command>"
```

**Helper: find pod PID for nsenter:**
```bash
# Find the pause container ID (owns the network namespace):
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo docker ps --format '{{.Names}} {{.ID}}' | grep 'POD_toolbox'"

# Get PID from container ID:
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo docker inspect --format '{{.State.Pid}}' <PAUSE_CONTAINER_ID>"
```

### Naming Conventions

Throughout this document:
- `<CILIUM_NS>` — namespace where cilium runs (e.g., `default`)
- `<GW0>` = 100.64.0.128, `<GW1>` = 100.64.0.130, `<WORKER>` = 100.64.0.131
- `<POD_PID>` — PID of the toolbox pause container on the worker
- `<POD2_PID>` — PID of the toolbox2 pause container on the worker

### Important: Gateway Recovery After Restart

After a cilium rollout restart, gateways may appear blacklisted from the
previous session. The control plane runs 40 recovery probes at 1-second
intervals (~40s total). **Wait for recovery before running tests.** Check logs:

```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker logs --tail=5 \$(sudo docker ps -q --filter name=cilium-agent) 2>&1 | grep -i recover"
# Expected (when ready): "Gateway node recovered, restoring to egress policy"
```

Verify both gateways appear in the policy map:
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress list"
# Expected: both Gateway IPs populated, ActiveGW = 3 (both active) (not "Not Found")
```

---

## Test Matrix

| # | Test | Section |
|---|------|---------|
| 1 | VxLAN + SNAT | [§1](#scenario-1-vxlan--snat) |
| 2 | Geneve + SNAT | [§2](#scenario-2-geneve--snat) |
| 3 | Geneve + DSR | [§3](#scenario-3-geneve--dsr) |
| 4 | Multiple Policy Pairs | [§4](#scenario-4-multiple-policy-pairs) |
| 5 | Asymmetric Failover | [§5](#scenario-5-asymmetric-failover) |
| 6 | Live Failover | [§6](#scenario-6-live-failover) |
| 7 | Removed: Worker Redirect | [§7](#scenario-7-removed-worker-redirect-path) |
| 8 | Gateway-Only Stress Test | [§8](#scenario-8-gateway-only-stress-test) |
| 9 | Gateway Failure + Recovery Under Load | [§9](#scenario-9-gateway-failure--recovery-under-load) |
| 10 | Widened SNAT Port Range | [§10](#scenario-10-widened-snat-port-range--failurerecovery-at-500-rps) |
| 11 | HTTP/2 Multiplexed — Failure/Recovery | [§11](#scenario-11-http2-multiplexed--failurerecovery-at-500-rps) |

Scenarios 1–3 follow the same structure:
1. Configure — patch configmap and restart cilium
2. Validate — verify tunnel device, BPF maps, and defines
3. Test — run bulk connectivity test
4. Verify — check steering map correctness
5. Cleanup — revert config if moving to next scenario

Scenarios 4–6 are functional tests that can be run on any tunnel/LB mode.
Scenario 7 documents the removal of the old worker-side reply interception path.
Scenario 8 is a gateway-only stress test in Geneve + DSR mode.
Scenarios 9–10 test gateway failure detection and recovery after the external
reply path has converged to a live gateway.
Scenario 11 tests HTTP/2 multiplexed traffic through failure/recovery cycles.

---

## Scenario 1: VxLAN + SNAT

This is the default configuration.

### 1.1 Configure

```bash
kubectl patch configmap cilium-config -n <CILIUM_NS> --type merge \
  -p '{"data":{"tunnel-protocol":"vxlan","loadbalancer-mode":"snat"}}'

kubectl rollout restart daemonset cilium -n <CILIUM_NS>
kubectl rollout status daemonset cilium -n <CILIUM_NS> --timeout=120s
```

Wait ~40s for gateway recovery (see [Prerequisites](#important-gateway-recovery-after-restart)).

### 1.2 Validate

**Tunnel device:**
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) ip link show cilium_vxlan"
# Expected: cilium_vxlan UP
```

**BPF defines:**
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) \
    cat /var/run/cilium/state/globals/node_config.h" | grep -E "TUNNEL_PROTOCOL|DSR_ENCAP_MODE"
# Expected: TUNNEL_PROTOCOL 1 (VxLAN), DSR_ENCAP_MODE 0
```

**Policy map (on each gateway):**
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress list"
# Expected: entry with src=<pod_ip>, egress_ip=100.64.0.200, both gateway IPs
```

**Reverse map (on each gateway):**
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) \
    bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_reverse4"
# Expected: key=<egress_ip>, value=<gw0_ip> <gw1_ip>
```

### 1.3 Test — Bulk Connectivity

Start the Go server on the external machine (100.64.0.129):

```bash
./server   # listens on :9999
```

Copy client binary to worker (one-time) and run:

```bash
# Copy client binary to worker (one-time)
scp ha_egress_gw_test/client rke@100.64.0.131:/tmp/

# Run 200 connections at 100 concurrency via nsenter
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -server 100.64.0.129:9999 -total 200 -parallel 100"
```

**Pass criteria:** 200 OK, 0 FAIL. Server connection count (Ctrl+C) should match.

### 1.4 Verify Steering Map

After the test, check that steering entries exist on each gateway using the
`cilium bpf egress steer list` command:

```bash
# On gateway 0 — all entries must have Owner IP = 100.64.0.128
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress steer list"

# On gateway 1 — all entries must have Owner IP = 100.64.0.130
sshpass -p rke ssh rke@<GW1> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress steer list"
```

Both gateways should have entries. The total across both should be >= 20.

**Verify no cross-node owner IPs** (gateway 0 must NOT have entries pointing to 130):
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) \
    cilium bpf egress steer list" | grep "100.64.0.130"
# Expected: no output (all entries should reference local node 128)
```

---

## Scenario 2: Geneve + SNAT

### 2.1 Configure

```bash
kubectl patch configmap cilium-config -n <CILIUM_NS> --type merge \
  -p '{"data":{"tunnel-protocol":"geneve","loadbalancer-mode":"snat"}}'

kubectl rollout restart daemonset cilium -n <CILIUM_NS>
kubectl rollout status daemonset cilium -n <CILIUM_NS> --timeout=120s
```

Wait ~40s for gateway recovery (see [Prerequisites](#important-gateway-recovery-after-restart)).

### 2.2 Validate

**Tunnel device:**
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) ip link show cilium_geneve"
# Expected: cilium_geneve UP

sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) ip link show cilium_vxlan" 2>&1
# Expected: "does not exist"
```

**BPF defines:**
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) \
    cat /var/run/cilium/state/globals/node_config.h" | grep TUNNEL_PROTOCOL
# Expected: TUNNEL_PROTOCOL 2 (Geneve)
```

**Policy map and reverse map:** same commands as §1.2 — both must be populated.

### 2.3 Test — Bulk Connectivity

Same as §1.3 — start the Go server on 100.64.0.129, run the Go client from the pod.

**Pass criteria:** 200 OK, 0 FAIL.

### 2.4 Verify Steering Map

Same commands as §1.4. Both gateways should have entries, all pointing to the local node.

---

## Scenario 3: Geneve + DSR

DSR (Direct Server Return) in tunnel mode uses Geneve option headers. This tests
that HA egress gateway coexists with DSR without interference.

### 3.1 Configure

```bash
kubectl patch configmap cilium-config -n <CILIUM_NS> --type merge \
  -p '{"data":{"tunnel-protocol":"geneve","loadbalancer-mode":"dsr"}}'

kubectl rollout restart daemonset cilium -n <CILIUM_NS>
kubectl rollout status daemonset cilium -n <CILIUM_NS> --timeout=180s
```

Wait ~40s for gateway recovery (see [Prerequisites](#important-gateway-recovery-after-restart)).

> **Note:** DSR requires `tunnel-protocol: geneve`. VxLAN + DSR is not supported
> by Cilium (DSR encodes return info in Geneve option headers).

### 3.2 Validate

**Tunnel device:**
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) ip link show cilium_geneve"
# Expected: cilium_geneve UP
```

**BPF defines:**
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) \
    cat /var/run/cilium/state/globals/node_config.h" | grep -E "DSR_ENCAP|TUNNEL_PROTOCOL"
# Expected:
#   DSR_ENCAP_GENEVE 3
#   DSR_ENCAP_MODE 0
#   TUNNEL_PROTOCOL 2
#   TUNNEL_PROTOCOL_GENEVE 2
```

**Policy map and reverse map:** same commands as §1.2 — both must be populated.

### 3.3 Test — Bulk Connectivity

Same as §1.3 — start the Go server on 100.64.0.129, run the Go client from the pod.

**Pass criteria:** 200 OK, 0 FAIL.

### 3.4 Verify Steering Map

Same commands as §1.4. Both gateways should have entries, all pointing to the local node.

---

## Scenario 4: Multiple Policy Pairs

This test verifies that multiple CiliumEgressGatewayPolicy resources work
simultaneously, each with a different egress IP and pod selector.

### 4.1 Setup

Create a second test namespace and deployment:

```bash
kubectl create namespace actor2
kubectl create deployment toolbox2 -n actor2 --image=<toolbox_image>
# Wait for the pod to be running
kubectl get pods -n actor2 -o wide
```

Note the pod name (`<TOOLBOX2>`) and its IP. Get its pause container PID
(see [Prerequisites](#access-pattern)).

Create a second CiliumEgressGatewayPolicy with a different egress IP (e.g., 100.64.0.201):

```yaml
apiVersion: cilium.io/v2
kind: CiliumEgressGatewayPolicy
metadata:
  name: policy-201
spec:
  selectors:
    - podSelector:
        matchLabels:
          app: toolbox2
      namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: actor2
  destinationCIDRs:
    - "0.0.0.0/0"
  egressGroups:
    - nodeSelector:
        matchLabels:
          egress-gateway: "true"
      egressIP: 100.64.0.201
```

Add an ECMP route on the external server for the second egress IP:

```bash
sudo ip route add 100.64.0.201/32 nexthop via 100.64.0.128 nexthop via 100.64.0.130
```

### 4.2 Validate

Verify both policies appear in the BPF policy map:

```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress list"
# Expected: two entries — pod1 → EIP 200, pod2 → EIP 201
```

Verify reverse map has two entries:

```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) \
    bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_reverse4"
# Expected: 2 entries (one for each egress IP)
```

### 4.3 Test — Both Pods

Start the Go server on 100.64.0.129:

```bash
./server   # listens on :9999
```

Run the Go client from each pod's network namespace:

```bash
# Pod1 (egress IP 100.64.0.200) — 200 connections
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -server 100.64.0.129:9999 -total 200 -parallel 100"

# Pod2 (egress IP 100.64.0.201) — 200 connections
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD2_PID> /tmp/client -server 100.64.0.129:9999 -total 200 -parallel 100"
```

**Pass criteria:** Both runs show 200 OK, 0 FAIL. Server total (Ctrl+C) should be 400.

### 4.4 Cleanup

```bash
kubectl delete cegp policy-201
kubectl delete namespace actor2
# On external server:
sudo ip route del 100.64.0.201/32
```

---

## Scenario 5: Asymmetric Failover

This test verifies the overlay reverse SNAT path by forcing ALL reply traffic
through a single gateway. Outbound traffic still splits across both gateways
via ECMP, so roughly half the connections are SNAT'd by a gateway that will
NOT receive the replies. The non-owner gateway must tunnel those replies to
the owning gateway for correct reverse SNAT.

This is the core test for the HA reply-path steering logic.

### 5.1 Prerequisites

Start with the normal ECMP route on the external server:

```bash
ip route show 100.64.0.200
# Expected: 100.64.0.200 nexthop via 100.64.0.128 nexthop via 100.64.0.130
```

Flush stale steering entries on both gateways (see [Quick Debugging](#quick-debugging-if-a-test-fails)).

### 5.2 Test A — All Replies via Gateway 1 (100.64.0.130)

On the external server, force all replies through gateway 1:

```bash
sudo ip route replace 100.64.0.200/32 via 100.64.0.130
```

Run the Go client from the pod (server must already be running on 100.64.0.129):

```bash
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -server 100.64.0.129:9999 -total 200 -parallel 100"
```

**Pass criteria:** 200 OK, 0 FAIL.

### 5.3 Verify Cross-Gateway Tunneling

After the test, inspect steering maps:

```bash
# Gateway 0 should have entries (connections it SNAT'd)
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress steer list"
# All entries must have Owner IP = 100.64.0.128

# Gateway 1 should have entries (connections it SNAT'd)
sshpass -p rke ssh rke@<GW1> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress steer list"
# All entries must have Owner IP = 100.64.0.130
```

The key insight: gw0 has entries even though NO replies were routed to it
directly. This proves gw1 tunneled the replies for gw0-owned connections.

### 5.4 Test B — All Replies via Gateway 0 (100.64.0.128)

Flush steering maps on both gateways, then on the external server:

```bash
sudo ip route replace 100.64.0.200/32 via 100.64.0.128
```

Run the Go client again (same command as §5.2).

**Pass criteria:** 200 OK, 0 FAIL.

### 5.5 Restore ECMP

```bash
sudo ip route replace 100.64.0.200/32 \
  nexthop via 100.64.0.128 nexthop via 100.64.0.130
```

---

## Scenario 6: Live Failover

This test verifies zero-downtime behavior during route changes. A long-running
test executes 1000 connections while the operator changes the reply route
mid-test, simulating real-world failover events.

### 6.1 Test Script

Start the Go server on 100.64.0.129, then run the Go client with a higher
total and moderate parallelism to give time for route changes:

```bash
# On external server:
./server

# On worker (while route rotator runs in another terminal):
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -server 100.64.0.129:9999 -total 1000 -parallel 50 -timeout 10s"
```

### 6.2 Route Changes During Test

While the test runs, cycle through these routes on the external server:

```bash
# Force all replies via gw1 only
sudo ip route replace 100.64.0.200/32 via 100.64.0.130

# Wait 10–20 seconds, then force via gw0 only
sudo ip route replace 100.64.0.200/32 via 100.64.0.128

# Wait 10–20 seconds, then restore ECMP
sudo ip route replace 100.64.0.200/32 \
  nexthop via 100.64.0.128 nexthop via 100.64.0.130
```

Repeat the cycle multiple times during the test to exercise different
transition patterns.

### 6.3 Pass Criteria

**1000 OK, 0 FAIL.** No connection should fail regardless of when and how
often routes change. Each individual connection is short-lived, so
transient route changes must not cause failures.

---

## Scenario 7: Removed Worker Redirect Path

The previous worker-side reply interception path has been removed. Reply
traffic for HA egress connections must now reach one of the two gateway nodes
directly. Routes that send replies to a non-gateway worker are expected to
fail because the worker no longer tunnels those packets to a gateway.

Use Scenarios 5, 6, and 8 to validate the remaining HA behavior: asymmetric
reply steering between gateways, route changes across gateways, and gateway-only
stress under Geneve + DSR.

---

## Scenario 8: Gateway-Only Stress Test

This is the gateway-only stress validation: Geneve + DSR mode, multiple egress
policies, 10K connections at high parallelism, with routes rotating every
second across the two gateway nodes. It exercises the active/active HA paths
without relying on any worker-side interception.

### 8.1 Prerequisites

- Geneve + DSR mode configured (see [§3.1](#31-configure))
- Two egress policies active (see [§4.1](#41-setup))
- ECMP routes for both egress IPs on external server

### 8.2 Route Rotator Script

Save this on the external server and run in a separate terminal:

```bash
#!/bin/bash
# route_rotator.sh — cycles reply routes for both EIPs every second
# Ctrl+C restores ECMP

routes=(
  "via 100.64.0.128"                                  # gw0 only
  "via 100.64.0.130"                                  # gw1 only
  "nexthop via 100.64.0.128 nexthop via 100.64.0.130" # ECMP gateways
  "via 100.64.0.130"                                  # gw1 only
  "via 100.64.0.128"                                  # gw0 only
)

trap 'echo "Restoring ECMP..."; \
  sudo ip route replace 100.64.0.200/32 nexthop via 100.64.0.128 nexthop via 100.64.0.130; \
  sudo ip route replace 100.64.0.201/32 nexthop via 100.64.0.128 nexthop via 100.64.0.130; \
  exit' INT

i=0
while true; do
  r="${routes[$((i % ${#routes[@]}))]}"
  echo "[$(date +%H:%M:%S)] Route: $r"
  sudo ip route replace 100.64.0.200/32 $r
  sudo ip route replace 100.64.0.201/32 $r
  i=$((i + 1))
  sleep 1
done
```

### 8.3 Test Script

Start the Go server on 100.64.0.129, then run the Go client from both pods
while the route rotator is running:

```bash
# On external server:
./server

# Run from pod1 (EIP 200) — 5000 connections
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -server 100.64.0.129:9999 -total 5000 -parallel 100 -timeout 10s" &

# Run from pod2 (EIP 201) — 5000 connections
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD2_PID> /tmp/client -server 100.64.0.129:9999 -total 5000 -parallel 100 -timeout 10s" &

wait
# Server Ctrl+C should show total=10000
```

### 8.4 What This Tests

Each batch of 100 parallel connections exercises multiple code paths
simultaneously because routes rotate every second:

| Route State | Code Path Exercised |
|-------------|---------------------|
| gw0 only | Direct reverse SNAT on gw0; gw1-owned connections redirected via overlay cross-gateway tunnel |
| gw1 only | Direct reverse SNAT on gw1; gw0-owned connections redirected via overlay cross-gateway tunnel |
| ECMP gateways | Normal active/active load balancing |

### 8.5 Pass Criteria

**10000 OK, 0 FAIL.** No connection should fail regardless of which node
gateway receives the reply or how often routes change.

---

## Scenario 9: Gateway Failure + Recovery Under Load

This test exercises the complete gateway failure and recovery lifecycle under
sustained load: prober detects the failure (~3s), policy map switches to
single-gateway mode, traffic continues without interruption, the gateway
recovers (~40s prober threshold), and traffic re-balances across both gateways.
It is a **new-flow failover** test, not a state takeover test: packets that
are still routed to the dead next hop never enter the cluster, and long-lived
connections owned by the dead gateway are expected to fail until the client
reconnects.

### 9.1 Prerequisites

- Geneve + DSR mode configured (current config after §8)
- Both gateways healthy and in policy map
- Reply route forced through surviving gateway (gw0) before the kill — in
  production BGP health-checking withdraws the dead nexthop; in the test lab
  set the route manually before the test starts. This is required because the
  datapath only works after the reply reaches a live gateway; it cannot
  recover packets sent to a powered-off gateway

### 9.2 Test — Full Failure/Recovery Cycle

**Step 1:** Force replies via gw0 only (so replies don't hit the gateway we're
about to kill). If you want to kill gw0 instead, first force replies via gw1:

```bash
# On external server:
sudo ip route replace 100.64.0.200/32 via 100.64.0.128
```

**Step 2:** Start a sustained test (180s at 50 rps = 9000 connections):

```bash
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -server 100.64.0.129:9999 \
    -total 0 -rps 100 -duration 300s -parallel 100 -timeout 10s"
```

**Step 3:** Sequence of operator actions during the test:

| Time | Action |
|------|--------|
| T+10s | **Shut down gw1 VM via hypervisor** (hard kill — no graceful shutdown) |
| T+15s | Verify single-gateway mode: policy map shows Gateway IP 1 = "Not Found" |
| T+70s | **Power on gw1 VM via hypervisor** |
| T+110s | Verify both gateways restored in policy map |
| T+120s | Restore ECMP: `sudo ip route replace 100.64.0.200/32 nexthop via 100.64.0.128 nexthop via 100.64.0.130` |

**Verify single-gateway mode** (~5s after kill):
```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress list -o json"
# Expected: Both gateway IPs preserved, ActiveGW = 1 (only gw0 active)
```

**Verify recovery** (~40s after gw1 boots):
```bash
# Check gw0 logs for recovery event:
sshpass -p rke ssh rke@<GW0> \
  "sudo docker logs --tail=5 \$(sudo docker ps -q --filter name=cilium-agent) 2>&1 | grep recover"
# Expected: "Gateway node recovered, restoring to egress policy"

# Verify policy map has both gateways:
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress list"
# Expected: both Gateway IPs populated, ActiveGW = 3 (both active)
```

**Step 4:** After the test, verify steering maps show entries on both gateways
(confirming traffic re-balanced after recovery):

```bash
sshpass -p rke ssh rke@<GW0> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress steer list" | wc -l

sshpass -p rke ssh rke@<GW1> \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress steer list" | wc -l
```

### 9.3 Pass Criteria

**~9000 OK, <=5 FAIL.** A handful of failures during the ~3s detection window
and the recovery transition are acceptable. After recovery, both gateways
should have steering entries showing traffic was re-balanced. If failures
continue after the detection window, the usual cause is that the external
reply path is still targeting the dead gateway rather than the surviving one.

### 9.4 What This Tests

| Phase | Duration | Code Path |
|-------|----------|-----------|
| Normal (both gw) | T+0 to T+10 | Active/active hash-based gateway selection, `ActiveGW=3` |
| Detection window | T+10 to T+13 | Prober detects failure (3 consecutive probe failures) |
| Single-gateway | T+13 to T+110 | All traffic via gw0, `ActiveGW=1`, both IPs preserved in fixed slots |
| Recovery | T+110 to T+120 | Prober restores gw1 after 40 consecutive probes, `ActiveGW=3` |
| Re-balanced | T+120 to T+180 | Active/active restored, ECMP route restored |

### 9.5 What This Does Not Test

- It does not prove takeover of packets still routed to the dead gateway's
  external next hop. That requires BGP/ECMP convergence outside Cilium.
- It does not preserve long-lived connections that were owned by the dead
  gateway. Scenario 11 covers that behavior for multiplexed HTTP/2 traffic.

---

## Scenario 10: Widened SNAT Port Range — Failure/Recovery at 500 rps

Same as Scenario 9 but with a minimal NodePort range to maximize per-gateway
SNAT capacity (32255 ports instead of 16384) and a 5× higher request rate.
This validates that the widened port range works correctly end-to-end: forward
SNAT allocation, reverse SNAT, steering, failover, and recovery.

### 10.1 Prerequisites

- Geneve + DSR mode configured
- Both gateways healthy and in policy map

### 10.2 Config Change — Widen SNAT Port Range

Narrow the NodePort range to its minimum to push `NODEPORT_PORT_MIN_NAT` down
to 1026, giving each gateway 32255 SNAT ports (2× the default 16384):

```bash
kubectl patch configmap cilium-config -n <CILIUM_NS> --type merge \
  -p '{"data":{"node-port-range":"1024,1025"}}'

kubectl rollout restart daemonset cilium -n <CILIUM_NS>
kubectl rollout status daemonset cilium -n <CILIUM_NS> --timeout=120s
```

**Verify the wider range on each gateway:**
```bash
# Check that NODEPORT_PORT_MIN_NAT = 1026 in node_config.h:
for GW in 100.64.0.128 100.64.0.130; do
  echo "=== $GW ==="
  sshpass -p rke ssh rke@$GW \
    "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) \
      grep NODEPORT_PORT_MIN_NAT /var/run/cilium/state/globals/node_config.h"
done
# Expected on both: #define NODEPORT_PORT_MIN_NAT 1026
```

**Verify HA port partitioning in BPF** — SNAT a flow and check the allocated
port falls in the expected wider range:
```bash
# GW0 (100.64.0.128) should use ports 1026–33280
# GW1 (100.64.0.130) should use ports 33281–65535
# Run a quick test to see SNAT port allocation:
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -server 100.64.0.129:9999 \
    -total 10 -parallel 1 -timeout 5s"

# Check steering entries — ports should be in the wider range:
sshpass -p rke ssh rke@100.64.0.128 \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress steer list"
sshpass -p rke ssh rke@100.64.0.130 \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress steer list"
```

### 10.3 Test — Full Failure/Recovery Cycle at 500 rps

**Step 1:** Force replies via gw0 only:

```bash
# On external server:
sudo ip route replace 100.64.0.200/32 via 100.64.0.128
```

**Verify the route actually took effect** before starting the load:

```bash
# On external server:
ip route show 100.64.0.200/32
# Expected: 100.64.0.200 via 100.64.0.128 dev <iface>
```

If the route is absent or still shows `100.64.0.200 dev <iface>` as an on-link
route, the pod-side preflight will fail 100%.

**Step 2:** Start a sustained high-rate test (300s at 500 rps = 150K connections):

```bash
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/client -server 100.64.0.129:9999 \
    -total 0 -rps 500 -duration 300s -parallel 500 -timeout 10s"
```

**Step 3:** Sequence of operator actions during the test:

| Time | Action |
|------|--------|
| T+10s | **Shut down gw1 VM via hypervisor** (hard kill) |
| T+15s | Verify single-gateway mode: policy map shows `ActiveGW = 1` |
| T+70s | **Power on gw1 VM via hypervisor** |
| T+110s | Verify both gateways restored: `ActiveGW = 3` |
| T+120s | Restore ECMP: `sudo ip route replace 100.64.0.200/32 nexthop via 100.64.0.128 nexthop via 100.64.0.130` |

**Verify single-gateway mode** (~5s after kill):
```bash
sshpass -p rke ssh rke@100.64.0.128 \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress list -o json"
# Expected: Both gateway IPs preserved, ActiveGW = 1 (only gw0 active)
```

**Verify recovery** (~40s after gw1 boots):
```bash
sshpass -p rke ssh rke@100.64.0.128 \
  "sudo docker logs --tail=5 \$(sudo docker ps -q --filter name=cilium-agent) 2>&1 | grep recover"
# Expected: "Gateway node recovered, restoring to egress policy"

sshpass -p rke ssh rke@100.64.0.128 \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress list"
# Expected: both Gateway IPs populated, ActiveGW = 3 (both active)
```

**Step 4:** After the test, verify steering maps on both gateways:

```bash
for GW in 100.64.0.128 100.64.0.130; do
  echo "=== $GW ==="
  sshpass -p rke ssh rke@$GW \
    "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress steer list" | wc -l
done
```

### 10.4 Pass Criteria

**~150K OK, <0.5% FAIL.** With 32255 ports per gateway (2× the default), the
single-gateway phase can sustain higher throughput before port exhaustion.
Failures during the ~3s detection window and recovery transition are
acceptable. After recovery, both gateways should have steering entries in
their respective wider port ranges (gw0: 1026–33280, gw1: 33281–65535).

**Latest rerun (2026-04-06):** `149500 OK / 500 FAIL / 150000 total` (0.33% fail).
The surviving gateway switched to `ActiveGW=1`, gw1 recovery restored `ActiveGW=3`,
and both gateways accumulated steering entries again after ECMP was restored.

### 10.5 What This Tests

| Aspect | Detail |
|--------|--------|
| Wider SNAT port range | `NODEPORT_PORT_MIN_NAT = 1026`, 32255 ports/gw instead of 16384 |
| Forward SNAT | Both gateways allocate from wider partitions without collision |
| Reverse SNAT | `snat_v4_rev_nat_can_skip()` covers the full [1026, 65535] range natively |
| Port-range reply steering | Midpoint at 33281 correctly routes replies to the right gateway |
| High request rate | 500 rps exercises port allocation and GC under pressure |
| Failover under load | Single-gateway uses full [1026, 65535] range during failure |
| Recovery re-balance | After gw1 returns, new flows hash to both gateways again |

### 10.6 Restore Default NodePort Range

After completing this scenario, restore the standard NodePort range:

```bash
kubectl patch configmap cilium-config -n <CILIUM_NS> --type merge \
  -p '{"data":{"node-port-range":"30000,32767"}}'

kubectl rollout restart daemonset cilium -n <CILIUM_NS>
kubectl rollout status daemonset cilium -n <CILIUM_NS> --timeout=120s
```

---

## Scenario 11: HTTP/2 Multiplexed — Failure/Recovery at 500 rps

Same as Scenario 10 (widened SNAT range, failure/recovery cycle) but using
HTTP/2 multiplexed connections instead of one-TCP-connection-per-request.
HTTP/2 multiplexes many requests over fewer long-lived TCP connections, testing
a fundamentally different traffic pattern: fewer SNAT ports consumed, long-lived
flows that must survive or recover through gateway failover, and multiplexed
streams on the BPF datapath.

### 11.1 Prerequisites

- Geneve + DSR mode configured
- Widened SNAT port range (`node-port-range: "1024,1025"`) — 32255 ports/gw
- Both gateways healthy and in policy map (`ActiveGW = 3`)
- HTTP/2 test tools built: `cd ha_egress_gw_test && go build -o h2server ./cmd/h2server && go build -o h2client ./cmd/h2client`

### 11.2 Validate

Same as §10.2 — verify `NODEPORT_PORT_MIN_NAT = 1026` on both gateways.

### 11.3 Test — Full Failure/Recovery Cycle at 500 rps

**Step 1:** Start the HTTP/2 server on the external machine (100.64.0.129):

```bash
./h2server -addr :9998   # HTTP/2 over TLS, self-signed cert
```

Copy h2client to worker (one-time):

```bash
scp ha_egress_gw_test/h2client rke@100.64.0.131:/tmp/
```

**Step 2:** Force replies via gw0 only:

```bash
# On external server:
sudo ip route replace 100.64.0.200/32 via 100.64.0.128
```

**Step 3:** Start a sustained HTTP/2 test (300s at 500 rps, 50 connections, 500 parallel):

```bash
sshpass -p rke ssh rke@100.64.0.131 \
  "sudo nsenter --net -t <POD_PID> /tmp/h2client -server https://100.64.0.129:9998 \
    -total 0 -rps 500 -duration 300s -parallel 500 -conns 50 -timeout 10s"
```

**Step 4:** Sequence of operator actions during the test:

| Time | Action |
|------|--------|
| T+10s | **Shut down gw1 VM via hypervisor** (hard kill) |
| T+15s | Verify single-gateway mode: policy map shows `ActiveGW = 1` |
| T+70s | **Power on gw1 VM via hypervisor** |
| T+110s | Verify both gateways restored: `ActiveGW = 3` |
| T+120s | Restore ECMP: `sudo ip route replace 100.64.0.200/32 nexthop via 100.64.0.128 nexthop via 100.64.0.130` |

**Verify single-gateway mode** (~5s after kill):
```bash
sshpass -p rke ssh rke@100.64.0.128 \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress list -o json"
# Expected: Both gateway IPs preserved, ActiveGW = 1 (only gw0 active)
```

**Verify recovery** (~40s after gw1 boots):
```bash
sshpass -p rke ssh rke@100.64.0.128 \
  "sudo docker logs --tail=5 \$(sudo docker ps -q --filter name=cilium-agent) 2>&1 | grep recover"
# Expected: "Gateway node recovered, restoring to egress policy"

sshpass -p rke ssh rke@100.64.0.128 \
  "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium bpf egress list"
# Expected: both Gateway IPs populated, ActiveGW = 3 (both active)
```

### 11.4 Pass Criteria

**~150K OK, <0.5% FAIL.** HTTP/2 connections that were routed through gw1 will
break when gw1 dies; the client's transport will establish replacement
connections via gw0. Failures are expected during the ~3s detection window.
After recovery, new HTTP/2 connections should hash to both gateways.

### 11.5 What This Tests

| Aspect | Detail |
|--------|--------|
| HTTP/2 multiplexing | 50 long-lived connections carry 500 rps (10 req/s per conn) |
| Fewer SNAT ports | ~50 ports vs ~500/s for TCP-per-request — validates port reuse |
| Long-lived flow failover | Connections through gw1 must fail and reconnect through gw0 |
| TLS over tunnel | HTTP/2 requires TLS; validates TLS traffic on Geneve overlay |
| Steering with persistent flows | Steering entries for long-lived connections vs short-lived |
| Recovery re-balance | New HTTP/2 connections after recovery hash to both gateways |

### 11.6 Key Differences from Scenario 10

| | Scenario 10 (TCP) | Scenario 11 (HTTP/2) |
|-|-------------------|---------------------|
| Protocol | Raw TCP, 1 conn/request | HTTP/2 over TLS, multiplexed |
| Connections | ~500 new/sec | ~50 persistent |
| SNAT ports | High churn | Low churn, long-held |
| Failure impact | Only in-flight requests fail | All streams on gw1-routed conns fail |
| Recovery | New connections auto-balance | New connections auto-balance |

---

## Revert to Default

After completing all scenarios, restore the original configuration:

```bash
kubectl patch configmap cilium-config -n <CILIUM_NS> --type merge \
  -p '{"data":{"tunnel-protocol":"geneve","loadbalancer-mode":"dsr"}}'

kubectl rollout restart daemonset cilium -n <CILIUM_NS>
kubectl rollout status daemonset cilium -n <CILIUM_NS> --timeout=120s
```

---

## Quick Debugging If a Test Fails

1. **Check cilium pods are ready:**
   ```bash
   kubectl get pods -A -l k8s-app=cilium -o wide
   ```

2. **Check policy and reverse maps are populated** (§1.2 commands).

3. **Flush stale steering entries** (old entries can persist through restarts):
   ```bash
   sshpass -p rke ssh rke@<GW0> \
     "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) sh -c '
       bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 2>/dev/null | \
         grep \"^key:\" | while read -r line; do
           key_hex=\$(echo \"\$line\" | sed \"s/key: //;s/  value:.*//\")
           bpftool map delete pinned /sys/fs/bpf/tc/globals/cilium_egress_gw_steer4 key hex \$key_hex
         done
       echo \"flushed\"
     '"
   ```
   Repeat on both gateways (`<GW0>` and `<GW1>`), then retest.

4. **Check for drops:**
   ```bash
   sshpass -p rke ssh rke@<GW0> \
     "sudo docker exec \$(sudo docker ps -q --filter name=cilium-agent) cilium-dbg monitor --type drop"
   ```

5. **Tcpdump on tunnel interface** (tcpdump is on the host, not in the container):
   ```bash
   sshpass -p rke ssh rke@<GW0> "sudo tcpdump -i cilium_geneve -n -c 20"
   # or cilium_vxlan for vxlan scenarios
   ```

See [HA_EGRESS_TROUBLESHOOTING_GUIDE.md](HA_EGRESS_TROUBLESHOOTING_GUIDE.md) for detailed troubleshooting.

---

## Test Results

| # | Config | Result | Date |
|---|--------|--------|------|
| 1 | VxLAN + SNAT | 200/200 | 2026-03-16 |
| 2 | Geneve + SNAT | 200/200 | 2026-03-16 |
| 3 | Geneve + DSR | 200/200 | 2026-03-16 |
| 4 | Multiple policy pairs (Geneve+DSR, 2 EIPs) | 400/400 | 2026-03-16 |
| 5a | Asymmetric failover (replies via gw1) | 200/200 | 2026-03-16 |
| 5b | Asymmetric failover (replies via gw0) | 200/200 | 2026-03-16 |
| 6 | Live failover (30s at 50 rps, route rotation) | 1500/1500 | 2026-03-16 |
| 7 | Removed worker redirect path | N/A | 2026-04-06 |
| 8 | Gateway-only 10K (Geneve+DSR, 2 policies, rotating routes) | 10000/10000 | 2026-03-16 |
| 9 | Gateway failure + recovery, no ECMP, 100rps 300s (c029) | 29864/30000 (136 fail, 0.45%) | 2026-03-17 |
| 10 | Widened SNAT range (32255/gw), failure+recovery, 500rps 300s | 149500/150000 (500 fail, 0.33%) | 2026-04-06 |
| 11a | HTTP/2 multiplexed (32255/gw), kill gw1+recovery, 500rps 300s | 149499/150000 (501 fail, 0.33%) | 2026-03-19 |
| 11b | HTTP/2 multiplexed (32255/gw), kill gw0+recovery, 500rps 300s | 149364/150000 (636 fail, 0.42%) | 2026-03-19 |
