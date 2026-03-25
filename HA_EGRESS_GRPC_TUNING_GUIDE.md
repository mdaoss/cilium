# HA Egress Gateway — gRPC Tuning Guide

Recommendations for running gRPC workloads through the HA active/active
egress gateway. gRPC's long-lived multiplexed connections have fundamentally
different characteristics from HTTP/1.1 traffic and require different tuning.

---

## Why gRPC Is Different

gRPC multiplexes many RPCs over a single long-lived TCP connection (HTTP/2).

| Property | HTTP/1.1 | gRPC |
|----------|----------|------|
| Connections per backend | Many (1 per request or short-lived pool) | Few (1–2, held open indefinitely) |
| Connection lifetime | Seconds to minutes | Hours to days |
| Impact of 1 connection loss | 1 request fails | **All in-flight RPCs fail simultaneously** |
| SNAT port consumption | High (one port per connection) | Very low |
| Load distribution across gateways | Statistical (many 5-tuples hash evenly) | Potentially skewed (few 5-tuples) |

---

## The Critical Risk: CT Entry Expiry Kills gRPC Streams

The CT entry timeout (`bpf-ct-timeout-regular-tcp`, BPF define
`CT_CONNECTION_LIFETIME_TCP`) is a hard deadline. Every packet through the
BPF datapath refreshes the entry's lifetime to `now + T_tcp`
(`bpf/lib/conntrack.h:104`). But if a connection goes idle longer than `T_tcp`:

1. CT entry expires (remains in the BPF map until the Go agent's GC runs)
2. GC deletes the CT entry **and** its associated NAT entry — the SNAT port
   mapping is gone (`pkg/maps/ctmap/ctmap.go:461-464`)
3. Next packet on the connection: CT lookup returns `CT_NEW`, NAT lookup
   returns NULL
4. BPF allocates a **new SNAT port** via `snat_v4_new_mapping()`
   (`bpf/lib/nat.h:337`) — source port changes mid-connection
5. Remote server receives a packet from a different source port → **TCP RST**
6. All multiplexed gRPC streams on that connection die at once

Between GC runs, an expired-but-not-yet-deleted entry is still found by the
BPF map lookup and gets refreshed — so the actual danger window is only the
moment GC deletes the entry. But once deleted, recovery is impossible for
that connection.

### The safety rule

```
T_tcp  >  max(gRPC_keepalive_interval, kernel_tcp_keepalive_time)
```

As long as **any** packet (gRPC PING, TCP keepalive probe, or actual RPC data)
traverses the connection within `T_tcp`, the CT entry is refreshed and never
expires.

---

## Recommended Cilium Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-config
  namespace: kube-system
data:
  # For gRPC workloads: keep CT timeout ABOVE keepalive interval.
  # Do NOT aggressively lower this — the HTTP/1.1 advice of "lower timeout
  # for more SNAT ports" is DANGEROUS for gRPC.
  bpf-ct-timeout-regular-tcp: "7200s"      # 2h, matches kernel tcp_keepalive_time
  bpf-ct-timeout-regular-tcp-fin: "10s"    # default, fine
  bpf-ct-timeout-regular-tcp-syn: "60s"    # default, fine
  conntrack-gc-interval: "30s"             # moderate — no need for aggressive GC
```

Port exhaustion is not a concern for gRPC (see below), so there is no reason
to lower `T_tcp` and risk breaking idle connections.

---

## gRPC Client-Side Settings

### Keepalive (mandatory)

Configure gRPC keepalive so that PING frames refresh the CT entry well within
the timeout window:

**Go:**
```go
import "google.golang.org/grpc/keepalive"

conn, err := grpc.Dial(target,
    grpc.WithKeepaliveParams(keepalive.ClientParameters{
        Time:                30 * time.Second,  // send PING every 30s when idle
        Timeout:             10 * time.Second,  // wait 10s for PING response
        PermitWithoutStream: true,              // CRITICAL — see below
    }),
)
```

**Python:**
```python
channel = grpc.insecure_channel(target, options=[
    ('grpc.keepalive_time_ms', 30000),
    ('grpc.keepalive_timeout_ms', 10000),
    ('grpc.keepalive_permit_without_calls', 1),
])
```

**Java:**
```java
ManagedChannel channel = ManagedChannelBuilder.forTarget(target)
    .keepAliveTime(30, TimeUnit.SECONDS)
    .keepAliveTimeout(10, TimeUnit.SECONDS)
    .keepAliveWithoutCalls(true)
    .build();
```

### Why `PermitWithoutStream` is critical

Without `PermitWithoutStream` (the default), gRPC only sends PING frames when
there are active RPCs. An idle channel with no open streams sends **no keepalive
traffic at all**. If the channel sits idle longer than `T_tcp`, the CT entry
expires and the next RPC on that channel triggers a new SNAT mapping → RST →
all subsequent RPCs fail until the client reconnects.

With `PermitWithoutStream: true`, PINGs flow even on idle channels, keeping the
CT entry alive indefinitely.

### Safety margin calculation

```
Required:   T_tcp > keepalive_interval
Safe:       T_tcp > 2 × keepalive_interval    (tolerates one missed PING)
```

With `keepalive_time = 30s` and `T_tcp = 7200s`: 240× safety margin.

### Retry policy (for gateway failover)

When a gateway goes down, all gRPC connections routed through it break
immediately. Configure retry so RPCs are automatically retried on the
reconnected channel:

```go
conn, err := grpc.Dial(target,
    grpc.WithDefaultServiceConfig(`{
        "methodConfig": [{
            "name": [{"service": ""}],
            "retryPolicy": {
                "maxAttempts": 5,
                "initialBackoff": "0.1s",
                "maxBackoff": "5s",
                "backoffMultiplier": 2,
                "retryableStatusCodes": ["UNAVAILABLE"]
            }
        }]
    }`),
)
```

Recovery time after gateway failure:

```
T_recovery = gRPC_reconnect_backoff + TCP_handshake + TLS_handshake + HTTP2_preface
           ≈ 100ms – 5s (depending on retry attempt)
```

---

## gRPC Server-Side Settings

### `MaxConnectionAge` for rebalancing

After a gateway recovers or the gateway topology changes, existing connections
remain pinned to the original hash result. Use server-side `MaxConnectionAge`
to force periodic reconnection — the new connection re-hashes and may land on
a different gateway:

```go
import "google.golang.org/grpc/keepalive"

server := grpc.NewServer(
    grpc.KeepaliveParams(keepalive.ServerParameters{
        MaxConnectionAge:      30 * time.Minute,  // send GOAWAY after 30min
        MaxConnectionAgeGrace: 10 * time.Second,  // grace period for in-flight RPCs
    }),
)
```

**Trade-off:** GOAWAY causes the client to drain the connection. In-flight RPCs
complete within the grace period; new RPCs go to the reconnected channel. With
a retry policy, this is transparent to callers.

### Server-side keepalive enforcement

If the server enforces a minimum keepalive interval
(`EnforcementPolicy.MinTime`), ensure it is ≤ the client's `keepalive_time`:

```go
server := grpc.NewServer(
    grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
        MinTime:             20 * time.Second,  // must be ≤ client's Time (30s)
        PermitWithoutStream: true,
    }),
)
```

If the client sends PINGs faster than `MinTime`, the server sends GOAWAY with
`ENHANCE_YOUR_CALM` — the connection dies and the CT entry eventually expires.

---

## Kernel TCP Keepalive as a Backstop

If gRPC keepalive is not configured or `PermitWithoutStream` is off, kernel TCP
keepalive is the last defense. The pod's kernel sends TCP keepalive probes that
traverse the BPF datapath and refresh the CT entry:

```bash
# Default kernel settings (check on worker/gateway nodes):
sysctl net.ipv4.tcp_keepalive_time      # 7200 (2h) — first probe after 2h idle
sysctl net.ipv4.tcp_keepalive_intvl     # 75s — interval between subsequent probes
sysctl net.ipv4.tcp_keepalive_probes    # 9 — give up after 9 failed probes
```

**Safety rule with kernel keepalive only:**
```
T_tcp > tcp_keepalive_time
```

Defaults: `T_tcp (8000s) > tcp_keepalive_time (7200s)` — safe by 800s.

**Danger scenario:** If `T_tcp` is lowered to 3600s without enabling gRPC
keepalive, the CT entry expires 3600s before the first TCP keepalive probe.
The connection breaks silently — the pod doesn't know until it tries to send.

**Note:** Kernel TCP keepalive only works if `SO_KEEPALIVE` is set on the
socket. Most gRPC implementations enable it by default, but verify for your
language/framework.

---

## Port Exhaustion Is Not a Concern

Unlike HTTP/1.1, gRPC uses very few SNAT ports:

```
PORTS_USED = num_backends × connections_per_backend
```

Typical: 10 backends × 2 connections = 20 ports out of 16,384 per gateway.

Port exhaustion requires >16K concurrent TCP connections per gateway, which
gRPC workloads virtually never reach due to multiplexing. This means:

- **No need to lower `T_tcp`** for port capacity — keep it high for safety
- **No need to shrink `node-port-range`** — ports are abundant
- **No need for multiple egress IPs** for capacity scaling (only if policy
  isolation is required)
- **No need for aggressive GC** — `conntrack-gc-interval: "30s"` is sufficient

---

## Gateway Load Imbalance

With few connections, the jhash-based 50/50 split is statistically noisy:

| Connections to same (dst_ip, dst_port) | P(all land on one gateway) |
|----------------------------------------|----------------------------|
| 1 | 50% |
| 2 | 25% |
| 4 | 6.25% |
| 10 | 0.1% |

With 1–2 connections per backend, there is a significant probability that all
traffic to a given backend routes through one gateway. This is inherent to
hash-based distribution with low cardinality — not a bug.

### Mitigation strategies

1. **Increase connection count per backend.** gRPC client-side load balancing
   with `round_robin` policy opens separate connections to each resolved address,
   increasing the number of distinct 5-tuples.

2. **Accept the imbalance.** With gRPC's low port consumption, one gateway
   handling more traffic than the other has no capacity impact. The only
   downside is bandwidth asymmetry.

3. **Use `MaxConnectionAge` on the server.** Periodic reconnection re-rolls the
   hash, giving a new chance at the other gateway. Over time, traffic
   distribution evens out statistically.

---

## Gateway Failover Behavior

When a gateway node goes down:

1. All gRPC connections routed through that gateway lose their SNAT mapping
2. The Cilium control plane removes the failed gateway from the policy map
   (`cilium_egress_gw_policy_v4`)
3. New connections from the same pods hash differently (single-gateway mode)
   and route through the surviving gateway
4. **Existing connections are NOT migrated** — they break with RST from the
   server side

Impact on gRPC:

- **All multiplexed streams on affected connections fail simultaneously**
- Client receives `UNAVAILABLE` status for in-flight RPCs
- gRPC's built-in reconnection logic establishes new connections
- With retry policy, failed RPCs are retried on the new connection
- `MaxConnectionAge` ensures connections through the recovered gateway
  eventually rebalance

---

## Tuning Checklist

| Item | Setting | Why |
|------|---------|-----|
| `bpf-ct-timeout-regular-tcp` | `≥ 7200s` (keep default or higher) | Must exceed keepalive interval; port exhaustion is not a concern |
| `conntrack-gc-interval` | `30s` (moderate) | No need for aggressive GC; few ports used |
| gRPC client keepalive `Time` | `30s` | Refresh CT entry well within timeout |
| gRPC client `PermitWithoutStream` | **`true`** | **Critical** — keeps idle channels alive |
| gRPC client retry policy | `UNAVAILABLE` retryable | Handles gateway failover gracefully |
| gRPC server `MaxConnectionAge` | `30m` | Rebalances connections after topology changes |
| gRPC server `EnforcementPolicy.MinTime` | `≤ client Time` | Prevents GOAWAY from keepalive rejection |
| `node-port-range` | default (`30000-32767`) | No need to shrink — ports are abundant |
| Multiple egress IPs | Not needed for capacity | Only useful for policy-level isolation |
| Kernel `tcp_keepalive_time` | Verify `< T_tcp` | Backstop if gRPC keepalive is misconfigured |

---

## Mixed Workloads (gRPC + HTTP/1.1)

If both gRPC and HTTP/1.1 workloads share the same egress gateway, their
tuning requirements conflict:

| Parameter | gRPC wants | HTTP/1.1 wants |
|-----------|-----------|----------------|
| `bpf-ct-timeout-regular-tcp` | High (≥ 7200s) | Low (900–3600s) for port capacity |
| `conntrack-gc-interval` | Moderate (30s) | Aggressive (10s) for port reclaim |

**Resolution:** Use separate `CiliumEgressGatewayPolicy` objects with different
egress IPs for each workload type. CT timeouts are global (not per-policy), so
set `T_tcp` to satisfy gRPC (the more demanding requirement) and scale HTTP/1.1
capacity through multiple egress IPs instead:

```yaml
# gRPC workloads — low port consumption, long-lived
apiVersion: cilium.io/v2
kind: CiliumEgressGatewayPolicy
metadata:
  name: egress-grpc
spec:
  egressIP: 100.64.0.200
  destinationCIDRs: [0.0.0.0/0]
  selectors:
    - podSelector:
        matchLabels:
          traffic-type: grpc

# HTTP/1.1 workloads — high port consumption, short-lived
# Use multiple egress IPs to scale port capacity
apiVersion: cilium.io/v2
kind: CiliumEgressGatewayPolicy
metadata:
  name: egress-http-1
spec:
  egressIP: 100.64.0.201
  destinationCIDRs: [0.0.0.0/0]
  selectors:
    - podSelector:
        matchLabels:
          traffic-type: http
          shard: "1"

apiVersion: cilium.io/v2
kind: CiliumEgressGatewayPolicy
metadata:
  name: egress-http-2
spec:
  egressIP: 100.64.0.202
  destinationCIDRs: [0.0.0.0/0]
  selectors:
    - podSelector:
        matchLabels:
          traffic-type: http
          shard: "2"
```

This gives gRPC the high CT timeout it needs while scaling HTTP/1.1 port
capacity through multiple egress IPs (each with its own 16,384 × 2 port space).
