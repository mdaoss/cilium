/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/fib.h"
#include "lib/identity.h"
#include "lib/jhash.h"
#include "lib/overloadable.h"

#include "encap.h"

#ifdef ENABLE_EGRESS_GATEWAY_COMMON

/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

/* These are special IP values in the CIDR 0.0.0.0/8 range that map to specific
 * case for in the egress gateway policies handling.
 */

/* Special values in the policy_entry->gateway_ip_0: */
#define EGRESS_GATEWAY_NO_GATEWAY (0)
#define EGRESS_GATEWAY_EXCLUDED_CIDR bpf_htonl(1)

/* Special values in the policy_entry->egress_ip: */
#define EGRESS_GATEWAY_NO_EGRESS_IP (0)

/* HA port partitioning: split the SNAT port range between two gateways.
 * Gateway 0 gets the lower half, gateway 1 gets the upper half.
 *
 * The range is derived from NODEPORT_PORT_MIN_NAT / NODEPORT_PORT_MAX_NAT,
 * which in turn are controlled by the node-port-range config option.
 * To widen per-gateway capacity, narrow the NodePort range (e.g.
 * node-port-range: "1024,1025"), which lowers NODEPORT_PORT_MIN_NAT and
 * gives more ports to the SNAT range.
 */
#define EGRESS_GW_PORT_RANGE_SIZE (NODEPORT_PORT_MAX_NAT - NODEPORT_PORT_MIN_NAT + 1)
#define EGRESS_GW_PORT_MID        (NODEPORT_PORT_MIN_NAT + EGRESS_GW_PORT_RANGE_SIZE / 2)
#define EGRESS_GW_PORT_MIN_0      NODEPORT_PORT_MIN_NAT
#define EGRESS_GW_PORT_MAX_0      (EGRESS_GW_PORT_MID - 1)
#define EGRESS_GW_PORT_MIN_1      EGRESS_GW_PORT_MID
#define EGRESS_GW_PORT_MAX_1      NODEPORT_PORT_MAX_NAT

static __always_inline
int egress_gw_fib_lookup_and_redirect(struct __ctx_buff *ctx, __be32 egress_ip, __be32 daddr,
				      __s8 *ext_err)
{
	struct bpf_fib_lookup_padded fib_params = {};
	int oif = 0;

	*ext_err = (__s8)fib_lookup_v4(ctx, &fib_params, egress_ip, daddr, 0);

	switch (*ext_err) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		break;
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		/* Don't redirect if we can't update the L2 DMAC: */
		if (!neigh_resolver_available())
			return CTX_ACT_OK;

		/* Don't redirect without a valid target ifindex: */
		if (!is_defined(HAVE_FIB_IFINDEX))
			return CTX_ACT_OK;
		break;
	default:
		return DROP_NO_FIB;
	}

	/* Skip redirect in to-netdev if we stay on the same iface: */
	if (is_defined(IS_BPF_HOST) && fib_params.l.ifindex == ctx_get_ifindex(ctx))
		return CTX_ACT_OK;

	return fib_do_redirect(ctx, true, &fib_params, false, ext_err, &oif);
}

/* egress_gw_select_owner - Deterministically select a gateway owner (0 or 1)
 * for a flow based on its forward-direction 5-tuple using jhash.
 *
 * @saddr:   source IP (pod IP)
 * @daddr:   destination IP (external server IP)
 * @sport:   source port (pod ephemeral port), network byte order
 * @dport:   destination port (server port), network byte order
 * @nexthdr: L4 protocol number
 *
 * Returns 0 or 1.
 */
static __always_inline __u8
egress_gw_select_owner(__be32 saddr, __be32 daddr,
		       __be16 sport, __be16 dport, __u8 nexthdr)
{
	__u32 hash = jhash_3words((__u32)saddr, (__u32)daddr,
				  ((__u32)sport << 16) | (__u32)dport,
				  (__u32)nexthdr);
	return hash & 1;
}

#ifdef ENABLE_EGRESS_GATEWAY
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct egress_gw_policy_key);
	__type(value, struct egress_gw_policy_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} EGRESS_POLICY_MAP __section_maps_btf;

#ifndef EGRESS_GW_STEER_MAP_SIZE
# define EGRESS_GW_STEER_MAP_SIZE 65536
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct egress_gw_steer_key);
	__type(value, struct egress_gw_steer_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_GW_STEER_MAP_SIZE);
} cilium_egress_gw_steer4 __section_maps_btf;

/* Reverse lookup map: egress_ip → (gw0, gw1).
 * Used by non-owner gateways to redirect reply traffic when no local
 * SNAT mapping or steering entry exists. Populated by the Go control plane.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct egress_gw_reverse_key);
	__type(value, struct egress_gw_reverse_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_egress_gw_reverse4 __section_maps_btf;

/* egress_gw_steer_update - Insert or update a steering map entry for a flow.
 *
 * Called after SNAT to record which gateway owns a flow so replies can be
 * steered back to the correct node for reverse SNAT.
 *
 * @saddr:     post-SNAT packet source IP (egress IP)
 * @daddr:     post-SNAT packet dest IP (server IP)
 * @sport:     post-SNAT source port (SNAT port), network byte order
 * @dport:     post-SNAT dest port (server port), network byte order
 * @nexthdr:   L4 protocol
 * @owner_ip:  gateway node IP that owns this flow
 * @owner_idx: gateway index (0 or 1)
 */
static __always_inline void
egress_gw_steer_update(__be32 saddr, __be32 daddr,
		       __be16 sport, __be16 dport, __u8 nexthdr,
		       __be32 owner_ip, __u8 owner_idx)
{
	/* Steering key uses the reply-path 5-tuple (before reverse SNAT):
	 *   reply src  = server IP  = post-SNAT daddr
	 *   reply dst  = egress IP  = post-SNAT saddr
	 *   reply sport = server port = post-SNAT dport
	 *   reply dport = SNAT port   = post-SNAT sport
	 */
	struct egress_gw_steer_key key;
	struct egress_gw_steer_val val;

	key.saddr   = daddr;
	key.daddr   = saddr;
	key.sport   = dport;
	key.dport   = sport;
	key.nexthdr = nexthdr;
	key.pad[0]  = 0;
	key.pad[1]  = 0;
	key.pad[2]  = 0;

	val.owner_ip  = owner_ip;
	val.owner_idx = owner_idx;
	val.pad[0]    = 0;
	val.pad[1]    = 0;
	val.pad[2]    = 0;

	map_update_elem(&cilium_egress_gw_steer4, &key, &val, BPF_ANY);
}

static __always_inline
struct egress_gw_policy_entry *lookup_ip4_egress_gw_policy(__be32 saddr, __be32 daddr)
{
	struct egress_gw_policy_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.saddr = saddr,
		.daddr = daddr,
	};
	return map_lookup_elem(&EGRESS_POLICY_MAP, &key);
}
#endif /* ENABLE_EGRESS_GATEWAY */

static __always_inline int
egress_gw_request_needs_redirect(struct ipv4_ct_tuple *rtuple __maybe_unused,
				 __be32 *gateway_ip __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	struct egress_gw_policy_entry *egress_gw_policy;

	egress_gw_policy = lookup_ip4_egress_gw_policy(ipv4_ct_reverse_tuple_saddr(rtuple),
						       ipv4_ct_reverse_tuple_daddr(rtuple));
	if (!egress_gw_policy)
		return CTX_ACT_OK;

	switch (egress_gw_policy->gateway_ip_0) {
	case EGRESS_GATEWAY_NO_GATEWAY:
		/* If no gateway is found, drop the packet. */
		return DROP_NO_EGRESS_GATEWAY;
	case EGRESS_GATEWAY_EXCLUDED_CIDR:
		return CTX_ACT_OK;
	}

	/* When active_gw is non-zero the control plane has set the HA
	 * bitmask — use it to select among the fixed-slot gateway IPs.
	 * When active_gw is zero this is either a legacy entry (old pad
	 * field) or a pre-reconciliation pinned entry after upgrade, so
	 * fall back to the original behavior to avoid a transient
	 * blackhole.  The "all gateways truly inactive" case is handled
	 * by the control plane writing gateway_ip_0 = NO_GATEWAY (0),
	 * which is caught by the switch above.
	 */
	if (egress_gw_policy->gateway_ip_1 != 0) {
		__u32 active = egress_gw_policy->active_gw;

		if (active != 0) {
			if (active == EGRESS_GW_ACTIVE_BOTH) {
				__u8 idx;

				idx = egress_gw_select_owner(
						rtuple->daddr,
						rtuple->saddr,
						rtuple->sport,
						rtuple->dport,
						rtuple->nexthdr);
				*gateway_ip = (idx == 0)
					? egress_gw_policy->gateway_ip_0
					: egress_gw_policy->gateway_ip_1;
			} else if (active & EGRESS_GW_ACTIVE_1) {
				*gateway_ip =
					egress_gw_policy->gateway_ip_1;
			} else {
				*gateway_ip =
					egress_gw_policy->gateway_ip_0;
			}
		} else {
			/* Legacy fallback: hash as before. */
			__u8 idx;

			idx = egress_gw_select_owner(rtuple->daddr,
						     rtuple->saddr,
						     rtuple->sport,
						     rtuple->dport,
						     rtuple->nexthdr);
			*gateway_ip = (idx == 0)
				? egress_gw_policy->gateway_ip_0
				: egress_gw_policy->gateway_ip_1;
		}
	} else {
		*gateway_ip = egress_gw_policy->gateway_ip_0;
	}

	return CTX_ACT_REDIRECT;
#else
	return CTX_ACT_OK;
#endif /* ENABLE_EGRESS_GATEWAY */
}

static __always_inline
bool egress_gw_snat_needed(__be32 saddr __maybe_unused,
			   __be32 daddr __maybe_unused,
			   __be32 *snat_addr __maybe_unused,
			   __be32 *gw_ip0 __maybe_unused,
			   __be32 *gw_ip1 __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	struct egress_gw_policy_entry *egress_gw_policy;

	egress_gw_policy = lookup_ip4_egress_gw_policy(saddr, daddr);
	if (!egress_gw_policy)
		return false;

	if (egress_gw_policy->gateway_ip_0 == EGRESS_GATEWAY_NO_GATEWAY ||
	    egress_gw_policy->gateway_ip_0 == EGRESS_GATEWAY_EXCLUDED_CIDR)
		return false;

	*snat_addr = egress_gw_policy->egress_ip;
	*gw_ip0 = egress_gw_policy->gateway_ip_0;
	*gw_ip1 = egress_gw_policy->gateway_ip_1;
	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY */
}

static __always_inline
bool egress_gw_reply_matches_policy(struct iphdr *ip4 __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY)
	struct egress_gw_policy_entry *egress_policy;

	/* Find a matching policy by looking up the reverse address tuple: */
	egress_policy = lookup_ip4_egress_gw_policy(ip4->daddr, ip4->saddr);
	if (!egress_policy)
		return false;

	if (egress_policy->gateway_ip_0 == EGRESS_GATEWAY_NO_GATEWAY ||
	    egress_policy->gateway_ip_0 == EGRESS_GATEWAY_EXCLUDED_CIDR)
		return false;

	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY */
}

/** Match a packet against EGW policy map, and return the gateway's IP.
 * @arg rtuple		CT tuple for the packet
 * @arg ct_status	CT result, to identify egressing connections
 * @arg gateway_ip	returns the gateway node's IP
 *
 * Returns
 * * CTX_ACT_REDIRECT if a matching policy entry was found,
 * * CTX_ACT_OK if no EGW logic should be applied,
 * * DROP_* for error conditions.
 */
static __always_inline int
egress_gw_request_needs_redirect_hook(struct ipv4_ct_tuple *rtuple,
				      enum ct_status ct_status,
				      __be32 *gateway_ip)
{
#if defined(IS_BPF_LXC)
	/* If the packet is a reply or is related, it means that outside
	 * has initiated the connection, and so we should skip egress
	 * gateway, since an egress policy is only matching connections
	 * originating from a pod.
	 */
	if (ct_status == CT_REPLY || ct_status == CT_RELATED)
		return CTX_ACT_OK;
#else
	/* We lookup CT in forward direction at to-netdev and expect to
	 * get CT_ESTABLISHED for outbound connection as
	 * from_container should have already created a CT entry.
	 * If we get CT_NEW here, it's an indication that it's a reply
	 * for inbound connection or host-level outbound connection.
	 * We don't expect to receive any other ct_status here.
	 */
	if (ct_status != CT_ESTABLISHED)
		return CTX_ACT_OK;
#endif

	return egress_gw_request_needs_redirect(rtuple, gateway_ip);
}

static __always_inline
bool egress_gw_snat_needed_hook(__be32 saddr, __be32 daddr, __be32 *snat_addr,
				__be32 *gw_ip0, __be32 *gw_ip1)
{
	struct remote_endpoint_info *remote_ep;

	remote_ep = lookup_ip4_remote_endpoint(daddr, 0);
	/* If the packet is destined to an entity inside the cluster, either EP
	 * or node, skip SNAT since only traffic leaving the cluster is supposed
	 * to be masqueraded with an egress IP.
	 */
	if (remote_ep &&
	    identity_is_cluster(remote_ep->sec_identity))
		return false;

	return egress_gw_snat_needed(saddr, daddr, snat_addr, gw_ip0, gw_ip1);
}

static __always_inline
bool egress_gw_reply_needs_redirect_hook(struct iphdr *ip4, __u32 *tunnel_endpoint,
					 __u32 *dst_sec_identity)
{
	if (egress_gw_reply_matches_policy(ip4)) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (!info || info->tunnel_endpoint == 0)
			return false;

		*tunnel_endpoint = info->tunnel_endpoint;
		*dst_sec_identity = info->sec_identity;

		return true;
	}

	return false;
}

static __always_inline
int egress_gw_handle_packet(struct __ctx_buff *ctx,
			    struct ipv4_ct_tuple *tuple,
			    enum ct_status ct_status,
			    __u32 src_sec_identity, __u32 dst_sec_identity,
			    const struct trace_ctx *trace)
{
	struct endpoint_info *gateway_node_ep;
	__be32 gateway_ip = 0;
	int ret;

	/* If the packet is destined to an entity inside the cluster,
	 * either EP or node, it should not be forwarded to an egress
	 * gateway since only traffic leaving the cluster is supposed to
	 * be masqueraded with an egress IP.
	 */
	if (identity_is_cluster(dst_sec_identity))
		return CTX_ACT_OK;

	ret = egress_gw_request_needs_redirect_hook(tuple, ct_status, &gateway_ip);
	if (IS_ERR(ret))
		return ret;

	if (ret == CTX_ACT_OK)
		return ret;

	/* If the gateway node is the local node, then just let the
	 * packet go through, as it will be SNATed later on by
	 * handle_nat_fwd().
	 */
	gateway_node_ep = __lookup_ip4_endpoint(gateway_ip);
	if (gateway_node_ep && (gateway_node_ep->flags & ENDPOINT_F_HOST))
		return CTX_ACT_OK;

	/* Send the packet to egress gateway node through a tunnel. */
	return __encap_and_redirect_with_nodeid(ctx, 0, gateway_ip,
						src_sec_identity, dst_sec_identity,
						NOT_VTEP_DST, trace);
}

/* egress_gw_reply_steer - Steer an incoming reply to the HA owner gateway.
 *
 * Called BEFORE snat_v4_rev_nat() in the NAT ingress path. If the steering
 * map indicates that another node owns this flow, redirect the packet to
 * the owner via tunnel encapsulation so it can perform reverse SNAT.
 *
 * Returns:
 *   CTX_ACT_REDIRECT — packet was tunneled to the owner gateway.
 *   CTX_ACT_OK       — no redirect needed (we are the owner, or no
 *                       steering entry exists). Caller should proceed
 *                       with local snat_v4_rev_nat().
 *   DROP_*           — error.
 */
static __always_inline int
egress_gw_reply_steer(struct __ctx_buff *ctx __maybe_unused,
		      struct iphdr *ip4 __maybe_unused,
		      __s8 *ext_err __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY) && !defined(IS_BPF_OVERLAY)
	/* Skip policy-map check here: this runs BEFORE rev SNAT, so
	 * ip4->daddr is still the egress IP (not the pod IP) and the
	 * policy lookup would always miss.  Instead, go straight to
	 * the steering-map lookup — the map itself is authoritative.
	 */

	/* Only steer TCP/UDP replies (ICMP has no port-based steering). */
	if (ip4->protocol != IPPROTO_TCP && ip4->protocol != IPPROTO_UDP)
		return CTX_ACT_OK;

	{
		int l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
		__be16 ports[2] = {0, 0};
		struct egress_gw_steer_key key;
		struct egress_gw_steer_val *steer;
		struct egress_gw_reverse_key rkey;
		struct egress_gw_reverse_val *rval;
		struct endpoint_info *ep;
		struct trace_ctx trace;
		__be32 port_owner;
		__u16 snat_port;

		if (ctx_load_bytes(ctx, l4_off, &ports, sizeof(ports)) < 0)
			return CTX_ACT_OK;

		/* Build the steering key from the reply 5-tuple (before
		 * reverse SNAT): src=server, dst=egress_ip,
		 * sport=server_port, dport=snat_port.
		 */
		key.saddr   = ip4->saddr;
		key.daddr   = ip4->daddr;
		key.sport   = ports[0];
		key.dport   = ports[1];
		key.nexthdr = ip4->protocol;
		key.pad[0]  = 0;
		key.pad[1]  = 0;
		key.pad[2]  = 0;

		steer = map_lookup_elem(&cilium_egress_gw_steer4, &key);
		if (!steer) {
			/* No steering entry. Use the SNAT port range to
			 * determine the owner and redirect if needed.
			 */
			rkey.egress_ip = ip4->daddr;
			rval = map_lookup_elem(&cilium_egress_gw_reverse4,
					       &rkey);
			if (rval && rval->gateway_ip_1 != 0) {
				snat_port = bpf_ntohs(ports[1]);
				if (snat_port >= EGRESS_GW_PORT_MIN_1)
					port_owner = rval->gateway_ip_1;
				else
					port_owner = rval->gateway_ip_0;

				ep = __lookup_ip4_endpoint(port_owner);
				if (!ep || !(ep->flags & ENDPOINT_F_HOST)) {
					trace.reason = TRACE_REASON_CT_REPLY;
					trace.monitor = 0;
					return __encap_and_redirect_with_nodeid(
						ctx, 0, port_owner,
						SECLABEL, 0,
						NOT_VTEP_DST, &trace);
				}
			}
			return CTX_ACT_OK;
		}

		/* Check if we are the owner */
		ep = __lookup_ip4_endpoint(steer->owner_ip);
		if (ep && (ep->flags & ENDPOINT_F_HOST)) {
			/* Steering says we own this flow. Verify against
			 * the SNAT port range. During single-gateway mode
			 * we used the full port range; after recovery, stale
			 * steering entries may claim ownership of ports that
			 * now belong to the recovered gateway. If the port
			 * range disagrees, redirect to the true owner.
			 */
			rkey.egress_ip = ip4->daddr;
			rval = map_lookup_elem(&cilium_egress_gw_reverse4,
					       &rkey);
			if (rval && rval->gateway_ip_1 != 0) {
				snat_port = bpf_ntohs(ports[1]);
				if (snat_port >= EGRESS_GW_PORT_MIN_1)
					port_owner = rval->gateway_ip_1;
				else
					port_owner = rval->gateway_ip_0;

				if (port_owner != steer->owner_ip) {
					trace.reason = TRACE_REASON_CT_REPLY;
					trace.monitor = 0;
					return __encap_and_redirect_with_nodeid(
						ctx, 0, port_owner,
						SECLABEL, 0,
						NOT_VTEP_DST, &trace);
				}
			}
			return CTX_ACT_OK; /* We are owner, do rev SNAT */
		}

		/* Not the owner. Redirect to owner via tunnel. */
		trace.reason = TRACE_REASON_CT_REPLY;
		trace.monitor = 0;

		return __encap_and_redirect_with_nodeid(
			ctx, 0, steer->owner_ip,
			SECLABEL, 0,
			NOT_VTEP_DST, &trace);
	}
#else
	return CTX_ACT_OK;
#endif
}

/* egress_gw_reply_steer_fallback - Fallback redirect when rev SNAT has no
 * mapping and no steering entry exists.
 *
 * Called AFTER snat_v4_rev_nat() fails with DROP_NAT_NO_MAPPING. Uses
 * the reverse lookup map (egress_ip → gw0, gw1) to identify the reply
 * and redirect to the other gateway for reverse SNAT.
 *
 * Returns:
 *   CTX_ACT_REDIRECT — packet was tunneled to the other gateway.
 *   CTX_ACT_OK       — no redirect possible. Caller should recircle.
 *   DROP_*           — error.
 */
static __always_inline int
egress_gw_reply_steer_fallback(struct __ctx_buff *ctx __maybe_unused,
			       __s8 *ext_err __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY) && !defined(IS_BPF_OVERLAY)
	void *data, *data_end;
	struct iphdr *ip4;
	struct egress_gw_reverse_key rkey;
	struct egress_gw_reverse_val *rval;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return CTX_ACT_OK;

	rkey.egress_ip = ip4->daddr;
	rval = map_lookup_elem(&cilium_egress_gw_reverse4, &rkey);
	if (!rval || rval->gateway_ip_1 == 0)
		return CTX_ACT_OK;

	{
		struct endpoint_info *ep;
		__be32 other_gw;

		ep = __lookup_ip4_endpoint(rval->gateway_ip_0);
		if (ep && (ep->flags & ENDPOINT_F_HOST))
			other_gw = rval->gateway_ip_1;
		else
			other_gw = rval->gateway_ip_0;

		{
			struct trace_ctx trace;

			trace.reason = TRACE_REASON_CT_REPLY;
			trace.monitor = 0;

			return __encap_and_redirect_with_nodeid(
				ctx, 0, other_gw,
				SECLABEL, 0,
				NOT_VTEP_DST, &trace);
		}
	}
#else
	return CTX_ACT_OK;
#endif
}

#endif /* ENABLE_EGRESS_GATEWAY_COMMON */
