// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "trapagg.h"

/* Define here to avoid conflicts with include files. */
#define ETH_HLEN	14		/* Total octets in header.	*/
#define ETH_P_IP	0x0800		/* Internet Protocol packet.	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook.		*/
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header.	*/
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN.	*/
#define USHRT_MAX	65535
#define IP_OFFSET	0x1FFF
#define GRE_VERSION	bpf_htons(0x0007)
#define GRE_CSUM	bpf_htons(0x8000)
#define GRE_KEY		bpf_htons(0x2000)
#define GRE_SEQ		bpf_htons(0x1000)
#define GRE_IS_CSUM(f)	((f) & GRE_CSUM)
#define GRE_IS_KEY(f)	((f) & GRE_KEY)
#define GRE_IS_SEQ(f)	((f) & GRE_SEQ)

const volatile bool targ_drop = false;
const volatile bool targ_exception = false;
const volatile bool targ_control = false;
const volatile bool targ_all = false;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct trap_flow_key);
	__type(value, u64);
} trap_flows SEC(".maps");

static __always_inline bool flow_dissector_valid_access(struct sk_buff *skb,
							u16 offset,
							u16 hdr_size)
{
	unsigned int len, data_len;

	bpf_probe_read(&len, sizeof(len), &skb->len);
	bpf_probe_read(&data_len, sizeof(data_len), &skb->data_len);

	/* Verify this variable offset does not overflow. */
	if (offset > (USHRT_MAX - hdr_size))
		return false;

	/* Make sure we only access data in linear area. */
	return offset + hdr_size < len - data_len;
}

static __always_inline bool
flow_dissector_ipv4_dissect(struct sk_buff *skb, struct trap_flow_key *flow,
			    u16 *p_offset)
{
	void *skb_data = skb->head + skb->mac_header;
	struct iphdr iph;

	if (!flow_dissector_valid_access(skb, *p_offset, sizeof(iph)))
		return false;

	bpf_probe_read(&iph, sizeof(iph), skb_data + *p_offset);

	if (iph.ihl < 5)
		return false;

	flow->addr_proto = ETH_P_IP;
	flow->saddrv4 = iph.saddr;
	flow->daddrv4 = iph.daddr;
	flow->ip_proto = iph.protocol;

	/* After the first frag, packets do not have headers to parse, so
	 * return false to stop the dissection.
	 */
	if (iph.frag_off & bpf_htons(IP_OFFSET))
		return false;

	*p_offset += iph.ihl << 2;

	return true;
}

static __always_inline bool
flow_dissector_ipv6_dissect(struct sk_buff *skb, struct trap_flow_key *flow,
			    u16 *p_offset)
{
	void *skb_data = skb->head + skb->mac_header;
	struct ipv6hdr ip6h;

	if (!flow_dissector_valid_access(skb, *p_offset, sizeof(ip6h)))
		return false;

	bpf_probe_read(&ip6h, sizeof(ip6h), skb_data + *p_offset);

	flow->addr_proto = ETH_P_IPV6;
	__builtin_memcpy(flow->saddrv6, &ip6h.saddr, sizeof(flow->saddrv6));
	__builtin_memcpy(flow->daddrv6, &ip6h.daddr, sizeof(flow->daddrv6));
	flow->ip_proto = ip6h.nexthdr;

	*p_offset += sizeof(ip6h);

	return true;
}

static __always_inline bool
flow_dissector_gre_dissect(struct sk_buff *skb, struct trap_flow_key *flow,
			   u16 *p_offset)
{
	void *skb_data = skb->head + skb->mac_header;
	struct gre_base_hdr gre;

	if (!flow_dissector_valid_access(skb, *p_offset, sizeof(gre)))
		return false;

	bpf_probe_read(&gre, sizeof(gre), skb_data + *p_offset);

	if (gre.flags & GRE_VERSION)
		return false;

	*p_offset += sizeof(gre);
	if (GRE_IS_CSUM(gre.flags))
		*p_offset += 4;
	if (GRE_IS_KEY(gre.flags))
		*p_offset += 4;
	if (GRE_IS_SEQ(gre.flags))
		*p_offset += 4;

	if (gre.protocol == bpf_htons(ETH_P_IP))
		return flow_dissector_ipv4_dissect(skb, flow, p_offset);
	else if (gre.protocol == bpf_htons(ETH_P_IPV6))
		return flow_dissector_ipv6_dissect(skb, flow, p_offset);

	return false;
}

static __always_inline bool
flow_dissector_udp_dissect(struct sk_buff *skb, struct trap_flow_key *flow,
			   u16 *p_offset)
{
	void *skb_data = skb->head + skb->mac_header;
	struct udphdr udp;

	if (!flow_dissector_valid_access(skb, *p_offset, sizeof(udp)))
		return false;

	bpf_probe_read(&udp, sizeof(udp), skb_data + *p_offset);

	flow->sport = bpf_ntohs(udp.source);
	flow->dport = bpf_ntohs(udp.dest);

	*p_offset += bpf_ntohs(udp.len);

	return true;
}

static __always_inline bool
flow_dissector_tcp_dissect(struct sk_buff *skb, struct trap_flow_key *flow,
			   u16 *p_offset)
{
	void *skb_data = skb->head + skb->mac_header;
	struct tcphdr tcp;

	if (!flow_dissector_valid_access(skb, *p_offset, sizeof(tcp)))
		return false;

	bpf_probe_read(&tcp, sizeof(tcp), skb_data + *p_offset);

	if (tcp.doff < 5 || tcp.doff > 15)
		return false;

	flow->sport = bpf_ntohs(tcp.source);
	flow->dport = bpf_ntohs(tcp.dest);

	*p_offset += tcp.doff << 2;

	return true;
}

static __always_inline void flow_dissector(struct sk_buff *skb,
					   struct trap_flow_key *flow)
{
	void *skb_data = skb->head + skb->mac_header;
	struct vlan_hdr vlan_hdr;
	u16 offset, eth_proto;
	struct ethhdr eth;

	/* Skip if MAC header was not set. */
	if (skb->mac_header == 0xffff)
		return;

	if (!flow_dissector_valid_access(skb, 0, sizeof(eth)))
		return;

	bpf_probe_read(&eth, sizeof(eth), skb_data);

	offset = ETH_HLEN;
	eth_proto = bpf_ntohs(eth.h_proto);

	if (eth_proto == ETH_P_8021AD) {
		bpf_probe_read(&vlan_hdr, sizeof(vlan_hdr), skb_data + offset);
		offset += sizeof(struct vlan_hdr);
		eth_proto = bpf_ntohs(vlan_hdr.h_vlan_encapsulated_proto);
	}

	if (eth_proto == ETH_P_8021Q) {
		bpf_probe_read(&vlan_hdr, sizeof(vlan_hdr), skb_data + offset);
		offset += sizeof(struct vlan_hdr);
		eth_proto = bpf_ntohs(vlan_hdr.h_vlan_encapsulated_proto);
	}

	switch (eth_proto) {
	case ETH_P_IP:
		if (!flow_dissector_ipv4_dissect(skb, flow, &offset))
			return;
		break;
	case ETH_P_IPV6:
		if (!flow_dissector_ipv6_dissect(skb, flow, &offset))
			return;
		break;
	default:
		return;
	}

	switch (flow->ip_proto) {
	case IPPROTO_IPIP:
		flow->is_encap = true;
		if (!flow_dissector_ipv4_dissect(skb, flow, &offset))
			return;
		break;
	case IPPROTO_IPV6:
		flow->is_encap = true;
		if (!flow_dissector_ipv6_dissect(skb, flow, &offset))
			return;
		break;
	case IPPROTO_GRE:
		flow->is_encap = true;
		if (!flow_dissector_gre_dissect(skb, flow, &offset))
			return;
		break;
	default:
		break;
	}

	switch (flow->ip_proto) {
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		if (!flow_dissector_udp_dissect(skb, flow, &offset))
			return;
		break;
	case IPPROTO_TCP:
		if (!flow_dissector_tcp_dissect(skb, flow, &offset))
			return;
		break;
	default:
		return;
	}
}

SEC("tp_btf/devlink_trap_report")
int BPF_PROG(devlink_trap_report, const struct devlink *devlink,
	     struct sk_buff *skb, const struct devlink_trap_metadata *metadata)
{
	enum devlink_trap_type type;
	struct trap_flow_key tfk;
	const char *trap_name;
	u64 *val, one = 1;

	/* Filter unwanted traps. */
	type = metadata->trap_type;
	if (!targ_all) {
		if ((type == DEVLINK_TRAP_TYPE_DROP && !targ_drop) ||
		    (type == DEVLINK_TRAP_TYPE_EXCEPTION && !targ_exception) ||
		    (type == DEVLINK_TRAP_TYPE_CONTROL && !targ_control))
			return 0;
	}

	/* Initialize key. */
	__builtin_memset(&tfk, 0, sizeof(tfk));
	bpf_probe_read_kernel_str(&tfk.trap_name, TRAP_NAME_LEN,
				  metadata->trap_name);
	flow_dissector(skb, &tfk);

	/* Update LRU hash table. */
	val = bpf_map_lookup_elem(&trap_flows, &tfk);
	if (!val) {
		bpf_map_update_elem(&trap_flows, &tfk, &one, BPF_NOEXIST);
		return 0;
	}
	__sync_fetch_and_add(val, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
