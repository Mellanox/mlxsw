/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TRAPAGG_H
#define __TRAPAGG_H

#define MAX_ENTRIES	10240

#define TRAP_NAME_LEN	80

struct trap_flow_key {
	__be32 saddrv4;
	__be32 daddrv4;
	__u32 saddrv6[4];
	__u32 daddrv6[4];
	__u16 addr_proto;	/* ETH_P_IP or ETH_P_IPV6 */
	__u16 sport;
	__u16 dport;
	__u8 ip_proto;
	__u8 is_encap;
	char trap_name[TRAP_NAME_LEN];
};

#endif /* __TRAPAGG_H */
