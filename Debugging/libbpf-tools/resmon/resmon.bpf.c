// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define EMAD_ETH_HDR_LEN		0x10
#define EMAD_OP_TLV_LEN			0x10
#define EMAD_OP_TLV_METHOD_MASK		0x7F
#define EMAD_OP_TLV_STATUS_MASK		0x7F

enum {
	EMAD_OP_TLV_METHOD_QUERY = 1,
	EMAD_OP_TLV_METHOD_WRITE = 2,
	EMAD_OP_TLV_METHOD_EVENT = 5,
};

struct emad_tlv_head {
	int type;
	int length;
};

struct emad_op_tlv {
	__be16 type_len_be;
	u8 status;
	u8 resv2;
	u16 reg_id;
	u8 r_method;
	u8 resv3;
	u64 tid;
};

static struct emad_tlv_head emad_tlv_decode_header(__be16 type_len_be)
{
	u16 type_len = bpf_ntohs(type_len_be);

	return (struct emad_tlv_head){
		.type = type_len >> 11,
		.length = type_len & 0x7ff,
	};
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024 /* 4 MB */);
} ringbuf SEC(".maps");

static int push_to_ringbuf(const u8 *buf, size_t len)
{
	u8 *space;

	if (len > 2048)
		return 0;

	else if (len > 1024)
		space = bpf_ringbuf_reserve(&ringbuf, 2048, 0);
	else if (len > 512)
		space = bpf_ringbuf_reserve(&ringbuf, 1024, 0);
	else if (len > 256)
		space = bpf_ringbuf_reserve(&ringbuf, 512, 0);
	else
		space = bpf_ringbuf_reserve(&ringbuf, 256, 0);

	if (!space) {
		bpf_printk("Unable to reserve %lu bytes for an EMAD on ring buffer\n",
			   len);
		return 0;
	}

	bpf_core_read(space, len, buf);
	bpf_ringbuf_submit(space, 0);

	return 0;
}

SEC("fentry/mlxsw_emad_rx_listener_func")
int BPF_PROG(mlxsw_emad_rx_listener_func, struct sk_buff *skb)
{
	struct emad_tlv_head tlv_head;
	struct emad_op_tlv op_tlv;
	void *buf = skb->data;
	unsigned int len;

	buf += EMAD_ETH_HDR_LEN;

	bpf_core_read(&op_tlv, sizeof(op_tlv), buf);
	tlv_head = emad_tlv_decode_header(op_tlv.type_len_be);

	/* Filter out queries and events. Later on we can assume `op'
	 * fields in a register refer to a write.
	 */
	if ((op_tlv.r_method & EMAD_OP_TLV_METHOD_MASK)
	    != EMAD_OP_TLV_METHOD_WRITE)
		return 0;

	/* Filter out errors. */
	if (op_tlv.status & EMAD_OP_TLV_STATUS_MASK)
		return 0;

	switch (bpf_ntohs(op_tlv.reg_id)) {
	case 0x8013: /* MLXSW_REG_RALUE_ID */
	case 0x3006: /* MLXSW_REG_PTAR_ID */
	case 0x3027: /* MLXSW_REG_PTCE3_ID */
	case 0x300F: /* MLXSW_REG_PEFA_ID */
	case 0x3804: /* MLXSW_REG_IEDR_ID */
	case 0x8014: /* MLXSW_REG_RAUHT_ID */
	case 0x8008: /* MLXSW_REG_RATR_ID */
	case 0x200A: /* MLXSW_REG_SFD_ID */
	case 0x2013: /* MLXSW_REG_SFDF_ID */
	case 0x201C: /* MLXSW_REG_SVFA_ID */
	case 0x8021: /* MLXSW_REG_RIPS_ID */
	case 0x201F: /* MLXSW_REG_SFMR_ID */
		return push_to_ringbuf(buf, skb->len - EMAD_ETH_HDR_LEN);
	};
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
