// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "emadlatency.h"
#include "bits.bpf.h"

#define EMAD_TXHDR_LEN			0x10

#define EMAD_ETH_HDR_LEN		0x10
#define EMAD_OP_TLV_LEN			0x10
#define EMAD_STRING_TLV_LEN		0x84
#define EMAD_LATENCY_TLV_LEN		0x1C
#define EMAD_OP_TLV_METHOD_MASK		0x7F

#define EMAD_HDR_LEN			EMAD_ETH_HDR_LEN + \
					EMAD_OP_TLV_LEN + \
					EMAD_STRING_TLV_LEN + \
					EMAD_LATENCY_TLV_LEN

#define EMAD_STRING_TLV_TYPE		2
#define EMAD_LATENCY_TLV_TYPE		4

enum {
	EMAD_OP_TLV_METHOD_QUERY = 1,
	EMAD_OP_TLV_METHOD_WRITE = 2,
	EMAD_OP_TLV_METHOD_EVENT = 5,
};

struct emad_op_tlv {
        u16 resv1;
        u8 status;
        u8 resv2;
        u16 reg_id;
        u8 r_method;
        u8 resv3;
        u64 tid;
};

struct emad_latency_tlv {
	u16 type_len;
	u16 resv1;
	u32 latency_time;
	u32 resv2;
	u32 resv3;
	u32 resv4;
	u32 resv5;
	u32 resv6;
};

struct emad_type_len_tlv {
	u16 type_len;
	u16 pad;
};

struct emad_type_len {
	u8 type;
	u16 len;
};

static struct emad_type_len emad_decode_tl(u16 type_len_be)
{
	u16 type_len = bpf_ntohs(type_len_be);

	return (struct emad_type_len) {
		.type = type_len >> 11,
		.len = type_len & 0x7ff,
	};
}

#define MAX_ENTRIES	10240

const volatile bool targ_ms = false;
const volatile __u16 targ_reg_id = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
} start SEC(".maps");

static struct hist initial_hist;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists_e2e SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists_fw SEC(".maps");

SEC("fentry/mlxsw_emad_transmit")
int BPF_PROG(mlxsw_emad_transmit, struct mlxsw_core *mlxsw_core,
	     struct mlxsw_reg_trans *trans)
{
	struct emad_latency_tlv *latency_tlv = NULL;
	struct emad_type_len_tlv *tmp_tlv;
	struct emad_type_len type_len;
	u64 ts = bpf_ktime_get_ns();
	struct emad_op_tlv *op_tlv;
	u8 emad[EMAD_HDR_LEN];
	struct sk_buff *skb;
	u32 latency_time;
	u32 next_tlv_off;
	void *buf;

	skb = trans->tx_skb;
	buf = skb->data + EMAD_TXHDR_LEN;

	bpf_probe_read(emad, EMAD_HDR_LEN, buf);

	next_tlv_off = EMAD_ETH_HDR_LEN;
	op_tlv = (struct emad_op_tlv *)(emad + next_tlv_off);

	/* Check if there is STRING_TLV. */
	next_tlv_off += EMAD_OP_TLV_LEN;
	tmp_tlv = (struct emad_type_len_tlv *)(emad + next_tlv_off);
	type_len = emad_decode_tl(tmp_tlv->type_len);
	if (type_len.type == EMAD_STRING_TLV_TYPE)
		next_tlv_off += EMAD_STRING_TLV_LEN;

	/* Check if there is LATENCY_TLV. */
	tmp_tlv = (struct emad_type_len_tlv *)(emad + next_tlv_off);
	type_len = emad_decode_tl(tmp_tlv->type_len);
	if (type_len.type == EMAD_LATENCY_TLV_TYPE) {
		latency_tlv = (struct emad_latency_tlv *)(emad + next_tlv_off);
		latency_time = bpf_ntohl(latency_tlv->latency_time);
	}

	if (targ_reg_id && bpf_ntohs(op_tlv->reg_id) != targ_reg_id)
		return 0;

	bpf_map_update_elem(&start, &op_tlv->tid, &ts, BPF_ANY);
	return 0;
}

SEC("fentry/mlxsw_emad_rx_listener_func")
int BPF_PROG(mlxsw_emad_rx_listener_func, struct sk_buff *skb)
{
	struct emad_latency_tlv *latency_tlv = NULL;
	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct hist *histp_e2e, *histp_fw;
	struct emad_type_len_tlv *tmp_tlv;
	struct emad_type_len type_len;
	struct emad_op_tlv *op_tlv;
	void *buf = skb->data;
	u8 emad[EMAD_HDR_LEN];
	struct hist_key hkey;
	u32 next_tlv_off;
	u32 latency_time;
	s64 delta;

	bpf_probe_read(emad, EMAD_HDR_LEN, buf);

	next_tlv_off = EMAD_ETH_HDR_LEN;
	op_tlv = (struct emad_op_tlv *)(emad + next_tlv_off);

	/* Check if there is STRING_TLV. */
	next_tlv_off += EMAD_OP_TLV_LEN;
	tmp_tlv = (struct emad_type_len_tlv *)(emad + next_tlv_off);
	type_len = emad_decode_tl(tmp_tlv->type_len);
	if (type_len.type == EMAD_STRING_TLV_TYPE)
		next_tlv_off += EMAD_STRING_TLV_LEN;

	/* Check if there is LATENCY_TLV. */
	tmp_tlv = (struct emad_type_len_tlv *)(emad + next_tlv_off);
	type_len = emad_decode_tl(tmp_tlv->type_len);
	if (type_len.type == EMAD_LATENCY_TLV_TYPE) {
		latency_tlv = (struct emad_latency_tlv *)(emad + next_tlv_off);
		latency_time = bpf_ntohl(latency_tlv->latency_time);
	}

	if (targ_reg_id && bpf_ntohs(op_tlv->reg_id) != targ_reg_id)
		return 0;

	tsp = bpf_map_lookup_elem(&start, &op_tlv->tid);
	if (!tsp)
		return 0;

	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;

	__builtin_memset(&hkey, 0, sizeof(hkey));
	hkey.reg_id = bpf_ntohs(op_tlv->reg_id);
	hkey.write = ((op_tlv->r_method & EMAD_OP_TLV_METHOD_MASK) ==
		      EMAD_OP_TLV_METHOD_WRITE);

	/* Lookup at hists_e2e */
	histp_e2e = bpf_map_lookup_elem(&hists_e2e, &hkey);
	if (!histp_e2e) {
		bpf_map_update_elem(&hists_e2e, &hkey, &initial_hist, BPF_ANY);
		histp_e2e = bpf_map_lookup_elem(&hists_e2e, &hkey);
		if (!histp_e2e)
			goto cleanup;
	}

	/* Insert to histp_e2e */
	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp_e2e->slots[slot], 1);
	__sync_fetch_and_add(&histp_e2e->latency, delta);
	__sync_fetch_and_add(&histp_e2e->count, 1);

	if (!latency_tlv)
		goto cleanup;

	/* Lookup at hists_fw */
	histp_fw = bpf_map_lookup_elem(&hists_fw, &hkey);
	if (!histp_fw) {
		bpf_map_update_elem(&hists_fw, &hkey, &initial_hist, BPF_ANY);
		histp_fw = bpf_map_lookup_elem(&hists_fw, &hkey);
		if (!histp_fw)
			goto cleanup;
	}

	/* Insert to histp_fw */
	slot = log2l(latency_time);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp_fw->slots[slot], 1);
	__sync_fetch_and_add(&histp_fw->latency, latency_time);
	__sync_fetch_and_add(&histp_fw->count, 1);

cleanup:
	bpf_map_delete_elem(&start, &op_tlv->tid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
