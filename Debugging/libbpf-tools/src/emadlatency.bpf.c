// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "emadlatency.h"
#include "bits.bpf.h"

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

SEC("tracepoint/devlink/devlink_hwmsg")
int handle__devlink_hwmsg(struct trace_event_raw_devlink_hwmsg *ctx)
{
	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct emad_op_tlv *op_tlv;
	struct hist *histp_e2e;
	u8 emad[EMAD_HDR_LEN];
	struct hist_key hkey;
	u32 buf_off;
	s64 delta;

	buf_off = ctx->__data_loc_buf & 0xFFFF;
	bpf_probe_read(emad, EMAD_HDR_LEN, (void *) ctx + buf_off);
	op_tlv = (struct emad_op_tlv *)(emad + EMAD_ETH_HDR_LEN);

	if (targ_reg_id && bpf_ntohs(op_tlv->reg_id) != targ_reg_id)
		return 0;

	if (!ctx->incoming) {
		bpf_map_update_elem(&start, &op_tlv->tid, &ts, BPF_ANY);
		return 0;
	}

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

cleanup:
	bpf_map_delete_elem(&start, &op_tlv->tid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
