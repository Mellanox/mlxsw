// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "emadump.h"
#include "bits.bpf.h"

#define EMAD_ETH_HDR_LEN		0x10
#define EMAD_OP_TLV_LEN			0x10
#define EMAD_OP_TLV_STATUS_MASK		0x7F

struct emad_op_tlv {
        u16 resv1;
        u8 status;
        u8 resv2;
        u16 reg_id;
        u8 r_method;
        u8 resv3;
        u64 tid;
};

#define MAX_ENTRIES	10240

const volatile bool targ_errors = false;
const volatile __u64 targ_thresh_us = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct emad_event);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct emad_event);
} heap SEC(".maps");

#define MLXSW_TXHDR_LEN 0x10

SEC("fentry/mlxsw_emad_transmit")
int BPF_PROG(mlxsw_emad_transmit, struct mlxsw_core *mlxsw_core,
	     struct mlxsw_reg_trans *trans)
{
	u8 emad[EMAD_ETH_HDR_LEN + EMAD_OP_TLV_LEN];
	u64 ts = bpf_ktime_get_ns() / 1000U;
	struct emad_op_tlv *op_tlv;
	struct emad_event *e;
	struct sk_buff *skb;
	size_t emad_len;
	int zero = 0;
	void *buf;

	skb = trans->tx_skb;
	emad_len = skb->len - MLXSW_TXHDR_LEN;
	buf = skb->data + MLXSW_TXHDR_LEN;

	/* This should never happen. */
	if (emad_len > EMAD_MAX_LEN)
		return 0;

	/* Allocate EMAD event from our "heap". */
	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) /* Cannot happen. */
		return 0;

	/* Initialize EMAD event. */
	bpf_probe_read(&e->buf, emad_len, buf);
	e->len = emad_len;
	e->ts = ts;

	/* If no filtering, then output the event to BPF ringbuf. */
	if (!targ_errors && !targ_thresh_us) {
		bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
		return 0;
	}

	bpf_probe_read(emad, EMAD_ETH_HDR_LEN + EMAD_OP_TLV_LEN, buf);
	op_tlv = (struct emad_op_tlv *)(emad + EMAD_ETH_HDR_LEN);

	/* Store EMAD request in a hash table for retrieval upon response. */
	bpf_map_update_elem(&start, &op_tlv->tid, e, BPF_ANY);
	return 0;
}

SEC("fentry/mlxsw_emad_rx_listener_func")
int BPF_PROG(mlxsw_emad_rx_listener_func, struct sk_buff *skb)
{
	u8 emad[EMAD_ETH_HDR_LEN + EMAD_OP_TLV_LEN];
	u64 ts = bpf_ktime_get_ns() / 1000U;
	unsigned int emad_len = skb->len;
	struct emad_event *e, *req_e;
	struct emad_op_tlv *op_tlv;
	void *buf = skb->data;
	int zero = 0;
	bool error;
	s64 delta;

	/* This should never happen. */
	if (emad_len > EMAD_MAX_LEN)
		return 0;

	/* Allocate EMAD event from our "heap". */
	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) /* Cannot happen. */
		return 0;

	/* Initialize EMAD event. */
	bpf_probe_read(&e->buf, emad_len, buf);
	e->len = emad_len;
	e->ts = ts;

	/* If no filtering, then output the event to BPF ringbuf. */
	if (!targ_errors && !targ_thresh_us) {
		bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
		return 0;
	}

	bpf_probe_read(emad, EMAD_ETH_HDR_LEN + EMAD_OP_TLV_LEN, buf);
	op_tlv = (struct emad_op_tlv *)(emad + EMAD_ETH_HDR_LEN);

	/* Retrieve the request from the response. */
	req_e = bpf_map_lookup_elem(&start, &op_tlv->tid);
	if (!req_e)
		return 0;

	delta = (s64)(ts - req_e->ts);
	if (delta < 0)
		goto out;
	error = (op_tlv->status & EMAD_OP_TLV_STATUS_MASK) != 0;

	/* Submit request and response if match filters. */
	if ((targ_errors && error) ||
	    (targ_thresh_us && delta > targ_thresh_us)) {
		bpf_ringbuf_output(&rb, req_e, sizeof(*req_e), 0);
		bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
	}

out:
	bpf_map_delete_elem(&start, &op_tlv->tid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
