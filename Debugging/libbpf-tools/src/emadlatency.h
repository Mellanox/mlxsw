/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EMADLATENCY_H
#define __EMADLATENCY_H

#define MAX_SLOTS	27

struct hist_key {
	__u16 reg_id;
	bool write;
};

struct hist {
	__u32 slots[MAX_SLOTS];
	__u64 latency;
	__u64 count;
};

#endif /* __EMADLATENCY_H */
