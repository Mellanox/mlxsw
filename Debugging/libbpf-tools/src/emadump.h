/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __EMADUMP_H
#define __EMADUMP_H

#define EMAD_MAX_LEN			2048

struct emad_event {
	char buf[EMAD_MAX_LEN];
	size_t len;
	__u64 ts;
};

#endif /* __EMADUMP_H */
