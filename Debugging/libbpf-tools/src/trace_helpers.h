/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TRACE_HELPERS_H
#define __TRACE_HELPERS_H

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type);

int bump_memlock_rlimit(void);

#endif /* __TRACE_HELPERS_H */
