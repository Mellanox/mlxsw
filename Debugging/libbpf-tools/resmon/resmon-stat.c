// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <stdlib.h>

#include "resmon.h"

struct resmon_stat {
	struct resmon_stat_gauges gauges;
};

struct resmon_stat *resmon_stat_create(void)
{
	struct resmon_stat *stat;

	stat = malloc(sizeof(*stat));
	if (stat == NULL)
		return NULL;

	*stat = (struct resmon_stat){
	};
	return stat;
}

void resmon_stat_destroy(struct resmon_stat *stat)
{
	free(stat);
}

struct resmon_stat_gauges resmon_stat_gauges(struct resmon_stat *stat)
{
	struct resmon_stat_gauges gauges = stat->gauges;

	for (size_t i = 0; i < resmon_resource_count; i++)
		gauges.total += gauges.values[i];

	return gauges;
}
