// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <json-c/linkhash.h>

#include "resmon.h"

static void resmon_stat_entry_free(struct lh_entry *e)
{
	if (!e->k_is_constant)
		free(lh_entry_k(e));
	free(lh_entry_v(e));
}

/* Fowler-Noll-Vo hash, variant FNV-1 */
static uint64_t resmon_stat_fnv_1(const void *ptr, size_t len)
{
	uint64_t hash = 0xcbf29ce484222325ULL;
	const uint8_t *buf = ptr;

	for (size_t i = 0; i < len; i++) {
		hash = hash * 0x100000001b3ULL;
		hash = hash ^ buf[i];
	}
	return hash;
}

struct resmon_stat_key {};

static struct resmon_stat_key *
resmon_stat_key_copy(const struct resmon_stat_key *key, size_t size)
{
	struct resmon_stat_key *copy;

	copy = malloc(size);
	if (copy == NULL)
		return NULL;

	memcpy(copy, key, size);
	return copy;
}

#define RESMON_STAT_KEY_HASH_FN(name, type)				\
	static unsigned long name(const void *k)			\
	{								\
		return resmon_stat_fnv_1(k, sizeof(type));		\
	}

#define RESMON_STAT_KEY_EQ_FN(name, type)				\
	static int name(const void *k1, const void *k2)			\
	{								\
		return memcmp(k1, k2, sizeof(type)) == 0;		\
	}

struct resmon_stat_ralue_key {
	struct resmon_stat_key base;
	enum mlxsw_reg_ralxx_protocol protocol;
	uint8_t prefix_len;
	uint16_t virtual_router;
	struct resmon_stat_dip dip;
};

static struct resmon_stat_ralue_key
resmon_stat_ralue_key(enum mlxsw_reg_ralxx_protocol protocol,
		      uint8_t prefix_len,
		      uint16_t virtual_router,
		      struct resmon_stat_dip dip)
{
	return (struct resmon_stat_ralue_key) {
		.protocol = protocol,
		.prefix_len = prefix_len,
		.virtual_router = virtual_router,
		.dip = dip,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_ralue_hash, struct resmon_stat_ralue_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_ralue_eq, struct resmon_stat_ralue_key);

struct resmon_stat {
	struct resmon_stat_gauges gauges;
	struct lh_table *ralue;
};

static struct resmon_stat_kvd_alloc *
resmon_stat_kvd_alloc_copy(struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_kvd_alloc *copy;

	copy = malloc(sizeof(*copy));
	if (copy == NULL)
		return NULL;

	*copy = kvd_alloc;
	return copy;
}

struct resmon_stat *resmon_stat_create(void)
{
	struct lh_table *ralue_tab;
	struct resmon_stat *stat;

	stat = malloc(sizeof(*stat));
	if (stat == NULL)
		return NULL;

	ralue_tab = lh_table_new(1, resmon_stat_entry_free,
				 resmon_stat_ralue_hash,
				 resmon_stat_ralue_eq);
	if (ralue_tab == NULL)
		goto free_stat;

	*stat = (struct resmon_stat){
		.ralue = ralue_tab,
	};
	return stat;

free_stat:
	free(stat);
	return NULL;
}

void resmon_stat_destroy(struct resmon_stat *stat)
{
	lh_table_free(stat->ralue);
	free(stat);
}

struct resmon_stat_gauges resmon_stat_gauges(struct resmon_stat *stat)
{
	struct resmon_stat_gauges gauges = stat->gauges;

	for (size_t i = 0; i < resmon_resource_count; i++)
		gauges.total += gauges.values[i];

	return gauges;
}

static void resmon_stat_gauge_inc(struct resmon_stat *stat,
				  struct resmon_stat_kvd_alloc kvd_alloc)
{
	stat->gauges.values[kvd_alloc.resource] += kvd_alloc.slots;
}

static void resmon_stat_gauge_dec(struct resmon_stat *stat,
				  struct resmon_stat_kvd_alloc kvd_alloc)
{
	stat->gauges.values[kvd_alloc.resource] -= kvd_alloc.slots;
}

static int
resmon_stat_lh_update_nostats(struct resmon_stat *stat,
			      struct lh_table *tab,
			      const struct resmon_stat_key *orig_key,
			      size_t orig_key_size,
			      struct resmon_stat_kvd_alloc orig_kvd_alloc)
{
	struct resmon_stat_kvd_alloc *kvd_alloc;
	struct resmon_stat_key *key;
	struct lh_entry *e;
	long hash;
	int rc;

	hash = tab->hash_fn(orig_key);
	e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e != NULL)
		return 1;

	key = resmon_stat_key_copy(orig_key, orig_key_size);
	if (key == NULL)
		return -ENOMEM;

	kvd_alloc = resmon_stat_kvd_alloc_copy(orig_kvd_alloc);
	if (kvd_alloc == NULL)
		goto free_key;

	rc = lh_table_insert_w_hash(tab, key, kvd_alloc, hash, 0);
	if (rc)
		goto free_kvd_alloc;

	return 0;

free_kvd_alloc:
	free(kvd_alloc);
free_key:
	free(key);
	return -1;
}

static int resmon_stat_lh_update(struct resmon_stat *stat,
				 struct lh_table *tab,
				 const struct resmon_stat_key *orig_key,
				 size_t orig_key_size,
				 struct resmon_stat_kvd_alloc orig_kvd_alloc)
{
	int err;

	err = resmon_stat_lh_update_nostats(stat, tab, orig_key, orig_key_size,
					    orig_kvd_alloc);
	if (err == 1)
		return 0;
	if (err != 0)
		return err;

	resmon_stat_gauge_inc(stat, orig_kvd_alloc);
	return 0;
}

static int resmon_stat_lh_delete_nostats(struct resmon_stat *stat,
					 struct lh_table *tab,
					 const struct resmon_stat_key *orig_key,
					 struct resmon_stat_kvd_alloc *kvd_alloc)
{
	const struct resmon_stat_kvd_alloc *vp;
	struct lh_entry *e;
	long hash;
	int rc;

	hash = tab->hash_fn(orig_key);
	e = lh_table_lookup_entry_w_hash(tab, orig_key, hash);
	if (e == NULL)
		return -1;

	vp = e->v;
	*kvd_alloc = *vp;
	rc = lh_table_delete_entry(tab, e);
	assert(rc == 0);
	return 0;
}

static int resmon_stat_lh_delete(struct resmon_stat *stat,
				 struct lh_table *tab,
				 const struct resmon_stat_key *orig_key)
{
	struct resmon_stat_kvd_alloc kvd_alloc;
	int err;

	err = resmon_stat_lh_delete_nostats(stat, tab, orig_key, &kvd_alloc);
	if (err != 0)
		return err;

	resmon_stat_gauge_dec(stat, kvd_alloc);
	return 0;
}

int resmon_stat_ralue_update(struct resmon_stat *stat,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip,
			     struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ralue_key key =
		resmon_stat_ralue_key(protocol, prefix_len, virtual_router,
				      dip);

	return resmon_stat_lh_update(stat, stat->ralue,
				     &key.base, sizeof(key), kvd_alloc);
}

int resmon_stat_ralue_delete(struct resmon_stat *stat,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip)
{
	struct resmon_stat_ralue_key key =
		resmon_stat_ralue_key(protocol, prefix_len, virtual_router,
				      dip);

	return resmon_stat_lh_delete(stat, stat->ralue, &key.base);
}
