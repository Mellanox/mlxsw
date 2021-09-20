// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <json-c/linkhash.h>

#include "resmon.h"

struct resmon_table {
	struct lh_table *lh;
	unsigned int seqnn;

	struct lh_entry *cursor;
};

struct resmon_stat_key {};

struct resmon_stat {
	struct resmon_stat_gauges gauges;
	struct resmon_table ralue;
	struct resmon_table ptar;
	struct resmon_table ptce3;
	struct resmon_table kvdl;
	struct resmon_table rauht;
	struct resmon_table sfd; /* resmon_stat_sfd_key -> resmon_stat_sfd_val */
	struct resmon_table svfa;
};

static void resmon_stat_entry_free(struct lh_entry *e)
{
	if (!e->k_is_constant)
		free(lh_entry_k(e));
	free(lh_entry_v(e));
}

static int resmon_table_init(struct resmon_table *tab,
			     lh_hash_fn *hash_fn, lh_equal_fn *equal_fn)
{
	tab->lh = lh_table_new(1, resmon_stat_entry_free, hash_fn, equal_fn);
	if (tab->lh == NULL)
		return -1;

	tab->seqnn = 0;
	tab->cursor = NULL;
	return 0;
}

static void resmon_table_fini(struct resmon_table *tab)
{
	lh_table_free(tab->lh);
}

#define RESMON_TABLE_INIT(STAT, NAME)				\
	resmon_table_init(&(STAT)->NAME,			\
			  resmon_stat_ ## NAME ## _hash,	\
			  resmon_stat_ ## NAME ## _eq)

#define RESMON_TABLE_FINI(STAT, NAME)				\
	resmon_table_fini(&(STAT)->NAME)

struct lh_entry *const resmon_table_cursor_done = (struct lh_entry *) 1;

static int resmon_table_insert_w_hash(struct resmon_table *tab,
				      struct resmon_stat_key *key,
				      void *v, const unsigned long h,
				      const unsigned int opts)
{
	int old_size = tab->lh->size;
	int rc;

	rc = lh_table_insert_w_hash(tab->lh, key, v, h, 0);

	if (tab->lh->size != old_size && tab->cursor != NULL)
		tab->cursor = resmon_table_cursor_done;

	return rc;
}

static void resmon_table_cursor_step(struct resmon_table *tab)
{
	tab->cursor = tab->cursor->next;
	if (tab->cursor == NULL)
		tab->cursor = resmon_table_cursor_done;
}

static int resmon_table_delete_entry(struct resmon_table *tab,
				     struct lh_entry *entry)
{
	int old_size = tab->lh->size;
	int rc;

	if (tab->cursor == entry)
		resmon_table_cursor_step(tab);

	rc = lh_table_delete_entry(tab->lh, entry);

	if (tab->lh->size != old_size && tab->cursor != NULL)
		tab->cursor = resmon_table_cursor_done;

	return rc;
}

static struct lh_entry *resmon_table_next(struct resmon_table *tab)
{
	struct lh_entry *ret;

	if (tab->cursor == resmon_table_cursor_done) {
		/* End iteration. */
		tab->cursor = NULL;
		return NULL;
	}

	if (tab->cursor == NULL) {
		/* Start iteration. */
		tab->cursor = tab->lh->head;
		if (tab->cursor == NULL)
			/* If there are no entries, there's no need to go
			 * through the done marker. Just return NULL right
			 * away, no iteration will take place at all.
			 */
			return NULL;
	}

	/* Iteration step. */
	ret = tab->cursor;
	resmon_table_cursor_step(tab);

	return ret;
}

static void resmon_table_bump_seqnn(struct resmon_table *tab)
{
	tab->seqnn++;
}

static unsigned int resmon_table_nrows(const struct resmon_table *tab)
{
	return lh_table_length(tab->lh);
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

#define RESMON_STAT_SEQNN_FN(name)					\
	unsigned int							\
	resmon_stat_ ## name ## _seqnn(const struct resmon_stat *stat)	\
	{								\
		const struct resmon_table *tab = &(stat->name);		\
									\
		return tab->seqnn;					\
	}

#define RESMON_STAT_NROWS_FN(name)		\
	unsigned int				\
	resmon_stat_ ## name ## _nrows(const struct resmon_stat *stat)	\
	{								\
		const struct resmon_table *tab = &(stat->name);		\
									\
		return resmon_table_nrows(tab);				\
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
RESMON_STAT_SEQNN_FN(ralue);
RESMON_STAT_NROWS_FN(ralue);

struct resmon_stat_ptar_key {
	struct resmon_stat_key base;
	struct resmon_stat_tcam_region_info tcam_region_info;
};

static struct resmon_stat_ptar_key
resmon_stat_ptar_key(struct resmon_stat_tcam_region_info tcam_region_info)
{
	return (struct resmon_stat_ptar_key) {
		.tcam_region_info = tcam_region_info,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_ptar_hash, struct resmon_stat_ptar_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_ptar_eq, struct resmon_stat_ptar_key);
RESMON_STAT_SEQNN_FN(ptar);
RESMON_STAT_NROWS_FN(ptar);

struct resmon_stat_ptce3_key {
	struct resmon_stat_key base;
	struct resmon_stat_tcam_region_info tcam_region_info;
	struct resmon_stat_flex2_key_blocks flex2_key_blocks;
	uint8_t delta_mask;
	uint8_t delta_value;
	uint16_t delta_start;
	uint8_t erp_id;
};

static struct resmon_stat_ptce3_key
resmon_stat_ptce3_key(struct resmon_stat_tcam_region_info tcam_region_info,
		      const struct resmon_stat_flex2_key_blocks *key_blocks,
		      uint8_t delta_mask,
		      uint8_t delta_value,
		      uint16_t delta_start,
		      uint8_t erp_id)
{
	return (struct resmon_stat_ptce3_key) {
		.tcam_region_info = tcam_region_info,
		.flex2_key_blocks = *key_blocks,
		.delta_mask = delta_mask,
		.delta_value = delta_value,
		.delta_start = delta_start,
		.erp_id = erp_id,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_ptce3_hash, struct resmon_stat_ptce3_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_ptce3_eq, struct resmon_stat_ptce3_key);
RESMON_STAT_SEQNN_FN(ptce3);
RESMON_STAT_NROWS_FN(ptce3);

struct resmon_stat_kvdl_key {
	struct resmon_stat_key base;
	enum resmon_resource resource;
	uint32_t index;
};

static struct resmon_stat_kvdl_key
resmon_stat_kvdl_key(uint32_t index, enum resmon_resource resource)
{
	return (struct resmon_stat_kvdl_key) {
		.index = index,
		.resource = resource,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_kvdl_hash, struct resmon_stat_kvdl_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_kvdl_eq, struct resmon_stat_kvdl_key);
RESMON_STAT_SEQNN_FN(kvdl);
RESMON_STAT_NROWS_FN(kvdl);

struct resmon_stat_rauht_key {
	struct resmon_stat_key base;
	enum mlxsw_reg_ralxx_protocol protocol;
	uint16_t rif;
	struct resmon_stat_dip dip;
};

static struct resmon_stat_rauht_key
resmon_stat_rauht_key(enum mlxsw_reg_ralxx_protocol protocol,
		      uint16_t rif,
		      struct resmon_stat_dip dip)
{
	return (struct resmon_stat_rauht_key) {
		.protocol = protocol,
		.rif = rif,
		.dip = dip,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_rauht_hash, struct resmon_stat_rauht_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_rauht_eq, struct resmon_stat_rauht_key);
RESMON_STAT_SEQNN_FN(rauht);

struct resmon_stat_sfd_key {
	struct resmon_stat_key base;
	struct resmon_stat_mac mac;
	uint16_t fid;
};

static struct resmon_stat_sfd_key
resmon_stat_sfd_key(struct resmon_stat_mac mac, uint16_t fid)
{
	return (struct resmon_stat_sfd_key) {
		.mac = mac,
		.fid = fid,
	};
}

struct resmon_stat_sfd_val {
	struct resmon_stat_kvd_alloc kvd_alloc;
	enum resmon_stat_sfd_param_type param_type;
	uint16_t param;
};

RESMON_STAT_KEY_HASH_FN(resmon_stat_sfd_hash, struct resmon_stat_sfd_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_sfd_eq, struct resmon_stat_sfd_key);
RESMON_STAT_SEQNN_FN(sfd);

struct resmon_stat_svfa_key {
	struct resmon_stat_key base;
	enum mlxsw_reg_svfa_mt mapping_table;
	uint16_t local_port;
	uint32_t vid_vni;
};

static struct resmon_stat_svfa_key
resmon_stat_svfa_key(enum mlxsw_reg_svfa_mt mapping_table, uint16_t local_port,
		     uint32_t vid_vni)
{
	return (struct resmon_stat_svfa_key) {
		.mapping_table = mapping_table,
		.local_port = local_port,
		.vid_vni = vid_vni,
	};
}

RESMON_STAT_KEY_HASH_FN(resmon_stat_svfa_hash, struct resmon_stat_svfa_key);
RESMON_STAT_KEY_EQ_FN(resmon_stat_svfa_eq, struct resmon_stat_svfa_key);
RESMON_STAT_SEQNN_FN(svfa);

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
	struct resmon_stat *stat;
	int err;

	stat = malloc(sizeof(*stat));
	if (stat == NULL)
		return NULL;

	err = RESMON_TABLE_INIT(stat, ralue);
	if (err != 0)
		goto free_stat;

	err = RESMON_TABLE_INIT(stat, ptar);
	if (err != 0)
		goto free_ralue_tab;

	err = RESMON_TABLE_INIT(stat, ptce3);
	if (err != 0)
		goto free_ptar_tab;

	err = RESMON_TABLE_INIT(stat, kvdl);
	if (err != 0)
		goto free_ptce3_tab;

	err = RESMON_TABLE_INIT(stat, rauht);
	if (err != 0)
		goto free_kvdl_tab;

	err = RESMON_TABLE_INIT(stat, sfd);
	if (err != 0)
		goto free_rauht_tab;

	err = RESMON_TABLE_INIT(stat, svfa);
	if (err != 0)
		goto free_sfd_tab;

	return stat;

free_sfd_tab:
	RESMON_TABLE_FINI(stat, sfd);
free_rauht_tab:
	RESMON_TABLE_FINI(stat, rauht);
free_kvdl_tab:
	RESMON_TABLE_FINI(stat, kvdl);
free_ptce3_tab:
	RESMON_TABLE_FINI(stat, ptce3);
free_ptar_tab:
	RESMON_TABLE_FINI(stat, ptar);
free_ralue_tab:
	RESMON_TABLE_FINI(stat, ralue);
free_stat:
	free(stat);
	return NULL;
}

void resmon_stat_destroy(struct resmon_stat *stat)
{
	RESMON_TABLE_FINI(stat, svfa);
	RESMON_TABLE_FINI(stat, sfd);
	RESMON_TABLE_FINI(stat, rauht);
	RESMON_TABLE_FINI(stat, kvdl);
	RESMON_TABLE_FINI(stat, ptce3);
	RESMON_TABLE_FINI(stat, ptar);
	RESMON_TABLE_FINI(stat, ralue);
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

static int resmon_table_get(struct resmon_table *tab,
			    const struct resmon_stat_key *orig_key,
			    struct resmon_stat_kvd_alloc *ret_kvd_alloc)
{
	const struct resmon_stat_kvd_alloc *kvd_alloc;
	struct lh_entry *e;
	long hash;

	hash = tab->lh->hash_fn(orig_key);
	e = lh_table_lookup_entry_w_hash(tab->lh, orig_key, hash);
	if (e == NULL)
		return -1;

	kvd_alloc = e->v;
	*ret_kvd_alloc = *kvd_alloc;
	return 0;
}

static int
resmon_table_update_nostats(struct resmon_stat *stat,
			    struct resmon_table *tab,
			    const struct resmon_stat_key *orig_key,
			    size_t orig_key_size,
			    struct resmon_stat_kvd_alloc orig_kvd_alloc)
{
	struct resmon_stat_kvd_alloc *kvd_alloc;
	struct resmon_stat_key *key;
	struct lh_entry *e;
	long hash;
	int rc;

	hash = tab->lh->hash_fn(orig_key);
	e = lh_table_lookup_entry_w_hash(tab->lh, orig_key, hash);
	if (e != NULL)
		return 1;

	key = resmon_stat_key_copy(orig_key, orig_key_size);
	if (key == NULL)
		return -ENOMEM;

	kvd_alloc = resmon_stat_kvd_alloc_copy(orig_kvd_alloc);
	if (kvd_alloc == NULL)
		goto free_key;

	rc = resmon_table_insert_w_hash(tab, key, kvd_alloc, hash, 0);
	if (rc)
		goto free_kvd_alloc;

	resmon_table_bump_seqnn(tab);
	return 0;

free_kvd_alloc:
	free(kvd_alloc);
free_key:
	free(key);
	return -1;
}

static int resmon_table_update(struct resmon_stat *stat,
			       struct resmon_table *tab,
			       const struct resmon_stat_key *orig_key,
			       size_t orig_key_size,
			       struct resmon_stat_kvd_alloc orig_kvd_alloc)
{
	int err;

	err = resmon_table_update_nostats(stat, tab, orig_key, orig_key_size,
					  orig_kvd_alloc);
	if (err == 1)
		return 0;
	if (err != 0)
		return err;

	resmon_stat_gauge_inc(stat, orig_kvd_alloc);
	return 0;
}

static int resmon_table_delete_nostats(struct resmon_stat *stat,
				       struct resmon_table *tab,
				       const struct resmon_stat_key *orig_key,
				       struct resmon_stat_kvd_alloc *kvd_alloc)
{
	const struct resmon_stat_kvd_alloc *vp;
	struct lh_entry *e;
	long hash;
	int rc;

	hash = tab->lh->hash_fn(orig_key);
	e = lh_table_lookup_entry_w_hash(tab->lh, orig_key, hash);
	if (e == NULL)
		return -1;

	vp = e->v;
	*kvd_alloc = *vp;
	rc = resmon_table_delete_entry(tab, e);
	assert(rc == 0);

	resmon_table_bump_seqnn(tab);
	return 0;
}

static int resmon_table_delete(struct resmon_stat *stat,
			       struct resmon_table *tab,
			       const struct resmon_stat_key *orig_key)
{
	struct resmon_stat_kvd_alloc kvd_alloc;
	int err;

	err = resmon_table_delete_nostats(stat, tab, orig_key, &kvd_alloc);
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

	return resmon_table_update(stat, &stat->ralue,
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

	return resmon_table_delete(stat, &stat->ralue, &key.base);
}

int resmon_stat_ralue_next_row(struct resmon_stat *stat,
			       enum mlxsw_reg_ralxx_protocol *protocol,
			       uint8_t *prefix_len,
			       uint16_t *virtual_router,
			       struct resmon_stat_dip *dip,
			       struct resmon_stat_kvd_alloc *kvd_alloc)
{
	const struct lh_entry *e = resmon_table_next(&stat->ralue);

	if (e == NULL)
		return -1;

	const struct resmon_stat_kvd_alloc *kvda = lh_entry_v(e);
	const struct resmon_stat_ralue_key *key = lh_entry_k(e);

	*protocol = key->protocol;
	*prefix_len = key->prefix_len;
	*virtual_router = key->virtual_router;
	*dip = key->dip;
	*kvd_alloc = *kvda;
	return 0;
}

int resmon_stat_ptar_alloc(struct resmon_stat *stat,
			   struct resmon_stat_tcam_region_info tcam_region_info,
			   struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ptar_key key =
		resmon_stat_ptar_key(tcam_region_info);

	return resmon_table_update_nostats(stat, &stat->ptar,
					   &key.base, sizeof(key), kvd_alloc);
}

int resmon_stat_ptar_free(struct resmon_stat *stat,
			  struct resmon_stat_tcam_region_info tcam_region_info)
{
	struct resmon_stat_ptar_key key =
		resmon_stat_ptar_key(tcam_region_info);
	struct resmon_stat_kvd_alloc kvd_alloc;

	return resmon_table_delete_nostats(stat, &stat->ptar, &key.base,
					   &kvd_alloc);
}

int resmon_stat_ptar_get(struct resmon_stat *stat,
			 struct resmon_stat_tcam_region_info tcam_region_info,
			 struct resmon_stat_kvd_alloc *ret_kvd_alloc)
{
	struct resmon_stat_ptar_key key =
		resmon_stat_ptar_key(tcam_region_info);

	return resmon_table_get(&stat->ptar, &key.base, ret_kvd_alloc);
}

int
resmon_stat_ptar_next_row(struct resmon_stat *stat,
			 struct resmon_stat_tcam_region_info *tcam_region_info,
			 struct resmon_stat_kvd_alloc *kvd_alloc)
{
	const struct lh_entry *e = resmon_table_next(&stat->ptar);

	if (e == NULL)
		return -1;

	const struct resmon_stat_kvd_alloc *kvda = lh_entry_v(e);
	const struct resmon_stat_ptar_key *key = lh_entry_k(e);

	*tcam_region_info = key->tcam_region_info;
	*kvd_alloc = *kvda;
	return 0;
}

int
resmon_stat_ptce3_alloc(struct resmon_stat *stat,
			struct resmon_stat_tcam_region_info tcam_region_info,
			const struct resmon_stat_flex2_key_blocks *key_blocks,
			uint8_t delta_mask,
			uint8_t delta_value,
			uint16_t delta_start,
			uint8_t erp_id,
			struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_ptce3_key key =
		resmon_stat_ptce3_key(tcam_region_info, key_blocks, delta_mask,
				      delta_value, delta_start, erp_id);

	return resmon_table_update(stat, &stat->ptce3,
				   &key.base, sizeof(key), kvd_alloc);
}

int
resmon_stat_ptce3_free(struct resmon_stat *stat,
		       struct resmon_stat_tcam_region_info tcam_region_info,
		       const struct resmon_stat_flex2_key_blocks *key_blocks,
		       uint8_t delta_mask,
		       uint8_t delta_value,
		       uint16_t delta_start,
		       uint8_t erp_id)
{
	struct resmon_stat_ptce3_key key =
		resmon_stat_ptce3_key(tcam_region_info, key_blocks, delta_mask,
				      delta_value, delta_start, erp_id);

	return resmon_table_delete(stat, &stat->ptce3, &key.base);
}

int resmon_stat_ptce3_next_row(struct resmon_stat *stat,
			struct resmon_stat_tcam_region_info *tcam_region_info,
			struct resmon_stat_flex2_key_blocks *flex2_key_blocks,
			uint8_t *delta_mask,
			uint8_t *delta_value,
			uint16_t *delta_start,
			uint8_t *erp_id,
			struct resmon_stat_kvd_alloc *kvd_alloc)
{
	struct lh_entry *e = resmon_table_next(&stat->ptce3);

	if (e == NULL)
		return -1;

	const struct resmon_stat_kvd_alloc *kvda = lh_entry_v(e);
	const struct resmon_stat_ptce3_key *key = lh_entry_k(e);

	*tcam_region_info = key->tcam_region_info;
	*flex2_key_blocks = key->flex2_key_blocks;
	*delta_mask = key->delta_mask;
	*delta_value = key->delta_value;
	*delta_start = key->delta_start;
	*erp_id = key->erp_id;
	*kvd_alloc = *kvda;
	return 0;
}

int resmon_stat_rauht_update(struct resmon_stat *stat,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     uint16_t rif,
			     struct resmon_stat_dip dip,
			     struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_rauht_key key =
		resmon_stat_rauht_key(protocol, rif, dip);

	return resmon_table_update(stat, &stat->rauht,
				   &key.base, sizeof(key), kvd_alloc);
}

int resmon_stat_rauht_delete(struct resmon_stat *stat,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     uint16_t rif,
			     struct resmon_stat_dip dip)
{
	struct resmon_stat_rauht_key key =
		resmon_stat_rauht_key(protocol, rif, dip);

	return resmon_table_delete(stat, &stat->rauht, &key.base);
}

static int resmon_stat_kvdl_alloc_1(struct resmon_stat *stat,
				    uint32_t index,
				    enum resmon_resource resource)
{
	struct resmon_stat_kvdl_key key = resmon_stat_kvdl_key(index, resource);
	struct resmon_stat_kvd_alloc kvd_alloc = {
		.slots = 1,
		.resource = resource,
	};

	return resmon_table_update(stat, &stat->kvdl,
				   &key.base, sizeof(key), kvd_alloc);
}

static int resmon_stat_kvdl_free_1(struct resmon_stat *stat,
				   uint32_t index,
				   enum resmon_resource resource)
{
	struct resmon_stat_kvdl_key key = resmon_stat_kvdl_key(index, resource);

	return resmon_table_delete(stat, &stat->kvdl, &key.base);
}

int resmon_stat_kvdl_alloc(struct resmon_stat *stat,
			   uint32_t index,
			   struct resmon_stat_kvd_alloc kvd_alloc)
{
	uint32_t i;
	int rc;

	for (i = 0; i < kvd_alloc.slots; i++) {
		rc = resmon_stat_kvdl_alloc_1(stat, index + i,
					      kvd_alloc.resource);
		if (rc != 0)
			goto unroll;
	}

	return 0;

unroll:
	while (i-- > 0)
		resmon_stat_kvdl_free_1(stat, index + i, kvd_alloc.resource);
	return rc;
}

int resmon_stat_kvdl_free(struct resmon_stat *stat,
			  uint32_t index,
			  struct resmon_stat_kvd_alloc kvd_alloc)
{
	int rc = 0;
	int rc_1;

	for (uint32_t i = 0; i < kvd_alloc.slots; i++) {
		rc_1 = resmon_stat_kvdl_free_1(stat, index + i,
					       kvd_alloc.resource);
		if (rc_1 != 0)
			rc = rc_1;
	}

	return rc;
}

int resmon_stat_kvdl_next_row(struct resmon_stat *stat,
			      uint32_t *index,
			      struct resmon_stat_kvd_alloc *kvd_alloc)
{
	const struct lh_entry *e = resmon_table_next(&stat->kvdl);

	if (e == NULL)
		return -1;

	const struct resmon_stat_kvd_alloc *kvda = lh_entry_v(e);
	const struct resmon_stat_kvdl_key *key = lh_entry_k(e);

	*index = key->index;
	*kvd_alloc = *kvda;
	return 0;
}

static int
resmon_stat_lh_sfd_insert(struct resmon_stat *stat,
			  struct resmon_stat_sfd_key *orig_key,
			  long hash, enum resmon_stat_sfd_param_type param_type,
			  uint16_t param,
			  struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_sfd_val *val;
	struct resmon_stat_key *key;
	int rc;

	key = resmon_stat_key_copy(&orig_key->base,
				   sizeof(struct resmon_stat_sfd_key));
	if (key == NULL)
		return -ENOMEM;

	val = malloc(sizeof(*val));
	if (val == NULL)
		goto free_key;

	val->param_type = param_type;
	val->param = param;
	val->kvd_alloc = kvd_alloc;

	rc = resmon_table_insert_w_hash(&stat->sfd, key, val, hash, 0);
	if (rc)
		goto free_val;

	resmon_stat_gauge_inc(stat, kvd_alloc);
	resmon_table_bump_seqnn(&stat->sfd);
	return 0;

free_val:
	free(val);
free_key:
	free(key);
	return -1;
}

static int resmon_stat_sfd_delete_entry(struct resmon_stat *stat,
					struct lh_entry *e)
{
	struct resmon_stat_kvd_alloc kvd_alloc;
	const struct resmon_stat_sfd_val *vp;
	int rc;

	vp = e->v;
	kvd_alloc = vp->kvd_alloc;
	rc = resmon_table_delete_entry(&stat->sfd, e);
	assert(rc == 0);
	resmon_stat_gauge_dec(stat, kvd_alloc);
	resmon_table_bump_seqnn(&stat->sfd);
	return 0;
}

int
resmon_stat_sfd_delete(struct resmon_stat *stat, struct resmon_stat_mac mac,
		       uint16_t fid)
{
	struct resmon_stat_sfd_key key;
	struct lh_entry *e;
	long hash;

	key = resmon_stat_sfd_key(mac, fid);
	hash = stat->sfd.lh->hash_fn(&key.base);
	e = lh_table_lookup_entry_w_hash(stat->sfd.lh, &key.base, hash);
	if (e == NULL)
		return -1;

	return resmon_stat_sfd_delete_entry(stat, e);
}

int
resmon_stat_sfd_update(struct resmon_stat *stat, struct resmon_stat_mac mac,
		       uint16_t fid, enum resmon_stat_sfd_param_type param_type,
		       uint16_t param, struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_sfd_val *vp;
	struct resmon_stat_sfd_key key;
	struct lh_entry *e;
	long hash;

	key = resmon_stat_sfd_key(mac, fid);
	hash = stat->sfd.lh->hash_fn(&key.base);
	e = lh_table_lookup_entry_w_hash(stat->sfd.lh, &key.base, hash);
	if (e != NULL) {
		vp = lh_entry_v(e);
		vp->param_type = param_type;
		vp->param = param;
		resmon_table_bump_seqnn(&stat->sfd);
		return 0;
	}

	return resmon_stat_lh_sfd_insert(stat, &key, hash, param_type, param,
					 kvd_alloc);
}

static bool resmon_stat_sfd_keys_match(uint16_t fid1, uint16_t fid2,
				       uint8_t flags)
{
	if ((flags & RESMON_STAT_SFD_MATCH_FID) && fid1 != fid2)
		return false;

	return true;
}

static bool
resmon_stat_sfd_vals_match(enum resmon_stat_sfd_param_type param_type1,
			   enum resmon_stat_sfd_param_type param_type2,
			   uint16_t param1, uint16_t param2, uint8_t flags)
{
	if ((flags & RESMON_STAT_SFD_MATCH_PARAM_TYPE) &&
	     param_type1 != param_type2)
		return false;

	if ((flags & RESMON_STAT_SFD_MATCH_PARAM) && param1 != param2)
		return false;

	return true;
}

int resmon_stat_sfdf_flush(struct resmon_stat *stat, uint16_t fid,
			   enum resmon_stat_sfd_param_type param_type,
			   uint16_t param, uint8_t flags)
{
	const struct resmon_stat_sfd_key *key;
	const struct resmon_stat_sfd_val *val;
	struct lh_entry *e, *tmp;
	int err;

	lh_foreach_safe(stat->sfd.lh, e, tmp) {
		key = e->k;
		val = e->v;

		if (!resmon_stat_sfd_keys_match(key->fid, fid, flags))
			continue;

		if (!resmon_stat_sfd_vals_match(val->param_type, param_type,
						val->param, param, flags))
			continue;

		err = resmon_stat_sfd_delete_entry(stat, e);
		if (err)
			return err;
	}

	return 0;
}

int resmon_stat_svfa_update(struct resmon_stat *stat,
			    enum mlxsw_reg_svfa_mt mapping_table,
			    uint16_t local_port, uint32_t vid_vni,
			    struct resmon_stat_kvd_alloc kvd_alloc)
{
	struct resmon_stat_svfa_key key =
		resmon_stat_svfa_key(mapping_table, local_port, vid_vni);

	return resmon_table_update(stat, &stat->svfa,
				   &key.base, sizeof(key), kvd_alloc);
}

int resmon_stat_svfa_delete(struct resmon_stat *stat,
			    enum mlxsw_reg_svfa_mt mapping_table,
			    uint16_t local_port, uint32_t vid_vni)
{
	struct resmon_stat_svfa_key key =
		resmon_stat_svfa_key(mapping_table, local_port, vid_vni);

	return resmon_table_delete(stat, &stat->svfa, &key.base);
}
