// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <systemd/sd-daemon.h>

#include "resmon.h"

static bool should_quit;

static void resmon_d_quit(void)
{
	if (env.verbosity > 0)
		fprintf(stderr, "Quitting\n");
	should_quit = true;
}

static void resmon_d_handle_signal(int sig)
{
	resmon_d_quit();
}

static int resmon_d_setup_signals(void)
{
	if (signal(SIGINT, resmon_d_handle_signal) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGINT handling: %m\n");
		return -1;
	}
	if (signal(SIGQUIT, resmon_d_handle_signal) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGQUIT handling: %m\n");
		return -1;
	}
	if (signal(SIGTERM, resmon_d_handle_signal) == SIG_ERR) {
		fprintf(stderr, "Failed to set up SIGTERM handling: %m\n");
		return -1;
	}
	return 0;
}

static void __resmon_d_respond(struct resmon_sock *ctl,
			       struct json_object *obj)
{
	if (obj != NULL) {
		resmon_jrpc_send(ctl, obj);
		json_object_put(obj);
	}
}

void resmon_d_respond_error(struct resmon_sock *ctl,
			    struct json_object *id, int code,
			    const char *message, const char *data)
{
	__resmon_d_respond(ctl,
			   resmon_jrpc_new_error(id, code, message, data));
}

void resmon_d_respond_invalid_params(struct resmon_sock *ctl,
				     struct json_object *id,
				     const char *data)
{
	__resmon_d_respond(ctl,
			   resmon_jrpc_new_error_inv_params(id, data));
}

static void resmon_d_respond_interr(struct resmon_sock *peer,
				    struct json_object *id,
				    const char *data)
{
	__resmon_d_respond(peer,
			   resmon_jrpc_new_error_int_error(id, data));
}

void resmon_d_respond_memerr(struct resmon_sock *peer, struct json_object *id)
{
	resmon_d_respond_interr(peer, id, "Memory allocation issue");
}

static void resmon_d_handle_ping(struct resmon_sock *peer,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	struct json_object *obj;
	int rc;

	obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	rc = json_object_object_add(obj, "result", params_obj);
	if (rc != 0)
		goto put_obj;
	json_object_get(params_obj);

	resmon_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_obj:
	json_object_put(obj);
	resmon_d_respond_memerr(peer, id);
}

static void resmon_d_handle_stop(struct resmon_sock *peer,
				 struct json_object *params_obj,
				 struct json_object *id)
{
	struct json_object *obj;
	char *error;
	int rc;

	rc = resmon_jrpc_dissect_params_empty(params_obj, &error);
	if (rc != 0) {
		resmon_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	resmon_d_quit();

	obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	if (json_object_object_add(obj, "result", NULL))
		goto put_obj;

	resmon_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_obj:
	json_object_put(obj);
	resmon_d_respond_memerr(peer, id);
}

#define RESMON_RSRC_EXPAND_AS_DESC(NAME, DESCRIPTION) \
	[RESMON_RSRC_ ## NAME] = DESCRIPTION,
#define RESMON_RSRC_EXPAND_AS_NAME_STR(NAME, DESCRIPTION) \
	[RESMON_RSRC_ ## NAME] = #NAME,

static const char *const resmon_d_gauge_descriptions[] = {
	RESMON_RESOURCES(RESMON_RSRC_EXPAND_AS_DESC)
};

static const char *const resmon_d_gauge_names[] = {
	RESMON_RESOURCES(RESMON_RSRC_EXPAND_AS_NAME_STR)
};

#undef RESMON_RSRC_EXPAND_AS_NAME_STR
#undef RESMON_RSRC_EXPAND_AS_DESC

static int resmon_d_stats_attach_gauge(struct json_object *gauges_obj,
				       const char *name, const char *descr,
				       int64_t value, uint64_t capacity)
{
	struct json_object *gauge_obj;
	int rc;

	gauge_obj = json_object_new_object();
	if (gauge_obj == NULL)
		return -1;

	rc = resmon_jrpc_object_add_str(gauge_obj, "name", name);
	if (rc != 0)
		goto put_gauge_obj;

	rc = resmon_jrpc_object_add_str(gauge_obj, "descr", descr);
	if (rc != 0)
		goto put_gauge_obj;

	rc = resmon_jrpc_object_add_int(gauge_obj, "value", value);
	if (rc != 0)
		goto put_gauge_obj;

	rc = resmon_jrpc_object_add_int(gauge_obj, "capacity", capacity);
	if (rc != 0)
		goto put_gauge_obj;

	rc = json_object_array_add(gauges_obj, gauge_obj);
	if (rc)
		goto put_gauge_obj;

	return 0;

put_gauge_obj:
	json_object_put(gauge_obj);
	return -1;
}

static void resmon_d_handle_stats(struct resmon_back *back,
				  struct resmon_stat *stat,
				  struct resmon_resources_enabled rsrc_en,
				  struct resmon_sock *peer,
				  struct json_object *params_obj,
				  struct json_object *id)
{
	struct resmon_stat_gauges gauges;
	struct json_object *gauges_obj;
	struct json_object *result_obj;
	struct json_object *obj;
	uint64_t capacity;
	char *error;
	int rc;

	/* The response is as follows:
	 *
	 * {
	 *     "id": ...,
	 *     "result": {
	 *         "gauges": [
	 *             {
	 *                 "name": symbolic gauge enum name,
	 *                 "description": string with human-readable descr.,
	 *                 "value": integer, value of the gauge
	 *             },
	 *             ....
	 *         ]
	 *     }
	 * }
	 */

	rc = resmon_jrpc_dissect_params_empty(params_obj, &error);
	if (rc) {
		resmon_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	rc = resmon_back_get_capacity(back, &capacity, &error);
	if (rc != 0) {
		resmon_d_respond_error(peer, id, resmon_jrpc_e_capacity,
				       "Issue while retrieving capacity", error);
		free(error);
		return;
	}

	obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	result_obj = json_object_new_object();
	if (result_obj == NULL)
		goto put_obj;

	gauges_obj = json_object_new_array();
	if (gauges_obj == NULL)
		goto put_result_obj;

	gauges = resmon_stat_gauges(stat);
	for (int i = 0; i < ARRAY_SIZE(gauges.values); i++) {
		if (!rsrc_en.enabled[i])
			continue;

		rc = resmon_d_stats_attach_gauge(gauges_obj,
					    resmon_d_gauge_names[i],
					    resmon_d_gauge_descriptions[i],
					    gauges.values[i],
					    capacity);
		if (rc)
			goto put_gauges_obj;
	}

	rc = resmon_d_stats_attach_gauge(gauges_obj, "TOTAL", "Total",
					 gauges.total, capacity);
	if (rc)
		goto put_gauges_obj;

	rc = json_object_object_add(result_obj, "gauges", gauges_obj);
	if (rc != 0)
		goto put_gauges_obj;

	rc = json_object_object_add(obj, "result", result_obj);
	if (rc != 0)
		goto put_result_obj;

	resmon_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_gauges_obj:
	json_object_put(gauges_obj);
put_result_obj:
	json_object_put(result_obj);
put_obj:
	json_object_put(obj);
	resmon_d_respond_memerr(peer, id);
}

struct resmon_d_table_info {
	const char *const name;
	unsigned int (*nrows)(const struct resmon_stat *stat);
	unsigned int (*seqnn)(const struct resmon_stat *stat);
	struct json_object *(*dump_next)(struct resmon_stat *stat,
					 char **error);
};

static int
resmon_d_get_tables_attach_table(const struct resmon_stat *stat,
				 struct json_object *array,
				 const struct resmon_d_table_info *tinfo)
{
	struct json_object *table_obj;
	unsigned int seqnn;
	unsigned int nrows;

	table_obj = json_object_new_object();
	if (table_obj == NULL)
		return -1;

	seqnn = tinfo->seqnn(stat);
	nrows = tinfo->nrows(stat);

	if (resmon_jrpc_object_add_str(table_obj, "name", tinfo->name) != 0 ||
	    resmon_jrpc_object_add_int(table_obj, "seqnn", seqnn) != 0 ||
	    resmon_jrpc_object_add_int(table_obj, "nrows", nrows) != 0 ||
	    json_object_array_add(array, table_obj) != 0)
		goto put_table_obj;

	return 0;

put_table_obj:
	json_object_put(table_obj);
	return -1;
}

static struct json_object *resmon_d_dump_ralue_next(struct resmon_stat *stat,
						    char **error);
static struct json_object *resmon_d_dump_ptar_next(struct resmon_stat *stat,
						   char **error);
static struct json_object *resmon_d_dump_ptce3_next(struct resmon_stat *stat,
						    char **error);

static struct resmon_d_table_info resmon_d_tables[] = {
	{
		.name = "ralue",
		.seqnn = resmon_stat_ralue_seqnn,
		.nrows = resmon_stat_ralue_nrows,
		.dump_next = resmon_d_dump_ralue_next,
	},
	{
		.name = "ptar",
		.seqnn = resmon_stat_ptar_seqnn,
		.nrows = resmon_stat_ptar_nrows,
		.dump_next = resmon_d_dump_ptar_next,
	},
	{
		.name = "ptce3",
		.seqnn = resmon_stat_ptce3_seqnn,
		.nrows = resmon_stat_ptce3_nrows,
		.dump_next = resmon_d_dump_ptce3_next,
	},
};

static void resmon_d_handle_get_tables(const struct resmon_stat *stat,
				       struct resmon_sock *peer,
				       struct json_object *params_obj,
				       struct json_object *id)
{
	struct json_object *result_obj;
	struct json_object *array;
	struct json_object *obj;
	char *error;
	int rc;

	/* The response is as follows:
	 *
	 * {
	 *     "id": ...,
	 *     "result": {
	 *         "tables": [ {"name": "$NAME", "nrows": $NR, "seqnn": $I }, ...]
	 *     }
	 * }
	 */

	rc = resmon_jrpc_dissect_params_empty(params_obj, &error);
	if (rc != 0) {
		resmon_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	result_obj = json_object_new_object();
	if (result_obj == NULL)
		goto put_obj;

	array = json_object_new_array();
	if (array == NULL)
		goto put_result_obj;

	for (size_t i = 0; i < ARRAY_SIZE(resmon_d_tables); i++) {
		struct resmon_d_table_info *tinfo = &resmon_d_tables[i];

		if (resmon_d_get_tables_attach_table(stat, array, tinfo) != 0)
			goto put_array;
	}

	rc = json_object_object_add(result_obj, "tables", array);
	if (rc != 0)
		goto put_array;

	if (json_object_object_add(obj, "result", result_obj))
		goto put_result_obj;

	resmon_jrpc_send(peer, obj);
	json_object_put(obj);
	return;

put_array:
	json_object_put(array);
put_result_obj:
	json_object_put(result_obj);
put_obj:
	json_object_put(obj);
	resmon_d_respond_memerr(peer, id);
}

static int resmon_d_dump_row_alloc(struct json_object **pkey,
				   struct json_object **pvalue,
				   struct json_object **prow,
				   char **error)
{
	struct json_object *value;
	struct json_object *key;
	struct json_object *row;
	int err;

	row = json_object_new_object();
	if (row == NULL) {
		resmon_fmterr(error, "Couldn't allocate row: %m");
		return -1;
	}

	value = json_object_new_object();
	if (value == NULL) {
		resmon_fmterr(error, "Couldn't allocate value: %m");
		goto put_row;
	}

	key = json_object_new_object();
	if (key == NULL) {
		resmon_fmterr(error, "Couldn't allocate key: %m");
		goto put_value;
	}

	err = json_object_object_add(row, "key", key);
	if (err != 0) {
		resmon_fmterr(error, "Couldn't attach key to row: %m");
		goto put_key;
	}
	/* N.B.: `key' is now owned by `row', the local merely references it. */

	err = json_object_object_add(row, "value", value);
	if (err != 0) {
		resmon_fmterr(error, "Couldn't attach value to row: %m");
		goto put_value;
	}
	/* N.B.: `value' now owned by `row' as well. */

	*pkey = key;
	*pvalue = value;
	*prow = row;
	return 0;

put_key:
	json_object_put(key);
put_value:
	json_object_put(value);
put_row:
	json_object_put(row);
	return -1;
}

static char *resmon_d_base64_encode(const uint8_t *in, size_t len)
{
	static const char tab[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t olen = 4 * ((len + 2) / 3) + 1;
	char *buf, *out;

	if (olen < len)
		return NULL;

	buf = malloc(olen);
	if (buf == NULL)
		return NULL;
	out = buf;

	for (size_t i = 0; i < len; i += 3) {
		uint8_t a = i + 0 < len ? in[i + 0] : 0;
		uint8_t b = i + 1 < len ? in[i + 1] : 0;
		uint8_t c = i + 2 < len ? in[i + 2] : 0;
		uint32_t abc = (a << 16) | b << 8 | c;

		*out++ = tab[(abc >> 18) & 0x3f];
		*out++ = tab[(abc >> 12) & 0x3f];
		*out++ = tab[(abc >> 6) & 0x3f];
		*out++ = tab[abc & 0x3f];
	}
	*out = '\0';

	return buf;
}

static int resmon_d_dump_dip(struct json_object *obj, const char *key,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     struct resmon_stat_dip dip,
			     uint8_t prefix_len)
{
	char buf[INET6_ADDRSTRLEN + 4]; /* +"/%d" for prefix length */
	int af;

	switch (protocol) {
	case MLXSW_REG_RALXX_PROTOCOL_IPV4:
		af = AF_INET;
		break;
	case MLXSW_REG_RALXX_PROTOCOL_IPV6:
		af = AF_INET6;
		break;
	}

	if (inet_ntop(af, &dip, buf, sizeof(buf)) == NULL)
		return -1;

	sprintf(strchr(buf, '\0'), "/%d", prefix_len);
	return resmon_jrpc_object_add_str(obj, key, buf);
}

static int
resmon_d_dump_tcam_region_info(struct json_object *obj, const char *key,
			       struct resmon_stat_tcam_region_info tcam_region_info)
{
	char *str;
	int err;

	str = resmon_d_base64_encode(tcam_region_info.tcam_region_info,
				     sizeof(tcam_region_info.tcam_region_info));
	if (str == NULL)
		return -1;

	err = resmon_jrpc_object_add_str(obj, key, str);
	free(str);
	return err;
}

static int
resmon_d_dump_flex2_key_blocks(struct json_object *obj, const char *key,
		    const struct resmon_stat_flex2_key_blocks *flex2_key_blocks)
{
	char *str;
	int err;

	str = resmon_d_base64_encode(flex2_key_blocks->flex2_key_blocks,
				     sizeof(flex2_key_blocks->flex2_key_blocks));
	if (str == NULL)
		return -1;

	err = resmon_jrpc_object_add_str(obj, key, str);
	free(str);
	return err;
}

static int resmon_d_dump_kvda(struct json_object *obj,
			      struct resmon_stat_kvd_alloc kvda)
{
	int err;

	err = resmon_jrpc_object_add_str(obj, "resource",
					 resmon_d_gauge_names[kvda.resource]);
	if (err != 0)
		return err;

	err = resmon_jrpc_object_add_int(obj, "slots", kvda.slots);
	if (err != 0)
		return err;

	return 0;
}

static struct json_object *resmon_d_dump_ralue_next(struct resmon_stat *stat,
						    char **error)
{
	struct json_object *value; /* Observer pointer. */
	struct json_object *key;   /* Observer pointer. */
	struct json_object *row;   /* Owner of key and value. */
	enum mlxsw_reg_ralxx_protocol protocol;
	struct resmon_stat_kvd_alloc kvda;
	struct resmon_stat_dip dip;
	uint16_t virtual_router;
	uint8_t prefix_len;
	int err;

	err = resmon_stat_ralue_next_row(stat, &protocol, &prefix_len,
					 &virtual_router, &dip, &kvda);
	if (err != 0) {
		*error = NULL;
		return NULL;
	}

	err = resmon_d_dump_row_alloc(&key, &value, &row, error);
	if (err != 0)
		goto err_out;

	err = resmon_d_dump_dip(key, "dip", protocol, dip, prefix_len);
	if (err != 0)
		goto err_form_row;

	err = resmon_jrpc_object_add_int(key, "vr", virtual_router);
	if (err != 0)
		goto err_form_row;

	err = resmon_d_dump_kvda(value, kvda);
	if (err != 0)
		goto err_form_row;

	return row;

err_form_row:
	json_object_put(row);
err_out:
	resmon_fmterr(error, "Couldn't form ralue row: %m");
	return NULL;
}

static struct json_object *resmon_d_dump_ptar_next(struct resmon_stat *stat,
						   char **error)
{
	struct json_object *value; /* Observer pointer. */
	struct json_object *key;   /* Observer pointer. */
	struct json_object *row;   /* Owner of key and value. */
	struct resmon_stat_tcam_region_info tcam_region_info;
	struct resmon_stat_kvd_alloc kvda;
	int err;

	err = resmon_d_dump_row_alloc(&key, &value, &row, error);
	if (err != 0)
		return NULL;

	err = resmon_stat_ptar_next_row(stat, &tcam_region_info, &kvda);
	if (err != 0) {
		*error = NULL;
		return NULL;
	}

	err = resmon_d_dump_tcam_region_info(key, "tcam_region_info",
					     tcam_region_info);
	if (err != 0)
		goto err_form_row;

	err = resmon_d_dump_kvda(value, kvda);
	if (err != 0)
		goto err_form_row;

	return row;

err_form_row:
	resmon_fmterr(error, "Couldn't form ptar row: %m");
	json_object_put(row);
	return NULL;
}

static struct json_object *resmon_d_dump_ptce3_next(struct resmon_stat *stat,
						    char **error)
{
	struct json_object *value; /* Observer pointer. */
	struct json_object *key;   /* Observer pointer. */
	struct json_object *row;   /* Owner of key and value. */
	struct resmon_stat_tcam_region_info tcam_region_info;
	struct resmon_stat_flex2_key_blocks flex2_key_blocks;
	struct resmon_stat_kvd_alloc kvd_alloc;
	uint16_t delta_start;
	uint8_t delta_value;
	uint8_t delta_mask;
	uint8_t erp_id;
	int err;

	err = resmon_d_dump_row_alloc(&key, &value, &row, error);
	if (err != 0)
		return NULL;

	err = resmon_stat_ptce3_next_row(stat, &tcam_region_info,
					 &flex2_key_blocks, &delta_mask,
					 &delta_value, &delta_start, &erp_id,
					 &kvd_alloc);
	if (err != 0) {
		*error = NULL;
		return NULL;
	}

	err = resmon_d_dump_tcam_region_info(key, "tcam_region_info",
					     tcam_region_info);
	if (err != 0)
		goto err_form_row;

	err = resmon_d_dump_flex2_key_blocks(key, "flex2_key_blocks",
					     &flex2_key_blocks);
	if (err != 0)
		goto err_form_row;

	err = resmon_jrpc_object_add_int(key, "delta_mask", delta_mask);
	if (err != 0)
		goto err_form_row;

	err = resmon_jrpc_object_add_int(key, "delta_value", delta_value);
	if (err != 0)
		goto err_form_row;

	err = resmon_jrpc_object_add_int(key, "delta_start", delta_start);
	if (err != 0)
		goto err_form_row;

	err = resmon_jrpc_object_add_int(key, "erp_id", erp_id);
	if (err != 0)
		goto err_form_row;

	err = resmon_d_dump_kvda(value, kvd_alloc);
	if (err != 0)
		goto err_form_row;

	return row;

err_form_row:
	resmon_fmterr(error, "Couldn't form ptce3 row: %m");
	json_object_put(row);
	return NULL;
}

static void resmon_d_handle_dump_next(struct resmon_stat *stat,
				      struct resmon_sock *peer,
				      struct json_object *params_obj,
				      struct json_object *id)
{
	struct resmon_d_table_info *found_tinfo = NULL;
	struct json_object *result_obj;
	struct json_object *row;
	struct json_object *obj;
	const char *table;
	char *error;
	int rc;

	/* The response is as follows:
	 *
	 * {
	 *     "id": ...,
	 *     "result": {
	 *         "row": {"key": KEY, "value": VAL},
	 *     }
	 * }
	 */

	rc = resmon_jrpc_dissect_params_dump_next(params_obj, &table, &error);
	if (rc != 0) {
		resmon_d_respond_invalid_params(peer, id, error);
		free(error);
		return;
	}

	for (size_t i = 0; i < ARRAY_SIZE(resmon_d_tables); i++) {
		struct resmon_d_table_info *tinfo = &resmon_d_tables[i];

		if (strcmp(tinfo->name, table) == 0) {
			found_tinfo = tinfo;
			break;
		}
	}

	if (found_tinfo == NULL) {
		resmon_d_respond_invalid_params(peer, id, "Table not found");
		return;
	}

	obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return;

	result_obj = json_object_new_object();
	if (result_obj == NULL)
		goto put_obj;

	row = found_tinfo->dump_next(stat, &error);
	if (row == NULL && error != NULL) {
		resmon_d_respond_interr(peer, id, error);
		free(error);
		rc = 0;
		goto put_result_obj;
	}

	rc = json_object_object_add(result_obj, "row", row);
	if (rc != 0)
		goto put_row;
	row = NULL;

	rc = json_object_object_add(obj, "result", result_obj);
	if (rc != 0)
		goto put_result_obj;
	result_obj = NULL;

	resmon_jrpc_send(peer, obj);

put_row:
	json_object_put(row);
put_result_obj:
	json_object_put(result_obj);
put_obj:
	json_object_put(obj);

	if (rc != 0)
		resmon_d_respond_memerr(peer, id);
}

static void resmon_d_handle_method(struct resmon_back *back,
				   struct resmon_stat *stat,
				   struct resmon_reg *rreg,
				   struct resmon_resources_enabled rsrc_en,
				   struct resmon_sock *peer,
				   const char *method,
				   struct json_object *params_obj,
				   struct json_object *id)
{
	if (strcmp(method, "stop") == 0) {
		resmon_d_handle_stop(peer, params_obj, id);
		return;
	} else if (strcmp(method, "ping") == 0) {
		resmon_d_handle_ping(peer, params_obj, id);
		return;
	} else if (strcmp(method, "stats") == 0) {
		resmon_d_handle_stats(back, stat, rsrc_en, peer,
				      params_obj, id);
		return;
	} else if (strcmp(method, "get_tables") == 0) {
		resmon_d_handle_get_tables(stat, peer, params_obj, id);
		return;
	} else if (strcmp(method, "dump_next") == 0) {
		resmon_d_handle_dump_next(stat, peer, params_obj, id);
		return;
	} else if (resmon_back_handle_method(back, stat, rreg, method,
					     peer, params_obj, id)) {
		return;
	}

	__resmon_d_respond(peer,
			   resmon_jrpc_new_error_method_nf(id, method));
}

static int resmon_d_ctl_activity(struct resmon_back *back,
				 struct resmon_stat *stat,
				 struct resmon_reg *rreg,
				 struct resmon_resources_enabled rsrc_en,
				 struct resmon_sock *ctl)
{
	struct json_object *request_obj;
	struct json_object *params;
	struct resmon_sock peer;
	struct json_object *id;
	char *request = NULL;
	const char *method;
	char *error;
	int err;

	err = resmon_sock_recv(ctl, &peer, &request);
	if (err < 0)
		return err;

	request_obj = json_tokener_parse(request);
	if (request_obj == NULL) {
		__resmon_d_respond(&peer,
				   resmon_jrpc_new_error_inv_request(NULL));
		goto free_req;
	}

	err = resmon_jrpc_dissect_request(request_obj, &id, &method, &params,
					  &error);
	if (err) {
		__resmon_d_respond(&peer,
				   resmon_jrpc_new_error_inv_request(error));
		free(error);
		goto put_req_obj;
	}

	resmon_d_handle_method(back, stat, rreg, rsrc_en,
			       &peer, method, params, id);

put_req_obj:
	json_object_put(request_obj);
free_req:
	free(request);
	return 0;
}

static int resmon_d_loop_sock(struct resmon_back *back, struct resmon_stat *stat,
			      struct resmon_reg *rreg,
			      struct resmon_resources_enabled rsrc_en,
			      struct resmon_sock *ctl)
{
	int err = 0;
	enum {
		pollfd_ctl,
		pollfd_back,
	};
	struct pollfd pollfds[] = {
		[pollfd_ctl] = {
			.fd = ctl->fd,
			.events = POLLIN,
		},
		[pollfd_back] = {
			.fd = resmon_back_pollfd(back),
			.events = POLLIN,
		},
	};

	if (env.verbosity > 0)
		fprintf(stderr, "Listening on %s\n", ctl->sa.sun_path);

	while (!should_quit) {
		int nfds;

		nfds = poll(pollfds, ARRAY_SIZE(pollfds), -1);
		if (nfds < 0 && errno != EINTR) {
			fprintf(stderr, "Failed to poll: %m\n");
			err = nfds;
			goto out;
		}
		if (nfds == 0)
			continue;
		for (size_t i = 0; i < ARRAY_SIZE(pollfds); i++) {
			struct pollfd *pollfd = &pollfds[i];

			if (pollfd->revents & (POLLERR | POLLHUP |
					       POLLNVAL)) {
				fprintf(stderr,
					"Problem on pollfd %zd: %m\n", i);
				err = -1;
				goto out;
			}
			if (pollfd->revents & POLLIN) {
				switch (i) {
				case pollfd_ctl:
					err = resmon_d_ctl_activity(back, stat,
								    rreg,
								    rsrc_en,
								    ctl);
					if (err != 0)
						goto out;
					break;
				case pollfd_back:
					err = resmon_back_activity(back, stat,
								   rreg);
					if (err != 0)
						goto out;
					break;
				}
			}
		}
	}

out:
	return err;
}

static int resmon_d_loop(struct resmon_back *back, struct resmon_stat *stat,
			 struct resmon_reg *rreg,
			 struct resmon_resources_enabled rsrc_en)
{
	struct resmon_sock ctl;
	int err;

	err = resmon_d_setup_signals();
	if (err < 0)
		return -1;

	err = resmon_sock_open_d(&ctl, env.sockdir);
	if (err)
		return err;

	sd_notify(0, "READY=1");

	err = resmon_d_loop_sock(back, stat, rreg, rsrc_en, &ctl);

	resmon_sock_close_d(&ctl);
	return err;
}

static int resmon_d_do_start(const struct resmon_back_cls *back_cls,
			     struct resmon_resources_enabled rsrc_en)
{
	struct resmon_back *back;
	struct resmon_stat *stat;
	struct resmon_reg *rreg;
	int err = 0;

	stat = resmon_stat_create();
	if (stat == NULL)
		return -1;

	rreg = resmon_reg_create(rsrc_en);
	if (rreg == NULL)
		goto destroy_stat;

	back = resmon_back_init(back_cls);
	if (back == NULL)
		goto destroy_rreg;

	openlog("resmon", LOG_PID | LOG_CONS, LOG_USER);

	err = resmon_d_loop(back, stat, rreg, rsrc_en);

	closelog();
	resmon_back_fini(back);
destroy_rreg:
	resmon_reg_destroy(rreg);
destroy_stat:
	resmon_stat_destroy(stat);
	return err;
}

struct resmon_d_resgrp_info {
	const char *const name;
	const struct resmon_resources_enabled rsrc_en;
};

#define RESMON_D_RSRC_AS_RESGRP_INFO(NAME, DESCR)	\
	{ #NAME, {{ [RESMON_RSRC_ ## NAME] = true }}},

static const struct resmon_d_resgrp_info resmon_d_resgrp_info[] = {
	RESMON_RESOURCES(RESMON_D_RSRC_AS_RESGRP_INFO)
	{
		"lpm",
		{{
			[RESMON_RSRC_LPM_IPV4] = true,
			[RESMON_RSRC_LPM_IPV6] = true,
		}}
	},
	{
		"hosttab",
		{{
			[RESMON_RSRC_HOSTTAB_IPV4] = true,
			[RESMON_RSRC_HOSTTAB_IPV6] = true,
		}}
	},
	{
		"kvdl",
		{{
			[RESMON_RSRC_ACTSET] = true,
			[RESMON_RSRC_ADJTAB] = true,
		}}
	},
};

#undef RESMON_D_RSRC_AS_RESGRP_INFO

static int resmon_d_enable_resources(const char *name,
				     struct resmon_resources_enabled *rsrc_en,
				     bool include)
{
	const struct resmon_d_resgrp_info *info;

	for (size_t i = 0; i < ARRAY_SIZE(resmon_d_resgrp_info); i++) {
		info = &resmon_d_resgrp_info[i];
		if (strcasecmp(name, info->name) != 0)
			continue;

		for (size_t j = 0; j < ARRAY_SIZE(info->rsrc_en.enabled); j++) {
			if (include)
				rsrc_en->enabled[j] |= info->rsrc_en.enabled[j];
			else
				rsrc_en->enabled[j] &= !info->rsrc_en.enabled[j];
		}

		return 0;
	}

	return -1;
}

static void resmon_d_resources_fill(int *p_argc, char ***p_argv,
				    struct resmon_resources_enabled *rsrc_en,
				    bool include)
{
	char **argv = *p_argv;
	int argc = *p_argc;

	while (argc > 0) {
		if (resmon_d_enable_resources(*argv, rsrc_en, include) < 0)
			goto out;

		NEXT_ARG_FWD();
	}

out:
	*p_argc = argc;
	*p_argv = argv;
}

static void
resmon_d_set_all_resources(struct resmon_resources_enabled *rsrc_en)
{
	for (int i = 0; i < ARRAY_SIZE(rsrc_en->enabled); i++)
		rsrc_en->enabled[i] = true;
}

static void resmon_d_resource_name_print(const char *name)
{
	for (const char *ptr = name; *ptr != '\0'; ptr++)
		fprintf(stderr, "%c", tolower(*ptr));
}

static void resmon_d_start_help(void)
{
	fprintf(stderr,
		"Usage: resmon start [mode {hw | mock}] [[include | exclude] resources RES RES ...]\n"
		"RES ::= [");

	for (size_t i = 0; i < ARRAY_SIZE(resmon_d_resgrp_info); i++) {
		if (i != 0)
			fprintf(stderr, " | ");
		resmon_d_resource_name_print(resmon_d_resgrp_info[i].name);
	}

	fprintf(stderr, "]\n");
}

int resmon_d_start(int argc, char **argv)
{
	struct resmon_resources_enabled rsrc_en = {};
	const struct resmon_back_cls *back_cls;
	bool filter_resources = false;
	enum {
		mode_hw,
		mode_mock
	} mode = mode_hw;

	while (argc > 0) {
		if (strcmp(*argv, "mode") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "hw") == 0) {
				mode = mode_hw;
			} else if (strcmp(*argv, "mock") == 0) {
				mode = mode_mock;
			} else {
				fprintf(stderr, "Unrecognized mode: %s\n", *argv);
				return -1;
			}
			NEXT_ARG_FWD();
		} else if (strcmp(*argv, "include") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "resources") != 0)
				goto incomplete_command;
		} else if (strcmp(*argv, "exclude") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "resources") != 0)
				goto incomplete_command;
			NEXT_ARG();
			resmon_d_set_all_resources(&rsrc_en);
			resmon_d_resources_fill(&argc, &argv, &rsrc_en, false);
			filter_resources = true;
		} else if (strcmp(*argv, "resources") == 0) {
			NEXT_ARG();
			resmon_d_resources_fill(&argc, &argv, &rsrc_en, true);
			filter_resources = true;
		} else if (strcmp(*argv, "help") == 0) {
			resmon_d_start_help();
			return 0;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			return -1;
		}
		continue;

incomplete_command:
		fprintf(stderr, "Command line is not complete. Try option \"help\"\n");
		return -1;
	}

	switch (mode) {
	case mode_hw:
		back_cls = &resmon_back_cls_hw;
		break;
	case mode_mock:
		back_cls = &resmon_back_cls_mock;
		break;
	}

	if (!filter_resources)
		resmon_d_set_all_resources(&rsrc_en);

	return resmon_d_do_start(back_cls, rsrc_en);
}
