// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <json-c/json_object.h>
#include <json-c/json_object_iterator.h>
#include <json-c/json_util.h>

#include "resmon.h"

static int __resmon_jrpc_object_add(struct json_object *obj,
				    const char *key,
				    struct json_object *val_obj)
{
	int rc;

	if (val_obj == NULL)
		return -1;

	rc = json_object_object_add(obj, key, val_obj);
	if (rc != 0)
		goto err_put_val_obj;

	return 0;

err_put_val_obj:
	json_object_put(val_obj);
	return -1;
}

int resmon_jrpc_object_add_int(struct json_object *obj,
			       const char *key, int64_t val)
{
	return __resmon_jrpc_object_add(obj, key, json_object_new_int64(val));
}

int resmon_jrpc_object_add_str(struct json_object *obj,
			       const char *key, const char *str)
{
	return __resmon_jrpc_object_add(obj, key, json_object_new_string(str));
}

int resmon_jrpc_object_add_bool(struct json_object *obj,
				const char *key, bool val)
{
	return __resmon_jrpc_object_add(obj, key, json_object_new_boolean(val));
}

static int resmon_jrpc_object_add_error(struct json_object *obj,
					int code, const char *message,
					const char *data)
{
	struct json_object *err_obj;
	int rc;

	err_obj = json_object_new_object();
	if (err_obj == NULL)
		return -1;

	rc = resmon_jrpc_object_add_int(err_obj, "code", code);
	if (rc != 0)
		goto err_put_err_obj;

	rc = resmon_jrpc_object_add_str(err_obj, "message", message);
	if (rc != 0)
		goto err_put_err_obj;

	if (data != NULL)
		/* Allow this to fail, the error object is valid without it. */
		resmon_jrpc_object_add_str(err_obj, "data", data);

	rc = json_object_object_add(obj, "error", err_obj);
	if (rc != 0)
		goto err_put_err_obj;

	return 0;

err_put_err_obj:
	json_object_put(err_obj);
	return -1;
}

struct json_object *resmon_jrpc_new_object(struct json_object *id)
{
	struct json_object *obj;
	int rc;

	obj = json_object_new_object();
	if (obj == NULL)
		return NULL;

	rc = resmon_jrpc_object_add_str(obj, "jsonrpc", "2.0");
	if (rc != 0)
		goto err_put_obj;

	rc = json_object_object_add(obj, "id", id);
	if (rc != 0)
		goto err_put_obj;
	json_object_get(id);

	return obj;

err_put_obj:
	json_object_put(obj);
	return NULL;
}

struct json_object *resmon_jrpc_new_request(int id, const char *method)
{
	struct json_object *request;
	struct json_object *id_obj;
	int rc;

	id_obj = json_object_new_int(id);
	if (id_obj == NULL) {
		fprintf(stderr, "Failed to allocate an ID object.\n");
		return NULL;
	}

	request = resmon_jrpc_new_object(id_obj);
	if (request == NULL) {
		fprintf(stderr, "Failed to allocate a request object.\n");
		goto put_id;
	}

	rc = resmon_jrpc_object_add_str(request, "method", method);
	if (rc != 0) {
		fprintf(stderr, "Failed to form a request object.\n");
		goto put_request;
	}

	goto put_id;

put_request:
	json_object_put(request);
put_id:
	json_object_put(id_obj);
	return request;
}

struct json_object *resmon_jrpc_new_error(struct json_object *id,
					  enum resmon_jrpc_e code,
					  const char *message,
					  const char *data)
{
	struct json_object *obj;
	int rc;

	obj = resmon_jrpc_new_object(id);
	if (obj == NULL)
		return NULL;

	rc = resmon_jrpc_object_add_error(obj, code, message, data);
	if (rc != 0)
		goto err_put_obj;

	return obj;

err_put_obj:
	json_object_put(obj);
	return NULL;
}

struct json_object *resmon_jrpc_new_error_inv_request(const char *data)
{
	return resmon_jrpc_new_error(NULL, resmon_jrpc_e_inv_request,
				     "Invalid Request", data);
}

struct json_object *resmon_jrpc_new_error_method_nf(struct json_object *id,
						    const char *method)
{
	return resmon_jrpc_new_error(id, resmon_jrpc_e_method_nf,
				     "Method not found", method);
}

struct json_object *resmon_jrpc_new_error_inv_params(struct json_object *id,
						     const char *data)
{
	return resmon_jrpc_new_error(id, resmon_jrpc_e_inv_params,
				     "Invalid params", data);
}

struct json_object *resmon_jrpc_new_error_int_error(struct json_object *id,
						    const char *data)
{
	return resmon_jrpc_new_error(id, resmon_jrpc_e_int_error,
				     "Internal error", data);
}

struct resmon_jrpc_policy {
	const char *key;
	enum json_type type;
	bool any_type;
	bool required;
};

static int resmon_jrpc_validate_array(struct json_object *obj,
				      enum json_type elm_type,
				      char **error)
{
	{
		enum json_type type = json_object_get_type(obj);

		if (type != json_type_array) {
			resmon_fmterr(error, "Value expected to be an array, but is %s",
				      json_type_to_name(type));
			return -1;
		}
	}

	for (size_t i = 0, len = json_object_array_length(obj); i < len; i++) {
		struct json_object *elm = json_object_array_get_idx(obj, i);
		enum json_type type = json_object_get_type(elm);

		if (type != elm_type) {
			resmon_fmterr(error, "Array element %zd is expected to be a %s, but is %s",
				      i, json_type_to_name(elm_type),
				      json_type_to_name(type));
			return -1;
		}
	}

	return 0;
}

static int resmon_jrpc_dissect(struct json_object *obj,
			       struct resmon_jrpc_policy policy[],
			       bool seen[],
			       struct json_object *values[],
			       size_t policy_size,
			       char **error)
{
	{
		enum json_type type = json_object_get_type(obj);

		if (type != json_type_object) {
			resmon_fmterr(error, "Value expected to be an object, but is %s",
				      json_type_to_name(type));
			return -1;
		}
	}

	for (struct json_object_iterator it = json_object_iter_begin(obj),
					 et = json_object_iter_end(obj);
	     !json_object_iter_equal(&it, &et);
	     json_object_iter_next(&it)) {
		struct json_object *val = json_object_iter_peek_value(&it);
		const char *key = json_object_iter_peek_name(&it);
		bool found = false;

		for (size_t i = 0; i < policy_size; i++) {
			struct resmon_jrpc_policy *pol = &policy[i];

			if (strcmp(key, pol->key) == 0) {
				enum json_type type = json_object_get_type(val);

				if (!pol->any_type && pol->type != type) {
					resmon_fmterr(error, "The member %s is expected to be a %s, but is %s",
						      key,
						      json_type_to_name(pol->type),
						      json_type_to_name(type));
					return -1;
				}

				if (seen[i]) {
					resmon_fmterr(error, "Duplicate member %s",
						      key);
					return -1;
				}

				seen[i] = true;
				values[i] = val;
				found = true;
				break;
			}
		}

		if (!found) {
			resmon_fmterr(error, "The member %s is not expected",
				      key);
			return -1;
		}
	}

	for (size_t i = 0; i < policy_size; i++) {
		struct resmon_jrpc_policy *pol = &policy[i];

		if (!seen[i] && pol->required) {
			resmon_fmterr(error, "Required member %s not present",
				      pol->key);
			return -1;
		}
	}

	return 0;
}

static bool resmon_jrpc_validate_version(struct json_object *ver_obj,
					 char **error)
{
	const char *ver;

	assert(json_object_get_type(ver_obj) == json_type_string);
	ver = json_object_get_string(ver_obj);
	if (strcmp(ver, "2.0") != 0) {
		resmon_fmterr(error, "Unsupported jsonrpc version: %s", ver);
		return false;
	}

	return true;
}

static int resmon_jrpc_extract_uint64(const char *key, struct json_object *obj,
				      uint64_t *pvalue64, char **error)
{
	int64_t value;

	value = json_object_get_int64(obj);
	if (value < 0) {
		resmon_fmterr(error, "Invalid %s < 0", key);
		return -1;
	}

	*pvalue64 = (uint64_t) value;
	return 0;
}

static int resmon_jrpc_extract_uint32(const char *key, struct json_object *obj,
				      uint32_t *pvalue, char **error)
{
	uint64_t value64;
	int err;

	err = resmon_jrpc_extract_uint64(key, obj, &value64, error);
	if (err != 0)
		return err;

	*pvalue = value64;
	if (*pvalue != value64) {
		resmon_fmterr(error, "Invalid %s: value too large", key);
		return -1;
	}

	return 0;
}

int resmon_jrpc_dissect_request(struct json_object *obj,
				struct json_object **id,
				const char **method,
				struct json_object **params,
				char **error)
{
	enum {
		pol_jsonrpc,
		pol_id,
		pol_method,
		pol_params,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_jsonrpc] = { .key = "jsonrpc", .type = json_type_string,
				  .required = true },
		[pol_id] =      { .key = "id", .any_type = true,
				  .required = true },
		[pol_method] =  { .key = "method", .type = json_type_string,
				  .required = true },
		[pol_params] =  { .key = "params", .any_type = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = resmon_jrpc_dissect(obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err)
		return err;

	if (!resmon_jrpc_validate_version(values[pol_jsonrpc], error))
		return -1;

	*id = values[pol_id];
	*method = json_object_get_string(values[pol_method]);
	*params = values[pol_params];
	return 0;
}

int resmon_jrpc_dissect_response(struct json_object *obj,
				 struct json_object **id,
				 struct json_object **result,
				 bool *is_error,
				 char **error)
{
	enum {
		pol_jsonrpc,
		pol_id,
		pol_result,
		pol_error,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_jsonrpc] = { .key = "jsonrpc", .type = json_type_string,
				  .required = true },
		[pol_id] =      { .key = "id", .any_type = true,
				  .required = true },
		[pol_error] =   { .key = "error", .type = json_type_object },
		[pol_result] =  { .key = "result", .any_type = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = resmon_jrpc_dissect(obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err)
		return err;

	if (!resmon_jrpc_validate_version(values[pol_jsonrpc], error))
		return -1;

	if (seen[pol_error] && seen[pol_result]) {
		resmon_fmterr(error, "Both error and result present in jsonrpc response");
		return -1;
	} else if (!seen[pol_error] && !seen[pol_result]) {
		resmon_fmterr(error, "Neither error nor result present in jsonrpc response");
		return -1;
	}

	*id = values[pol_id];
	*result = seen[pol_result] ? values[pol_result] : values[pol_error];
	*is_error = seen[pol_error];
	return 0;
}

int resmon_jrpc_dissect_error(struct json_object *obj,
			      int64_t *code,
			      const char **message,
			      struct json_object **data,
			      char **error)
{
	enum {
		pol_code,
		pol_message,
		pol_data,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_code] =    { .key = "code", .type = json_type_int,
				  .required = true },
		[pol_message] = { .key = "message", .type = json_type_string,
				  .required = true },
		[pol_data] =    { .key = "data", .any_type = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = resmon_jrpc_dissect(obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err)
		return err;

	*code = json_object_get_int64(values[pol_code]);
	*message = json_object_get_string(values[pol_message]);
	*data = values[pol_data];
	return 0;
}

int resmon_jrpc_dissect_params_empty(struct json_object *obj,
				     char **error)
{
	if (obj == NULL)
		return 0;
	return resmon_jrpc_dissect(obj, NULL, NULL, NULL, 0, error);
}

int resmon_jrpc_dissect_params_emad(struct json_object *obj,
				    const char **payload,
				    size_t *payload_len,
				    char **error)
{
	enum {
		pol_payload,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_payload] = { .key = "payload", .type = json_type_string,
				  .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = resmon_jrpc_dissect(obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err)
		return err;

	*payload = json_object_get_string(values[pol_payload]);
	*payload_len = json_object_get_string_len(values[pol_payload]);
	return 0;
}

int resmon_jrpc_dissect_params_dump_next(struct json_object *obj,
					 const char **table,
					 char **error)
{
	enum {
		pol_table,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_table] = { .key = "table", .type = json_type_string,
				.required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = resmon_jrpc_dissect(obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err != 0)
		return err;

	*table = json_object_get_string(values[pol_table]);
	return 0;
}

static int
resmon_jrpc_dissect_stats_gauge(struct json_object *gauge_obj,
				struct resmon_jrpc_gauge *pgauge,
				char **error)
{
	enum {
		pol_id,
		pol_descr,
		pol_value,
		pol_capacity,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_id] =	 { .key = "name", .type = json_type_string,
				   .required = true },
		[pol_descr] =	 { .key = "descr", .type = json_type_string,
				   .required = true },
		[pol_value] =	 { .key = "value", .type = json_type_int,
				   .required = true },
		[pol_capacity] = { .key = "capacity", .type = json_type_int,
				   .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	uint64_t capacity;
	int err;

	err = resmon_jrpc_dissect(gauge_obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err)
		return err;

	err = resmon_jrpc_extract_uint64(policy[pol_capacity].key,
					 values[pol_capacity],
					 &capacity, error);
	if (err != 0)
		return err;

	*pgauge = (struct resmon_jrpc_gauge) {
		.descr = json_object_get_string(values[pol_descr]),
		.value = json_object_get_int64(values[pol_value]),
		.capacity = capacity,
	};
	return 0;
}

static int
resmon_jrpc_dissect_stats_gauges(struct json_object *gauges_array,
				 struct resmon_jrpc_gauge **pgauges,
				 size_t *pnum_gauges, char **error)
{
	size_t gauges_array_len = json_object_array_length(gauges_array);
	struct resmon_jrpc_gauge *gauges;

	gauges = calloc(gauges_array_len, sizeof(*gauges));
	if (gauges == NULL) {
		resmon_fmterr(error, "Couldn't allocate gauges: %m");
		return -1;
	}

	for (size_t i = 0; i < gauges_array_len; i++) {
		struct json_object *gauge_obj =
			json_object_array_get_idx(gauges_array, i);
		struct resmon_jrpc_gauge *gauge = &gauges[i];
		int err;

		err = resmon_jrpc_dissect_stats_gauge(gauge_obj, gauge, error);
		if (err != 0)
			goto free_gauges;
	}

	*pgauges = gauges;
	*pnum_gauges = gauges_array_len;
	return 0;

free_gauges:
	free(gauges);
	return -1;
}

int resmon_jrpc_dissect_stats(struct json_object *obj,
			      struct resmon_jrpc_gauge **gauges,
			      size_t *num_gauges,
			      char **error)
{
	/* Result for query with "stats" method is supposed to look like:
	 *
	 * { { "gauges": [ { "id": a, "descr": "b",
	 *                     "value": c, "capacity": d },
	 *                 { "id": e, "descr": "u", ... },
	 *                   ...
	 *               ] } }
	 */
	enum {
		pol_gauges,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_gauges] = { .key = "gauges", .type = json_type_array,
				 .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = resmon_jrpc_dissect(obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err)
		return err;

	return resmon_jrpc_dissect_stats_gauges(values[pol_gauges],
						gauges, num_gauges,
						error);
}

static int
resmon_jrpc_dissect_tables_table(struct json_object *table_obj,
				 struct resmon_jrpc_table *ptable,
				 char **error)
{
	enum {
		pol_name,
		pol_nrows,
		pol_seqnn,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_name] =	 { .key = "name", .type = json_type_string,
				   .required = true },
		[pol_nrows] =	 { .key = "nrows", .type = json_type_int,
				   .required = true },
		[pol_seqnn] =	 { .key = "seqnn", .type = json_type_int,
				   .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	uint32_t nrows;
	uint32_t seqnn;
	char *name;
	int err;

	err = resmon_jrpc_dissect(table_obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err)
		return err;

	err = resmon_jrpc_extract_uint32(policy[pol_nrows].key,
					 values[pol_nrows], &nrows, error);
	if (err != 0)
		return err;

	err = resmon_jrpc_extract_uint32(policy[pol_seqnn].key,
					 values[pol_seqnn], &seqnn, error);
	if (err != 0)
		return err;

	name = strdup(json_object_get_string(values[pol_name]));
	if (name == NULL) {
		resmon_fmterr(error, "Couldn't allocate table name: %m");
		return -1;
	}

	*ptable = (struct resmon_jrpc_table) {
		.name = name,
		.nrows = nrows,
		.seqnn = seqnn,
	};
	return 0;
}

void resmon_jrpc_tables_free(struct resmon_jrpc_table *tables,
			     size_t num_tables)
{
	for (size_t i = 0; i < num_tables; i++)
		free(tables[i].name);
	free(tables);
}

static int
resmon_jrpc_dissect_get_tables_tables(struct json_object *tables_array,
				      struct resmon_jrpc_table **ptables,
				      size_t *pnum_tables, char **error)
{
	size_t tables_array_len = json_object_array_length(tables_array);
	struct resmon_jrpc_table *tables;

	if (resmon_jrpc_validate_array(tables_array, json_type_object,
				       error) != 0)
		return -1;

	tables = calloc(tables_array_len, sizeof(*tables));
	if (tables == NULL) {
		resmon_fmterr(error, "Couldn't allocate tables: %m");
		return -1;
	}

	for (size_t i = 0; i < tables_array_len; i++) {
		struct json_object *table_obj =
			json_object_array_get_idx(tables_array, i);
		struct resmon_jrpc_table *table = &tables[i];
		int err;

		err = resmon_jrpc_dissect_tables_table(table_obj, table, error);
		if (err != 0)
			goto free_tables;
	}

	*ptables = tables;
	*pnum_tables = tables_array_len;
	return 0;

free_tables:
	free(tables);
	return -1;
}

int resmon_jrpc_dissect_get_tables(struct json_object *obj,
				   struct resmon_jrpc_table **tables,
				   size_t *num_tables, char **error)
{
	/* Result for query with "get_tables" method is supposed to look
	 * like:
	 *
	 * { "tables": [ {"name": "$NAME", "nrows": $NR, "seqnn": $I }, ...] }
	 */
	enum {
		pol_tables,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_tables] = { .key = "tables", .type = json_type_array,
				 .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = resmon_jrpc_dissect(obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err != 0)
		return err;

	return resmon_jrpc_dissect_get_tables_tables(values[pol_tables],
						     tables, num_tables,
						     error);
}

static int resmon_jrpc_dissect_dump_row_row(struct json_object *row_obj,
					    struct resmon_jrpc_dump_row *row,
					    char **error)
{
	enum {
		pol_key,
		pol_value,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_key] = { .key = "key", .type = json_type_object,
			      .required = true },
		[pol_value] = { .key = "value", .type = json_type_object,
				.required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	int err;

	err = resmon_jrpc_dissect(row_obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err != 0)
		return err;

	/* row->X are Rc pointers, so get them. */
	row->key = json_object_get(values[pol_key]);
	row->value = json_object_get(values[pol_value]);
	return 0;
}

int resmon_jrpc_dissect_dump_next(struct json_object *obj, const char *table_name,
				  struct resmon_jrpc_dump_row *row, char **error)
{
	/* Result for query with "dump_next" method is supposed to look
	 * either like this:
	 *     { "row": { "key": {...}, "value": {...} } }
	 *
	 * Or like this, if the iteration is over:
	 *     { "row": null }
	 */
	enum {
		pol_row,
	};
	struct resmon_jrpc_policy policy[] = {
		[pol_row] = { .key = "row", .any_type = true,
			      .required = true },
	};
	struct json_object *values[ARRAY_SIZE(policy)] = {};
	bool seen[ARRAY_SIZE(policy)] = {};
	enum json_type type;
	int err;

	err = resmon_jrpc_dissect(obj, policy, seen, values,
				  ARRAY_SIZE(policy), error);
	if (err != 0)
		return err;

	type = json_object_get_type(values[pol_row]);
	if (type == json_type_object)
		return resmon_jrpc_dissect_dump_row_row(values[pol_row],
							row, error);
	if (type == json_type_null)
		return 1;

	resmon_fmterr(error, "The member row is expected to be either an object, or a null, but is %s",
		      json_type_to_name(type));
	return -1;
}

int resmon_jrpc_send(struct resmon_sock *sock, struct json_object *obj)
{
	const char *str;
	size_t len;
	int rc;

	str = json_object_to_json_string(obj);
	if (str == NULL)
		return -1;

	len = strlen(str);
	rc = sendto(sock->fd, str, len, 0,
		    (struct sockaddr *) &sock->sa, sock->len);
	return rc == len ? 0 : -1;
}
