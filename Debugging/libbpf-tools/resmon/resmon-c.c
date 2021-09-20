// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>
#include <json-c/linkhash.h>

#include "resmon.h"

static bool resmon_c_validate_id(struct json_object *id_obj, int expect_id)
{
	int64_t id;

	id = json_object_get_int64(id_obj);
	return id == expect_id;
}

static void resmon_c_response_handle_error(struct json_object *error_obj)
{
	struct json_object *data;
	const char *message;
	int64_t code;
	char *error;
	int err;

	err = resmon_jrpc_dissect_error(error_obj, &code, &message, &data,
					&error);
	if (err != 0) {
		fprintf(stderr, "Invalid error object: %s\n", error);
		free(error);
		return;
	}

	if (data != NULL)
		fprintf(stderr, "Error %" PRId64 ": %s (%s)\n", code, message,
			json_object_to_json_string(data));
	else
		fprintf(stderr, "Error %" PRId64 ": %s\n", code, message);
}

static bool resmon_c_response_extract_result(struct json_object *j,
					     int expect_id,
					     enum json_type result_type,
					     struct json_object **ret_result)
{
	struct json_object *result;
	struct json_object *id;
	bool is_error;
	char *error;
	int err;

	err = resmon_jrpc_dissect_response(j, &id, &result, &is_error, &error);
	if (err) {
		fprintf(stderr, "Invalid response object: %s\n", error);
		free(error);
		return false;
	}

	if (!resmon_c_validate_id(id, expect_id)) {
		fprintf(stderr, "Unknown response ID: %s\n",
			json_object_to_json_string(id));
		return false;
	}

	if (is_error) {
		resmon_c_response_handle_error(result);
		return false;
	}

	if (json_object_get_type(result) != result_type) {
		fprintf(stderr, "Unexpected result type: %s expected, got %s\n",
			json_type_to_name(result_type),
			json_type_to_name(json_object_get_type(result)));
		return false;
	}

	*ret_result = json_object_get(result);
	return true;
}

static bool __resmon_c_result_show_json(struct json_object *result)
{
	const char *dump;

	if (env.show_json) {
		dump = json_object_to_json_string(result);
		fprintf(stdout, "%s", dump);
		return true;
	}

	return false;
}

static bool resmon_c_result_show_json(struct json_object *result)
{
	bool ret = __resmon_c_result_show_json(result);

	if (ret)
		putchar('\n');
	return ret;
}

static struct json_object *resmon_c_send_request_on(struct json_object *request,
						    struct resmon_sock *cli,
						    struct resmon_sock *peer)
{
	struct json_object *response_obj = NULL;
	char *response;
	int err;

	err = resmon_jrpc_send(peer, request);
	if (err < 0) {
		fprintf(stderr, "Failed to send the RPC message: %m\n");
		return NULL;
	}

	err = resmon_sock_recv(cli, peer, &response);
	if (err < 0) {
		fprintf(stderr, "Failed to receive an RPC response\n");
		return NULL;
	}

	response_obj = json_tokener_parse(response);
	if (response_obj == NULL) {
		fprintf(stderr, "Failed to parse RPC response as JSON.\n");
		goto free_response;
	}

free_response:
	free(response);
	return response_obj;
}

static struct json_object *resmon_c_send_request(struct json_object *request)
{
	struct json_object *response_obj = NULL;
	struct resmon_sock peer;
	struct resmon_sock cli;
	int err;

	err = resmon_sock_open_c(&cli, &peer, env.sockdir);
	if (err < 0) {
		fprintf(stderr, "Failed to open a socket: %m\n");
		return NULL;
	}

	response_obj = resmon_c_send_request_on(request, &cli, &peer);

	resmon_sock_close_c(&cli);
	return response_obj;
}

static int resmon_c_cmd_noargs(int argc, char **argv, void (*help_cb)(void))
{
	while (argc > 0) {
		if (strcmp(*argv, "help") == 0) {
			help_cb();
			return 0;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			return -1;
		}
	}

	return 0;
}

static void resmon_c_ping_help(void)
{
	fprintf(stderr,
		"Usage: resmon ping\n"
		"\n"
	);
}

static int resmon_c_ping_jrpc(void)
{
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const int id = 1;
	int err;
	int nr;
	int rc;
	int r;

	request = resmon_jrpc_new_request(id, "ping");
	if (request == NULL)
		return -1;

	srand(time(NULL));
	r = rand();
	rc = resmon_jrpc_object_add_int(request, "params", r);
	if (rc != 0) {
		fprintf(stderr, "Failed to form a request object.\n");
		err = -1;
		goto put_request;
	}

	response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!resmon_c_response_extract_result(response, id, json_type_int,
					      &result)) {
		err = -1;
		goto put_response;
	}

	if (resmon_c_result_show_json(result)) {
		err = 0;
		goto put_result;
	}

	nr = json_object_get_int(result);
	if (nr != r) {
		fprintf(stderr, "Unexpected ping response: sent %d, got %d.\n",
			r, nr);
		err = -1;
		goto put_result;
	}

	if (env.verbosity > 0)
		fprintf(stderr, "resmond is alive\n");
	err = 0;

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

int resmon_c_ping(int argc, char **argv)
{
	int err;

	err = resmon_c_cmd_noargs(argc, argv, resmon_c_ping_help);
	if (err != 0)
		return err;

	return resmon_c_ping_jrpc();
}

static void resmon_c_stop_help(void)
{
	fprintf(stderr,
		"Usage: resmon stop\n"
		"\n"
	);
}

static int resmon_c_stop_jrpc(void)
{
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const int id = 1;
	int err;

	request = resmon_jrpc_new_request(id, "stop");
	if (request == NULL)
		return -1;

	response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!resmon_c_response_extract_result(response, id, json_type_null,
					      &result)) {
		err = -1;
		goto put_response;
	}

	if (resmon_c_result_show_json(result)) {
		err = 0;
		goto put_result;
	}

	if (env.verbosity > 0)
		fprintf(stderr, "resmond will stop\n");
	err = 0;

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

int resmon_c_stop(int argc, char **argv)
{
	int err;

	err = resmon_c_cmd_noargs(argc, argv, resmon_c_stop_help);
	if (err != 0)
		return err;

	return resmon_c_stop_jrpc();
}

static void resmon_c_emad_help(void)
{
	fprintf(stderr,
		"Usage: resmon emad [hex | raw] string PAYLOAD\n"
		"\n"
	);
}

static int resmon_c_emad_jrpc(const char *payload, size_t payload_len)
{
	struct json_object *payload_obj;
	struct json_object *params_obj;
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const int id = 1;
	int err;

	request = resmon_jrpc_new_request(id, "emad");
	if (request == NULL)
		return -1;

	params_obj = json_object_new_object();
	if (params_obj == NULL) {
		err = -ENOMEM;
		goto put_request;
	}

	payload_obj = json_object_new_string_len(payload, payload_len);
	if (payload_obj == NULL) {
		err = -ENOMEM;
		goto put_params_obj;
	}

	if (json_object_object_add(params_obj, "payload", payload_obj)) {
		err = -ENOMEM;
		goto put_payload_obj;
	}
	payload_obj = NULL;

	if (json_object_object_add(request, "params", params_obj)) {
		err = -1;
		goto put_params_obj;
	}
	params_obj = NULL;

	response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!resmon_c_response_extract_result(response, id, json_type_null,
					      &result)) {
		err = -1;
		goto put_response;
	}

	if (resmon_c_result_show_json(result)) {
		err = 0;
		goto put_result;
	}

	if (env.verbosity > 0)
		fprintf(stderr, "resmond took the EMAD\n");

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_payload_obj:
	json_object_put(payload_obj);
put_params_obj:
	json_object_put(params_obj);
put_request:
	json_object_put(request);
	return err;
}

int resmon_c_emad(int argc, char **argv)
{
	char *payload = NULL;
	size_t payload_len;
	enum {
		mode_hex,
		mode_raw,
	} mode = mode_hex;
	int rc = 0;

	while (argc > 0) {
		if (strcmp(*argv, "string") == 0) {
			NEXT_ARG();
			payload = strdup(*argv);
			if (payload == NULL) {
				fprintf(stderr, "Failed to strdup: %m\n");
				rc = -1;
				goto out;
			}
			payload_len = strlen(payload);
			NEXT_ARG_FWD();
			break;
		} else if (strcmp(*argv, "help") == 0) {
			resmon_c_emad_help();
			goto out;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			rc = -1;
			goto out;
		}
		continue;

incomplete_command:
		fprintf(stderr, "Command line is not complete. Try option \"help\"\n");
		rc = -1;
		goto out;
	}

	if (payload == NULL) {
		fprintf(stderr, "EMAD payload not given.\n");
		rc = -1;
		goto out;
	}

	if (mode == mode_raw) {
		char *enc_payload = malloc(payload_len * 2 + 1);

		if (enc_payload == NULL) {
			fprintf(stderr, "Failed to allocate buffer for decoded payload: %m\n");
			rc = -1;
			goto out;
		}

		for (size_t i = 0; i < payload_len; i++)
			sprintf(&enc_payload[2 * i], "%02x", payload[i]);

		free(payload);
		payload = enc_payload;
		payload_len = payload_len * 2;
	}

	rc = resmon_c_emad_jrpc(payload, payload_len);

out:
	free(payload);
	return rc;
}

static void resmon_c_stats_help(void)
{
	fprintf(stderr,
		"Usage: resmon stats\n"
		"\n"
	);
}

static void resmon_c_stats_print(struct resmon_jrpc_gauge *gauges,
				 size_t num_gauges)
{
	fprintf(stderr, "%-30s%s\n", "Resource", "Usage");

	for (size_t i = 0; i < num_gauges; i++)
		fprintf(stderr, "%-30s%" PRId64 " / %" PRIu64 " (%" PRIu64 "%%)\n",
			gauges[i].descr, gauges[i].value,
			gauges[i].capacity,
			gauges[i].value * 100 / gauges[i].capacity);
}

static int resmon_c_stats_jrpc(void)
{
	struct resmon_jrpc_gauge *gauges;
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	size_t num_gauges;
	const int id = 1;
	char *error;
	int err = 0;

	request = resmon_jrpc_new_request(id, "stats");
	if (request == NULL)
		return -1;

	response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!resmon_c_response_extract_result(response, id, json_type_object,
					      &result)) {
		err = -1;
		goto put_response;
	}

	if (resmon_c_result_show_json(result)) {
		err = 0;
		goto put_result;
	}

	err = resmon_jrpc_dissect_stats(result, &gauges, &num_gauges,
					&error);
	if (err != 0) {
		fprintf(stderr, "Invalid gauges object: %s\n", error);
		free(error);
		goto put_result;
	}

	resmon_c_stats_print(gauges, num_gauges);

	free(gauges);
put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

int resmon_c_stats(int argc, char **argv)
{
	int err;

	err = resmon_c_cmd_noargs(argc, argv, resmon_c_stats_help);
	if (err != 0)
		return err;

	return resmon_c_stats_jrpc();
}

static int __resmon_c_get_tables_jrpc(struct resmon_jrpc_table **tables,
				      size_t *num_tables,
				      bool allow_show_json)
{
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const int id = 1;
	char *error;
	int err = 0;

	request = resmon_jrpc_new_request(id, "get_tables");
	if (request == NULL)
		return -1;

	response = resmon_c_send_request(request);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!resmon_c_response_extract_result(response, id, json_type_object,
					      &result)) {
		err = -1;
		goto put_response;
	}

	if (allow_show_json && resmon_c_result_show_json(result)) {
		err = 0;
		goto put_result;
	}

	err = resmon_jrpc_dissect_get_tables(result, tables, num_tables,
					     &error);
	if (err != 0) {
		fprintf(stderr, "Invalid tables object: %s\n", error);
		free(error);
		goto put_result;
	}

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_request:
	json_object_put(request);
	return err;
}

static int resmon_c_get_tables_jrpc(void)
{
	struct resmon_jrpc_table *tables = NULL;
	size_t num_tables;
	int err;

	err = __resmon_c_get_tables_jrpc(&tables, &num_tables, true);
	if (err != 0)
		return err;

	if (env.verbosity > 0 && num_tables == 0)
		fprintf(stderr, "no supported tables\n");
	for (size_t i = 0; i < num_tables; i++) {
		if (env.verbosity)
			fprintf(stdout, "%s seqnn %d nrows %d\n",
				tables[i].name, tables[i].seqnn,
				tables[i].nrows);
		else
			fprintf(stdout, "%s\n", tables[i].name);
	}
	resmon_jrpc_tables_free(tables, num_tables);
	return 0;
}

static int resmon_c_get_table(const char *name, struct resmon_jrpc_table *table)
{
	struct resmon_jrpc_table *tables;
	size_t num_tables;
	int err;

	err = __resmon_c_get_tables_jrpc(&tables, &num_tables, false);
	if (err != 0)
		return err;

	err = -1;
	for (size_t i = 0; i < num_tables; i++) {
		if (strcmp(tables[i].name, name) == 0) {
			*table = tables[i];
			tables[i].name = NULL; /* Steal the name buffer. */
			err = 0;
			break;
		}
	}

	resmon_jrpc_tables_free(tables, num_tables);
	return err;
}

struct resmon_c_fmtab_column {
	bool double_left;
	int width;
};

struct resmon_c_fmtab {
	struct resmon_c_fmtab_column *columns;
	size_t num_columns;
	const char **cells;
};

static const char **resmon_c_fmtab_cell(struct resmon_c_fmtab *fmtab,
					size_t row, size_t col)
{
	size_t cell_i = row * fmtab->num_columns + col;

	return &fmtab->cells[cell_i];
}

static int resmon_c_dump_table_show(struct resmon_jrpc_dump_row *rows,
				    size_t num_rows)
{
	struct resmon_jrpc_dump_row *row1;
	struct resmon_c_fmtab fmtab;
	int err;

	if (num_rows == 0) {
		if (env.verbosity > 0)
			fprintf(stderr, "no data\n");
		return 0;
	}

	row1 = &rows[0];
	fmtab.num_columns = json_object_object_length(row1->key) +
			    json_object_object_length(row1->value);

	fmtab.columns = calloc(fmtab.num_columns, sizeof(*fmtab.columns));
	if (fmtab.columns == NULL)
		return -1;

	fmtab.cells = calloc(fmtab.num_columns * (num_rows + 1),
			     sizeof(*fmtab.cells));
	if (fmtab.cells == NULL) {
		err = -1;
		goto free_columns;
	}

	/* Fill the header. */
	{
		size_t col = 0;

		if (col < fmtab.num_columns)
			fmtab.columns[col].double_left = true;
		json_object_object_foreach(row1->key, key_key, key_value)
			*resmon_c_fmtab_cell(&fmtab, 0, col++) = key_key;

		if (col < fmtab.num_columns)
			fmtab.columns[col].double_left = true;
		json_object_object_foreach(row1->value, val_key, val_value)
			*resmon_c_fmtab_cell(&fmtab, 0, col++) = val_key;
	}

	/* Fill contents. */
	for (size_t i = 0; i < num_rows; i++) {
		struct resmon_jrpc_dump_row *row = &rows[i];
		size_t col = 0;

		json_object_object_foreach(row->key, key_key, key_value) {
			*resmon_c_fmtab_cell(&fmtab, i + 1, col++) =
				json_object_get_string(key_value);
			(void) key_key;
		}
		json_object_object_foreach(row->value, val_key, val_value) {
			*resmon_c_fmtab_cell(&fmtab, i + 1, col++) =
				json_object_get_string(val_value);
			(void) val_key;
		}
	}

	/* Determine cell widths. */
	for (size_t i = 0; i < num_rows + 1; i++) {
		for (size_t col = 0; col < fmtab.num_columns; col++) {
			const char *cell = *resmon_c_fmtab_cell(&fmtab, i, col);
			size_t cell_len = strlen(cell);

			if (cell_len > fmtab.columns[col].width)
				fmtab.columns[col].width = cell_len;
		}
	}

	/* Show the table. */
	for (size_t i = 0; i < num_rows + 1; i++) {
		fprintf(stdout, "|");

		for (size_t col = 0; col < fmtab.num_columns; col++) {
			struct resmon_c_fmtab_column *column = &fmtab.columns[col];
			const char *cell = *resmon_c_fmtab_cell(&fmtab, i, col);

			if (column->double_left)
				printf("|");
			printf(" %-*s |", column->width, cell);
		}

		fprintf(stdout, "|\n");
	}

	err = 0;

free_columns:
	free(fmtab.columns);
	free(fmtab.cells);
	return err;
}

static int resmon_c_dump_table_row_jrpc(const struct resmon_jrpc_table *table,
					struct resmon_sock *cli,
					struct resmon_sock *peer,
					struct resmon_jrpc_dump_row *row)
{
	struct json_object *params_obj;
	struct json_object *response;
	struct json_object *request;
	struct json_object *result;
	const int id = 1;
	char *error;
	int err;

	request = resmon_jrpc_new_request(id, "dump_next");
	if (request == NULL)
		return -ENOMEM;

	params_obj = json_object_new_object();
	if (params_obj == NULL) {
		err = -ENOMEM;
		goto put_request;
	}

	if (resmon_jrpc_object_add_str(params_obj, "table", table->name) != 0) {
		fprintf(stderr, "Failed to form a request object.\n");
		err = -1;
		goto put_params_obj;
	}

	if (json_object_object_add(request, "params", params_obj)) {
		err = -1;
		goto put_params_obj;
	}
	params_obj = NULL;

	response = resmon_c_send_request_on(request, cli, peer);
	if (response == NULL) {
		err = -1;
		goto put_request;
	}

	if (!resmon_c_response_extract_result(response, id, json_type_object,
					      &result)) {
		err = -1;
		goto put_response;
	}

	err = resmon_jrpc_dissect_dump_next(result, table->name, row, &error);
	if (err < 0) {
		fprintf(stderr, "Invalid dump object: %s\n", error);
		free(error);
		goto put_result;
	}

	if (__resmon_c_result_show_json(result)) {
		puts("," + (err > 0));
		goto put_result;
	}

put_result:
	json_object_put(result);
put_response:
	json_object_put(response);
put_params_obj:
	json_object_put(params_obj);
put_request:
	json_object_put(request);
	return err;
}

static int resmon_c_dump_table(const char *name)
{
	struct resmon_jrpc_dump_row *rows = NULL;
	struct resmon_jrpc_table table_post;
	struct resmon_jrpc_table table;
	struct resmon_sock peer;
	struct resmon_sock cli;
	size_t nrows = 0;
	uint32_t i = 0;
	int err;

	err = resmon_c_get_table(name, &table);
	if (err != 0) {
		fprintf(stderr, "The daemon reports no table named `%s'.\n",
			name);
		return err;
	}

	err = resmon_sock_open_c(&cli, &peer, env.sockdir);
	if (err < 0) {
		fprintf(stderr, "Failed to open a socket: %m\n");
		goto free_table_name;
	}

	if (env.show_json)
		puts("[");

	for (; true; i++) {
		if (i >= nrows) {
			struct resmon_jrpc_dump_row *new_rows;
			size_t new_nrows = (nrows ?: 1) * 2;

			new_rows = reallocarray(rows, new_nrows, sizeof(*rows));
			if (new_rows == NULL) {
				err = -ENOMEM;
				goto free_rows;
			}

			rows = new_rows;
			nrows = new_nrows;
		}

		err = resmon_c_dump_table_row_jrpc(&table, &cli, &peer,
						   &rows[i]);
		if (err > 0)
			break;
		if (err < 0)
			goto close_cli;
	}

	err = resmon_c_get_table(name, &table_post);
	if (err != 0)
		fprintf(stderr, "The table named `%s' seems to have disappeared.\n",
			name);
	else if (table.seqnn != table_post.seqnn)
		fprintf(stderr, "Table changed during the iteration.\n");
	else if (table.nrows != i)
		/* This can happen if there are concurrent dumpers. */
		fprintf(stderr, "Inconsistent dump: expected %d rows, dumped %d\n",
			table.nrows, i);

	if (env.show_json) {
		puts("]");
		goto close_cli;
	}

	err = resmon_c_dump_table_show(rows, i);
	if (err != 0)
		goto close_cli;

close_cli:
	resmon_sock_close_c(&cli);
free_rows:
	while (i-- > 0) {
		json_object_put(rows[i].key);
		json_object_put(rows[i].value);
	}
	free(rows);
free_table_name:
	free(table.name);
	return err;
}

static void resmon_c_dump_help(void)
{
	fprintf(stderr,
		"Usage: resmon dump table TAB\n"
		"       resmon dump list tables\n");
}

int resmon_c_dump(int argc, char **argv)
{
	const char *dump_table = NULL;
	bool list_tables = false;

	while (argc > 0) {
		if (strcmp(*argv, "list") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "tables") != 0)
				goto incomplete_command;
			if (list_tables || dump_table != NULL)
				goto incomplete_command;
			list_tables = true;
			NEXT_ARG_FWD();
		} else if (strcmp(*argv, "table") == 0) {
			NEXT_ARG();
			if (list_tables || dump_table != NULL)
				goto incomplete_command;
			dump_table = *argv;
			NEXT_ARG_FWD();
		} else if (strcmp(*argv, "help") == 0) {
			resmon_c_dump_help();
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

	if (list_tables)
		return resmon_c_get_tables_jrpc();
	if (dump_table != NULL)
		return resmon_c_dump_table(dump_table);
	return 0;
}
