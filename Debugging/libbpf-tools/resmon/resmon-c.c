// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>

#include "resmon.h"

static bool resmon_c_validate_id(struct json_object *id_obj, int expect_id)
{
	int64_t id;

	id = json_object_get_int64(id_obj);
	return id == expect_id;
}

static void resmon_c_handle_response_error(struct json_object *error_obj)
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

static bool resmon_c_handle_response(struct json_object *j, int expect_id,
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
		resmon_c_handle_response_error(result);
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

static struct json_object *resmon_c_send_request(struct json_object *request)
{
	struct json_object *response_obj = NULL;
	struct resmon_sock peer;
	struct resmon_sock cli;
	char *response;
	int err;

	err = resmon_sock_open_c(&cli, &peer, env.sockdir);
	if (err < 0) {
		fprintf(stderr, "Failed to open a socket: %m\n");
		return NULL;
	}

	err = resmon_jrpc_send(&peer, request);
	if (err < 0) {
		fprintf(stderr, "Failed to send the RPC message: %m\n");
		goto close_fd;
	}

	err = resmon_sock_recv(&cli, &peer, &response);
	if (err < 0) {
		fprintf(stderr, "Failed to receive an RPC response\n");
		goto close_fd;
	}

	response_obj = json_tokener_parse(response);
	if (response_obj == NULL) {
		fprintf(stderr, "Failed to parse RPC response as JSON.\n");
		goto free_response;
	}

free_response:
	free(response);
close_fd:
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

	if (!resmon_c_handle_response(response, id, json_type_int, &result)) {
		err = -1;
		goto put_response;
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

	if (!resmon_c_handle_response(response, id, json_type_null, &result)) {
		err = -1;
		goto put_response;
	}

	if (env.verbosity > 0)
		fprintf(stderr, "resmond will stop\n");
	err = 0;

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
