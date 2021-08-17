// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
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

static void resmon_d_handle_method(struct resmon_back *back,
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
	}

	__resmon_d_respond(peer,
			   resmon_jrpc_new_error_method_nf(id, method));
}

static int resmon_d_ctl_activity(struct resmon_back *back,
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

	resmon_d_handle_method(back, &peer, method, params, id);

put_req_obj:
	json_object_put(request_obj);
free_req:
	free(request);
	return 0;
}

static int resmon_d_loop_sock(struct resmon_back *back, struct resmon_sock *ctl)
{
	int err = 0;
	enum {
		pollfd_ctl,
	};
	struct pollfd pollfds[] = {
		[pollfd_ctl] = {
			.fd = ctl->fd,
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
					err = resmon_d_ctl_activity(back, ctl);
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

static int resmon_d_loop(struct resmon_back *back)
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

	err = resmon_d_loop_sock(back, &ctl);

	resmon_sock_close_d(&ctl);
	return err;
}

static int resmon_d_do_start(const struct resmon_back_cls *back_cls)
{
	struct resmon_back *back;
	int err = 0;

	back = resmon_back_init(back_cls);
	if (back == NULL)
		return -1;

	openlog("resmon", LOG_PID | LOG_CONS, LOG_USER);

	err = resmon_d_loop(back);

	closelog();
	resmon_back_fini(back);
	return err;
}

static void resmon_d_start_help(void)
{
	fprintf(stderr,
		"Usage: resmon start [mode mock]\n"
		"\n"
	);
}

int resmon_d_start(int argc, char **argv)
{
	const struct resmon_back_cls *back_cls;
	enum {
		mode_mock
	} mode = mode_mock;

	while (argc > 0) {
		if (strcmp(*argv, "mode") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "mock") == 0) {
				mode = mode_mock;
			} else {
				fprintf(stderr, "Unrecognized mode: %s\n", *argv);
				return -1;
			}
			NEXT_ARG_FWD();
			break;
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
	case mode_mock:
		back_cls = &resmon_back_cls_mock;
		break;
	}

	return resmon_d_do_start(back_cls);
}
