/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/un.h>
#include <json-c/json_object.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define NEXT_ARG() do { argv++; if (--argc <= 0) goto incomplete_command; } while (0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define NEXT_ARG_FWD() do { argv++; argc--; } while (0)
#define PREV_ARG() do { argv--; argc++; } while (0)

/* resmon.c */

extern struct resmon_env {
	const char *sockdir;
	int verbosity;
} env;

int resmon_fmterr(char **strp, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* resmon-sock.c */

struct resmon_sock {
	int fd;
	struct sockaddr_un sa;
	socklen_t len;
};

int resmon_sock_open_d(struct resmon_sock *ctl, const char *sockdir);
void resmon_sock_close_d(struct resmon_sock *ctl);
int resmon_sock_open_c(struct resmon_sock *cli,
		       struct resmon_sock *peer,
		       const char *sockdir);
void resmon_sock_close_c(struct resmon_sock *cli);

int resmon_sock_recv(struct resmon_sock *sock,
		     struct resmon_sock *peer,
		     char **bufp);

/* resmon-jrpc.c */

enum resmon_jrpc_e {
	resmon_jrpc_e_inv_request = -32600,
	resmon_jrpc_e_method_nf = -32601,
	resmon_jrpc_e_inv_params = -32602,
	resmon_jrpc_e_int_error = -32603,
};

int resmon_jrpc_object_add_int(struct json_object *obj,
			       const char *key, int64_t val);
int resmon_jrpc_object_add_str(struct json_object *obj,
			       const char *key, const char *str);
int resmon_jrpc_object_add_bool(struct json_object *obj,
				const char *key, bool val);

struct json_object *resmon_jrpc_new_object(struct json_object *id);
struct json_object *resmon_jrpc_new_request(int id, const char *method);
struct json_object *resmon_jrpc_new_error(struct json_object *id,
					  enum resmon_jrpc_e code,
					  const char *message,
					  const char *data);
struct json_object *resmon_jrpc_new_error_inv_request(const char *data);
struct json_object *resmon_jrpc_new_error_method_nf(struct json_object *id,
						    const char *method);
struct json_object *resmon_jrpc_new_error_inv_params(struct json_object *id,
						     const char *data);
struct json_object *resmon_jrpc_new_error_int_error(struct json_object *id,
						    const char *data);

int resmon_jrpc_dissect_request(struct json_object *obj,
				struct json_object **id,
				const char **method,
				struct json_object **params,
				char **error);
int resmon_jrpc_dissect_response(struct json_object *obj,
				 struct json_object **id,
				 struct json_object **result,
				 bool *is_error,
				 char **error);
int resmon_jrpc_dissect_error(struct json_object *obj,
			      int64_t *code,
			      const char **message,
			      struct json_object **data,
			      char **error);
int resmon_jrpc_dissect_params_empty(struct json_object *obj,
				     char **error);

int resmon_jrpc_send(struct resmon_sock *sock, struct json_object *obj);

/* resmon-c.c */

int resmon_c_ping(int argc, char **argv);
int resmon_c_stop(int argc, char **argv);

/* resmon-back.c */

struct resmon_back;
struct resmon_back_cls;

extern const struct resmon_back_cls resmon_back_cls_mock;

struct resmon_back *resmon_back_init(const struct resmon_back_cls *cls);
void resmon_back_fini(struct resmon_back *back);

/* resmon-d.c */

int resmon_d_start(int argc, char **argv);

void resmon_d_respond_invalid_params(struct resmon_sock *ctl,
				     struct json_object *id,
				     const char *data);
void resmon_d_respond_memerr(struct resmon_sock *peer, struct json_object *id);
