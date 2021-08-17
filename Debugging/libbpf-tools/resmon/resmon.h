/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/un.h>
#include <json-c/json_object.h>

#include "mlxsw.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define NEXT_ARG() do { argv++; if (--argc <= 0) goto incomplete_command; } while (0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define NEXT_ARG_FWD() do { argv++; argc--; } while (0)
#define PREV_ARG() do { argv--; argc++; } while (0)

#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })

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
	resmon_jrpc_e_capacity = -1,
	resmon_jrpc_e_reg_process_emad = -2,

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
int resmon_jrpc_dissect_params_emad(struct json_object *obj,
				    const char **payload,
				    size_t *payload_len,
				    char **error);

struct resmon_jrpc_gauge {
	const char *descr;
	int64_t value;
	uint64_t capacity;
};
int resmon_jrpc_dissect_stats(struct json_object *obj,
			      struct resmon_jrpc_gauge **gauges,
			      size_t *num_gauges,
			      char **error);

int resmon_jrpc_send(struct resmon_sock *sock, struct json_object *obj);

/* resmon-c.c */

int resmon_c_ping(int argc, char **argv);
int resmon_c_stop(int argc, char **argv);
int resmon_c_emad(int argc, char **argv);
int resmon_c_stats(int argc, char **argv);

/* resmon-stat.c */

#define RESMON_RSRC_EXPAND_AS_ENUM(NAME, DESCRIPTION) \
	RESMON_RSRC_ ## NAME,
#define RESMON_RSRC_EXPAND_AS_PLUS1(...) + 1

#define RESMON_RESOURCES(X) \
	X(LPM_IPV4, "IPv4 LPM") \
	X(LPM_IPV6, "IPv6 LPM")

enum resmon_resource {
	RESMON_RESOURCES(RESMON_RSRC_EXPAND_AS_ENUM)
};

enum {
	resmon_resource_count =
		0 RESMON_RESOURCES(RESMON_RSRC_EXPAND_AS_PLUS1)
};

struct resmon_stat;

struct resmon_stat_gauges {
	int64_t values[resmon_resource_count];
	int64_t total;
};

struct resmon_stat_dip {
	uint8_t dip[16];
};

struct resmon_stat_kvd_alloc {
	unsigned int slots;
	enum resmon_resource resource;
};

struct resmon_stat *resmon_stat_create(void);
void resmon_stat_destroy(struct resmon_stat *stat);
struct resmon_stat_gauges resmon_stat_gauges(struct resmon_stat *stat);

int resmon_stat_ralue_update(struct resmon_stat *stat,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip,
			     struct resmon_stat_kvd_alloc kvda);
int resmon_stat_ralue_delete(struct resmon_stat *stat,
			     enum mlxsw_reg_ralxx_protocol protocol,
			     uint8_t prefix_len,
			     uint16_t virtual_router,
			     struct resmon_stat_dip dip);


/* resmon-dl.c */

struct resmon_dl;

struct resmon_dl *resmon_dl_create(void);
void resmon_dl_destroy(struct resmon_dl *dl);
int resmon_dl_get_kvd_size(struct resmon_dl *dl, uint64_t *size, char **error);

/* resmon-reg.c */

int resmon_reg_process_emad(struct resmon_stat *stat,
			    const uint8_t *buf, size_t len, char **error);

/* resmon-back.c */

struct resmon_back;
struct resmon_back_cls;

extern const struct resmon_back_cls resmon_back_cls_hw;
extern const struct resmon_back_cls resmon_back_cls_mock;

struct resmon_back *resmon_back_init(const struct resmon_back_cls *cls);
void resmon_back_fini(struct resmon_back *back);

int resmon_back_get_capacity(struct resmon_back *back, uint64_t *capacity,
			     char **error);
bool resmon_back_handle_method(struct resmon_back *back,
			       struct resmon_stat *stat,
			       const char *method,
			       struct resmon_sock *peer,
			       struct json_object *params_obj,
			       struct json_object *id);
int resmon_back_pollfd(struct resmon_back *back);
int resmon_back_activity(struct resmon_back *back, struct resmon_stat *stat);

/* resmon-d.c */

int resmon_d_start(int argc, char **argv);

void resmon_d_respond_error(struct resmon_sock *ctl,
			    struct json_object *id, int code,
			    const char *message, const char *data);
void resmon_d_respond_invalid_params(struct resmon_sock *ctl,
				     struct json_object *id,
				     const char *data);
void resmon_d_respond_memerr(struct resmon_sock *peer, struct json_object *id);
