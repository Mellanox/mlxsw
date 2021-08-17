// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <linux/devlink.h>
#include <linux/socket.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/socket.h>

#include "resmon.h"
#include "trace_helpers.h"

struct cb_args {
	char **devname;
	char **busname;
	int err;
};

enum devlink_multicast_groups {
	DEVLINK_MCGRP_CONFIG,
};

static const struct nla_policy devlink_nl_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_BUS_NAME] = { .type = NLA_NUL_STRING },
	[DEVLINK_ATTR_DEV_NAME] = { .type = NLA_NUL_STRING },
	[DEVLINK_ATTR_RESOURCE_SIZE] = { .type = NLA_U64},
};

static int resmon_dl_dev_info_parser(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct cb_args *args = (struct cb_args *) arg;
	struct nlattr *attrs[DEVLINK_ATTR_MAX + 1];
	char *attr_driver_name;
	char *attr_bus;
	char *attr_dev;
	int err;

	err = nla_parse(attrs, DEVLINK_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0)
		goto nl_skip;

	attr_driver_name = nla_get_string(attrs[DEVLINK_ATTR_INFO_DRIVER_NAME]);
	attr_bus = nla_get_string(attrs[DEVLINK_ATTR_BUS_NAME]);
	attr_dev = nla_get_string(attrs[DEVLINK_ATTR_DEV_NAME]);

	if (attr_driver_name == NULL || attr_bus == NULL || attr_dev == NULL)
		goto nl_skip;

	if (strstr(attr_driver_name, "mlxsw_spectrum") == NULL)
		goto nl_skip;

	*args->busname = strdup(attr_bus);
	if (args->busname == NULL)
		goto nl_skip;

	*args->devname = strdup(attr_dev);
	if (args->devname == NULL)
		goto free_busname;

	args->err = 0;
	return 0;

free_busname:
	free(*args->busname);
nl_skip:
	return NL_SKIP;
}

struct resmon_dl {
	struct nl_sock *sk;
	int family;
};

struct resmon_dl *resmon_dl_create(void)
{
	struct resmon_dl *dl;
	int err;

	dl = malloc(sizeof(*dl));
	if (dl == NULL)
		return NULL;

	dl->sk = nl_socket_alloc();
	if (!dl->sk) {
		fprintf(stderr, "Failed to allocate data socket\n");
		goto free_dl;
	}

	err = genl_connect(dl->sk);
	if (err) {
		fprintf(stderr, "Failed to connect socket\n");
		goto free_sock;
	}

	err = nl_socket_set_nonblocking(dl->sk);
	if (err) {
		fprintf(stderr, "Failed to set socket nonblocking\n");
		goto free_sock;
	}

	dl->family = genl_ctrl_resolve(dl->sk, "devlink");
	if (dl->family < 0) {
		fprintf(stderr, "Failed to resolve ID of \"devlink\" family\n");
		goto free_sock;
	}

	return dl;

free_sock:
	nl_socket_free(dl->sk);
free_dl:
	free(dl);
	return NULL;
}

void resmon_dl_destroy(struct resmon_dl *dl)
{
	nl_socket_free(dl->sk);
	free(dl);
}

static int resmon_dl_netlink_get_dev(struct nl_sock *sk, int family,
				     char **busname, char **devname,
				     char **error)
{
	struct cb_args args;
	struct nl_cb *cb;
	int err;

	err = genl_send_simple(sk, family, DEVLINK_CMD_INFO_GET, 0, NLM_F_DUMP);
	if (err < 0) {
		resmon_fmterr(error, "Failed to send devlink get command");
		return err;
	}

	args.devname = devname;
	args.busname = busname;
	args.err = -1;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (cb == NULL)
		return -NLE_NOMEM;

	err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, resmon_dl_dev_info_parser, &args);
	if (err < 0) {
		resmon_fmterr(error, "Failed to set devlink info parser");
		goto err_out;
	}

	err = nl_recvmsgs(sk, cb);
	if (err < 0 || args.err < 0) {
		err = -1;
		resmon_fmterr(error, "Failed to receive devlink get messages from netlink");
		goto err_out;
	}
	err = 0;

err_out:
	nl_cb_put(cb);
	return err;
}

static int resmon_dl_netlink_resources_get(struct nlattr **attrs,
					   struct nlattr *nla_resources,
					   uint64_t *size)
{
	struct nlattr *nla_resource[DEVLINK_ATTR_MAX + 1];
	struct nlattr *attr_name, *attr_size;
	struct nlattr *resource;
	int rem, err;
	char *name;

	err = nla_parse_nested(nla_resource, DEVLINK_ATTR_MAX, nla_resources,
			       devlink_nl_policy);
	if (err < 0)
		return err;

	attr_name = nla_resource[DEVLINK_ATTR_RESOURCE_NAME];
	attr_size = nla_resource[DEVLINK_ATTR_RESOURCE_SIZE];

	if (attr_name && attr_size) {
		name = nla_get_string(attr_name);
		if (strcmp(name, "kvd") == 0) {
			*size = nla_get_u64(attr_size);
			return 0;
		}
	}

	nla_for_each_nested(resource, nla_resources, rem) {
		if (nla_resource[DEVLINK_ATTR_RESOURCE] ||
		    nla_resource[DEVLINK_ATTR_RESOURCE_LIST])
			resmon_dl_netlink_resources_get(nla_resource, resource,
							size);
	}
	if (!(*size))
		return -1;

	return 0;
}

static int resmon_dl_netlink_get_kvd_size(struct nl_sock *sk, int family,
					  char *busname, char *devname,
					  uint64_t *size, char **error)
{
	struct nlattr *attrs[DEVLINK_ATTR_MAX + 1];
	struct sockaddr_nl nla;
	unsigned char *buf;
	struct nl_msg *msg;
	int err, len;

	msg = nlmsg_alloc();
	if (!msg) {
		resmon_fmterr(error, "Failed to allocate netlink message");
		return -1;
	}

	if (!genlmsg_put(msg, 0, NL_AUTO_SEQ, family, 0,
	    NLM_F_REQUEST, DEVLINK_CMD_RESOURCE_DUMP, 0))
		goto genlmsg_put_failure;

	if (nla_put_string(msg, DEVLINK_ATTR_BUS_NAME, busname))
		goto nla_put_failure;

	if (nla_put_string(msg, DEVLINK_ATTR_DEV_NAME, devname))
		goto nla_put_failure;

	err = nl_send_sync(sk, msg);
	if (err < 0) {
		resmon_fmterr(error, "Failed to send devlink resource get command");
		return err;
	}

	len = nl_recv(sk, &nla, &buf, NULL);
	if (len < 0) {
		resmon_fmterr(error, "Failed to receive message");
		return -1;
	}

	err = genlmsg_parse((void *) buf, 0, attrs, DEVLINK_ATTR_MAX,
			    devlink_nl_policy);
	if (err < 0)
		return err;

	err = resmon_dl_netlink_resources_get(attrs,
					      attrs[DEVLINK_ATTR_RESOURCE_LIST],
					      size);
	if (err < 0)
		return err;

	free(buf);
	return 0;

nla_put_failure:
genlmsg_put_failure:
	nlmsg_free(msg);
	return -EMSGSIZE;
}

int resmon_dl_get_kvd_size(struct resmon_dl *dl, uint64_t *size, char **error)
{
	char *busname, *devname = NULL;
	int err;

	nl_socket_disable_auto_ack(dl->sk);

	err = resmon_dl_netlink_get_dev(dl->sk, dl->family, &busname, &devname,
					error);
	if (err < 0)
		return -1;

	err = resmon_dl_netlink_get_kvd_size(dl->sk, dl->family, busname,
					     devname, size, error);
	if (err < 0)
		resmon_fmterr(error, "Failed to get devlink resource size from netlink");

	free(busname);
	free(devname);
	return err;
}
