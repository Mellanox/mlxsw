// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/types.h>

#include "resmon.h"

static int resmon_sock_sockaddr(const char *sockdir, const char *sockname,
				struct sockaddr_un *sa)
{
	const char *maybe_slash = "/";
	int len;

	if (sockdir[strlen(sockdir) - 1] == '/')
		maybe_slash++;

	sa->sun_family = AF_LOCAL;
	len = snprintf(sa->sun_path, sizeof(sa->sun_path), "%s%s%s",
		       sockdir, maybe_slash, sockname);
	if (len < 0)
		return len;
	if (len >= sizeof(sa->sun_path))
		return -ENOBUFS;

	return 0;
}

static int resmon_ctl_sockaddr(const char *sockdir, struct sockaddr_un *ctl_sa)
{
	return resmon_sock_sockaddr(sockdir, "resmon.ctl", ctl_sa);
}

static int resmon_cli_sockaddr(const char *sockdir, struct sockaddr_un *cli_sa)
{
	char *sockname;
	int rc;

	rc = asprintf(&sockname, "resmon.cli.%d", getpid());
	if (rc < 0)
		return rc;

	rc = resmon_sock_sockaddr(sockdir, sockname, cli_sa);
	free(sockname);
	return rc;
}

static int resmon_sock_open(struct sockaddr_un sa, struct resmon_sock *sock)
{
	int fd;
	int rc;

	*sock = (struct resmon_sock) { .fd = -1 };

	fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Failed to create control socket: %m\n");
		return -1;
	}

	unlink(sa.sun_path);

	rc = bind(fd, (struct sockaddr *) &sa, sizeof(sa));
	if (rc < 0) {
		fprintf(stderr, "Failed to bind control socket `%s': %m\n",
			sa.sun_path);
		goto close_fd;
	}

	*sock = (struct resmon_sock) {
		.fd = fd,
		.sa = sa,
		.len = sizeof(sa),
	};
	return 0;

close_fd:
	close(fd);
	return rc;
}

static void resmon_sock_close(struct resmon_sock *sock)
{
	close(sock->fd);
	unlink(sock->sa.sun_path);
}

int resmon_sock_open_d(struct resmon_sock *ctl, const char *sockdir)
{
	struct sockaddr_un sa;
	int rc;

	rc = resmon_ctl_sockaddr(sockdir, &sa);
	if (rc != 0)
		return rc;

	return resmon_sock_open(sa, ctl);
}

void resmon_sock_close_d(struct resmon_sock *ctl)
{
	resmon_sock_close(ctl);
}

int resmon_sock_open_c(struct resmon_sock *cli,
		       struct resmon_sock *peer,
		       const char *sockdir)
{
	struct sockaddr_un ctl_sa;
	struct sockaddr_un cli_sa;
	int rc;

	rc = resmon_ctl_sockaddr(sockdir, &ctl_sa);
	if (rc != 0)
		return rc;

	rc = resmon_cli_sockaddr(sockdir, &cli_sa);
	if (rc != 0)
		return rc;

	rc = resmon_sock_open(cli_sa, cli);
	if (rc != 0)
		return rc;

	*peer = (struct resmon_sock) {
		.fd = cli->fd,
		.sa = ctl_sa,
		.len = sizeof(peer->sa),
	};
	rc = connect(cli->fd, (struct sockaddr *) &peer->sa, peer->len);
	if (rc != 0) {
		fprintf(stderr, "Failed to connect to %s: %m\n",
			peer->sa.sun_path);
		goto close_cli;
	}

	return 0;

close_cli:
	resmon_sock_close_c(cli);
	return -1;

}

void resmon_sock_close_c(struct resmon_sock *cli)
{
	resmon_sock_close(cli);
}

int resmon_sock_recv(struct resmon_sock *sock, struct resmon_sock *peer,
		     char **bufp)
{
	ssize_t msgsz;
	char *buf;
	ssize_t n;
	int rc;

	*bufp = NULL;
	*peer = (struct resmon_sock) {
		.fd = sock->fd,
		.len = sizeof(peer->sa),
	};
	msgsz = recvfrom(sock->fd, NULL, 0, MSG_PEEK | MSG_TRUNC,
			 (struct sockaddr *) &peer->sa, &peer->len);
	if (msgsz < 0) {
		fprintf(stderr, "Failed to receive data on control socket: %m\n");
		return -1;
	}

	buf = calloc(1, msgsz + 1);
	if (buf == NULL) {
		fprintf(stderr, "Failed to allocate control message buffer: %m\n");
		return -1;
	}

	n = recv(sock->fd, buf, msgsz, 0);
	if (n < 0) {
		fprintf(stderr, "Failed to receive data on control socket: %m\n");
		rc = -1;
		goto out;
	}
	buf[n] = '\0';

	*bufp = buf;
	buf = NULL;
	rc = 0;

out:
	free(buf);
	return rc;
}
