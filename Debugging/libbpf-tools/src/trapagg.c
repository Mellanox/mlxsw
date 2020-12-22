// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <linux/if_ether.h>
#include "trapagg.h"
#include "trapagg.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

static struct env {
	bool drop;
	bool exception;
	bool control;
	bool all;
	bool pin;
	bool unpin;
	bool stats;
	bool timestamp;
	bool verbose;
	time_t interval;
	int times;
} env = {
	.all = true,
	.interval = 99999999,
	.times = 99999999,
};

static const char *link_pin_path = "/sys/fs/bpf/pinned_trapagg_link";
static const char *map_pin_path = "/sys/fs/bpf/pinned_trapagg_map";
static volatile bool exiting;

const char *argp_program_version = "trapagg 0.0";
const char *argp_program_bug_address = "<mlxsw@nvidia.com>";
const char argp_program_doc[] =
"Dump aggregated per-{trap, flow} statistics.\n"
"\n"
"USAGE: trapagg [--help] [-d] [-e] [-c] [-p] [-u] [-s] [-T] [-v] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    trapagg                 # dump aggregated per-{trap, flow} statistics\n"
"    trapagg -d              # dump aggregated statistics of drop traps only\n"
"    trapagg -p              # pin BPF objects and exit\n"
"    trapagg -u              # unpin BPF objects and exit\n"
"    trapagg -s              # dump statistics from pinned objects and exit\n"
"    trapagg 1 10            # print 1 second summaries, 10 times\n"
"    trapagg -T 1            # 1s summaries with timestamps\n";

static const struct argp_option opts[] = {
	{ "drop", 'd', NULL, 0, "Trace drop traps only" },
	{ "exception", 'e', NULL, 0, "Trace exception traps only" },
	{ "control", 'c', NULL, 0, "Trace control traps only" },
	{ "pin", 'p', NULL, 0, "Pin BPF objects and exit" },
	{ "unpin", 'u', NULL, 0, "Unpin BPF objects and exit" },
	{ "stats", 's', NULL, 0, "Dump aggregated statistics from pinned objects and exit" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'd':
		env.drop = true;
		env.all = false;
		break;
	case 'e':
		env.exception = true;
		env.all = false;
		break;
	case 'c':
		env.control = true;
		env.all = false;
		break;
	case 'p':
		env.pin = true;
		break;
	case 'u':
		env.unpin = true;
		break;
	case 's':
		env.stats = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			env.interval = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			env.times = strtol(arg, NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid times\n");
				argp_usage(state);
			}
		} else {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format,
		    va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int pin_objects(struct trapagg_bpf *obj)
{
	int err;

	err = bpf_link__pin(obj->links.devlink_trap_report, link_pin_path);
	if (err) {
		fprintf(stderr, "Failed to pin BPF link: %d\n", err);
		return err;
	}

	err = bpf_map__pin(obj->maps.trap_flows, map_pin_path);
	if (err) {
		fprintf(stderr, "Failed to pin BPF map: %d\n", err);
		goto err_link_unpin;
	}

	return 0;

err_link_unpin:
	bpf_link__unpin(obj->links.devlink_trap_report);
	return err;
}

static void unpin_objects()
{
	struct bpf_link *link;
	int err;

	if (unlink(map_pin_path)) {
		fprintf(stderr, "Failed to unpin BPF map: %s\n",
			strerror(errno));
		return;
	}

	link = bpf_link__open(link_pin_path);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "Failed to open pinned BPF link: %d\n", err);
		return;
	}
	bpf_link__unpin(link);
	bpf_link__destroy(link);
}

static void print_trap_v4(const struct trap_flow_key *tfk, __u64 count)
{
	char s[INET_ADDRSTRLEN];
	char d[INET_ADDRSTRLEN];
	struct in_addr src;
	struct in_addr dst;

	src.s_addr = tfk->saddrv4;
	dst.s_addr = tfk->daddrv4;

	printf("%-40s %-25s %-25s %-10d %-10d %-10u %-10u %-10llu\n",
	       tfk->trap_name, inet_ntop(AF_INET, &src, s, sizeof(s)),
	       inet_ntop(AF_INET, &dst, d, sizeof(d)), tfk->sport, tfk->dport,
	       tfk->ip_proto, tfk->is_encap, count);
}

static void print_trap_v6(const struct trap_flow_key *tfk, __u64 count)
{
	char s[INET6_ADDRSTRLEN];
	char d[INET6_ADDRSTRLEN];
	struct in6_addr src;
	struct in6_addr dst;

	memcpy(src.s6_addr, tfk->saddrv6, sizeof(src.s6_addr));
	memcpy(dst.s6_addr, tfk->daddrv6, sizeof(src.s6_addr));

	printf("%-40s %-25s %-25s %-10d %-10d %-10u %-10u %-10llu\n",
	       tfk->trap_name, inet_ntop(AF_INET6, &src, s, sizeof(s)),
	       inet_ntop(AF_INET6, &dst, d, sizeof(d)), tfk->sport, tfk->dport,
	       tfk->ip_proto, tfk->is_encap, count);
}

static void print_trap_non_ip(const struct trap_flow_key *tfk, __u64 count)
{
	printf("%-40s %-25s %-25s %-10d %-10d %-10u %-10u %-10llu\n",
	       tfk->trap_name, "", "", 0, 0, 0, 0, count);
}

static int print_traps(int map_fd)
{
	static struct trap_flow_key tfks[MAX_ENTRIES];
	__u32 key_size = sizeof(struct trap_flow_key);
	static struct trap_flow_key zero;
	__u32 value_size = sizeof(__u64);
	static __u64 counts[MAX_ENTRIES];
	static const char *header_fmt;
	__u32 i, n = MAX_ENTRIES;

	header_fmt = "\n%-40s %-25s %-25s %-10s %-10s %-10s %-10s\n";
	printf(header_fmt, "TRAP", "SIP", "DIP", "SPORT", "DPORT", "IP_PROTO",
	       "IS_ENCAP");

	if (dump_hash(map_fd, tfks, key_size, counts, value_size, &n, &zero)) {
		fprintf(stderr, "dump_hash: %s", strerror(errno));
		return -1;
	}

	for (i = 0; i < n; i++) {
		switch (tfks[i].addr_proto) {
		case ETH_P_IP:
			print_trap_v4(&tfks[i], counts[i]);
			break;
		case ETH_P_IPV6:
			print_trap_v6(&tfks[i], counts[i]);
			break;
		default:
			print_trap_non_ip(&tfks[i], counts[i]);
			break;
		}
	}

	return 0;
}

static int print_stats()
{
	int map_fd;

	map_fd = bpf_obj_get(map_pin_path);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get pinned BPF map: %d\n", map_fd);
		return map_fd;
	}

	return print_traps(map_fd);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct trapagg_bpf *obj;
	struct tm *tm;
	char ts[32];
	time_t t;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "Failed to increase rlimit: %d\n", err);
		return 1;
	}

	if (env.stats)
		return print_stats();

	if (env.unpin) {
		unpin_objects();
		return 0;
	}

	obj = trapagg_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open BPF object\n");
		return 1;
	}

	/* Initialize global data (filtering options). */
	obj->rodata->targ_drop = env.drop;
	obj->rodata->targ_exception = env.exception;
	obj->rodata->targ_control = env.control;
	obj->rodata->targ_all = env.all;

	err = trapagg_bpf__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = trapagg_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}

	if (env.pin) {
		err = pin_objects(obj);
		if (err)
			fprintf(stderr, "Failed to pin BPF objects: %d\n", err);
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Tracing packet traps... Hit Ctrl-C to end.\n");

	/* main: poll */
	while (1) {
		sleep(env.interval);
		printf("\n");

		if (env.timestamp) {
			time(&t);
			tm = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("%-8s\n", ts);
		}

		err = print_traps(bpf_map__fd(obj->maps.trap_flows));
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	trapagg_bpf__destroy(obj);

	return err != 0;
}
