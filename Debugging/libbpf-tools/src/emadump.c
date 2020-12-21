// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <pcap/dlt.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include "emadump.h"
#include "emadump.skel.h"
#include "trace_helpers.h"

static struct env {
	bool errors;
	uint64_t thresh_us;
	const char *dumpfile;
	bool verbose;
	pcap_t *pcap_handle;
	pcap_dumper_t *pcap_dumper;
	struct timeval boot_tv; /* Boot time relative to the Epoch. */
} env = {
	.dumpfile = "/dev/stdout",
};

static volatile bool exiting;

const char *argp_program_version = "emadump 0.0";
const char *argp_program_bug_address = "<mlxsw@nvidia.com>";
const char argp_program_doc[] =
"Dump EMADs to a PCAP file.\n"
"\n"
"USAGE: emadump [--help] [-e] [-l] [-f] [-v]\n"
"\n"
"EXAMPLES:\n"
"    emadump                # dump all EMADs to stdout\n"
"    emadump -e             # only dump EMADs (request & response) with errors\n"
"    emadump -l 1000        # only dump EMADs that took longer than 1000 usecs\n"
"    emadump -f emads.pcap  # dump EMADs to emads.pcap instead of stdout\n";

static const struct argp_option opts[] = {
	{ "errors", 'e', NULL, 0, "Only dump EMADs with errors" },
	{ "latency", 'l', "LAT", 0,
	  "Only dump EMADs that took longer than specified threshold in microseconds" },
	{ "file", 'f', "FILE", 0, "Dump EMADs to this file" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'e':
		env.errors = true;
		break;
	case 'l':
		errno = 0;
		env.thresh_us = strtoull(arg, NULL, 0);
		if (errno) {
			fprintf(stderr, "Invaild threshold specified\n");
			argp_usage(state);
		}
		break;
	case 'f':
		env.dumpfile = arg;
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int emadump_pcap_init(void)
{
	struct timespec tp_real, tp_mono;
	int err;

	env.pcap_handle = pcap_open_dead(DLT_EN10MB, EMAD_MAX_LEN);
	if (!env.pcap_handle) {
		perror("pcap_open_dead");
		return -1;
	}

	env.pcap_dumper = pcap_dump_open(env.pcap_handle, env.dumpfile);
	if (!env.pcap_dumper) {
		pcap_perror(env.pcap_handle, "pcap_dump_open");
		goto err_pcap_close;
	}

	/* Each event contains a timestamp which is recorded as number of
	 * microseconds since boot (CLOCK_MONOTONIC), but in the packet header
	 * we need to record a timestamp which is relative to the Epoch. We
	 * therefore need to calculate the boot time relative to the Epoch.
	 */
	err = clock_gettime(CLOCK_REALTIME, &tp_real);
	if (err)
		goto err_pcap_dump_close;

	err = clock_gettime(CLOCK_MONOTONIC, &tp_mono);
	if (err)
		goto err_pcap_dump_close;

	env.boot_tv.tv_sec = tp_real.tv_sec - tp_mono.tv_sec;
	env.boot_tv.tv_usec = 0;

	return 0;

err_pcap_dump_close:
	pcap_dump_close(env.pcap_dumper);
err_pcap_close:
	pcap_close(env.pcap_handle);
	return -1;
}

static void emadump_pcap_fini(void)
{
	pcap_dump_close(env.pcap_dumper);
	pcap_close(env.pcap_handle);
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct emad_event *e = data;
	struct pcap_pkthdr hdr;

	hdr.caplen = e->len;
	hdr.len = e->len;
	hdr.ts.tv_sec = env.boot_tv.tv_sec + (e->ts / 1000000);
	hdr.ts.tv_usec = env.boot_tv.tv_usec + (e->ts % 1000000);

	pcap_dump((unsigned char *) env.pcap_dumper, &hdr,
		  (const unsigned char *) e->buf);
	/* In case packets are written to stdout, make sure each packet is
	 * immediately written and not buffered.
	 */
	fflush(NULL);

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct ring_buffer *rb = NULL;
	struct emadump_bpf *obj;
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

	obj = emadump_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open BPF object\n");
		return 1;
	}

	/* Initialize global data (filtering options). */
	obj->rodata->targ_errors = env.errors;
	obj->rodata->targ_thresh_us = env.thresh_us;

	err = emadump_bpf__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = emadump_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Set up ring buffer polling. */
	rb = ring_buffer__new(bpf_map__fd(obj->maps.rb), handle_event, NULL,
			      NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	err = emadump_pcap_init();
	if (err) {
		fprintf(stderr, "Failed to initialize PCAP\n");
		goto rb_free;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* Timeout, ms */);
		/* Ctrl-C will cause -EINTR. */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

	emadump_pcap_fini();
rb_free:
	ring_buffer__free(rb);
cleanup:
	emadump_bpf__destroy(obj);

	return err != 0;
}
