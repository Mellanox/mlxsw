// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Based on biolatency(8) from BCC by Brendan Gregg and Wenbo Zhang.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include "emadlatency.h"
#include "emadlatency.skel.h"
#include "trace_helpers.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static struct env {
	bool milliseconds;
	bool timestamp;
	uint16_t reg_id;
	bool queries;
	bool writes;
	bool average;
	bool verbose;
	time_t interval;
	int times;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char *argp_program_version = "emadlatency 0.0";
const char *argp_program_bug_address = "<mlxsw@nvidia.com>";
const char argp_program_doc[] =
"Summarize EMAD latency as a histogram.\n"
"\n"
"USAGE: emadlatency [--help] [-T] [-m] [-r] [-q] [-w] [-a] [-v] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    emadlatency             # summarize EMAD latency as a histogram\n"
"    emadlatency 1 10        # print 1 second summaries, 10 times\n"
"    emadlatency -mT 1       # 1s summaries, milliseconds, and timestamps\n"
"    emadlatency -r SFN      # measure latency of SFN EMADs only\n"
"    emadlatency -q          # only show latency of EMAD queries\n"
"    emadlatency -w          # only show latency of EMAD writes\n"
"    emadlatency -a          # also show average latency\n";

static const struct argp_option opts[] = {
	{ "milliseconds", 'm', NULL, 0, "Millisecond histogram" },
	{ "timestamp", 'T', NULL, 0, "Include timestamp on output" },
	{ "register", 'r', "REG", 0, "Trace this register only" },
	{ "query", 'q', NULL, 0, "Show latency of EMAD queries only" },
	{ "write", 'w', NULL, 0, "Show latency of EMAD writes only" },
	{ "average", 'a', NULL, 0, "Also show average latency" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static const struct { uint16_t id; const char *name; } emad_arr[] = {
	{ 0x2000, "SGCR" },
	{ 0x2002, "SPAD" },
	{ 0x2007, "SMID" },
	{ 0x2008, "SSPR" },
	{ 0x2009, "SFDAT" },
	{ 0x200A, "SFD" },
	{ 0x200B, "SFN" },
	{ 0x200D, "SPMS" },
	{ 0x200E, "SPVID" },
	{ 0x200F, "SPVM" },
	{ 0x2010, "SPAFT" },
	{ 0x2011, "SFGC" },
	{ 0x2012, "SFTR" },
	{ 0x2013, "SFDF" },
	{ 0x2014, "SLDR" },
	{ 0x2015, "SLCR" },
	{ 0x2016, "SLCOR" },
	{ 0x2018, "SPMLR" },
	{ 0x201C, "SVFA" },
	{ 0x201D, "SPVTR" },
	{ 0x201E, "SVPE" },
	{ 0x201F, "SFMR" },
	{ 0x2020, "SPVMLR" },
	{ 0x202A, "SPEVET" },
	{ 0x2802, "CWTP" },
	{ 0x2803, "CWTPM" },
	{ 0x3001, "PGCR" },
	{ 0x3002, "PPBT" },
	{ 0x3004, "PACL" },
	{ 0x3005, "PAGT" },
	{ 0x3006, "PTAR" },
	{ 0x300C, "PPBS" },
	{ 0x300D, "PRCR" },
	{ 0x300F, "PEFA" },
	{ 0x3014, "PEMRBT" },
	{ 0x3017, "PTCE2" },
	{ 0x3021, "PERPT" },
	{ 0x3022, "PEABFE" },
	{ 0x3026, "PERAR" },
	{ 0x3027, "PTCE3" },
	{ 0x302A, "PERCR" },
	{ 0x302B, "PERERP" },
	{ 0x3804, "IEDR" },
	{ 0x4002, "QPTS" },
	{ 0x4004, "QPCR" },
	{ 0x400A, "QTCT" },
	{ 0x400D, "QEEC" },
	{ 0x400F, "QRWE" },
	{ 0x4011, "QPDSM" },
	{ 0x4007, "QPDP" },
	{ 0x4013, "QPDPM" },
	{ 0x401A, "QTCTM" },
	{ 0x401B, "QPSC" },
	{ 0x5002, "PMLP" },
	{ 0x5003, "PMTU" },
	{ 0x5004, "PTYS" },
	{ 0x5005, "PPAD" },
	{ 0x5006, "PAOS" },
	{ 0x5007, "PFCC" },
	{ 0x5008, "PPCNT" },
	{ 0x500A, "PLIB" },
	{ 0x500B, "PPTB" },
	{ 0x500C, "PBMC" },
	{ 0x500D, "PSPA" },
	{ 0x5018, "PPLR" },
	{ 0x5031, "PDDR" },
	{ 0x5067, "PMTM" },
	{ 0x7002, "HTGT" },
	{ 0x7003, "HPKT" },
	{ 0x8001, "RGCR" },
	{ 0x8002, "RITR" },
	{ 0x8004, "RTAR" },
	{ 0x8008, "RATR" },
	{ 0x8020, "RTDP" },
	{ 0x8009, "RDPM" },
	{ 0x800B, "RICNT" },
	{ 0x800F, "RRCR" },
	{ 0x8010, "RALTA" },
	{ 0x8011, "RALST" },
	{ 0x8012, "RALTB" },
	{ 0x8013, "RALUE" },
	{ 0x8014, "RAUHT" },
	{ 0x8015, "RALEU" },
	{ 0x8018, "RAUHTD" },
	{ 0x8023, "RIGR2" },
	{ 0x8025, "RECR2" },
	{ 0x8027, "RMFT2" },
	{ 0x9001, "MFCR" },
	{ 0x9002, "MFSC" },
	{ 0x9003, "MFSM" },
	{ 0x9004, "MFSL" },
	{ 0x9007, "FORE" },
	{ 0x9009, "MTCAP" },
	{ 0x900A, "MTMP" },
	{ 0x900F, "MTBR" },
	{ 0x9014, "MCIA" },
	{ 0x901A, "MPAT" },
	{ 0x901B, "MPAR" },
	{ 0x9020, "MGIR" },
	{ 0x9023, "MRSR" },
	{ 0x902B, "MLCR" },
	{ 0x9053, "MTPPS" },
	{ 0x9055, "MTUTC" },
	{ 0x9080, "MPSC" },
	{ 0x9061, "MCQI" },
	{ 0x9062, "MCC" },
	{ 0x9063, "MCDA" },
	{ 0x9081, "MGPC" },
	{ 0x9083, "MPRS" },
	{ 0x9086, "MOGCR" },
	{ 0x9089, "MPAGR" },
	{ 0x908D, "MOMTE" },
	{ 0x9090, "MTPPPC" },
	{ 0x9091, "MTPPTR" },
	{ 0x9092, "MTPTPT" },
	{ 0x90F0, "MFGD" },
	{ 0x9100, "MGPIR" },
	{ 0xA001, "TNGCR" },
	{ 0xA003, "TNUMT" },
	{ 0xA010, "TNQCR" },
	{ 0xA011, "TNQDR" },
	{ 0xA012, "TNEEM" },
	{ 0xA013, "TNDEM" },
	{ 0xA020, "TNPC" },
	{ 0xA801, "TIGCR" },
	{ 0xA812, "TIEEM" },
	{ 0xA813, "TIDEM" },
	{ 0xB001, "SBPR" },
	{ 0xB002, "SBCM" },
	{ 0xB003, "SBPM" },
	{ 0xB004, "SBMM" },
	{ 0xB005, "SBSR" },
	{ 0xB006, "SBIB" },
};

static int reg_id_find_by_name(const char *name, uint16_t *p_reg_id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(emad_arr); i++) {
		if (!strcmp(emad_arr[i].name, name)) {
			*p_reg_id = emad_arr[i].id;
			return 0;
		}
	}

	return -EINVAL;
}

static const char *name_find_by_reg_id(uint16_t reg_id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(emad_arr); i++) {
		if (emad_arr[i].id == reg_id)
			return emad_arr[i].name;
	}

	return NULL;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'm':
		env.milliseconds = true;
		break;
	case 'T':
		env.timestamp = true;
		break;
	case 'r':
		errno = 0;
		if (reg_id_find_by_name(arg, &env.reg_id)) {
			env.reg_id = strtol(arg, NULL, 0);
			if (errno || !name_find_by_reg_id(env.reg_id)) {
				fprintf(stderr, "Invaild register specified\n");
				argp_usage(state);
			}
		}
		break;
	case 'q':
		env.queries = true;
		break;
	case 'w':
		env.writes = true;
		break;
	case 'a':
		env.average = true;
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

static
int print_log2_hists(struct bpf_map *hists)
{
	const char *units = env.milliseconds ? "msecs" : "usecs";
	struct hist_key lookup_key, next_key;
	int err, fd = bpf_map__fd(hists);
	struct hist hist;

	memset(&lookup_key, 0, sizeof(lookup_key));
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		const char *reg_name;

		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "Failed to lookup hist: %d\n", err);
			return -1;
		}
		if ((env.writes && env.writes != next_key.write) ||
		    (env.queries && env.queries != !next_key.write)) {
			lookup_key = next_key;
			continue;
		}

		reg_name = name_find_by_reg_id(next_key.reg_id);
		printf("Register %s = %s (0x%x)\n",
		       next_key.write ? "write" : "query",
		       reg_name ? reg_name : "Unknown register",
		       next_key.reg_id);
		if (env.average)
			printf(" average = %llu %s, total = %llu %s, count = %llu\n",
			       hist.latency / hist.count, units, hist.latency,
			       units, hist.count);
		print_log2_hist(hist.slots, MAX_SLOTS, units);
		lookup_key = next_key;
	}

	memset(&lookup_key, 0, sizeof(lookup_key));
	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0) {
			fprintf(stderr, "Failed to cleanup hist : %d\n", err);
			return -1;
		}
		lookup_key = next_key;
	}

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct emadlatency_bpf *obj;
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

	obj = emadlatency_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open BPF object\n");
		return 1;
	}

	/* Initialize global data (filtering options). */
	obj->rodata->targ_ms = env.milliseconds;
	obj->rodata->targ_reg_id = env.reg_id;

	err = emadlatency_bpf__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = emadlatency_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	printf("Tracing EMADs... Hit Ctrl-C to end.\n");

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

		err = print_log2_hists(obj->maps.hists);
		if (err)
			break;

		if (exiting || --env.times == 0)
			break;
	}

cleanup:
	emadlatency_bpf__destroy(obj);

	return err != 0;
}
