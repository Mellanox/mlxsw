// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
#define _GNU_SOURCE
#include <argp.h>
#include <stdarg.h>
#include <stdio.h>

#include "resmon.h"
#include "config.h"

struct resmon_env env = {
	.verbosity = 0,
};
const char *program_version = "resmon 1.0";
const char *program_bug_address = "<mlxsw@nvidia.com>";

static int resmon_help(void)
{
	puts("Monitor resource usage in a Spectrum switch.\n"
	     "\n"
	     "Usage: resmon [OPTIONS] { COMMAND | help }\n"
	     "where  OPTIONS := [ -h | --help | -q | --quiet | -v | --verbose |\n"
	     "			  -V | --version | --sockdir <DIR> | --json ]\n"
	     "	     COMMAND := { start | stop | ping | emad | stats | dump }\n"
	     );
	return 0;
}

static int resmon_cmd(int argc, char **argv)
{
	if (!argc || strcmp(*argv, "help") == 0) {
		return resmon_help();
	} else if (strcmp(*argv, "start") == 0) {
		NEXT_ARG_FWD();
		return resmon_d_start(argc, argv);
	} else if (strcmp(*argv, "stop") == 0) {
		NEXT_ARG_FWD();
		return resmon_c_stop(argc, argv);
	} else if (strcmp(*argv, "ping") == 0) {
		NEXT_ARG_FWD();
		return resmon_c_ping(argc, argv);
	} else if (strcmp(*argv, "emad") == 0) {
		NEXT_ARG_FWD();
		return resmon_c_emad(argc, argv);
	} else if (strcmp(*argv, "stats") == 0) {
		NEXT_ARG_FWD();
		return resmon_c_stats(argc, argv);
	} else if (strcmp(*argv, "dump") == 0) {
		NEXT_ARG_FWD();
		return resmon_c_dump(argc, argv);
	}

	fprintf(stderr, "Unknown command \"%s\"\n", *argv);
	return -EINVAL;
}

int main(int argc, char **argv)
{
	enum {
		opt_sockaddr = 257,
		opt_json,
	};
	static const struct option long_options[] = {
		{ "help",	no_argument,	   NULL, 'h' },
		{ "json",	no_argument,	   NULL, opt_json },
		{ "quiet",	no_argument,	   NULL, 'q' },
		{ "verbose",	no_argument,	   NULL, 'v' },
		{ "version",	no_argument,	   NULL, 'V' },
		{ "sockdir",	required_argument, NULL, opt_sockaddr },
		{ NULL, 0, NULL, 0 }
	};
	int opt;

	env.sockdir = RESMON_DEFAULT_SOCKDIR;
	while ((opt = getopt_long(argc, argv, "hqvV",
				  long_options, NULL)) >= 0) {
		switch (opt) {
		case 'V':
			printf("mlxsw resource monitoring tool, %s\n",
			       program_version);
			return 0;
		case 'h':
			resmon_help();
			return 0;
		case 'v':
			env.verbosity++;
			break;
		case 'q':
			env.verbosity--;
			break;
		case opt_sockaddr:
			env.sockdir = optarg;
			break;
		case opt_json:
			env.show_json = true;
			break;
		default:
			fprintf(stderr, "Unknown option.\n");
			resmon_help();
			return 1;
		}
	}

	argc -= optind;
	argv += optind;

	return resmon_cmd(argc, argv);
}

__attribute__((format(printf, 2, 3)))
int resmon_fmterr(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vasprintf(strp, fmt, ap);
	va_end(ap);

	if (rc < 0)
		*strp = NULL;
	return rc;
}
