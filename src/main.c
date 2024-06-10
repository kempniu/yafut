// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <stdio.h>

#include "copy.h"
#include "options.h"

static char *program_name;

/*
 * Invoke the proper copy function from src/copy.c depending on the operation
 * mode (read/write) specified via command-line options.
 */
static int perform_action(struct opts *opts) {
	switch (opts->mode) {
	case PROGRAM_MODE_READ:
	case PROGRAM_MODE_WRITE:
		return copy_file_based_on_opts(opts);
	default:
		return -1;
	};
}

/*
 * Program entry point.  Process command-line options and set things up for the
 * src/copy.c module to do its job.
 */
int main(int argc, char *argv[]) {
	struct opts opts;
	int ret;

	program_name = argv[0];

	options_parse_env();

	ret = options_parse_cli(argc, argv, &opts);
	if (ret < 0) {
		fprintf(stderr, USAGE_MSG, program_name);
		return ret;
	}

	ret = options_validate(&opts);
	if (ret < 0) {
		fprintf(stderr, USAGE_MSG, program_name);
		return ret;
	}

	return -perform_action(&opts);
}
