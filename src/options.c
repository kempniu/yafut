// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "options.h"
#include "util.h"

/*
 * Parse the YAFFS_TRACE_MASK environment variable and use its value to set up
 * Yaffs tracing if requested.
 */
void options_parse_env(void) {
	const char *env_yaffs_trace_mask = getenv("YAFFS_TRACE_MASK");
	unsigned int mask;

	if (!env_yaffs_trace_mask) {
		return;
	}

	if (util_parse_number(env_yaffs_trace_mask, 16, &mask) < 0) {
		log("Invalid Yaffs trace mask '%s'", env_yaffs_trace_mask);
		return;
	}

	log_set_yaffs_trace_mask(mask);
}

/*
 * Read command-line options into the provided variable pointers.  Return an
 * error if any option except -v is specified more than once or if both -r and
 * -w are used simultaneously.
 */
int options_parse_cli(int argc, char *argv[], struct opts *opts) {
	int opt;

	*opts = (struct opts){
		.mode = PROGRAM_MODE_UNSPECIFIED,
		.dst_mode = FILE_MODE_UNSPECIFIED,
	};

	while ((opt = getopt(argc, argv, "d:hi:m:o:rvw")) != -1) {
		switch (opt) {
		case 'd':
			if (opts->device_path) {
				log("-d can only be used once");
				return -1;
			}
			opts->device_path = optarg;
			break;
		case 'i':
			if (opts->src_path) {
				log("-i can only be used once");
				return -1;
			}
			opts->src_path = optarg;
			break;
		case 'm':
			if (opts->dst_mode != FILE_MODE_UNSPECIFIED) {
				log("-m can only be used once");
				return -1;
			}
			{
				unsigned int mode;

				if (util_parse_number(optarg, 8, &mode) < 0
				    || mode > INT_MAX) {
					return -1;
				}

				opts->dst_mode = mode;
			}
			break;
		case 'o':
			if (opts->dst_path) {
				log("-o can only be used once");
				return -1;
			}
			opts->dst_path = optarg;
			break;
		case 'r':
			if (opts->mode != PROGRAM_MODE_UNSPECIFIED) {
				log("-r/-w can only be used once");
				return -1;
			}
			opts->mode = PROGRAM_MODE_READ;
			break;
		case 'v':
			if (log_level >= 2) {
				log("-v can only be used at most twice");
				return -1;
			}
			log_level++;
			break;
		case 'w':
			if (opts->mode != PROGRAM_MODE_UNSPECIFIED) {
				log("-r/-w can only be used once");
				return -1;
			}
			opts->mode = PROGRAM_MODE_WRITE;
			break;
		default:
			return -1;
		}
	}

	return 0;
}

/*
 * Ensure that all the necessary information was provided via command-line
 * options.
 */
int options_validate(const struct opts *opts) {
	switch (opts->mode) {
	case PROGRAM_MODE_UNSPECIFIED:
		log("mode of operation not specified, use either -r or -w");
		return -1;
	case PROGRAM_MODE_READ:
	case PROGRAM_MODE_WRITE:
		if (!opts->device_path) {
			log("MTD device path not specified, use -d");
			return -1;
		}
		if (!opts->src_path) {
			log("source path not specified, use -i");
			return -1;
		}
		if (!opts->dst_path) {
			log("destination path not specified, use -o");
			return -1;
		}
		break;
	default:
		log("unexpected mode of operation %d", opts->mode);
		return -1;
	}

	if (opts->dst_mode > 07777) {
		log("invalid file access permissions %o", opts->dst_mode);
		return -1;
	}

	return 0;
}
