// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
 * Convert the provided 'string' to a signed integer value according to the
 * given 'base', storing the result in 'result'.  If 'suffixes_allowed' is
 * 'true', also handle an optional 'k' suffix (kilobytes).
 */
static int parse_int(const char *string, int base, bool suffixes_allowed,
		     int *result) {
	unsigned int multiplier = 1;
	unsigned int value;
	char copy[32];
	int ret;

	ret = snprintf(copy, sizeof(copy), "%s", string);
	if (ret < 0 || (unsigned int)ret >= sizeof(copy)) {
		log("'%s' is too long to parse as a number", string);
		return -1;
	}

	if (suffixes_allowed) {
		size_t len = strlen(copy);

		if (copy[len - 1] == 'k') {
			multiplier = 1024;
			copy[len - 1] = '\0';
		}
	}

	ret = util_parse_number(copy, base, &value);
	if (ret < 0) {
		return -1;
	}

	if (value > INT_MAX / multiplier) {
		log("number '%s' is too large", string);
		return -1;
	}

	*result = value * multiplier;

	return 0;
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
		.chunk_size = SIZE_UNSPECIFIED,
		.block_size = SIZE_UNSPECIFIED,
		.byte_order = BYTE_ORDER_CPU,
	};

	while ((opt = getopt(argc, argv, "B:C:d:Ehi:LMm:o:PrSTvw")) != -1) {
		switch (opt) {
		case 'B':
			if (opts->block_size != SIZE_UNSPECIFIED) {
				log("-B can only be used once");
				return -1;
			}
			if (parse_int(optarg, 10, true, &opts->block_size)
			    < 0) {
				return -1;
			}
			break;
		case 'C':
			if (opts->chunk_size != SIZE_UNSPECIFIED) {
				log("-C can only be used once");
				return -1;
			}
			if (parse_int(optarg, 10, true, &opts->chunk_size)
			    < 0) {
				return -1;
			}
			break;
		case 'd':
			if (opts->device_path) {
				log("-d can only be used once");
				return -1;
			}
			opts->device_path = optarg;
			break;
		case 'E':
			if (opts->disable_ecc_for_tags) {
				log("-E can only be used once");
				return -1;
			}
			opts->disable_ecc_for_tags = true;
			break;
		case 'i':
			if (opts->src_path) {
				log("-i can only be used once");
				return -1;
			}
			opts->src_path = optarg;
			break;
		case 'L':
			if (opts->byte_order != BYTE_ORDER_CPU) {
				log("-L/-M can only be used once");
				return -1;
			}
			opts->byte_order = BYTE_ORDER_LITTLE_ENDIAN;
			break;
		case 'M':
			if (opts->byte_order != BYTE_ORDER_CPU) {
				log("-L/-M can only be used once");
				return -1;
			}
			opts->byte_order = BYTE_ORDER_BIG_ENDIAN;
			break;
		case 'm':
			if (opts->dst_mode != FILE_MODE_UNSPECIFIED) {
				log("-m can only be used once");
				return -1;
			}
			if (parse_int(optarg, 8, false, &opts->dst_mode) < 0) {
				return -1;
			}
			break;
		case 'o':
			if (opts->dst_path) {
				log("-o can only be used once");
				return -1;
			}
			opts->dst_path = optarg;
			break;
		case 'P':
			if (opts->disable_checkpoints) {
				log("-P can only be used once");
				return -1;
			}
			opts->disable_checkpoints = true;
			break;
		case 'r':
			if (opts->mode != PROGRAM_MODE_UNSPECIFIED) {
				log("-r/-w can only be used once");
				return -1;
			}
			opts->mode = PROGRAM_MODE_READ;
			break;
		case 'S':
			if (opts->disable_summaries) {
				log("-S can only be used once");
				return -1;
			}
			opts->disable_summaries = true;
			break;
		case 'T':
			if (opts->force_inband_tags) {
				log("-T can only be used once");
				return -1;
			}
			opts->force_inband_tags = true;
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
#if defined(NO_MTD_DEVICE)
			log("Image path not specified, use -d");
#else
			log("MTD device/image path not specified, use -d");
#endif
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
