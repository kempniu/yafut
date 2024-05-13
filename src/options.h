// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <stdbool.h>

#define USAGE_MSG                                                              \
	"Usage: %s "                                                           \
	"-d { /dev/mtdX | /path/to/yaffs.img } "                               \
	"{ -r | -w } "                                                         \
	"-i <src> "                                                            \
	"-o <dst> "                                                            \
	"[ -m <mode> ] "                                                       \
	"[ -C <bytes> ] "                                                      \
	"[ -B <bytes> ] "                                                      \
	"[ -T ] "                                                              \
	"[ -E ] "                                                              \
	"[ -v ] "                                                              \
	"[ -h ] "                                                              \
	"\n\n"                                                                 \
	"    -d  path to the MTD character device (or Yaffs image) to use\n"   \
	"    -r  read a file from the MTD into a local file\n"                 \
	"    -w  write a local file to a file on the MTD\n"                    \
	"    -i  path to the source file (use '-' to read from stdin)\n"       \
	"    -o  path to the destination file (use '-' to write to stdout)\n"  \
	"    -m  set destination file access permissions to <mode> (octal)\n"  \
	"        (default: copy access permissions from <src>)\n"              \
	"    -C  force Yaffs chunk size to <bytes> (use 'k' suffix for KiB)\n" \
	"    -B  force Yaffs block size to <bytes> (use 'k' suffix for KiB)\n" \
	"    -T  force inband tags\n"                                          \
	"    -E  disable ECC for tags\n"                                       \
	"    -v  verbose output (can be used up to two times)\n"               \
	"    -h  show usage information and exit\n"

enum program_mode {
	PROGRAM_MODE_UNSPECIFIED,
	PROGRAM_MODE_READ,
	PROGRAM_MODE_WRITE,
};

#define FILE_MODE_UNSPECIFIED -1
#define SIZE_UNSPECIFIED -1

struct opts {
	enum program_mode mode;
	const char *device_path;
	const char *src_path;
	const char *dst_path;
	int dst_mode;
	int chunk_size;
	int block_size;
	bool force_inband_tags;
	bool disable_ecc_for_tags;
};

void options_parse_env(void);
int options_parse_cli(int argc, char *argv[], struct opts *opts);
int options_validate(const struct opts *opts);
