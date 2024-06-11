// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <stdbool.h>

#if defined(NO_MTD_DEVICE)
#define USAGE_FLAG_D "-d /path/to/yaffs.img "
#define USAGE_DESC_D "    -d  path to the Yaffs image to use\n"
#define USAGE_MTDIMAGE "image"
#else
#define USAGE_FLAG_D "-d { /dev/mtdX | /path/to/yaffs.img } "
#define USAGE_DESC_D                                                           \
	"    -d  path to the MTD character device or Yaffs image to use\n"
#define USAGE_MTDIMAGE "MTD/image"
#endif

#define USAGE_MSG                                                              \
	"Usage: %s "                                                           \
	USAGE_FLAG_D                                                           \
	"{ -r | -w } "                                                         \
	"-i <src> "                                                            \
	"-o <dst> "                                                            \
	"[ -m <mode> ] "                                                       \
	"[ -C <bytes> ] "                                                      \
	"[ -B <bytes> ] "                                                      \
	"[ -T ] "                                                              \
	"[ -E ] "                                                              \
	"[ -P ] "                                                              \
	"[ -S ] "                                                              \
	"[ -L ] "                                                              \
	"[ -M ] "                                                              \
	"[ -v ] "                                                              \
	"[ -h ] "                                                              \
	"\n\n"                                                                 \
	USAGE_DESC_D                                                           \
	"    -r  read a file from the " USAGE_MTDIMAGE " into a local file\n"  \
	"    -w  write a local file to a file on the " USAGE_MTDIMAGE "\n"     \
	"    -i  path to the source file (use '-' to read from stdin)\n"       \
	"    -o  path to the destination file (use '-' to write to stdout)\n"  \
	"    -m  set destination file access permissions to <mode> (octal)\n"  \
	"        (default: copy access permissions from <src>)\n"              \
	"    -C  force Yaffs chunk size to <bytes> (use 'k' suffix for KiB)\n" \
	"    -B  force Yaffs block size to <bytes> (use 'k' suffix for KiB)\n" \
	"    -T  force inband tags\n"                                          \
	"    -E  disable ECC for tags\n"                                       \
	"    -P  disable Yaffs2 checkpoints\n"                                 \
	"    -S  disable writing Yaffs2 summaries\n"                           \
	"    -L  force little-endian byte order\n"                             \
	"    -M  force big-endian byte order\n"                                \
	"    -v  verbose output (can be used up to two times)\n"               \
	"    -h  show usage information and exit\n"

enum program_mode {
	PROGRAM_MODE_UNSPECIFIED,
	PROGRAM_MODE_READ,
	PROGRAM_MODE_WRITE,
};

enum byte_order {
	BYTE_ORDER_CPU = 0,
	BYTE_ORDER_LITTLE_ENDIAN = 1,
	BYTE_ORDER_BIG_ENDIAN = 2,
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
	bool disable_checkpoints;
	bool disable_summaries;
	enum byte_order byte_order;
};

void options_parse_env(void);
int options_parse_cli(int argc, char *argv[], struct opts *opts);
int options_validate(const struct opts *opts);
