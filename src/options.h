// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <stdbool.h>

#define USAGE_MSG                                                              \
	"Usage: %s "                                                           \
	"-d /dev/mtdX "                                                        \
	"{ -r | -w } "                                                         \
	"-i <src> "                                                            \
	"-o <dst> "                                                            \
	"[ -m <mode> ] "                                                       \
	"[ -T ] "                                                              \
	"[ -v ] "                                                              \
	"[ -h ] "                                                              \
	"\n\n"                                                                 \
	"    -d  path to the MTD character device to read from or write to\n"  \
	"    -r  read a file from the MTD into a local file\n"                 \
	"    -w  write a local file to a file on the MTD\n"                    \
	"    -i  path to the source file (use '-' to read from stdin)\n"       \
	"    -o  path to the destination file (use '-' to write to stdout)\n"  \
	"    -m  set destination file access permissions to <mode> (octal)\n"  \
	"        (default: copy access permissions from <src>)\n"              \
	"    -T  force inband tags\n"                                          \
	"    -v  verbose output (can be used up to two times)\n"               \
	"    -h  show usage information and exit\n"

enum program_mode {
	PROGRAM_MODE_UNSPECIFIED,
	PROGRAM_MODE_READ,
	PROGRAM_MODE_WRITE,
};

#define FILE_MODE_UNSPECIFIED -1

struct opts {
	enum program_mode mode;
	const char *device_path;
	const char *src_path;
	const char *dst_path;
	int dst_mode;
	bool force_inband_tags;
};

void options_parse_env(void);
int options_parse_cli(int argc, char *argv[], struct opts *opts);
int options_validate(const struct opts *opts);
