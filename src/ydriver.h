// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <stdbool.h>

#include <yaffs_guts.h>
#include <yportenv.h>

#define ydriver_debug_hexdump(fmt, ...)                                        \
	ydriver_debug_hexdump_location(__FILE__, __LINE__, __func__, fmt,      \
				       ##__VA_ARGS__)

extern const struct yaffs_driver ydriver;

/*
 * The structure passed around by Yaffs code.  The higher-level layer (storage)
 * is responsible for setting up all of this structure's fields and also for
 * setting a pointer to it in struct yaffs_dev's 'driver_context' field.
 */
struct ydriver_data {
	const struct ydriver_callbacks *callbacks;
	int fd;
	unsigned int block_size;
	unsigned int chunk_size;
	bool is_yaffs2;
};

/*
 * Pointers to storage-type-specific callbacks that perform the operations
 * requested by Yaffs code using the data passed in 'ydriver_data'.  These are
 * provided by a storage driver.
 */
struct ydriver_callbacks {
	int (*check_bad)(struct ydriver_data *ydriver_data, int block_no);
	int (*erase_block)(struct ydriver_data *ydriver_data, int block_no);
	int (*mark_bad)(struct ydriver_data *ydriver_data, int block_no);
	int (*read_chunk)(struct ydriver_data *ydriver_data, int chunk,
			  u8 *data, int data_len, u8 *oob, int oob_len,
			  enum yaffs_ecc_result *ecc_result_out);
	int (*write_chunk)(struct ydriver_data *ydriver_data, int chunk,
			   const u8 *data, int data_len, const u8 *oob,
			   int oob_len);
};

void ydriver_debug_hexdump_location(const char *file, int line,
				    const char *func, const u8 *buf,
				    int buf_len, const char *description);
long long ydriver_get_data_offset(const struct ydriver_data *data, int chunk);
int ydriver_get_ecc_result(int read_result, enum yaffs_ecc_result *ecc_result);
