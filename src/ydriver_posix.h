// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <yaffs_guts.h>
#include <yportenv.h>

#include "ydriver.h"

int ydriver_posix_always_ok(struct ydriver_data *ydriver_data, int block_no);
int ydriver_posix_always_fail(struct ydriver_data *ydriver_data, int block_no);
int ydriver_posix_erase_block(struct ydriver_data *ydriver_data, int block_no);
int ydriver_posix_read_chunk(struct ydriver_data *ydriver_data, int chunk,
			     u8 *data, int data_len, u8 *oob, int oob_len,
			     enum yaffs_ecc_result *ecc_result_out);
int ydriver_posix_write_chunk(struct ydriver_data *ydriver_data, int chunk,
			      const u8 *data, int data_len, const u8 *oob,
			      int oob_len);
