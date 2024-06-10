// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <stdbool.h>

#include <yaffs_guts.h>
#include <yportenv.h>

#include "ydriver.h"

int ydriver_ioctl_check_bad(struct ydriver_data *ydriver_data, int block_no);
int ydriver_ioctl_erase_block(struct ydriver_data *ydriver_data, int block_no);
int ydriver_ioctl_mark_bad(struct ydriver_data *ydriver_data, int block_no);
int ydriver_ioctl_read_chunk(struct ydriver_data *ydriver_data, int chunk,
			     u8 *data, int data_len, u8 *oob, int oob_len,
			     enum yaffs_ecc_result *ecc_result_out);
int ydriver_ioctl_write_chunk(struct ydriver_data *ydriver_data, int chunk,
			      const u8 *data, int data_len, const u8 *oob,
			      int oob_len);
