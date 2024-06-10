// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <yaffs_guts.h>
#include <yportenv.h>

#include "log.h"
#include "util.h"
#include "ydriver.h"

/*
 * This module contains Yaffs driver callbacks performing the operations
 * requested by Yaffs code using POSIX APIs.  They are intended to be used by
 * storage drivers.
 */

int ydriver_posix_always_ok(struct ydriver_data *ydriver_data, int block_no) {
	(void)ydriver_data;
	(void)block_no;

	return YAFFS_OK;
}

int ydriver_posix_always_fail(struct ydriver_data *ydriver_data, int block_no) {
	(void)ydriver_data;
	(void)block_no;

	return YAFFS_FAIL;
}

int ydriver_posix_erase_block(struct ydriver_data *ydriver_data, int block_no) {
	long long offset = block_no * ydriver_data->block_size;
	int err = 0;
	int ret;

	u8 *erased = calloc(1, ydriver_data->block_size);
	if (!erased) {
		log_debug("failed to allocate memory for erasure markers");
		return YAFFS_FAIL;
	}

	memset(erased, 0xff, ydriver_data->block_size);

	ret = pwrite(ydriver_data->fd, erased, ydriver_data->block_size,
		     offset);
	if (ret < 0) {
		err = util_get_errno();
	}

	log_debug("pwrite, block_no=%d, offset=%lld (0x%08llx), data=%p (%d), "
		  "ret=%d, err=%d (%s)",
		  block_no, offset, offset, erased, ydriver_data->block_size,
		  ret, err, util_get_error(err));
	ydriver_debug_hexdump(erased, ydriver_data->block_size, "data");

	free(erased);

	if (ret < 0) {
		return YAFFS_FAIL;
	}

	return YAFFS_OK;
}

int ydriver_posix_read_chunk(struct ydriver_data *ydriver_data, int chunk,
			     u8 *data, int data_len, u8 *oob, int oob_len,
			     enum yaffs_ecc_result *ecc_result_out) {
	long long offset = ydriver_get_data_offset(ydriver_data, chunk);
	enum yaffs_ecc_result ecc_result;
	int err = 0;
	int ret;

	(void)oob;
	(void)oob_len;

	ret = pread(ydriver_data->fd, data, data_len, offset);
	if (ret < 0) {
		err = util_get_errno();
	}

	log_debug("pread, chunk=%d, offset=%lld (0x%08llx), data=%p (%d), "
		  "ret=%d, err=%d (%s)",
		  chunk, offset, offset, data, data_len, ret, err,
		  util_get_error(err));
	ydriver_debug_hexdump(data, data_len, "data");

	ret = ydriver_get_ecc_result(ret < 0 ? ret : 0, &ecc_result);

	if (ecc_result_out) {
		*ecc_result_out = ecc_result;
	}

	return ret;
}

int ydriver_posix_write_chunk(struct ydriver_data *ydriver_data, int chunk,
			      const u8 *data, int data_len, const u8 *oob,
			      int oob_len) {
	long long offset = ydriver_get_data_offset(ydriver_data, chunk);
	int err = 0;
	int ret;

	(void)oob;
	(void)oob_len;

	ret = pwrite(ydriver_data->fd, data, data_len, offset);
	if (ret < 0) {
		err = util_get_errno();
	}

	log_debug("pwrite, chunk=%d, offset=%lld (0x%08llx), data=%p (%d), "
		  "ret=%d, err=%d (%s)",
		  chunk, offset, offset, data, data_len, ret, err,
		  util_get_error(err));
	ydriver_debug_hexdump(data, data_len, "data");

	if (ret < 0) {
		return YAFFS_FAIL;
	}

	return YAFFS_OK;
}
