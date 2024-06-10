// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <mtd/mtd-user.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include <yaffs_guts.h>
#include <yportenv.h>

#include "ioctl.h"
#include "log.h"
#include "util.h"
#include "ydriver.h"

/*
 * This module contains Yaffs driver callbacks performing the operations
 * requested by Yaffs code using MTD ioctls.  They are intended to be used by
 * storage drivers.
 */

int ydriver_ioctl_check_bad(struct ydriver_data *ydriver_data, int block_no) {
	long long offset = block_no * ydriver_data->block_size;
	int err = 0;
	int ret;

	ret = linux_ioctl(ydriver_data->fd, MEMGETBADBLOCK, &offset);
	if (ret < 0) {
		err = util_get_errno();
	}

	log_debug("ioctl=MEMGETBADBLOCK, block=%d, offset=%lld (0x%08llx), "
		  "ret=%d, err=%d (%s)",
		  block_no, offset, offset, ret, err, util_get_error(err));

	return (ret == 0 ? YAFFS_OK : YAFFS_FAIL);
}

int ydriver_ioctl_erase_block(struct ydriver_data *ydriver_data, int block_no) {
	long long offset = block_no * ydriver_data->block_size;
	int err = 0;
	int ret;

	struct erase_info_user64 einfo64 = {
		.start = offset,
		.length = ydriver_data->block_size,
	};

	ret = linux_ioctl(ydriver_data->fd, MEMERASE64, &einfo64);
	if (ret < 0) {
		err = util_get_errno();
	}

	log_debug("ioctl=MEMERASE64, block=%d, offset=%lld (0x%08llx), ret=%d, "
		  "err=%d (%s)",
		  block_no, offset, offset, ret, err, util_get_error(err));

	if (ret < 0) {
		return YAFFS_FAIL;
	}

	return YAFFS_OK;
}

int ydriver_ioctl_mark_bad(struct ydriver_data *ydriver_data, int block_no) {
	long long offset = block_no * ydriver_data->block_size;
	int err = 0;
	int ret;

	ret = linux_ioctl(ydriver_data->fd, MEMSETBADBLOCK, &offset);
	if (ret < 0) {
		err = util_get_errno();
	}

	log_debug("ioctl=MEMSETBADBLOCK, block=%d, offset=%lld (0x%08llx), "
		  "ret=%d, err=%d (%s)",
		  block_no, offset, offset, ret, err, util_get_error(err));

	if (ret < 0) {
		return YAFFS_FAIL;
	}

	return YAFFS_OK;
}

int ydriver_ioctl_read_chunk(struct ydriver_data *ydriver_data, int chunk,
			     u8 *data, int data_len, u8 *oob, int oob_len,
			     enum yaffs_ecc_result *ecc_result_out) {
	long long offset = ydriver_get_data_offset(ydriver_data, chunk);
	bool is_yaffs2 = ydriver_data->is_yaffs2;
	enum yaffs_ecc_result ecc_result;
	int err = 0;
	int ret;

	struct mtd_read_req req = {
		.start = offset,
		.len = data_len,
		.ooblen = oob_len,
		.usr_data = (uintptr_t)data,
		.usr_oob = (uintptr_t)oob,
		.mode = is_yaffs2 ? MTD_OPS_AUTO_OOB : MTD_OPS_RAW,
	};

	ret = linux_ioctl(ydriver_data->fd, MEMREAD, &req);
	if (ret < 0) {
		err = util_get_errno();
	}

	log_debug("ioctl=MEMREAD, chunk=%d, offset=%lld (0x%08llx), "
		  "data=%p (%d), oob=%p (%d), ret=%d, err=%d (%s)",
		  chunk, offset, offset, data, data_len, oob, oob_len, ret, err,
		  util_get_error(err));
	ydriver_debug_hexdump(data, data_len, "data");
	ydriver_debug_hexdump(oob, oob_len, "oob");

	ret = ydriver_get_ecc_result(ret, &ecc_result);

	if (ecc_result_out) {
		*ecc_result_out = ecc_result;
	}

	return ret;
}

int ydriver_ioctl_write_chunk(struct ydriver_data *ydriver_data, int chunk,
			      const u8 *data, int data_len, const u8 *oob,
			      int oob_len) {
	long long offset = ydriver_get_data_offset(ydriver_data, chunk);
	bool is_yaffs2 = ydriver_data->is_yaffs2;
	int err = 0;
	int ret;

	struct mtd_write_req req = {
		.start = offset,
		.len = data_len,
		.ooblen = oob_len,
		.usr_data = (uintptr_t)data,
		.usr_oob = (uintptr_t)oob,
		.mode = is_yaffs2 ? MTD_OPS_AUTO_OOB : MTD_OPS_RAW,
	};

	ret = linux_ioctl(ydriver_data->fd, MEMWRITE, &req);
	if (ret < 0) {
		err = util_get_errno();
	}

	log_debug("ioctl=MEMWRITE, chunk=%d, offset=%lld (0x%08llx), "
		  "data=%p (%d), oob=%p (%d), ret=%d, err=%d (%s)",
		  chunk, offset, offset, data, data_len, oob, oob_len, ret, err,
		  util_get_error(err));
	ydriver_debug_hexdump(data, data_len, "data");
	ydriver_debug_hexdump(oob, oob_len, "oob");

	if (ret < 0) {
		return YAFFS_FAIL;
	}

	return YAFFS_OK;
}
