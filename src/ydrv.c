// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <mtd/mtd-user.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <yaffs_guts.h>
#include <yportenv.h>

#include "ioctl.h"
#include "log.h"
#include "util.h"
#include "ydrv.h"

/*
 * Structure passed around in the 'driver_context' field of struct yaffs_dev.
 */
struct ydrv_ctx {
	int mtd_fd;
	unsigned int chunk_size;
	unsigned int block_size;
};

#define ydrv_debug(fmt, ...)                                                   \
	ydrv_debug_location(__FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

/*
 * Print the message provided in 'fmt' (and any optional arguments following
 * it) to stderr, prefixing it with the provided file/line/function
 * information.  Only used for debugging; requires at least -v to be specified
 * on the command line in order to do anything.
 */
static void ydrv_debug_location(const char *file, int line, const char *func,
				const char *fmt, ...) {
	va_list args;

	if (log_level < 1) {
		return;
	}

	va_start(args, fmt);
	log_location_varargs(file, line, func, fmt, args);
	va_end(args);
}

#define ydrv_debug_hexdump(fmt, ...)                                           \
	ydrv_debug_hexdump_location(__FILE__, __LINE__, __func__, fmt,         \
				    ##__VA_ARGS__)

/*
 * Helper macro to reduce code repetition in ydrv_debug_hexdump_location().
 */
#define HEXDUMP_APPEND(fmt, ...)                                               \
	{                                                                      \
		int ret = snprintf(hex + hex_pos, sizeof(hex) - hex_pos, fmt,  \
				   ##__VA_ARGS__);                             \
		if (ret < 0 || (unsigned int)ret >= sizeof(hex) - hex_pos) {   \
			return;                                                \
		}                                                              \
		hex_pos += ret;                                                \
	}

/*
 * Print a hex dump of up to the first 32 bytes of a NAND chunk read by
 * ydrv_read_chunk() or written by ydrv_write_chunk().  Only used for debugging;
 * requires -v -v to be specified on the command line in order to do anything.
 */
static void ydrv_debug_hexdump_location(const char *file, int line,
					const char *func, const u8 *buf,
					int buf_len, const char *description) {
	unsigned char hex_pos = 0;
	char hex[128];

	if (log_level < 2 || !buf || buf_len < 1) {
		return;
	}

	for (int i = 0; i < (buf_len < 32 ? buf_len : 32); i++) {
		if (i % 16 == 0) {
			HEXDUMP_APPEND("    ");
		}

		HEXDUMP_APPEND("%02x ", buf[i]);

		if (i % 16 == 15) {
			HEXDUMP_APPEND("\n");
		} else if (i % 8 == 7) {
			HEXDUMP_APPEND(" ");
		}
	}

	ydrv_debug_location(file, line, func, "%s:\n%s%s", description, hex,
			    buf_len > 32 ? "    ..." : "");
}

/*
 * Get the offset at which data starts for the given Yaffs 'chunk' on the MTD
 * described by 'ctx'.  This routine is more than a simple multiplication so
 * that it can handle Yaffs layouts in which the block size is not a multiple
 * of the chunk size (with padding between the last chunk in a block and the
 * first chunk of the following block).
 */
static long long ydrv_get_data_offset_for_chunk(const struct ydrv_ctx *ctx,
						int nand_chunk) {
	unsigned int chunks_per_block = ctx->block_size / ctx->chunk_size;
	unsigned int block = nand_chunk / chunks_per_block;
	unsigned int chunk_in_block = nand_chunk % chunks_per_block;

	return (block * ctx->block_size) + (chunk_in_block * ctx->chunk_size);
}

/*
 * Check whether the given MTD block is a bad one.
 *
 * (This is the 'drv_check_bad_fn' callback of struct yaffs_driver.)
 */
static int ydrv_check_bad(struct yaffs_dev *dev, int block_no) {
	const struct ydrv_ctx *ctx = dev->driver_context;
	long long offset = block_no * ctx->block_size;
	int err = 0;
	int ret;

	if (block_no < 0) {
		ydrv_debug("block_no=%d", block_no);
		return YAFFS_FAIL;
	}

	ret = linux_ioctl(ctx->mtd_fd, MEMGETBADBLOCK, &offset);
	if (ret < 0) {
		err = util_get_errno();
	}

	ydrv_debug("ioctl=MEMGETBADBLOCK, block=%d, ret=%d, err=%d (%s)",
		   block_no, ret, err, util_get_error(err));

	return (ret == 0 ? YAFFS_OK : YAFFS_FAIL);
}

/*
 * Erase the given MTD block.
 *
 * (This is the 'drv_erase_fn' callback of struct yaffs_driver.)
 */
static int ydrv_erase_block(struct yaffs_dev *dev, int block_no) {
	const struct ydrv_ctx *ctx = dev->driver_context;
	long long offset = block_no * ctx->block_size;
	int err = 0;
	int ret;

	if (block_no < 0) {
		ydrv_debug("block_no=%d", block_no);
		return YAFFS_FAIL;
	}

	struct erase_info_user64 einfo64 = {
		.start = offset,
		.length = ctx->block_size,
	};

	ret = linux_ioctl(ctx->mtd_fd, MEMERASE64, &einfo64);
	if (ret < 0) {
		err = util_get_errno();
	}

	ydrv_debug("ioctl=MEMERASE64, block=%d, ret=%d, err=%d (%s)", block_no,
		   ret, err, util_get_error(err));

	if (ret < 0) {
		return YAFFS_FAIL;
	}

	return YAFFS_OK;
}

/*
 * Mark the given MTD block as bad.
 *
 * (This is the 'drv_mark_bad_fn' callback of struct yaffs_driver.)
 */
static int ydrv_mark_bad(struct yaffs_dev *dev, int block_no) {
	const struct ydrv_ctx *ctx = dev->driver_context;
	long long offset = block_no * ctx->block_size;
	int err = 0;
	int ret;

	if (block_no < 0) {
		ydrv_debug("block_no=%d", block_no);
		return YAFFS_FAIL;
	}

	ret = linux_ioctl(ctx->mtd_fd, MEMSETBADBLOCK, &offset);
	if (ret < 0) {
		err = util_get_errno();
	}

	ydrv_debug("ioctl=MEMSETBADBLOCK, block=%d, ret=%d, err=%d (%s)",
		   block_no, ret, err, util_get_error(err));

	if (ret < 0) {
		return YAFFS_FAIL;
	}

	return YAFFS_OK;
}

/*
 * Helper function for ydrv_read_chunk() that translates the result code of the
 * ioctl() system call into an <ECC result, Yaffs result code> tuple.  Yaffs
 * uses these values to properly handle deficiencies in flash memory.
 */
static int ydrv_ecc_result(int read_result, enum yaffs_ecc_result *ecc_result) {
	switch (read_result) {
	case -EUCLEAN:
		*ecc_result = YAFFS_ECC_RESULT_FIXED;
		return YAFFS_OK;
	case -EBADMSG:
		*ecc_result = YAFFS_ECC_RESULT_UNFIXED;
		return YAFFS_FAIL;
	case 0:
		*ecc_result = YAFFS_ECC_RESULT_NO_ERROR;
		return YAFFS_OK;
	default:
		*ecc_result = YAFFS_ECC_RESULT_UNKNOWN;
		return YAFFS_FAIL;
	}
}

/*
 * Read a data+OOB chunk from the MTD.
 *
 * (This is the 'drv_read_chunk_fn' callback of struct yaffs_driver.)
 */
static int ydrv_read_chunk(struct yaffs_dev *dev, int nand_chunk, u8 *data,
			   int data_len, u8 *oob, int oob_len,
			   enum yaffs_ecc_result *ecc_result_out) {
	const struct ydrv_ctx *ctx = dev->driver_context;
	long long offset = ydrv_get_data_offset_for_chunk(ctx, nand_chunk);
	enum yaffs_ecc_result ecc_result;
	int err = 0;
	int ret;

	if (nand_chunk < 0 || data_len < 0 || oob_len < 0) {
		ydrv_debug("nand_chunk=%d, data_len=%d, oob_len=%d", nand_chunk,
			   data_len, oob_len);
		return YAFFS_FAIL;
	}

	struct mtd_read_req req = {
		.start = offset,
		.len = data_len,
		.ooblen = oob_len,
		.usr_data = (uintptr_t)data,
		.usr_oob = (uintptr_t)oob,
		.mode = dev->param.is_yaffs2 ? MTD_OPS_AUTO_OOB : MTD_OPS_RAW,
	};

	ret = linux_ioctl(ctx->mtd_fd, MEMREAD, &req);
	if (ret < 0) {
		err = util_get_errno();
	}

	ydrv_debug(
		"ioctl=MEMREAD, chunk=%d, data=%p (%d), oob=%p (%d), ret=%d, "
		"err=%d (%s)",
		nand_chunk, data, data_len, oob, oob_len, ret, err,
		util_get_error(err));
	ydrv_debug_hexdump(data, data_len, "data");
	ydrv_debug_hexdump(oob, oob_len, "oob");

	ret = ydrv_ecc_result(ret, &ecc_result);

	if (ecc_result_out) {
		*ecc_result_out = ecc_result;
	}

	return ret;
}

/*
 * Write a data+OOB chunk to the MTD.
 *
 * (This is the 'drv_write_chunk_fn' callback of struct yaffs_driver.)
 */
static int ydrv_write_chunk(struct yaffs_dev *dev, int nand_chunk,
			    const u8 *data, int data_len, const u8 *oob,
			    int oob_len) {
	const struct ydrv_ctx *ctx = dev->driver_context;
	long long offset = ydrv_get_data_offset_for_chunk(ctx, nand_chunk);
	int err = 0;
	int ret;

	if (nand_chunk < 0 || data_len < 0 || oob_len < 0) {
		ydrv_debug("nand_chunk=%d, data_len=%d, oob_len=%d", nand_chunk,
			   data_len, oob_len);
		return YAFFS_FAIL;
	}

	struct mtd_write_req req = {
		.start = offset,
		.len = data_len,
		.ooblen = oob_len,
		.usr_data = (uintptr_t)data,
		.usr_oob = (uintptr_t)oob,
		.mode = dev->param.is_yaffs2 ? MTD_OPS_AUTO_OOB : MTD_OPS_RAW,
	};

	ret = linux_ioctl(ctx->mtd_fd, MEMWRITE, &req);
	if (ret < 0) {
		err = util_get_errno();
	}

	ydrv_debug("ioctl=MEMWRITE, chunk=%d, data=%p (%d), oob=%p (%d), "
		   "ret=%d, err=%d (%s)",
		   nand_chunk, data, data_len, oob, oob_len, ret, err,
		   util_get_error(err));
	ydrv_debug_hexdump(data, data_len, "data");
	ydrv_debug_hexdump(oob, oob_len, "oob");

	if (ret < 0) {
		return YAFFS_FAIL;
	}

	return YAFFS_OK;
}

/*
 * Yaffs driver structure stored by ydrv_init() in the struct yaffs_dev that
 * init_mtd_context() (in src/mtd.c) passes to yaffs_add_device().
 */
static const struct yaffs_driver ydrv = {
	.drv_check_bad_fn = ydrv_check_bad,
	.drv_erase_fn = ydrv_erase_block,
	.drv_mark_bad_fn = ydrv_mark_bad,
	.drv_read_chunk_fn = ydrv_read_chunk,
	.drv_write_chunk_fn = ydrv_write_chunk,
};

/*
 * Initialize 'yaffs_dev->drv' with pointers to callbacks necessary for Yaffs
 * code to do its job.  Save a pointer to a structure holding all the data that
 * needs to be kept around while the Yaffs file system is in use in
 * 'yaffs_dev->driver_context'.
 */
int ydrv_init(struct yaffs_dev *yaffs_dev, int mtd_fd, unsigned int chunk_size,
	      unsigned int block_size) {
	struct ydrv_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	*ctx = (struct ydrv_ctx){
		.mtd_fd = mtd_fd,
		.chunk_size = chunk_size,
		.block_size = block_size,
	};

	yaffs_dev->drv = ydrv;
	yaffs_dev->driver_context = ctx;

	return 0;
}

/*
 * Free the structure holding all the data that needs to be kept around while
 * the Yaffs file system is in use.
 */
void ydrv_destroy(struct yaffs_dev *yaffs_dev) {
	free(yaffs_dev->driver_context);
};
