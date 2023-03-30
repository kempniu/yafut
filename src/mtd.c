// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <yaffs_guts.h>
#include <yportenv.h>

#include "ioctl.h"
#include "log.h"
#include "mtd.h"
#include "options.h"
#include "util.h"

#define mtd_debug(ctx, fmt, ...)                                               \
	mtd_debug_location(__FILE__, __LINE__, __func__, ctx, fmt,             \
			   ##__VA_ARGS__)

#define mtd_debug_hexdump(ctx, fmt, ...)                                       \
	mtd_debug_hexdump_location(__FILE__, __LINE__, __func__, ctx, fmt,     \
				   ##__VA_ARGS__)

/*
 * Structure passed around in the 'driver_context' field of struct yaffs_dev.
 */
struct mtd_ctx {
	struct mtd_info_user mtd;
	struct yaffs_dev *yaffs_dev;
	const char *mtd_path;
	int mtd_fd;
};

/*
 * Print the message provided in 'fmt' (and any optional arguments following
 * it) to stderr, prefixing it with the provided file/line/function information
 * and the path to the MTD device that the MTD context provided in 'ctx' is
 * associated with.
 */
static void mtd_debug_location(const char *file, int line, const char *func,
			       const struct mtd_ctx *ctx, const char *fmt,
			       ...) {
	char format[1024];
	va_list args;
	int ret;

	if (log_level < 1) {
		return;
	}

	ret = log_format(format, sizeof(format), "%s: %s", ctx->mtd_path, fmt);
	if (ret < 0) {
		return;
	}

	va_start(args, fmt);
	log_location_varargs(file, line, func, format, args);
	va_end(args);
}

/*
 * Helper macro to reduce code repetition in mtd_debug_hexdump_location().
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
 * mtd_read_chunk() or written by mtd_write_chunk().  Only used for debugging;
 * requires -v -v to be specified on the command line in order to do anything.
 */
static void mtd_debug_hexdump_location(const char *file, int line,
				       const char *func,
				       const struct mtd_ctx *ctx, const u8 *buf,
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

	mtd_debug_location(file, line, func, ctx, "%s:\n%s%s", description, hex,
			   buf_len > 32 ? "    ..." : "");
}

/*
 * Read the raw contents of the sysfs attribute at the provided 'sysfs_path'
 * into 'buf', which is 'buf_len' bytes large.  The given sysfs attribute is
 * expected to contain no more than 'buf_len' bytes of data.
 */
static int read_sysfs_attribute(const char *sysfs_path, char *buf,
				size_t buf_len) {
	int ret;
	int fd;

	fd = open(sysfs_path, O_RDONLY);
	if (fd < 0) {
		ret = util_get_errno();
		log_error(ret, "unable to open %s", sysfs_path);
		return ret;
	}

	ret = read(fd, buf, buf_len);
	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "error reading %s", sysfs_path);
	}

	close(fd);

	return ret;
}

/*
 * Store the value reported by /sys/class/mtd/mtd<X>/oobavail (derived from
 * 'mtd_path') in 'oobavail'.  That value is necessary for determining whether
 * use of inband tags is required and it is not returned by the MEMGETINFO
 * ioctl, so it has to be retrieved in a different way than the other MTD
 * parameters.
 */
static int read_oobavail_from_sysfs(const char *mtd_path,
				    unsigned int *oobavail) {
	char oobavail_str[16] = {0};
	char path[32];
	char *newline;
	int ret;

	ret = snprintf(path, sizeof(path), "/sys/class/mtd/%s/oobavail",
		       basename(mtd_path));
	if (ret < 0 || (unsigned int)ret >= sizeof(path)) {
		return -ENOMEM;
	}

	ret = read_sysfs_attribute(path, oobavail_str, sizeof(oobavail_str));
	if (ret < 0) {
		return ret;
	}

	newline = strrchr(oobavail_str, '\n');
	if (newline) {
		*newline = '\0';
	}

	return util_parse_number(oobavail_str, 10, oobavail);
}

/*
 * Check whether the given MTD block is a bad one.
 *
 * (This is the 'drv_check_bad_fn' callback of struct yaffs_driver.)
 */
static int mtd_check_bad(struct yaffs_dev *dev, int block_no) {
	const struct mtd_ctx *ctx = dev->driver_context;
	const struct mtd_info_user *mtd = &ctx->mtd;
	off_t offset = block_no * mtd->erasesize;
	int err = 0;
	int ret;

	if (block_no < 0) {
		mtd_debug(ctx, "block_no=%d", block_no);
		return YAFFS_FAIL;
	}

	ret = linux_ioctl(ctx->mtd_fd, MEMGETBADBLOCK, &offset);
	if (ret < 0) {
		err = util_get_errno();
	}

	mtd_debug(ctx, "ioctl=MEMGETBADBLOCK, block=%d, ret=%d, err=%d (%s)",
		  block_no, ret, err, util_get_error(err));

	return (ret == 0 ? YAFFS_OK : YAFFS_FAIL);
}

/*
 * Erase the given MTD block.
 *
 * (This is the 'drv_erase_fn' callback of struct yaffs_driver.)
 */
static int mtd_erase_block(struct yaffs_dev *dev, int block_no) {
	const struct mtd_ctx *ctx = dev->driver_context;
	const struct mtd_info_user *mtd = &ctx->mtd;
	off_t offset = block_no * mtd->erasesize;
	int err = 0;
	int ret;

	if (block_no < 0) {
		mtd_debug(ctx, "block_no=%d", block_no);
		return YAFFS_FAIL;
	}

	struct erase_info_user64 einfo64 = {
		.start = offset,
		.length = mtd->erasesize,
	};

	ret = linux_ioctl(ctx->mtd_fd, MEMERASE64, &einfo64);
	if (ret < 0) {
		err = util_get_errno();
	}

	mtd_debug(ctx, "ioctl=MEMERASE64, block=%d, ret=%d, err=%d (%s)",
		  block_no, ret, err, util_get_error(err));

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
static int mtd_mark_bad(struct yaffs_dev *dev, int block_no) {
	const struct mtd_ctx *ctx = dev->driver_context;
	const struct mtd_info_user *mtd = &ctx->mtd;
	off_t offset = block_no * mtd->erasesize;
	int err = 0;
	int ret;

	if (block_no < 0) {
		mtd_debug(ctx, "block_no=%d", block_no);
		return YAFFS_FAIL;
	}

	ret = linux_ioctl(ctx->mtd_fd, MEMSETBADBLOCK, &offset);
	if (ret < 0) {
		err = util_get_errno();
	}

	mtd_debug(ctx, "ioctl=MEMSETBADBLOCK, block=%d, ret=%d, err=%d (%s)",
		  block_no, ret, err, util_get_error(err));

	if (ret < 0) {
		return YAFFS_FAIL;
	}

	return YAFFS_OK;
}

/*
 * Helper function for mtd_read_chunk() that translates the result code of the
 * ioctl() system call into an <ECC result, Yaffs result code> tuple.  Yaffs
 * uses these values to properly handle deficiencies in flash memory.
 */
static int mtd_ecc_result(int read_result, enum yaffs_ecc_result *ecc_result) {
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
static int mtd_read_chunk(struct yaffs_dev *dev, int nand_chunk, u8 *data,
			  int data_len, u8 *oob, int oob_len,
			  enum yaffs_ecc_result *ecc_result_out) {
	const struct mtd_ctx *ctx = dev->driver_context;
	const struct mtd_info_user *mtd = &ctx->mtd;
	off_t offset = nand_chunk * mtd->writesize;
	enum yaffs_ecc_result ecc_result;
	int err = 0;
	int ret;

	if (nand_chunk < 0 || data_len < 0 || oob_len < 0) {
		mtd_debug(ctx, "nand_chunk=%d, data_len=%d, oob_len=%d",
			  nand_chunk, data_len, oob_len);
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

	mtd_debug(ctx,
		  "ioctl=MEMREAD, chunk=%d, data=%p (%d), oob=%p (%d), ret=%d, "
		  "err=%d (%s)",
		  nand_chunk, data, data_len, oob, oob_len, ret, err,
		  util_get_error(err));
	mtd_debug_hexdump(ctx, data, data_len, "data");
	mtd_debug_hexdump(ctx, oob, oob_len, "oob");

	ret = mtd_ecc_result(ret, &ecc_result);

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
static int mtd_write_chunk(struct yaffs_dev *dev, int nand_chunk,
			   const u8 *data, int data_len, const u8 *oob,
			   int oob_len) {
	const struct mtd_ctx *ctx = dev->driver_context;
	const struct mtd_info_user *mtd = &ctx->mtd;
	off_t offset = nand_chunk * mtd->writesize;
	int err = 0;
	int ret;

	if (nand_chunk < 0 || data_len < 0 || oob_len < 0) {
		mtd_debug(ctx, "nand_chunk=%d, data_len=%d, oob_len=%d",
			  nand_chunk, data_len, oob_len);
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

	mtd_debug(ctx,
		  "ioctl=MEMWRITE, chunk=%d, data=%p (%d), oob=%p (%d), "
		  "ret=%d, err=%d (%s)",
		  nand_chunk, data, data_len, oob, oob_len, ret, err,
		  util_get_error(err));
	mtd_debug_hexdump(ctx, data, data_len, "data");
	mtd_debug_hexdump(ctx, oob, oob_len, "oob");

	if (ret < 0) {
		return YAFFS_FAIL;
	}

	return YAFFS_OK;
}

/*
 * Yaffs driver structure that is passed along the MTD layout information to
 * yaffs_add_device().
 */
static const struct yaffs_driver yaffs_driver_mtd = {
	.drv_check_bad_fn = mtd_check_bad,
	.drv_erase_fn = mtd_erase_block,
	.drv_mark_bad_fn = mtd_mark_bad,
	.drv_read_chunk_fn = mtd_read_chunk,
	.drv_write_chunk_fn = mtd_write_chunk,
};

/*
 * Initialize the structure used by Yaffs code to interact with the given MTD.
 */
static int init_yaffs_dev(struct mtd_ctx *ctx, unsigned int oobavail) {
	const struct mtd_info_user *mtd = &ctx->mtd;

	mtd_debug(ctx,
		  "type=%02x, flags=%08x, size=%08x, erasesize=%08x, "
		  "writesize=%08x, oobsize=%08x, oobavail=%08x",
		  mtd->type, mtd->flags, mtd->size, mtd->erasesize,
		  mtd->writesize, mtd->oobsize, oobavail);

	ctx->yaffs_dev = calloc(1, sizeof(*ctx->yaffs_dev));
	if (!ctx->yaffs_dev) {
		return -ENOMEM;
	}

	*ctx->yaffs_dev = (struct yaffs_dev) {
		.param = {
			.total_bytes_per_chunk = mtd->writesize,
			.chunks_per_block = mtd->erasesize / mtd->writesize,
			.spare_bytes_per_chunk = mtd->oobsize,
			.start_block = 0,
			.end_block = (mtd->size / mtd->erasesize) - 1,
			.n_reserved_blocks = 2,
			.is_yaffs2 = (mtd->writesize >= 2048 ? 1 : 0),
		},
		.drv = yaffs_driver_mtd,
		.driver_context = ctx,
	};

	yaffs_add_device(ctx->yaffs_dev);

	return 0;
}

/*
 * Retrieve MTD layout information using the ioctl() system call and store it
 * in the structure passed around in the 'driver_context' field of struct
 * yaffs_dev.  Then initialize Yaffs code for the MTD in question.
 */
static int init_mtd_context(const struct opts *opts, struct mtd_ctx **ctxp) {
	unsigned int oobavail;
	struct mtd_ctx *ctx;
	int flags;
	int ret;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}

	ctx->mtd_path = opts->device_path;

	flags = (opts->mode == PROGRAM_MODE_READ ? O_RDONLY : O_RDWR);
	ctx->mtd_fd = open(opts->device_path, flags);
	if (ctx->mtd_fd < 0) {
		ret = util_get_errno();
		log_error(ret, "unable to open MTD character device");
		goto err_free_ctx;
	}

	ret = linux_ioctl(ctx->mtd_fd, MEMGETINFO, &ctx->mtd);
	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "unable to get MTD information");
		goto err_close_mtd_fd;
	}

	ret = read_oobavail_from_sysfs(ctx->mtd_path, &oobavail);
	if (ret < 0) {
		log_error(ret, "unable to get count of available OOB bytes");
		goto err_close_mtd_fd;
	}

	ret = init_yaffs_dev(ctx, oobavail);
	if (ret < 0) {
		log_error(ret, "unable to initialize Yaffs device");
		goto err_close_mtd_fd;
	}

	*ctxp = ctx;

	return 0;

err_close_mtd_fd:
	close(ctx->mtd_fd);
err_free_ctx:
	free(ctx);

	return ret;
}

/*
 * Release all resources associated with the MTD used.
 */
static void destroy_mtd_context(struct mtd_ctx **ctxp) {
	struct mtd_ctx *ctx = *ctxp;

	*ctxp = NULL;

	close(ctx->mtd_fd);
	free(ctx->yaffs_dev);
	free(ctx);
}

/*
 * Ensure that the device path provided via the -d command-line option points
 * to an accessible character device (which is expected for MTD devices).
 * Basic sanity check.
 */
static int check_device_path(const char *device_path) {
	struct stat statbuf;
	int ret;

	ret = stat(device_path, &statbuf);
	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "unable to stat() path '%s'", device_path);
		return ret;
	}

	if ((statbuf.st_mode & S_IFMT) != S_IFCHR) {
		ret = -ENODEV;
		log_error(ret, "'%s' is not a character device", device_path);
		return ret;
	}

	return 0;
}

/*
 * Initialize the MTD at the given path and mount it for subsequent operations.
 */
int mtd_mount(const struct opts *opts, struct mtd_ctx **ctxp) {
	struct mtd_ctx *ctx = NULL;
	int ret;

	ret = check_device_path(opts->device_path);
	if (ret < 0) {
		return ret;
	}

	ret = init_mtd_context(opts, &ctx);
	if (ret < 0 || !ctx) {
		return ret;
	}

	ret = yaffs_mount_reldev(ctx->yaffs_dev);
	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		log_error(ret, "unable to mount Yaffs filesystem");
		destroy_mtd_context(&ctx);
		return ret;
	}

	mtd_debug(ctx, "successfully mounted Yaffs filesystem");

	*ctxp = ctx;

	return 0;
}

/*
 * Unmount the MTD used and release all resources associated with it.
 */
void mtd_unmount(struct mtd_ctx **ctxp) {
	struct mtd_ctx *ctx = *ctxp;
	int ret;

	mtd_debug(ctx, "unmounting Yaffs filesystem");

	ret = yaffs_unmount_reldev(ctx->yaffs_dev);
	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		log_error(ret, "error unmounting Yaffs filesystem");
	}

	destroy_mtd_context(ctxp);
}

/*
 * Common bits for opening a file on an MTD for reading/writing.
 */
static int mtd_file_open(const struct mtd_ctx *ctx, const char *path, int *fd,
			 int flags) {
	int ret;

	ret = yaffs_open_reldev(ctx->yaffs_dev, path, flags, 0);
	mtd_debug(ctx, "yaffs_open, path=%s, ret=%d", path, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		mtd_debug(ctx, "yaffs_open, err=%d", ret);
		return ret;
	}

	*fd = ret;

	return 0;
}

/*
 * Open a file on an MTD for reading.  See local_file_open_read() for the local
 * file counterpart.
 */
int mtd_file_open_read(const struct mtd_ctx *ctx, const char *path, int *fd) {
	return mtd_file_open(ctx, path, fd, O_RDONLY);
}

/*
 * Open a file on an MTD for writing.  See local_file_open_write() for the
 * local file counterpart.
 */
int mtd_file_open_write(const struct mtd_ctx *ctx, const char *path, int *fd) {
	return mtd_file_open(ctx, path, fd, O_WRONLY | O_CREAT | O_TRUNC);
}

/*
 * Get access permissions for a file on an MTD pointed to by the provided file
 * descriptor.  See local_file_get_mode() for the local file counterpart.
 */
int mtd_file_get_mode(const struct mtd_ctx *ctx, int fd) {
	struct yaffs_stat stat;
	int mode;
	int ret;

	ret = yaffs_fstat(fd, &stat);
	mtd_debug(ctx, "yaffs_fstat, fd=%d, ret=%d", fd, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		mtd_debug(ctx, "yaffs_fstat, err=%d", ret);
		return ret;
	}

	mode = stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
	mtd_debug(ctx, "yaffs_fstat, fd=%d, mode=%04o", fd, mode);

	return mode;
}

/*
 * Set access permissions for a file on an MTD pointed to by the provided file
 * descriptor.  This is the MTD counterpart of the POSIX fchmod() call.
 */
int mtd_file_set_mode(const struct mtd_ctx *ctx, int fd, int mode) {
	int ret;

	ret = yaffs_fchmod(fd, mode);
	mtd_debug(ctx, "yaffs_fchmod, fd=%d, mode=%04o, ret=%d", fd, mode, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		mtd_debug(ctx, "yaffs_fchmod, err=%d", ret);
	}

	return ret;
}

/*
 * Close a previously-opened file on an MTD.
 */
void mtd_file_close(const struct mtd_ctx *ctx, int fd) {
	mtd_debug(ctx, "yaffs_close, fd=%d", fd);
	yaffs_close(fd);
}

/*
 * Read a part of a previously-opened file on an MTD.  This is the MTD
 * counterpart of the POSIX read() call.
 */
ssize_t mtd_file_read(const struct mtd_ctx *ctx, int fd, unsigned char *buf,
		      size_t count) {
	int ret;

	ret = yaffs_read(fd, buf, count);
	mtd_debug(ctx, "yaffs_read, fd=%d, count=%d, ret=%d", fd, count, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		mtd_debug(ctx, "yaffs_read, err=%d", ret);
	}

	return ret;
}

/*
 * Write a part of a previously-opened file on an MTD.  This is the MTD
 * counterpart of the POSIX write() call.
 */
ssize_t mtd_file_write(const struct mtd_ctx *ctx, int fd,
		       const unsigned char *buf, size_t count) {
	int ret;

	ret = yaffs_write(fd, buf, count);
	mtd_debug(ctx, "yaffs_write, fd=%d, count=%d, ret=%d", fd, count, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		mtd_debug(ctx, "yaffs_write, err=%d", ret);
	}

	return ret;
}
