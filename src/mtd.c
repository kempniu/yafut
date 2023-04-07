// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <yaffs_guts.h>
#include <yaffs_packedtags2.h>
#include <yaffsfs.h>
#include <yportenv.h>

#include "ioctl.h"
#include "log.h"
#include "mtd.h"
#include "options.h"
#include "util.h"
#include "ydrv.h"

/*
 * Structure passed around in the 'driver_context' field of struct yaffs_dev.
 */
struct mtd_ctx {
	struct mtd_info_user mtd;
	struct yaffs_dev *yaffs_dev;
	const char *mtd_path;
	int mtd_fd;
};

#define mtd_debug(ctx, fmt, ...)                                               \
	mtd_debug_location(__FILE__, __LINE__, __func__, ctx, fmt,             \
			   ##__VA_ARGS__)

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
 * Given an MTD context 'ctx' with its 'mtd_fd' member containing an open file
 * descriptor for an MTD character device, use the MEMGETINFO ioctl and sysfs
 * attribute values to determine the parameters of the provided MTD and store
 * most of them in 'ctx->mtd'; store the number of available bytes in the OOB
 * area in 'oobavail_out' (this value does not need to be retained in
 * 'ctx->mtd' because it is only used during Yaffs device initialization).
 */
static int discover_mtd_parameters(struct mtd_ctx *ctx,
				   unsigned int *oobavail_out) {
	unsigned int oobavail;
	int ret;

	ret = linux_ioctl(ctx->mtd_fd, MEMGETINFO, &ctx->mtd);
	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "unable to get MTD information");
		return ret;
	}

	ret = read_oobavail_from_sysfs(ctx->mtd_path, &oobavail);
	if (ret < 0) {
		log_error(ret, "unable to get count of available OOB bytes");
		return ret;
	}

	*oobavail_out = oobavail;

	mtd_debug(ctx,
		  "type=%d, flags=0x%08x, size=%d, erasesize=%d, writesize=%d, "
		  "oobsize=%d, oobavail=%d",
		  ctx->mtd.type, ctx->mtd.flags, ctx->mtd.size,
		  ctx->mtd.erasesize, ctx->mtd.writesize, ctx->mtd.oobsize,
		  oobavail);

	return 0;
}

/*
 * Initialize the structure used by Yaffs code to interact with the given MTD.
 */
static int init_yaffs_dev(struct mtd_ctx *ctx, unsigned int oobavail,
			  bool force_inband_tags) {
	const struct mtd_info_user *mtd = &ctx->mtd;
	int inband_tags;
	int is_yaffs2;

	ctx->yaffs_dev = calloc(1, sizeof(*ctx->yaffs_dev));
	if (!ctx->yaffs_dev) {
		return -ENOMEM;
	}

	is_yaffs2 = (mtd->writesize >= 2048);
	inband_tags = (is_yaffs2
		       && (oobavail < sizeof(struct yaffs_packed_tags2)
			   || force_inband_tags));

	*ctx->yaffs_dev = (struct yaffs_dev) {
		.param = {
			.total_bytes_per_chunk = mtd->writesize,
			.chunks_per_block = mtd->erasesize / mtd->writesize,
			.spare_bytes_per_chunk = mtd->oobsize,
			.start_block = 0,
			.end_block = (mtd->size / mtd->erasesize) - 1,
			.n_reserved_blocks = 2,
			.is_yaffs2 = is_yaffs2,
			.inband_tags = inband_tags,
		},
		.drv = yaffs_driver_mtd,
		.driver_context = ctx,
	};

	mtd_debug(ctx,
		  "total_bytes_per_chunk=%d, chunks_per_block=%d, "
		  "spare_bytes_per_chunk=%d, end_block=%d, is_yaffs2=%d, "
		  "inband_tags=%d",
		  ctx->yaffs_dev->param.total_bytes_per_chunk,
		  ctx->yaffs_dev->param.chunks_per_block,
		  ctx->yaffs_dev->param.spare_bytes_per_chunk,
		  ctx->yaffs_dev->param.end_block,
		  ctx->yaffs_dev->param.is_yaffs2,
		  ctx->yaffs_dev->param.inband_tags);

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

	ret = discover_mtd_parameters(ctx, &oobavail);
	if (ret < 0) {
		goto err_close_mtd_fd;
	}

	ret = init_yaffs_dev(ctx, oobavail, opts->force_inband_tags);
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
