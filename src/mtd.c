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

#define DEFAULT_NOR_CHUNK_SIZE 2048
#define DEFAULT_NOR_BLOCK_SIZE (64 * DEFAULT_NOR_CHUNK_SIZE)

/*
 * Structure passed around while src/copy.c does its job.
 */
struct mtd_ctx {
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
 * associated with.  Only used for debugging; requires at least -v to be
 * specified on the command line in order to do anything.
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
 * most of them in 'mtd'; store the number of available bytes in the OOB area
 * in 'oobavail_out'.
 */
static int discover_mtd_parameters(const struct mtd_ctx *ctx,
				   struct mtd_info_user *mtd,
				   unsigned int *oobavail_out) {
	unsigned int oobavail;
	int ret;

	ret = linux_ioctl(ctx->mtd_fd, MEMGETINFO, mtd);
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
		  mtd->type, mtd->flags, mtd->size, mtd->erasesize,
		  mtd->writesize, mtd->oobsize, oobavail);

	return 0;
}

/*
 * Set 'chunk_size' and 'block_size' to the default values used by Yaffs code
 * when creating Yaffs2 file system images.
 */
static void init_yaffs_geometry_default(const struct mtd_ctx *ctx,
					unsigned int *chunk_size,
					unsigned int *block_size) {
	mtd_debug(ctx, "using default chunk size of %d bytes",
		  DEFAULT_NOR_CHUNK_SIZE);
	mtd_debug(ctx, "using default block size of %d bytes",
		  DEFAULT_NOR_BLOCK_SIZE);
	*chunk_size = DEFAULT_NOR_CHUNK_SIZE;
	*block_size = DEFAULT_NOR_BLOCK_SIZE;
}

/*
 * Set 'chunk_size' and 'block_size' to the relevant MTD parameters provided in
 * 'mtd'.
 */
static void init_yaffs_geometry_autodetected(const struct mtd_ctx *ctx,
					     const struct mtd_info_user *mtd,
					     unsigned int *chunk_size,
					     unsigned int *block_size) {
	mtd_debug(ctx, "using autodetected chunk size of %d bytes",
		  mtd->writesize);
	mtd_debug(ctx, "using autodetected block size of %d bytes",
		  mtd->erasesize);
	*chunk_size = mtd->writesize;
	*block_size = mtd->erasesize;
}

/*
 * Set 'chunk_size' and 'block_size' to the values provided in command-line
 * options -C and -B, respectively, if these options were used.
 */
static void override_yaffs_geometry_from_options(const struct mtd_ctx *ctx,
						 const struct opts *opts,
						 unsigned int *chunk_size,
						 unsigned int *block_size) {
	if (opts->chunk_size != SIZE_UNSPECIFIED) {
		mtd_debug(ctx, "overriding chunk size to %d bytes",
			  opts->chunk_size);
		*chunk_size = opts->chunk_size;
	}

	if (opts->block_size != SIZE_UNSPECIFIED) {
		mtd_debug(ctx, "overriding block size to %d bytes",
			  opts->block_size);
		*block_size = opts->block_size;
	}
}

/*
 * Determine the MTD type and the values to use for 'chunk_size' and
 * 'block_size':
 *
 *  1. If NOR flash is detected, use default chunk size and block size values
 *     used by Yaffs code when creating Yaffs2 file system images.  (NOR flash
 *     does not have a spare area and is byte-addressable, so the values stored
 *     in struct mtd_info_user by the MEMGETINFO ioctl cannot be used
 *     verbatim.)
 *
 *     If NAND flash is detected, use autodetected MTD parameters provided in
 *     'mtd'.
 *
 *  2. If -C and/or -B were used, override any default values with those
 *     provided on the command line.
 *
 * Set 'mtd_type' accordingly, so that the Yaffs driver knows which helper
 * functions to use for this specific MTD.
 */
static void
init_yaffs_geometry(const struct mtd_ctx *ctx, const struct mtd_info_user *mtd,
		    const struct opts *opts, enum ydrv_mtd_type *mtd_type,
		    unsigned int *chunk_size, unsigned int *block_size) {
	if (mtd->oobsize == 0 && mtd->writesize == 1) {
		mtd_debug(ctx, "NOR flash detected");
		*mtd_type = MTD_TYPE_NOR;
		init_yaffs_geometry_default(ctx, chunk_size, block_size);
	} else {
		mtd_debug(ctx, "NAND flash detected");
		*mtd_type = MTD_TYPE_NAND;
		init_yaffs_geometry_autodetected(ctx, mtd, chunk_size,
						 block_size);
	}

	override_yaffs_geometry_from_options(ctx, opts, chunk_size, block_size);
}

/*
 * Return 'true' if inband tags should be used, taking into account the Yaffs
 * file system version, the amount of available space in the OOB area of the
 * MTD device, and the command-line options used; return 'false' otherwise.
 */
static bool use_inband_tags(bool is_yaffs2, unsigned int oobavail,
			    const struct opts *opts) {
	struct yaffs_packed_tags2 tags;

	if (!is_yaffs2) {
		return false;
	}

	if (opts->force_inband_tags) {
		return true;
	}

	if (opts->disable_ecc_for_tags) {
		return (oobavail < sizeof(tags.t));
	}

	return (oobavail < sizeof(tags));
}

/*
 * Initialize the structure used by Yaffs code to interact with the given MTD.
 */
static int init_yaffs_dev(struct mtd_ctx *ctx, const struct mtd_info_user *mtd,
			  unsigned int oobavail, unsigned int chunk_size,
			  unsigned int block_size, const struct opts *opts) {
	bool is_yaffs2;

	ctx->yaffs_dev = calloc(1, sizeof(*ctx->yaffs_dev));
	if (!ctx->yaffs_dev) {
		return -ENOMEM;
	}

	is_yaffs2 = (chunk_size >= 1024);

	*ctx->yaffs_dev = (struct yaffs_dev) {
		.param = {
			.total_bytes_per_chunk = chunk_size,
			.chunks_per_block = block_size / chunk_size,
			.spare_bytes_per_chunk = mtd->oobsize,
			.start_block = 0,
			.end_block = (mtd->size / block_size) - 1,
			.n_reserved_blocks = 2,
			.is_yaffs2 = is_yaffs2,
			.inband_tags = use_inband_tags(is_yaffs2, oobavail,
						       opts),
			.no_tags_ecc = opts->disable_ecc_for_tags,
		},
	};

	mtd_debug(ctx,
		  "total_bytes_per_chunk=%d, chunks_per_block=%d, "
		  "spare_bytes_per_chunk=%d, end_block=%d, is_yaffs2=%d, "
		  "inband_tags=%d, no_tags_ecc=%d",
		  ctx->yaffs_dev->param.total_bytes_per_chunk,
		  ctx->yaffs_dev->param.chunks_per_block,
		  ctx->yaffs_dev->param.spare_bytes_per_chunk,
		  ctx->yaffs_dev->param.end_block,
		  ctx->yaffs_dev->param.is_yaffs2,
		  ctx->yaffs_dev->param.inband_tags,
		  ctx->yaffs_dev->param.no_tags_ecc);

	return 0;
}

/*
 * Discover MTD parameters and initialize Yaffs code for the MTD in question.
 * Save a pointer to a structure holding all the data that needs to be passed
 * around while src/copy.c does its job in 'ctxp'.
 */
static int init_mtd_context(const struct opts *opts, struct mtd_ctx **ctxp) {
	enum ydrv_mtd_type mtd_type;
	struct mtd_info_user mtd;
	unsigned int chunk_size;
	unsigned int block_size;
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

	ret = discover_mtd_parameters(ctx, &mtd, &oobavail);
	if (ret < 0) {
		goto err_close_mtd_fd;
	}

	init_yaffs_geometry(ctx, &mtd, opts, &mtd_type, &chunk_size,
			    &block_size);

	ret = init_yaffs_dev(ctx, &mtd, oobavail, chunk_size, block_size, opts);
	if (ret < 0) {
		log_error(ret, "unable to initialize Yaffs device");
		goto err_close_mtd_fd;
	}

	ret = ydrv_init(ctx->yaffs_dev, ctx->mtd_fd, mtd_type, chunk_size,
			block_size);
	if (ret < 0) {
		log_error(ret, "unable to initialize Yaffs driver");
		goto err_free_yaffs_dev;
	}

	yaffs_add_device(ctx->yaffs_dev);

	*ctxp = ctx;

	return 0;

err_free_yaffs_dev:
	free(ctx->yaffs_dev);
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

	ydrv_destroy(ctx->yaffs_dev);

	free(ctx->yaffs_dev);
	close(ctx->mtd_fd);
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
 * Save a pointer to a structure holding all the data that needs to be passed
 * around while src/copy.c does its job in 'ctxp'.
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
