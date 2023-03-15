// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "copy.h"
#include "log.h"
#include "mtd.h"
#include "options.h"
#include "util.h"

/*
 * Open a local file (or stdin) for reading.  See mtd_file_open_read() for the
 * MTD counterpart.
 */
static int local_file_open_read(const char *file_path, int *fdp) {
	int fd;

	if (!strcmp(file_path, "-")) {
		fd = 0;
	} else {
		fd = open(file_path, O_RDONLY);
	}

	if (fd < 0) {
		return util_get_errno();
	}

	*fdp = fd;

	return 0;
}

/*
 * Open a local file (or stdout) for writing.  See mtd_file_open_write() for
 * the MTD counterpart.
 */
static int local_file_open_write(const char *file_path, int *fdp) {
	int fd;

	if (!strcmp(file_path, "-")) {
		fd = 1;
	} else {
		fd = creat(file_path, 0);
	}

	if (fd < 0) {
		return util_get_errno();
	}

	*fdp = fd;

	return 0;
}

/*
 * Copy data from a file on an MTD to a local file.  Read counterpart of
 * copy_from_file_to_mtd().
 */
static int copy_from_mtd_to_file(const struct mtd_ctx *mtd, int src, int dst) {
	unsigned char buf[2048];
	int ret;

	while ((ret = mtd_file_read(mtd, src, buf, sizeof(buf))) > 0) {
		if (write(dst, buf, ret) < 0) {
			ret = util_get_errno();
			log_error(ret, "error writing local file");
			return ret;
		}
	}

	if (ret < 0) {
		log_error(ret, "error reading file from MTD");
	}

	return ret;
}

/*
 * Copy data from a local file to a file on an MTD.  Write counterpart of
 * copy_from_mtd_to_file().
 */
static int copy_from_file_to_mtd(const struct mtd_ctx *mtd, int src, int dst) {
	unsigned char buf[2048];
	int ret;

	while ((ret = read(src, buf, sizeof(buf))) > 0) {
		if ((ret = mtd_file_write(mtd, dst, buf, ret)) < 0) {
			log_error(ret, "error writing file to MTD");
			return ret;
		}
	}

	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "error reading local file");
	}

	return ret;
}

/*
 * Get access permissions for a local file pointed to by the provided file
 * descriptor.  See mtd_file_get_mode() for the MTD counterpart.
 */
static int local_file_get_mode(int fd) {
	struct stat stat;
	int ret;

	ret = fstat(fd, &stat);
	if (ret < 0) {
		return util_get_errno();
	}

	return stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
}

/*
 * Ensure that the local file pointed to by the 'fd_out' file descriptor has
 * the same access permissions as the file on the MTD pointed to by the 'fd_in'
 * file descriptor.  This function is used while reading a file from an MTD;
 * see copy_mode_from_file_to_mtd() for the write counterpart.
 */
static int copy_mode_from_mtd_to_file(const struct mtd_ctx *mtd, int fd_in,
				      int fd_out) {
	int ret;

	ret = mtd_file_get_mode(mtd, fd_in);
	if (ret < 0) {
		log_error(ret, "unable to get file mode from MTD");
		return ret;
	}

	ret = fchmod(fd_out, ret);
	if (ret < 0) {
		log_error(ret, "unable to fchmod() local file");
	}

	return ret;
}

/*
 * Ensure that the file on the MTD pointed to by the 'fd_out' file descriptor
 * has the same access permissions as the local file pointed to by the 'fd_in'
 * file descriptor.  This function is used while writing a file to an MTD; see
 * copy_mode_from_mtd_to_file() for the read counterpart.
 */
static int copy_mode_from_file_to_mtd(const struct mtd_ctx *mtd, int fd_in,
				      int fd_out) {
	int ret;

	ret = local_file_get_mode(fd_in);
	if (ret < 0) {
		log_error(ret, "unable to get local file mode");
		return ret;
	}

	ret = mtd_file_set_mode(mtd, fd_out, ret);
	if (ret < 0) {
		log_error(ret, "unable to fchmod() file on the MTD");
	}

	return ret;
}

/*
 * Set up reading a file from an MTD to a local file.  Read counterpart of
 * write_file_to_mtd().
 */
static int read_file_from_mtd(const struct mtd_ctx *mtd,
			      const struct opts *opts) {
	int fd_out;
	int fd_in;
	int ret;

	ret = mtd_file_open_read(mtd, opts->src_path, &fd_in);
	if (ret < 0) {
		log_error(ret, "unable to open file on MTD for reading");
		return ret;
	}

	ret = local_file_open_write(opts->dst_path, &fd_out);
	if (ret < 0) {
		log_error(ret, "unable to open local file for writing");
		goto err_close_fd_in;
	}

	ret = copy_from_mtd_to_file(mtd, fd_in, fd_out);
	if (ret < 0) {
		goto err_close_fd_out;
	}

	if (opts->dst_mode == FILE_MODE_UNSPECIFIED) {
		ret = copy_mode_from_mtd_to_file(mtd, fd_in, fd_out);
	} else {
		ret = fchmod(fd_out, (mode_t)opts->dst_mode);
		if (ret < 0) {
			log_error(ret, "unable to fchmod() local file");
		}
	}

err_close_fd_out:
	close(fd_out);
err_close_fd_in:
	mtd_file_close(mtd, fd_in);

	return ret;
}

/*
 * Set up writing a local file to a file on an MTD.  Write counterpart of
 * read_file_from_mtd().
 */
static int write_file_to_mtd(const struct mtd_ctx *mtd,
			     const struct opts *opts) {
	int fd_out;
	int fd_in;
	int ret;

	ret = local_file_open_read(opts->src_path, &fd_in);
	if (ret < 0) {
		log_error(ret, "could not open local file for reading");
		return ret;
	}

	ret = mtd_file_open_write(mtd, opts->dst_path, &fd_out);
	if (ret < 0) {
		log_error(ret, "unable to open file on MTD for writing");
		goto err_close_fd_in;
	}

	ret = copy_from_file_to_mtd(mtd, fd_in, fd_out);
	if (ret < 0) {
		goto err_close_fd_out;
	}

	if (opts->dst_mode == FILE_MODE_UNSPECIFIED) {
		ret = copy_mode_from_file_to_mtd(mtd, fd_in, fd_out);
	} else {
		ret = mtd_file_set_mode(mtd, fd_out, (mode_t)opts->dst_mode);
		if (ret < 0) {
			log_error(ret, "unable to fchmod() file on the MTD");
		}
	}

err_close_fd_out:
	mtd_file_close(mtd, fd_out);
err_close_fd_in:
	close(fd_in);

	return ret;
}

/*
 * Common bits for reading from/writing to an MTD.
 */
static int copy_file(int (*copy_fn)(const struct mtd_ctx *mtd,
				    const struct opts *opts),
		     const struct opts *opts) {
	struct mtd_ctx *mtd;
	int ret;

	ret = mtd_mount(opts->device_path, &mtd);
	if (ret < 0) {
		log_error(ret, "unable to mount MTD");
		return ret;
	}

	/*
	 * Perform the requested action.  Note that an error here causes an
	 * early return.  While calling mtd_unmount() also in case of an error
	 * would allow all resources to be released, unmounting a YAFFS
	 * filesystem may cause the MTD device to be written to, which is
	 * arguably prudent to avoid after failing to read a file from an
	 * existing filesystem (to prevent further damage to a potentially
	 * broken filesystem).
	 */
	ret = copy_fn(mtd, opts);
	if (ret < 0) {
		log_error(ret, "copying failed");
		return ret;
	}

	return mtd_unmount(&mtd);
}

/*
 * Public helper for copying a file from an MTD into a local file.  Called from
 * src/main.c.
 */
int copy_read_file_from_mtd(const struct opts *opts) {
	return copy_file(read_file_from_mtd, opts);
}

/*
 * Public helper for copying a local file to a file on an MTD.  Called from
 * src/main.c.
 */
int copy_write_file_to_mtd(const struct opts *opts) {
	return copy_file(write_file_to_mtd, opts);
}
