// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "copy.h"
#include "file.h"
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
	int bytes_written;
	int bytes_read;
	int ret;

	while ((bytes_read = mtd_file_read(mtd, src, buf, sizeof(buf))) > 0) {
		bytes_written = 0;
		do {
			ret = write(dst, buf + bytes_written,
				    bytes_read - bytes_written);
			if (ret < 0) {
				ret = util_get_errno();
				log_error(ret, "error writing local file");
				return ret;
			}

			bytes_written += ret;
		} while (bytes_written < bytes_read);
	}

	if (bytes_read < 0) {
		log_error(bytes_read, "error reading file from MTD");
		return bytes_read;
	}

	return 0;
}

/*
 * Copy data from a local file to a file on an MTD.  Write counterpart of
 * copy_from_mtd_to_file().
 */
static int copy_from_file_to_mtd(const struct mtd_ctx *mtd, int src, int dst) {
	unsigned char buf[2048];
	int bytes_written;
	int bytes_read;
	int ret;

	while ((bytes_read = read(src, buf, sizeof(buf))) > 0) {
		bytes_written = 0;
		do {
			ret = mtd_file_write(mtd, dst, buf + bytes_written,
					     bytes_read - bytes_written);
			if (ret < 0) {
				log_error(ret, "error writing file to MTD");
				return ret;
			}

			bytes_written += ret;
		} while (bytes_written < bytes_read);
	}

	if (bytes_read < 0) {
		bytes_read = util_get_errno();
		log_error(bytes_read, "error reading local file");
		return bytes_read;
	}

	return 0;
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

	ret = mtd_mount(opts, &mtd);
	if (ret < 0) {
		log_error(ret, "unable to mount MTD");
		return ret;
	}

	ret = copy_fn(mtd, opts);
	if (ret < 0) {
		log_error(ret, "copying failed");
	}

	mtd_unmount(&mtd);

	return ret;
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

struct copy_file {
	struct file_spec spec;
	struct file *file;
};

struct copy_operation {
	struct copy_file src;
	struct copy_file dst;
	const struct opts *opts;
};

static int copy_init(struct copy_operation *copy, const struct opts *opts) {
	*copy = (struct copy_operation){
		.src = {
			.spec = {
				.path = opts->src_path,
				.opts = opts,
			},
		},
		.dst = {
			.spec = {
				.path = opts->dst_path,
				.opts = opts,
			},
		},
		.opts = opts,
	};

	switch (opts->mode) {
	case PROGRAM_MODE_READ:
		copy->src.spec.type = FILE_TYPE_MTD;
		copy->dst.spec.type = FILE_TYPE_POSIX;
		return 0;
	case PROGRAM_MODE_WRITE:
		copy->src.spec.type = FILE_TYPE_POSIX;
		copy->dst.spec.type = FILE_TYPE_MTD;
		return 0;
	default:
		return -EINVAL;
	};
}

static int copy_files_instantiate(struct copy_operation *copy) {
	int ret;

	ret = file_instantiate(&copy->src.spec, &copy->src.file);
	if (ret < 0) {
		return ret;
	}

	ret = file_instantiate(&copy->dst.spec, &copy->dst.file);
	if (ret < 0) {
		file_destroy(&copy->src.file);
	}

	return ret;
}

static void copy_files_destroy(struct copy_operation *copy) {
	file_destroy(&copy->src.file);
	file_destroy(&copy->dst.file);
}

static int copy_files_open(struct copy_operation *copy) {
	int ret;

	ret = file_open_for_reading(copy->src.file);
	if (ret < 0) {
		return ret;
	}

	ret = file_open_for_writing(copy->dst.file);
	if (ret < 0) {
		file_close(copy->src.file);
	}

	return ret;
}

static void copy_files_close(struct copy_operation *copy) {
	file_close(copy->src.file);
	file_close(copy->dst.file);
}

static int copy_prepare_files(struct copy_operation *copy) {
	int ret;

	ret = copy_files_instantiate(copy);
	if (ret < 0) {
		return ret;
	}

	ret = copy_files_open(copy);
	if (ret < 0) {
		copy_files_destroy(copy);
	}

	return ret;
}

static int copy_prepare(struct copy_operation *copy, const struct opts *opts) {
	int ret;

	ret = copy_init(copy, opts);
	if (ret < 0) {
		return ret;
	}

	return copy_prepare_files(copy);
}

static int copy_file_contents(struct copy_operation *copy) {
	unsigned char buf[2048];
	int bytes_written;
	int bytes_read;
	int ret;

	while ((bytes_read = file_read(copy->src.file, buf, sizeof(buf))) > 0) {
		bytes_written = 0;
		do {
			ret = file_write(copy->dst.file, buf + bytes_written,
					 bytes_read - bytes_written);
			if (ret < 0) {
				return ret;
			}

			bytes_written += ret;
		} while (bytes_written < bytes_read);
	}

	if (bytes_read < 0) {
		return bytes_read;
	}

	return 0;
}

static int copy_file_mode(struct copy_operation *copy) {
	int src_mode;
	int ret;

	ret = file_get_mode(copy->src.file, &src_mode);
	if (ret < 0) {
		return ret;
	}

	return file_set_mode(copy->dst.file, src_mode);
}

static int copy_or_set_file_mode(struct copy_operation *copy) {
	if (copy->opts->dst_mode == FILE_MODE_UNSPECIFIED) {
		return copy_file_mode(copy);
	}

	return file_set_mode(copy->dst.file, copy->opts->dst_mode);
}

static int copy_perform(struct copy_operation *copy) {
	int ret;

	ret = copy_file_contents(copy);
	if (ret < 0) {
		return ret;
	}

	return copy_or_set_file_mode(copy);
}

static void copy_destroy(struct copy_operation *copy) {
	copy_files_close(copy);
	copy_files_destroy(copy);
}

int copy_file_based_on_opts(const struct opts *opts) {
	struct copy_operation copy;
	int ret;

	ret = copy_prepare(&copy, opts);
	if (ret < 0) {
		return ret;
	}

	ret = copy_perform(&copy);

	copy_destroy(&copy);

	return ret;
}
