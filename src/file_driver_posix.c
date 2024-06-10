// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "file_driver.h"
#include "log.h"
#include "util.h"

static int file_posix_open_for_reading(struct file *file) {
	int ret;
	int fd;

	if (!strcmp(file->path, "-")) {
		fd = STDIN_FILENO;
		log_debug("reading from stdin");
	} else {
		fd = open(file->path, O_RDONLY);
		log_debug("open, path=%s, fd=%d", file->path, fd);
	}

	if (fd < 0) {
		ret = util_get_errno();
		log_error(ret, "unable to open '%s' for reading", file->path);
		return ret;
	}

	file->fd = fd;

	return 0;
}

static int file_posix_open_for_writing(struct file *file) {
	int ret;
	int fd;

	if (!strcmp(file->path, "-")) {
		fd = STDOUT_FILENO;
		log_debug("writing to stderr");
	} else {
		fd = creat(file->path, 0);
		log_debug("creat, path=%s, fd=%d", file->path, fd);
	}

	if (fd < 0) {
		ret = util_get_errno();
		log_error(ret, "unable to open '%s' for writing", file->path);
		return ret;
	}

	file->fd = fd;

	return 0;
}

static void file_posix_close(struct file *file) {
	close(file->fd);
}

static int file_posix_read(struct file *file, unsigned char *buf,
			   size_t count) {
	int ret;

	ret = read(file->fd, buf, count);
	log_debug("read, fd=%d, count=%d, ret=%d", file->fd, count, ret);

	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "error reading '%s'", file->path);
	}

	return ret;
}

static int file_posix_write(struct file *file, const unsigned char *buf,
			    size_t count) {
	int ret;

	ret = write(file->fd, buf, count);
	log_debug("write, fd=%d, count=%d, ret=%d", file->fd, count, ret);

	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "error writing '%s'", file->path);
	}

	return ret;
}

static int file_posix_get_mode(struct file *file, int *modep) {
	struct stat stat;
	int ret;

	ret = fstat(file->fd, &stat);
	log_debug("fstat, fd=%d, ret=%d", file->fd, ret);

	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "error getting permissions for '%s'",
			  file->path);
		return ret;
	}

	*modep = stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
	log_debug("fstat, fd=%d, mode=%04o", file->fd, *modep);

	return 0;
}

static bool file_posix_is_stdout(struct file *file) {
	bool is_stdout;

	is_stdout = (file->fd == STDOUT_FILENO);
	log_debug("fd=%d, is_stdout=%d", file->fd, is_stdout);

	return is_stdout;
}

static bool file_posix_is_regular_file(struct file *file) {
	bool is_regular_file;
	struct stat stat;
	int ret;

	ret = fstat(file->fd, &stat);
	log_debug("fstat, fd=%d, ret=%d", file->fd, ret);

	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "fstat() failed for '%s'", file->path);
		return false;
	}

	is_regular_file = S_ISREG(stat.st_mode);
	log_debug("fd=%d, mode=%04o, is_regular_file=%d", file->fd,
		  stat.st_mode, is_regular_file);

	return is_regular_file;
}

static bool file_posix_can_set_mode(struct file *file) {
	return file_posix_is_stdout(file) || file_posix_is_regular_file(file);
}

static int file_posix_set_mode(struct file *file, int mode) {
	int ret;

	if (!file_posix_can_set_mode(file)) {
		return 0;
	}

	ret = fchmod(file->fd, (mode_t)mode);
	log_debug("fchmod, fd=%d, mode=%04o, ret=%d", file->fd, mode, ret);

	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "error setting permissions for '%s'",
			  file->path);
	}

	return ret;
}

static const struct file_ops file_ops_posix = {
	.open_for_reading = file_posix_open_for_reading,
	.open_for_writing = file_posix_open_for_writing,
	.close = file_posix_close,
	.read = file_posix_read,
	.write = file_posix_write,
	.get_mode = file_posix_get_mode,
	.set_mode = file_posix_set_mode,
};

const struct file_driver file_driver_posix = {
	.ops = &file_ops_posix,
};
