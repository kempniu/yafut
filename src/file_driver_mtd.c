// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <yaffsfs.h>

#include "file.h"
#include "file_driver.h"
#include "log.h"
#include "mtd.h"

static int file_mtd_instantiate(const struct file_spec *spec,
				void **driver_datap) {
	return mtd_mount(spec->opts, (struct mtd_ctx **)driver_datap);
}

static void file_mtd_destroy(void **driver_datap) {
	mtd_unmount((struct mtd_ctx **)driver_datap);
}

static int file_mtd_open(struct file *file, int flags) {
	struct mtd_ctx *mtd_ctx = (struct mtd_ctx *)file->driver_data;
	int ret;

	ret = yaffs_open_reldev(mtd_get_device(mtd_ctx), file->path, flags, 0);
	log_debug("yaffs_open_reldev, path=%s, ret=%d", file->path, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		return ret;
	}

	file->fd = ret;

	return 0;
}

static int file_mtd_open_for_reading(struct file *file) {
	int ret;

	ret = file_mtd_open(file, O_RDONLY);
	if (ret < 0) {
		log_error(ret, "unable to open '%s' for reading", file->path);
	}

	return ret;
}

static int file_mtd_open_for_writing(struct file *file) {
	int ret;

	ret = file_mtd_open(file, O_WRONLY | O_CREAT | O_TRUNC);
	if (ret < 0) {
		log_error(ret, "unable to open '%s' for writing", file->path);
	}

	return ret;
}

static void file_mtd_close(struct file *file) {
	log_debug("yaffs_close, fd=%d", file->fd);
	yaffs_close(file->fd);
}

static int file_mtd_read(struct file *file, unsigned char *buf, size_t count) {
	int ret;

	ret = yaffs_read(file->fd, buf, count);
	log_debug("yaffs_read, fd=%d, count=%d, ret=%d", file->fd, count, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		log_error(ret, "error reading '%s'", file->path);
	}

	return ret;
}

static int file_mtd_write(struct file *file, const unsigned char *buf,
			  size_t count) {
	int ret;

	ret = yaffs_write(file->fd, buf, count);
	log_debug("yaffs_write, fd=%d, count=%d, ret=%d", file->fd, count, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		log_error(ret, "error writing '%s'", file->path);
	}

	return ret;
}

static int file_mtd_get_mode(struct file *file, int *modep) {
	struct yaffs_stat stat;
	int ret;

	ret = yaffs_fstat(file->fd, &stat);
	log_debug("yaffs_fstat, fd=%d, ret=%d", file->fd, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		log_error(ret, "error getting permissions for '%s'",
			  file->path);
		return ret;
	}

	*modep = stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
	log_debug("yaffs_fstat, fd=%d, mode=%04o", file->fd, *modep);

	return 0;
}

static int file_mtd_set_mode(struct file *file, int mode) {
	int ret;

	ret = yaffs_fchmod(file->fd, mode);
	log_debug("yaffs_fchmod, fd=%d, mode=%04o, ret=%d", file->fd, mode,
		  ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		log_error(ret, "error setting permissions for '%s'",
			  file->path);
	}

	return ret;
}

static const struct file_ops file_ops_mtd = {
	.open_for_reading = file_mtd_open_for_reading,
	.open_for_writing = file_mtd_open_for_writing,
	.close = file_mtd_close,
	.read = file_mtd_read,
	.write = file_mtd_write,
	.get_mode = file_mtd_get_mode,
	.set_mode = file_mtd_set_mode,
};

const struct file_driver file_driver_mtd = {
	.instantiate = file_mtd_instantiate,
	.destroy = file_mtd_destroy,
	.ops = &file_ops_mtd,
};
