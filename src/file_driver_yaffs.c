// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <fcntl.h>
#include <sys/stat.h>

#include <yaffsfs.h>

#include "file.h"
#include "file_driver.h"
#include "log.h"
#include "storage.h"

static int file_yaffs_instantiate(const struct file_spec *spec,
				  void **driver_datap) {
	struct storage *storage;
	int ret;

	ret = storage_instantiate(spec->opts, &storage);
	if (ret < 0) {
		return ret;
	}

	ret = yaffs_mount_reldev((struct yaffs_dev *)storage);
	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		log_error(ret, "unable to mount Yaffs filesystem");
		storage_destroy(&storage);
		return ret;
	}

	*driver_datap = storage;

	return 0;
}

static void file_yaffs_destroy(void **driver_datap) {
	struct storage *storage = *(struct storage **)driver_datap;
	int ret;

	*driver_datap = NULL;

	ret = yaffs_unmount_reldev((struct yaffs_dev *)storage);
	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		log_error(ret, "error unmounting Yaffs filesystem");
	}

	storage_destroy(&storage);
}

static int file_yaffs_open(struct file *file, int flags) {
	struct storage *storage = file->driver_data;
	struct yaffs_dev *yaffs_device = (struct yaffs_dev *)storage;
	int ret;

	ret = yaffs_open_reldev(yaffs_device, file->path, flags, 0);
	log_debug("yaffs_open_reldev, path=%s, ret=%d", file->path, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		return ret;
	}

	file->fd = ret;

	return 0;
}

static int file_yaffs_open_for_reading(struct file *file) {
	int ret;

	ret = file_yaffs_open(file, O_RDONLY);
	if (ret < 0) {
		log_error(ret, "unable to open '%s' for reading", file->path);
	}

	return ret;
}

static int file_yaffs_open_for_writing(struct file *file) {
	int ret;

	ret = file_yaffs_open(file, O_WRONLY | O_CREAT | O_TRUNC);
	if (ret < 0) {
		log_error(ret, "unable to open '%s' for writing", file->path);
	}

	return ret;
}

static void file_yaffs_close(struct file *file) {
	log_debug("yaffs_close, fd=%d", file->fd);
	yaffs_close(file->fd);
}

static int file_yaffs_read(struct file *file, unsigned char *buf,
			   size_t count) {
	int ret;

	ret = yaffs_read(file->fd, buf, count);
	log_debug("yaffs_read, fd=%d, count=%d, ret=%d", file->fd, count, ret);

	if (ret < 0) {
		ret = yaffsfs_GetLastError();
		log_error(ret, "error reading '%s'", file->path);
	}

	return ret;
}

static int file_yaffs_write(struct file *file, const unsigned char *buf,
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

static int file_yaffs_get_mode(struct file *file, int *modep) {
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

static int file_yaffs_set_mode(struct file *file, int mode) {
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

static const struct file_ops file_ops_yaffs = {
	.open_for_reading = file_yaffs_open_for_reading,
	.open_for_writing = file_yaffs_open_for_writing,
	.close = file_yaffs_close,
	.read = file_yaffs_read,
	.write = file_yaffs_write,
	.get_mode = file_yaffs_get_mode,
	.set_mode = file_yaffs_set_mode,
};

const struct file_driver file_driver_yaffs = {
	.instantiate = file_yaffs_instantiate,
	.destroy = file_yaffs_destroy,
	.ops = &file_ops_yaffs,
};
