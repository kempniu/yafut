// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <stdlib.h>

#include "file.h"
#include "file_driver.h"

static const struct file_driver *file_drivers[] = {
};

static int file_driver_instantiate(const struct file_spec *spec,
				   void **driver_datap) {
	if (!file_drivers[spec->type]->instantiate) {
		*driver_datap = NULL;
		return 0;
	}

	return file_drivers[spec->type]->instantiate(spec, driver_datap);
}

int file_instantiate(const struct file_spec *spec, struct file **filep) {
	struct file *file;
	void *driver_data;
	int ret;

	file = calloc(1, sizeof(*file));
	if (!file) {
		return -ENOMEM;
	}

	ret = file_driver_instantiate(spec, &driver_data);
	if (ret < 0) {
		free(file);
		return ret;
	}

	*file = (struct file){
		.path = spec->path,
		.ops = file_drivers[spec->type]->ops,
		.driver_data = driver_data,
		.destroy_callback = file_drivers[spec->type]->destroy,
	};

	*filep = file;

	return 0;
}

void file_destroy(struct file **filep) {
	struct file *file = *filep;

	*filep = NULL;

	if (file->destroy_callback) {
		file->destroy_callback(&file->driver_data);
	}
	free(file);
}

int file_open_for_reading(struct file *file) {
	return file->ops->open_for_reading(file);
}

int file_open_for_writing(struct file *file) {
	return file->ops->open_for_writing(file);
}

void file_close(struct file *file) {
	file->ops->close(file);
}

int file_read(struct file *file, unsigned char *buf, size_t count) {
	return file->ops->read(file, buf, count);
}

int file_write(struct file *file, const unsigned char *buf, size_t count) {
	return file->ops->write(file, buf, count);
}

int file_get_mode(struct file *file, int *modep) {
	return file->ops->get_mode(file, modep);
}

int file_set_mode(struct file *file, int mode) {
	return file->ops->set_mode(file, mode);
}
