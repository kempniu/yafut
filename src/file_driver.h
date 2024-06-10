// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <unistd.h>

#include "file.h"

struct file_ops {
	int (*open_for_reading)(struct file *file);
	int (*open_for_writing)(struct file *file);
	void (*close)(struct file *file);
	int (*read)(struct file *file, unsigned char *buf, size_t count);
	int (*write)(struct file *file, const unsigned char *buf, size_t count);
	int (*get_mode)(struct file *file, int *modep);
	int (*set_mode)(struct file *file, int mode);
};

struct file {
	const char *path;
	int fd;
	const struct file_ops *ops;
	void *driver_data;
	void (*destroy_callback)(void **driver_datap);
};

struct file_driver {
	int (*instantiate)(const struct file_spec *spec, void **driver_datap);
	void (*destroy)(void **driver_datap);
	const struct file_ops *ops;
};
