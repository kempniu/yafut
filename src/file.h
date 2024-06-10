// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <unistd.h>

enum file_type {
	FILE_TYPE_POSIX,
	FILE_TYPE_MTD,
};

/*
 * The structure containing the data necessary to instantiate a struct file.
 */
struct file_spec {
	enum file_type type;
	const char *path;
	const struct opts *opts;
};

struct file;

int file_instantiate(const struct file_spec *spec, struct file **filep);
void file_destroy(struct file **filep);

int file_open_for_reading(struct file *file);
int file_open_for_writing(struct file *file);
void file_close(struct file *file);

int file_read(struct file *file, unsigned char *buf, size_t count);
int file_write(struct file *file, const unsigned char *buf, size_t count);

int file_get_mode(struct file *file, int *modep);
int file_set_mode(struct file *file, int mode);
