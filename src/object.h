// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <stdbool.h>

#include "storage.h"

enum object_type {
	LIST_OBJECT_TYPE_UNKNOWN,
	LIST_OBJECT_TYPE_ROOT,
	LIST_OBJECT_TYPE_FILE,
	LIST_OBJECT_TYPE_DIRECTORY,
	LIST_OBJECT_TYPE_SYMLINK,
};

struct object {
	char path_array[32];
	char *path_ptr;
	enum object_type type;
	unsigned int mode;
	unsigned long long size;
	unsigned long long mtime;
	union {
		struct object_file {
			bool executable;
		} file;
		struct object_directory {
			unsigned int children_allocated;
			unsigned int children_count;
			struct object *children;
		} directory;
		struct object_symlink {
			char *target;
			bool broken;
		} symlink;
	} data;
};

const char *object_get_path(const struct object *object);

int object_recursive_instantiate(struct object **objectp);
void object_recursive_destroy(struct object **objectp);

int object_recursive_prepare(struct object *object,
			     const struct storage *storage);
int object_recursive_call(const struct object *object,
			  int (*callback)(const struct object *, void *),
			  void *callback_data);
