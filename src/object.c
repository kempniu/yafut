// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <yaffs_guts.h>
#include <yaffsfs.h>

#include "log.h"
#include "object.h"
#include "storage.h"
#include "util.h"

static int object_recursive_discover(struct object *object,
				     const struct storage *storage);
static void object_recursive_free(struct object *object);

const char *object_get_path(const struct object *object) {
	if (object->path_ptr) {
		return object->path_ptr;
	}

	return object->path_array;
}

int object_recursive_instantiate(struct object **objectp) {
	struct object *object;

	object = calloc(1, sizeof(*object));
	if (!object) {
		return -ENOMEM;
	}

	*object = (struct object){.type = LIST_OBJECT_TYPE_ROOT};

	*objectp = object;

	return 0;
}

static void object_free_directory(struct object *object) {
	struct object_directory *directory = &object->data.directory;

	for (unsigned int i = 0; i < directory->children_count; i++) {
		object_recursive_free(&directory->children[i]);
	}

	free(directory->children);
}

static void object_free_symlink(struct object *object) {
	struct object_symlink *symlink = &object->data.symlink;

	free(symlink->target);
}

static void (*const object_free_callbacks[])(struct object *) = {
	[LIST_OBJECT_TYPE_ROOT] = object_free_directory,
	[LIST_OBJECT_TYPE_DIRECTORY] = object_free_directory,
	[LIST_OBJECT_TYPE_SYMLINK] = object_free_symlink,
};

static void object_recursive_free(struct object *object) {
	void (*free_callback)(struct object *);

	free_callback = object_free_callbacks[object->type];
	if (free_callback) {
		free_callback(object);
	}

	free(object->path_ptr);
}

void object_recursive_destroy(struct object **objectp) {
	struct object *object = *objectp;

	*objectp = NULL;

	object_recursive_free(object);

	free(object);
}

static int object_get_new_children_size(const struct object *object,
					unsigned int *children_countp,
					unsigned int *children_sizep) {
	const struct object_directory *directory = &object->data.directory;
	unsigned int new_children_count;
	unsigned int new_children_size;
	unsigned int cur_children_size;
	size_t child_size;

	new_children_count = directory->children_count > 0
				     ? directory->children_count * 2
				     : 4;

	child_size = sizeof(directory->children[0]);
	new_children_size = new_children_count * child_size;
	cur_children_size = directory->children_count * child_size;

	if (new_children_size < cur_children_size) {
		log("unable to allocate more than %u bytes for '%s'",
		    cur_children_size, object_get_path(object));
		return -ENOMEM;
	}

	*children_countp = new_children_count;
	*children_sizep = new_children_size;

	return 0;
}

static int object_reallocate_children(struct object *object,
				      unsigned int new_children_size) {
	struct object_directory *directory = &object->data.directory;
	struct object *new_children;
	int ret;

	new_children = realloc(directory->children, new_children_size);
	if (!new_children) {
		ret = util_get_errno();
		log_error(ret, "unable to allocate %u bytes for '%s'",
			  new_children_size, object_get_path(object));
		return ret;
	}

	directory->children = new_children;

	return 0;
}

static int object_allocate_more_children(struct object *object) {
	struct object_directory *directory = &object->data.directory;
	unsigned int new_children_count;
	unsigned int new_children_size;
	int ret;

	ret = object_get_new_children_size(object, &new_children_count,
					   &new_children_size);
	if (ret < 0) {
		return ret;
	}

	ret = object_reallocate_children(object, new_children_size);
	if (ret < 0) {
		return ret;
	}

	directory->children_allocated = new_children_count;

	return 0;
}

static int object_ensure_children_available(struct object *object) {
	struct object_directory *directory = &object->data.directory;

	if (directory->children_count < directory->children_allocated) {
		return 0;
	}

	return object_allocate_more_children(object);
}

static void object_get_next_available_child(struct object *parent_object,
					    struct object **objectp) {
	struct object_directory *parent_directory;
	struct object *object;

	parent_directory = &parent_object->data.directory;

	object = &parent_directory->children[parent_directory->children_count];
	*object = (struct object){};

	parent_directory->children_count++;

	*objectp = object;
}

static int object_get_child(struct object *parent_object,
			    struct object **objectp) {
	int ret;

	ret = object_ensure_children_available(parent_object);
	if (ret < 0) {
		return ret;
	}

	object_get_next_available_child(parent_object, objectp);

	return 0;
}

static void object_set_path_array(struct object *object,
				  const char *directory_path,
				  const char *entry_name) {
	(void)snprintf(object->path_array, sizeof(object->path_array), "%s/%s",
		       directory_path, entry_name);
}

static int object_set_path_ptr(struct object *object,
			       const char *directory_path,
			       const char *entry_name, int path_length) {
	object->path_ptr = calloc(1, path_length + 1);
	if (!object->path_ptr) {
		return -ENOMEM;
	}

	(void)snprintf(object->path_ptr, path_length + 1, "%s/%s",
		       directory_path, entry_name);

	return 0;
}

static int object_set_path(struct object *object, const char *directory_path,
			   const char *entry_name) {
	int path_length;

	path_length = snprintf(NULL, 0, "%s/%s", directory_path, entry_name);

	if ((unsigned int)path_length <= sizeof(object->path_array) - 1) {
		object_set_path_array(object, directory_path, entry_name);
		return 0;
	}

	return object_set_path_ptr(object, directory_path, entry_name,
				   path_length);
}

static int object_stat(const struct storage *storage, struct object *object) {
	struct yaffs_stat stat;
	int ret;

	ret = yaffs_lstat_reldev((struct yaffs_dev *)storage,
				 object_get_path(object), &stat);
	if (ret < 0) {
		ret = util_get_yaffs_errno();
		log_error(ret, "yaffs_lstat_reldev() failed for '%s'",
			  object_get_path(object));
		return ret;
	}

	if (S_ISREG(stat.st_mode)) {
		object->type = LIST_OBJECT_TYPE_FILE;
	} else if (S_ISDIR(stat.st_mode)) {
		object->type = LIST_OBJECT_TYPE_DIRECTORY;
	} else if (S_ISLNK(stat.st_mode)) {
		object->type = LIST_OBJECT_TYPE_SYMLINK;
	}

	object->mode = stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
	object->size = stat.st_size;
	object->mtime = stat.yst_mtime;

	return 0;
}

static int object_initialize_child(struct object *object,
				   const struct storage *storage,
				   const char *directory_path,
				   const char *entry_name) {
	int ret;

	ret = object_set_path(object, directory_path, entry_name);
	if (ret < 0) {
		return ret;
	}

	return object_stat(storage, object);
}

static int object_create_from_directory_entry(
	const struct storage *storage, struct object *parent_object,
	const struct yaffs_dirent *directory_entry, struct object **objectp) {
	struct object *object;
	int ret;

	ret = object_get_child(parent_object, &object);
	if (ret < 0) {
		return ret;
	}

	ret = object_initialize_child(object, storage,
				      object_get_path(parent_object),
				      directory_entry->d_name);
	if (ret < 0) {
		return ret;
	}

	*objectp = object;

	return 0;
}

static int object_process_file(struct object *object,
			       const struct storage *storage) {
	struct object_file *file = &object->data.file;
	(void)storage;

	file->executable = !!(object->mode & S_IXUSR);

	return 0;
}

static int object_process_directory(struct object *object,
				    const struct storage *storage) {
	return object_recursive_discover(object, storage);
}

static int object_get_symlink_target(const struct object *object,
				     const struct storage *storage,
				     char *symlink_target,
				     size_t symlink_target_size) {
	int ret;

	ret = yaffs_readlink_reldir(((struct yaffs_dev *)storage)->root_dir,
				    object_get_path(object), symlink_target,
				    symlink_target_size);
	if (ret < 0) {
		ret = util_get_yaffs_errno();
		log_error(ret, "yaffs_readlink() failed for '%s'",
			  object_get_path(object));
	}

	return ret;
}

static int object_set_symlink_target(struct object *object,
				     const char *symlink_target) {
	struct object_symlink *symlink = &object->data.symlink;
	size_t symlink_target_size = object->size + 1;

	symlink->target = calloc(1, symlink_target_size);
	if (!symlink->target) {
		return -ENOMEM;
	}

	(void)snprintf(symlink->target, symlink_target_size, "%s",
		       symlink_target);

	return 0;
}

static void object_detect_broken_symlink(struct object *object,
					 const struct storage *storage) {

	struct yaffs_stat stat;
	int ret;

	ret = yaffs_lstat_reldev((struct yaffs_dev *)storage,
				 object->data.symlink.target, &stat);
	if (ret < 0) {
		object->data.symlink.broken = true;
	}
}

static int object_process_symlink(struct object *object,
				  const struct storage *storage) {
	char symlink_target[256];
	int ret;

	ret = object_get_symlink_target(object, storage, symlink_target,
					sizeof(symlink_target));
	if (ret < 0) {
		return ret;
	}

	object_set_symlink_target(object, symlink_target);

	object_detect_broken_symlink(object, storage);

	return 0;
}

static int (*const object_process_callbacks[])(struct object *,
					       const struct storage *)
	= {
		[LIST_OBJECT_TYPE_FILE] = object_process_file,
		[LIST_OBJECT_TYPE_DIRECTORY] = object_process_directory,
		[LIST_OBJECT_TYPE_SYMLINK] = object_process_symlink,
};

static int object_process(struct object *object,
			  const struct storage *storage) {
	int (*process_callback)(struct object *, const struct storage *);

	process_callback = object_process_callbacks[object->type];
	if (!process_callback) {
		return 0;
	}

	return (process_callback)(object, storage);
}

static int
object_process_directory_entry(const struct storage *storage,
			       struct object *parent_object,
			       const struct yaffs_dirent *directory_entry) {
	struct object *object;
	int ret;

	ret = object_create_from_directory_entry(storage, parent_object,
						 directory_entry, &object);
	if (ret < 0) {
		return ret;
	}

	return object_process(object, storage);
}

static int object_recursive_discover(struct object *object,
				     const struct storage *storage) {
	const char *parent_path = object_get_path(object);
	struct yaffs_dirent *directory_entry;
	yaffs_DIR *dir;
	int ret = 0;

	dir = yaffs_opendir_reldev((struct yaffs_dev *)storage, parent_path);
	if (!dir) {
		ret = util_get_yaffs_errno();
		log_error(ret, "error opening directory '%s'", parent_path);
		return ret;
	}

	while ((directory_entry = yaffs_readdir(dir))) {
		ret = object_process_directory_entry(storage, object,
						     directory_entry);
		if (ret < 0) {
			break;
		}
	}

	yaffs_closedir(dir);

	return ret;
}

static bool object_is_directory(const struct object *object) {
	switch (object->type) {
	case LIST_OBJECT_TYPE_ROOT:
	case LIST_OBJECT_TYPE_DIRECTORY:
		return true;
	default:
		return false;
	}
}

static int object_compare(const void *pointer1, const void *pointer2) {
	const struct object *object1 = pointer1;
	const struct object *object2 = pointer2;

	return strcasecmp(object_get_path(object1), object_get_path(object2));
}

static void object_recursive_sort(struct object *object) {
	struct object_directory *directory = &object->data.directory;

	if (!object_is_directory(object)) {
		return;
	}

	qsort(directory->children, directory->children_count,
	      sizeof(directory->children[0]), object_compare);

	for (unsigned int i = 0; i < directory->children_count; i++) {
		object_recursive_sort(&directory->children[i]);
	}
}

int object_recursive_prepare(struct object *object,
			     const struct storage *storage) {
	int ret;

	ret = object_recursive_discover(object, storage);
	if (ret < 0) {
		return ret;
	}

	object_recursive_sort(object);

	return 0;
}

static int object_call(const struct object *object,
		       int (*callback)(const struct object *, void *),
		       void *callback_data) {
	if (object->type == LIST_OBJECT_TYPE_ROOT) {
		return 0;
	}

	return callback(object, callback_data);
}

static int object_call_for_children(const struct object *object,
				    int (*callback)(const struct object *,
						    void *),
				    void *callback_data) {
	const struct object_directory *directory = &object->data.directory;
	int ret;

	if (!object_is_directory(object)) {
		return 0;
	}

	for (unsigned int i = 0; i < directory->children_count; i++) {
		ret = object_recursive_call(&directory->children[i], callback,
					    callback_data);
		if (ret < 0) {
			return ret;
		}
	}

	return 0;
}

int object_recursive_call(const struct object *object,
			  int (*callback)(const struct object *, void *),
			  void *callback_data) {
	int ret;

	ret = object_call(object, callback, callback_data);
	if (ret < 0) {
		return ret;
	}

	return object_call_for_children(object, callback, callback_data);
}
