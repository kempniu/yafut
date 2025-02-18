// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <yaffsfs.h>

#include "log.h"
#include "object.h"
#include "options.h"
#include "printer.h"
#include "storage.h"
#include "tree.h"
#include "util.h"

static int tree_mount(const struct opts *opts, struct storage **storagep) {
	struct storage *storage;
	int ret;

	ret = storage_instantiate(opts, &storage);
	if (ret < 0) {
		return ret;
	}

	ret = yaffs_mount_reldev((struct yaffs_dev *)storage);
	if (ret < 0) {
		ret = util_get_yaffs_errno();
		log_error(ret, "unable to mount Yaffs filesystem");
		storage_destroy(&storage);
		return ret;
	}

	*storagep = storage;

	return 0;
}

static void tree_unmount(struct storage **storagep) {
	struct storage *storage = *storagep;
	int ret;

	ret = yaffs_unmount_reldev((struct yaffs_dev *)storage);
	if (ret < 0) {
		ret = util_get_yaffs_errno();
		log_error(ret, "error unmounting Yaffs filesystem");
	}

	storage_destroy(storagep);
}

static int tree_print_with_printer(const struct storage *storage,
				   const struct printer *printer) {
	struct object *tree_root;
	int ret;

	ret = object_recursive_instantiate(&tree_root);
	if (ret < 0) {
		return ret;
	}

	ret = object_recursive_prepare(tree_root, storage);
	if (ret < 0) {
		object_recursive_destroy(&tree_root);
		return ret;
	}

	ret = object_recursive_call(tree_root, printer_print_object,
				    (void *)printer);

	object_recursive_destroy(&tree_root);

	return ret;
}

static int tree_print(const struct opts *opts, const struct storage *storage) {
	struct printer *printer;
	int ret;

	ret = printer_instantiate(opts, &printer);
	if (ret < 0) {
		return ret;
	}

	ret = tree_print_with_printer(storage, printer);

	printer_destroy(&printer);

	return ret;
}

int tree_print_based_on_opts(const struct opts *opts) {
	struct storage *storage;
	int ret;

	ret = tree_mount(opts, &storage);
	if (ret < 0) {
		return ret;
	}

	ret = tree_print(opts, storage);

	tree_unmount(&storage);

	return ret;
}
