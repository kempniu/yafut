// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <yaffs_guts.h>

#include "layout.h"
#include "log.h"
#include "options.h"
#include "storage.h"
#include "storage_driver.h"
#include "storage_platform.h"
#include "util.h"
#include "ydriver.h"

/*
 * This module serves as a focal point for lower-level abstraction layers,
 * combining the data they provide into a ready-to-use struct yaffs_dev that
 * can be mounted by higher-level layers using the appropriate Yaffs APIs.
 *
 * The high-level flow used for preparing a struct yaffs_dev is as follows:
 *
 *   - various bits of structured information are collected about the
 *     device/file passed via the -d command-line option,
 *
 *   - the storage driver to use is determined based on the information
 *     collected in the previous step,
 *
 *   - the Yaffs parameters to use are determined by passing the callbacks
 *     provided by the selected storage driver to the layout module,
 *
 *   - the Yaffs driver is set up with callbacks provided by the selected
 *     storage driver and a data structure containing layout information.
 */

static void storage_init(struct storage *storage, const struct opts *opts) {
	*storage = (struct storage){
		.path = opts->device_path,
		.opts = opts,
	};
}

static int storage_open(struct storage *storage) {
	int flags;
	int ret;

	flags = (storage->opts->mode == PROGRAM_MODE_READ ? O_RDONLY : O_RDWR);
	storage->fd = open(storage->path, flags);
	if (storage->fd < 0) {
		ret = util_get_errno();
		log_error(ret, "unable to open '%s'", storage->path);
		return ret;
	}

	return 0;
}

static void storage_close(struct storage *storage) {
	close(storage->fd);
}

static int storage_probe_stat(struct storage *storage) {
	struct stat *stat = &storage->probe_info.stat;
	int ret;

	ret = fstat(storage->fd, stat);
	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "unable to fstat() '%s'", storage->path);
		return ret;
	}

	log_debug("st_mode=%x, st_size=%ld", stat->st_mode, stat->st_size);

	return 0;
}

static int storage_probe(struct storage *storage) {
	int ret;

	ret = storage_probe_stat(storage);
	if (ret < 0) {
		return ret;
	}

	return storage_platform_probe(storage);
}

static int storage_match_driver(struct storage *storage) {
	const struct storage_driver *driver;

	for (int i = 0; storage_platform_drivers[i] != NULL; i++) {
		driver = storage_platform_drivers[i];

		log_debug("trying driver %s", driver->name);

		if (driver->match(&storage->probe_info)) {
			log_debug("matched driver %s", driver->name);
			storage->driver = driver;
			return 0;
		}
	}

	log("unable to find a driver for %s", storage->path);

	return -ENODEV;
}

static int storage_setup_driver(struct storage *storage) {
	int ret;

	ret = storage_probe(storage);
	if (ret < 0) {
		return ret;
	}

	return storage_match_driver(storage);
}

static int storage_setup_yaffs_layout(struct storage *storage) {
	struct layout *layout;
	int ret;

	ret = layout_create(&layout);
	if (ret < 0) {
		return ret;
	}

	ret = layout_prepare(layout, storage->driver->layout_callbacks, storage,
			     storage->opts);
	if (ret < 0) {
		layout_destroy(&layout);
		return ret;
	}

	layout_to_yaffs_parameters(layout, &storage->yaffs_device.param);
	layout_to_ydriver_data(layout, &storage->ydriver_data);

	layout_destroy(&layout);

	return 0;
}

static void storage_setup_yaffs_driver(struct storage *storage) {
	storage->ydriver_data.fd = storage->fd;
	storage->ydriver_data.callbacks = storage->driver->ydriver_callbacks;
	storage->yaffs_device.driver_context = &storage->ydriver_data;
	storage->yaffs_device.drv = ydriver;
}

static int storage_setup_yaffs(struct storage *storage) {
	int ret;

	ret = storage_setup_yaffs_layout(storage);
	if (ret < 0) {
		return ret;
	}

	storage_setup_yaffs_driver(storage);

	return 0;
}

static int storage_setup_device(struct storage *storage) {
	int ret;

	ret = storage_setup_driver(storage);
	if (ret < 0) {
		return ret;
	}

	return storage_setup_yaffs(storage);
}

static int storage_prepare(struct storage *storage, const struct opts *opts) {
	int ret;

	storage_init(storage, opts);

	ret = storage_open(storage);
	if (ret < 0) {
		return ret;
	}

	ret = storage_setup_device(storage);
	if (ret < 0) {
		storage_close(storage);
		storage_platform_destroy(storage);
	}

	return ret;
}

int storage_instantiate(const struct opts *opts, struct storage **storagep) {
	struct storage *storage;
	int ret;

	storage = calloc(1, sizeof(*storage));
	if (!storage) {
		return -ENOMEM;
	}

	ret = storage_prepare(storage, opts);
	if (ret < 0) {
		free(storage);
		return ret;
	}

	*storagep = storage;

	return 0;
}

void storage_destroy(struct storage **storagep) {
	struct storage *storage = *storagep;

	*storagep = NULL;

	storage_close(storage);
	storage_platform_destroy(storage);

	free(storage);
}
