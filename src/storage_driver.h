// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <mtd/mtd-user.h>
#include <sys/stat.h>

#include "layout.h"
#include "ydriver.h"

/*
 * The structure passed to each storage driver during the storage driver
 * selection stage.  The driver's match() callback inspects this structure (and
 * this structure only) to determine whether it is able to handle the type of
 * storage used.
 */
struct storage_probe_info {
	struct stat stat;
	struct mtd_info_user mtd_info;
};

/*
 * Every storage driver needs to define:
 *
 *   - a callback matching it to a particular storage type,
 *   - a set of callbacks providing the layout module with the inputs it needs,
 *   - a set of callbacks to be invoked when Yaffs operations are performed.
 */
struct storage_driver {
	const char *name;
	bool (*match)(const struct storage_probe_info *probe_info);
	const struct layout_callbacks *layout_callbacks;
	const struct ydriver_callbacks *ydriver_callbacks;
};

/*
 * The structure describing a storage device.  The struct yaffs_dev field needs
 * to be the first one in this structure so that higher-level layers can simply
 * cast a 'struct storage *' to a 'struct yaffs_dev *' and use it with the
 * appropriate Yaffs APIs.  This structure is also passed to the
 * 'layout_callbacks' defined by each storage driver.
 */
struct storage {
	struct yaffs_dev yaffs_device;
	const char *path;
	int fd;
	struct storage_probe_info probe_info;
	const struct storage_driver *driver;
	struct ydriver_data ydriver_data;
	const struct opts *opts;
};
