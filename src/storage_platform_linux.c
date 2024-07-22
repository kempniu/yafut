// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <mtd/mtd-user.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "ioctl.h"
#include "log.h"
#include "storage_driver.h"
#include "storage_driver_image.h"
#include "storage_driver_nand.h"
#include "storage_driver_nor.h"
#include "storage_platform.h"
#include "util.h"

const struct storage_driver *storage_platform_drivers[] = {
	&storage_driver_nand,
	&storage_driver_nor,
	&storage_driver_image,
	NULL,
};

static int storage_platform_data_get_mtd_info(struct storage *storage,
					      struct mtd_info_user *mtd_info) {
	int ret;

	ret = linux_ioctl(storage->fd, MEMGETINFO, mtd_info);
	if (ret < 0) {
		ret = util_get_errno();
		log_debug("unable to get MTD information for %s (error %d: %s)",
			  storage->path, ret, util_get_error(ret));
		return ret;
	}

	log_debug("type=%d, flags=0x%08x, size=%d, erasesize=%d, writesize=%d, "
		  "oobsize=%d",
		  mtd_info->type, mtd_info->flags, mtd_info->size,
		  mtd_info->erasesize, mtd_info->writesize, mtd_info->oobsize);

	return 0;
}

static int storage_platform_data_instantiate(struct storage *storage) {
	struct mtd_info_user *mtd_info;
	int ret;

	mtd_info = calloc(1, sizeof(*mtd_info));
	if (!mtd_info) {
		return -ENOMEM;
	}

	ret = storage_platform_data_get_mtd_info(storage, mtd_info);
	if (ret < 0) {
		free(mtd_info);
		return ret;
	}

	storage->probe_info.platform_data = mtd_info;

	return 0;
}

int storage_platform_probe(struct storage *storage) {
	if (!S_ISCHR(storage->probe_info.stat.st_mode)) {
		log_debug("%s is not a character device, ioctls suppressed",
			  storage->path);
		return 0;
	}

	return storage_platform_data_instantiate(storage);
}

void storage_platform_destroy(struct storage *storage) {
	free(storage->probe_info.platform_data);
}
