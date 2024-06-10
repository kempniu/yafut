// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "layout.h"
#include "log.h"
#include "storage_driver.h"
#include "ydriver.h"
#include "ydriver_ioctl.h"
#include "ydriver_posix.h"

static bool storage_nor_match(const struct storage_probe_info *probe_info) {
	return (S_ISCHR(probe_info->stat.st_mode)
		&& probe_info->mtd_info.oobsize == 0
		&& probe_info->mtd_info.writesize == 1);
}

static int storage_nor_get_total_size(void *callback_data,
				      unsigned int *total_sizep) {
	struct storage *storage = callback_data;

	*total_sizep = storage->probe_info.mtd_info.size;
	log_debug("detected storage size: %u bytes", *total_sizep);

	return 0;
}

static const struct layout_callbacks storage_nor_layout_callbacks = {
	.get_total_size = storage_nor_get_total_size,
};

static const struct ydriver_callbacks storage_nor_ydriver_callbacks = {
	.check_bad = ydriver_ioctl_check_bad,
	.erase_block = ydriver_ioctl_erase_block,
	.mark_bad = ydriver_ioctl_mark_bad,
	.read_chunk = ydriver_posix_read_chunk,
	.write_chunk = ydriver_posix_write_chunk,
};

const struct storage_driver storage_driver_nor = {
	.name = "NOR",
	.match = storage_nor_match,
	.layout_callbacks = &storage_nor_layout_callbacks,
	.ydriver_callbacks = &storage_nor_ydriver_callbacks,
};
