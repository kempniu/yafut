// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "layout.h"
#include "log.h"
#include "storage_driver.h"
#include "ydriver.h"
#include "ydriver_posix.h"

static bool storage_image_match(const struct storage_probe_info *probe_info) {
	return S_ISREG(probe_info->stat.st_mode);
}

static int storage_image_get_total_size(void *callback_data,
					unsigned int *total_sizep) {
	struct storage *storage = callback_data;

	*total_sizep = storage->probe_info.stat.st_size;
	log_debug("detected storage size: %u bytes", *total_sizep);

	return 0;
}

static const struct layout_callbacks storage_image_layout_callbacks = {
	.get_total_size = storage_image_get_total_size,
};

static const struct ydriver_callbacks storage_image_ydriver_callbacks = {
	.check_bad = ydriver_posix_always_ok,
	.erase_block = ydriver_posix_erase_block,
	.mark_bad = ydriver_posix_always_fail,
	.read_chunk = ydriver_posix_read_chunk,
	.write_chunk = ydriver_posix_write_chunk,
};

const struct storage_driver storage_driver_image = {
	.name = "image",
	.match = storage_image_match,
	.layout_callbacks = &storage_image_layout_callbacks,
	.ydriver_callbacks = &storage_image_ydriver_callbacks,
};
