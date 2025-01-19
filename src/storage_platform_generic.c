// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <stddef.h>

#include "storage_driver.h"
#include "storage_driver_image.h"
#include "storage_platform.h"

const struct storage_driver *storage_platform_drivers[] = {
	&storage_driver_image,
	NULL,
};

int storage_platform_probe(struct storage *storage) {
	(void)storage;

	return 0;
}

void storage_platform_destroy(struct storage *storage) {
	(void)storage;
}
