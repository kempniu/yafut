// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <yaffs_guts.h>

int ydrv_init(struct yaffs_dev *yaffs_dev, int mtd_fd, unsigned int chunk_size,
	      unsigned int block_size);
void ydrv_destroy(struct yaffs_dev *yaffs_dev);
