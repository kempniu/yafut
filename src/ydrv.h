// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <yaffs_guts.h>

enum ydrv_mtd_type {
	MTD_TYPE_NAND,
	MTD_TYPE_NOR,
};

int ydrv_init(struct yaffs_dev *yaffs_dev, int mtd_fd,
	      enum ydrv_mtd_type mtd_type, unsigned int chunk_size,
	      unsigned int block_size);
void ydrv_destroy(struct yaffs_dev *yaffs_dev);
