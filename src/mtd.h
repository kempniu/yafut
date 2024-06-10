// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <unistd.h>

#include "options.h"

struct mtd_ctx;

int mtd_mount(const struct opts *opts, struct mtd_ctx **ctxp);
void mtd_unmount(struct mtd_ctx **ctxp);

int mtd_file_open_read(const struct mtd_ctx *ctx, const char *path, int *fd);
int mtd_file_open_write(const struct mtd_ctx *ctx, const char *path, int *fd);
void mtd_file_close(const struct mtd_ctx *ctx, int fd);
ssize_t mtd_file_read(const struct mtd_ctx *ctx, int fd, unsigned char *buf,
		      size_t count);
ssize_t mtd_file_write(const struct mtd_ctx *ctx, int fd,
		       const unsigned char *buf, size_t count);
int mtd_file_get_mode(const struct mtd_ctx *ctx, int fd);
int mtd_file_set_mode(const struct mtd_ctx *ctx, int fd, int mode);

struct yaffs_dev *mtd_get_device(const struct mtd_ctx *ctx);
