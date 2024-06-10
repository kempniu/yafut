// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include "options.h"

struct mtd_ctx;

int mtd_mount(const struct opts *opts, struct mtd_ctx **ctxp);
void mtd_unmount(struct mtd_ctx **ctxp);

struct yaffs_dev *mtd_get_device(const struct mtd_ctx *ctx);
