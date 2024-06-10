// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include "options.h"

int copy_read_file_from_mtd(const struct opts *opts);
int copy_write_file_to_mtd(const struct opts *opts);

int copy_file_based_on_opts(const struct opts *opts);
