// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include "options.h"

struct storage;

int storage_instantiate(const struct opts *opts, struct storage **storagep);
void storage_destroy(struct storage **storagep);
