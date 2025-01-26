// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include "object.h"
#include "options.h"

struct printer;

int printer_instantiate(const struct opts *opts, struct printer **printerp);
void printer_destroy(struct printer **printerp);

int printer_print_object(const struct object *object, void *data);
