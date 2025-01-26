// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include "object.h"

struct printer_ops {
	int (*print_object)(const struct object *object, void *data);
};

struct printer_driver {
	const char *name;
	int (*instantiate)(const char *options, void **driver_datap);
	void (*destroy)(void **driver_datap);
	const struct printer_ops *ops;
};
