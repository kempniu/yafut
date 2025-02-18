// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "options.h"
#include "printer.h"
#include "printer_driver.h"
#include "printer_driver_text.h"
#include "util.h"

struct printer {
	const struct printer_ops *ops;
	void *driver_data;
	void (*destroy_callback)(void **driver_datap);
};

static const struct printer_driver *printer_drivers[] = {
	&printer_driver_text,
	NULL,
};

static int printer_driver_parse(const struct opts *opts, char *driver_name,
				size_t driver_name_size, char *driver_options,
				size_t driver_options_size) {
	const char *string = opts->output_format;
	int ret;

	ret = util_get_tokens(&string, ":", 2, driver_name, driver_name_size,
			      driver_options, driver_options_size);
	switch (ret) {
	case 0:
	case -EINTR:
		return 0;
	default:
		log_error(ret, "failed to parse output format '%s'",
			  opts->output_format);
		return ret;
	}
}

static int printer_driver_match(const char *driver_name,
				const struct printer_driver **driverp) {
	for (int i = 0; printer_drivers[i] != NULL; i++) {
		const struct printer_driver *driver = printer_drivers[i];

		if (!strcmp(driver->name, driver_name)) {
			*driverp = driver;
			return 0;
		}
	}

	log("unknown output format '%s'", driver_name);

	return -EINVAL;
}

static int printer_driver_instantiate(const struct printer_driver *driver,
				      const char *driver_options,
				      void **driver_datap) {
	if (!driver->instantiate) {
		*driver_datap = NULL;
		return 0;
	}

	return driver->instantiate(driver_options, driver_datap);
}

static int printer_instantiate_with_options(const struct printer_driver *driver,
					    const char *driver_options,
					    struct printer **printerp) {
	struct printer *printer;
	void *driver_data;
	int ret;

	printer = calloc(1, sizeof(*printer));
	if (!printer) {
		return -ENOMEM;
	}

	ret = printer_driver_instantiate(driver, driver_options, &driver_data);
	if (ret < 0) {
		free(printer);
		return ret;
	}

	*printer = (struct printer){
		.ops = driver->ops,
		.driver_data = driver_data,
		.destroy_callback = driver->destroy,
	};

	*printerp = printer;

	return 0;
}

int printer_instantiate(const struct opts *opts, struct printer **printerp) {
	const struct printer_driver *driver;
	char driver_name[16] = {0};
	char driver_options[48] = {0};
	int ret;

	ret = printer_driver_parse(opts, driver_name, sizeof(driver_name),
				   driver_options, sizeof(driver_options));
	if (ret < 0) {
		return ret;
	}

	ret = printer_driver_match(driver_name, &driver);
	if (ret < 0) {
		return ret;
	}

	return printer_instantiate_with_options(driver, driver_options,
						printerp);
}

void printer_destroy(struct printer **printerp) {
	struct printer *printer = *printerp;

	*printerp = NULL;

	if (printer->destroy_callback) {
		printer->destroy_callback(&printer->driver_data);
	}

	free(printer);
}

int printer_print_object(const struct object *object, void *data) {
	const struct printer *printer = data;

	return printer->ops->print_object(object, printer->driver_data);
}
