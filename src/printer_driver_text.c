// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "object.h"
#include "printer_driver.h"
#include "printer_driver_text.h"
#include "util.h"

#define LS_COLORS_MAX_PATTERN_LENGTH 32
#define LS_COLORS_MAX_COLOR_CODE_LENGTH 32

struct printer_text_data_color {
	const char *mnemonic;
	const char *code;
	char code_array[LS_COLORS_MAX_COLOR_CODE_LENGTH];
};

struct printer_text_data {
	struct printer_text_data_colors {
		struct printer_text_data_color file;
		struct printer_text_data_color executable;
		struct printer_text_data_color directory;
		struct printer_text_data_color symlink;
		struct printer_text_data_color symlink_broken;
		bool enable;
	} colors;
};

static void printer_text_colors_init(struct printer_text_data *text_data) {
	text_data->colors = (struct printer_text_data_colors){
		.file = {.mnemonic = "fi"},
		.executable = {.mnemonic = "ex", .code = "1;32"},
		.directory = {.mnemonic = "di", .code = "1;34"},
		.symlink = {.mnemonic = "ln", .code = "1;36"},
		.symlink_broken = {.mnemonic = "mi", .code = "1;31"},
		.enable = true,

	};
}

static void printer_text_LS_COLORS_find(const char *env_colors,
					struct printer_text_data_color *color) {
	const char *string = env_colors;
	char pattern[LS_COLORS_MAX_PATTERN_LENGTH];
	char color_code[LS_COLORS_MAX_COLOR_CODE_LENGTH];

	while (!util_get_tokens(&string, "=:", 2, pattern, sizeof(pattern),
				color_code, sizeof(color_code))) {
		if (!strcmp(pattern, color->mnemonic)) {
			(void)snprintf(color->code_array,
				       sizeof(color->code_array), "%s",
				       color_code);
			color->code = color->code_array;
			return;
		}
	}
}

static void printer_text_LS_COLORS_parse(struct printer_text_data *text_data) {
	struct printer_text_data_colors *colors = &text_data->colors;
	char *env_colors;

	env_colors = getenv("LS_COLORS");
	if (!env_colors) {
		return;
	}

	printer_text_LS_COLORS_find(env_colors, &colors->file);
	printer_text_LS_COLORS_find(env_colors, &colors->executable);
	printer_text_LS_COLORS_find(env_colors, &colors->directory);
	printer_text_LS_COLORS_find(env_colors, &colors->symlink);
	printer_text_LS_COLORS_find(env_colors, &colors->symlink_broken);
}

static void printer_text_colors_setup(struct printer_text_data *text_data) {
	printer_text_colors_init(text_data);
	printer_text_LS_COLORS_parse(text_data);
}

static int
printer_text_process_option_color(const char *value,
				  struct printer_text_data *text_data) {
	unsigned int value_number;
	int ret;

	ret = util_parse_number(value, 10, &value_number);
	if (ret < 0) {
		return ret;
	}

	if (value_number == 1) {
		printer_text_colors_setup(text_data);
	}

	return 0;
}

static int printer_text_process_option(const char *name, const char *value,
				       struct printer_text_data *text_data) {
	if (!strcmp(name, "color")) {
		return printer_text_process_option_color(value, text_data);
	}

	log("unknown option '%s'", name);

	return -EINVAL;
}

static int printer_text_parse_option(const char **optionsp,
				     struct printer_text_data *text_data,
				     bool *donep) {
	char name[16];
	char value[2];
	int ret;

	ret = util_get_tokens(optionsp, "=,", 2, name, sizeof(name), value,
			      sizeof(value));
	switch (ret) {
	case 0:
		ret = printer_text_process_option(name, value, text_data);
		*donep = (ret < 0);
		return ret;
	case -EPIPE:
		*donep = true;
		return 0;
	default:
		log_error(ret, "error parsing options near '%s'", *optionsp);
		*donep = true;
		return ret;
	}
}

static int printer_text_parse_options(const char *options,
				      struct printer_text_data *text_data) {
	const char *string = options;
	bool done;
	int ret;

	do {
		ret = printer_text_parse_option(&string, text_data, &done);
	} while (!done);

	return ret;
}

static int printer_text_instantiate(const char *options, void **driver_datap) {
	struct printer_text_data *text_data;
	int ret;

	text_data = calloc(1, sizeof(*text_data));
	if (!text_data) {
		return -ENOMEM;
	}

	ret = printer_text_parse_options(options, text_data);
	if (ret < 0) {
		free(text_data);
		return ret;
	}

	*driver_datap = text_data;

	return 0;
}

static void printer_text_destroy(void **driver_datap) {
	struct printer_text_data *text_data = *driver_datap;

	*driver_datap = NULL;

	free(text_data);
}

static char printer_text_get_type_char(const struct object *object) {
	switch (object->type) {
	case LIST_OBJECT_TYPE_DIRECTORY:
		return 'd';
	case LIST_OBJECT_TYPE_SYMLINK:
		return 'l';
	default:
		return '-';
	}
}

static void printer_text_print_mode(const struct object *object) {
	printf("%c%c%c%c%c%c%c%c%c%c", printer_text_get_type_char(object),
	       (object->mode & S_IRUSR) ? 'r' : '-',
	       (object->mode & S_IWUSR) ? 'w' : '-',
	       (object->mode & S_IXUSR) ? 'x' : '-',
	       (object->mode & S_IRGRP) ? 'r' : '-',
	       (object->mode & S_IWGRP) ? 'w' : '-',
	       (object->mode & S_IXGRP) ? 'x' : '-',
	       (object->mode & S_IROTH) ? 'r' : '-',
	       (object->mode & S_IWOTH) ? 'w' : '-',
	       (object->mode & S_IXOTH) ? 'x' : '-');
}

static void printer_text_print_size(const struct object *object) {
	printf("%8llu", object->size);
}

static void printer_text_print_mtime(const struct object *object) {
	struct tm *mtime = gmtime((const time_t *)&object->mtime);
	char mtime_formatted[32];

	(void)strftime(mtime_formatted, sizeof(mtime_formatted),
		       "%Y-%m-%d %H:%M:%S", mtime);

	printf("%s", mtime_formatted);
}

static const char *
printer_text_get_object_color(const struct object *object,
			      const struct printer_text_data *text_data) {
	const struct printer_text_data_colors *colors = &text_data->colors;

	switch (object->type) {
	case LIST_OBJECT_TYPE_FILE:
		if (object->data.file.executable && colors->executable.code) {
			return colors->executable.code;
		}
		return colors->file.code ?: "0";
	case LIST_OBJECT_TYPE_DIRECTORY:
		return colors->directory.code ?: "0";
	case LIST_OBJECT_TYPE_SYMLINK:
		if (object->data.symlink.broken
		    && colors->symlink_broken.code) {
			return colors->symlink_broken.code;
		}
		return text_data->colors.symlink.code ?: "0";
	default:
		return "0";
	}
}

static void printer_text_print_colored_string(const char *string,
					      const char *color) {
	if (color) {
		printf("\e[%sm", color);
	}

	printf("%s", string);

	if (color) {
		printf("\e[0m");
	}
}

static void printer_text_print_path(const struct object *object,
				    const struct printer_text_data *text_data) {
	const char *color = NULL;

	if (text_data->colors.enable) {
		color = printer_text_get_object_color(object, text_data);
	}

	printer_text_print_colored_string(object_get_path(object), color);

	if (object->type == LIST_OBJECT_TYPE_SYMLINK) {
		printf(" -> ");
		printer_text_print_colored_string(object->data.symlink.target,
						  color);
	}
}

static int printer_text_print_object(const struct object *object, void *data) {
	const struct printer_text_data *text_data = data;

	printer_text_print_mode(object);
	printf("  ");
	printer_text_print_size(object);
	printf("  ");
	printer_text_print_mtime(object);
	printf("  ");
	printer_text_print_path(object, text_data);
	printf("\n");

	return 0;
}

static const struct printer_ops printer_text_ops = {
	.print_object = printer_text_print_object,
};

const struct printer_driver printer_driver_text = {
	.name = "text",
	.instantiate = printer_text_instantiate,
	.destroy = printer_text_destroy,
	.ops = &printer_text_ops,
};
