// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>

#include "copy.h"
#include "file.h"
#include "options.h"

struct copy_file {
	struct file_spec spec;
	struct file *file;
};

struct copy_operation {
	struct copy_file src;
	struct copy_file dst;
	const struct opts *opts;
};

static int copy_init(struct copy_operation *copy, const struct opts *opts) {
	*copy = (struct copy_operation){
		.src = {
			.spec = {
				.path = opts->src_path,
				.opts = opts,
			},
		},
		.dst = {
			.spec = {
				.path = opts->dst_path,
				.opts = opts,
			},
		},
		.opts = opts,
	};

	switch (opts->mode) {
	case PROGRAM_MODE_READ:
		copy->src.spec.type = FILE_TYPE_MTD;
		copy->dst.spec.type = FILE_TYPE_POSIX;
		return 0;
	case PROGRAM_MODE_WRITE:
		copy->src.spec.type = FILE_TYPE_POSIX;
		copy->dst.spec.type = FILE_TYPE_MTD;
		return 0;
	default:
		return -EINVAL;
	};
}

static int copy_files_instantiate(struct copy_operation *copy) {
	int ret;

	ret = file_instantiate(&copy->src.spec, &copy->src.file);
	if (ret < 0) {
		return ret;
	}

	ret = file_instantiate(&copy->dst.spec, &copy->dst.file);
	if (ret < 0) {
		file_destroy(&copy->src.file);
	}

	return ret;
}

static void copy_files_destroy(struct copy_operation *copy) {
	file_destroy(&copy->src.file);
	file_destroy(&copy->dst.file);
}

static int copy_files_open(struct copy_operation *copy) {
	int ret;

	ret = file_open_for_reading(copy->src.file);
	if (ret < 0) {
		return ret;
	}

	ret = file_open_for_writing(copy->dst.file);
	if (ret < 0) {
		file_close(copy->src.file);
	}

	return ret;
}

static void copy_files_close(struct copy_operation *copy) {
	file_close(copy->src.file);
	file_close(copy->dst.file);
}

static int copy_prepare_files(struct copy_operation *copy) {
	int ret;

	ret = copy_files_instantiate(copy);
	if (ret < 0) {
		return ret;
	}

	ret = copy_files_open(copy);
	if (ret < 0) {
		copy_files_destroy(copy);
	}

	return ret;
}

static int copy_prepare(struct copy_operation *copy, const struct opts *opts) {
	int ret;

	ret = copy_init(copy, opts);
	if (ret < 0) {
		return ret;
	}

	return copy_prepare_files(copy);
}

static int copy_file_contents(struct copy_operation *copy) {
	unsigned char buf[2048];
	int bytes_written;
	int bytes_read;
	int ret;

	while ((bytes_read = file_read(copy->src.file, buf, sizeof(buf))) > 0) {
		bytes_written = 0;
		do {
			ret = file_write(copy->dst.file, buf + bytes_written,
					 bytes_read - bytes_written);
			if (ret < 0) {
				return ret;
			}

			bytes_written += ret;
		} while (bytes_written < bytes_read);
	}

	if (bytes_read < 0) {
		return bytes_read;
	}

	return 0;
}

static int copy_file_mode(struct copy_operation *copy) {
	int src_mode;
	int ret;

	ret = file_get_mode(copy->src.file, &src_mode);
	if (ret < 0) {
		return ret;
	}

	return file_set_mode(copy->dst.file, src_mode);
}

static int copy_or_set_file_mode(struct copy_operation *copy) {
	if (copy->opts->dst_mode == FILE_MODE_UNSPECIFIED) {
		return copy_file_mode(copy);
	}

	return file_set_mode(copy->dst.file, copy->opts->dst_mode);
}

static int copy_perform(struct copy_operation *copy) {
	int ret;

	ret = copy_file_contents(copy);
	if (ret < 0) {
		return ret;
	}

	return copy_or_set_file_mode(copy);
}

static void copy_destroy(struct copy_operation *copy) {
	copy_files_close(copy);
	copy_files_destroy(copy);
}

int copy_file_based_on_opts(const struct opts *opts) {
	struct copy_operation copy;
	int ret;

	ret = copy_prepare(&copy, opts);
	if (ret < 0) {
		return ret;
	}

	ret = copy_perform(&copy);

	copy_destroy(&copy);

	return ret;
}
