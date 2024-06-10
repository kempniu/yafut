// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "layout.h"
#include "log.h"
#include "storage_driver.h"
#include "util.h"
#include "ydriver.h"
#include "ydriver_ioctl.h"

static bool storage_nand_match(const struct storage_probe_info *probe_info) {
	return (S_ISCHR(probe_info->stat.st_mode)
		&& probe_info->mtd_info.oobsize > 0
		&& probe_info->mtd_info.writesize > 1);
}

static int storage_nand_get_total_size(void *callback_data,
				       unsigned int *total_sizep) {
	struct storage *storage = callback_data;

	*total_sizep = storage->probe_info.mtd_info.size;
	log_debug("detected storage size: %u bytes", *total_sizep);

	return 0;
}

static int storage_nand_get_block_size(void *callback_data,
				       unsigned int *block_sizep) {
	struct storage *storage = callback_data;

	*block_sizep = storage->probe_info.mtd_info.erasesize;
	log_debug("detected block size: %u bytes", *block_sizep);

	return 0;
}

static int storage_nand_get_chunk_size(void *callback_data,
				       unsigned int *chunk_sizep) {
	struct storage *storage = callback_data;

	*chunk_sizep = storage->probe_info.mtd_info.writesize;
	log_debug("detected chunk size: %u bytes", *chunk_sizep);

	return 0;
}

static int storage_nand_get_oob_size(void *callback_data,
				     unsigned int *oob_sizep) {
	struct storage *storage = callback_data;

	*oob_sizep = storage->probe_info.mtd_info.oobsize;
	log_debug("detected OOB data size: %u bytes", *oob_sizep);

	return 0;
}

static int storage_nand_get_oobavail_path(struct storage *storage, char *buf,
					  size_t buf_size) {
	const char *mtd_name;
	char *last_slash;
	int ret;

	last_slash = strrchr(storage->path, '/');
	mtd_name = last_slash ? last_slash + 1 : storage->path;

	ret = snprintf(buf, buf_size, "/sys/class/mtd/%s/oobavail", mtd_name);
	if (ret < 0 || (unsigned int)ret >= buf_size) {
		return -ENOMEM;
	}

	return 0;
}

static int storage_nand_read_oobavail(const char *sysfs_path, char *buf,
				      size_t buf_len) {
	int ret;
	int fd;

	fd = open(sysfs_path, O_RDONLY);
	if (fd < 0) {
		ret = util_get_errno();
		log_error(ret, "unable to open %s", sysfs_path);
		return ret;
	}

	ret = read(fd, buf, buf_len);
	if (ret < 0) {
		ret = util_get_errno();
		log_error(ret, "error reading %s", sysfs_path);
	}

	close(fd);

	return ret;
}

static void storage_nand_trim_string_at_newline(char *buf) {
	char *newline;

	newline = strrchr(buf, '\n');
	if (newline) {
		*newline = '\0';
	}
}

static int storage_nand_get_oob_available_string(struct storage *storage,
						 char *buf) {
	char path[32];
	int ret;

	ret = storage_nand_get_oobavail_path(storage, path, sizeof(path));
	if (ret < 0) {
		return ret;
	}

	ret = storage_nand_read_oobavail(path, buf, sizeof(buf));
	if (ret < 0) {
		return ret;
	}

	storage_nand_trim_string_at_newline(buf);

	return 0;
}

/*
 * Store the value reported by /sys/class/mtd/mtd<X>/oobavail (derived from the
 * device path provided by 'callback_data') in 'oob_availablep'.  That value is
 * not returned by the MEMGETINFO ioctl used during storage probing, so it has
 * to be retrieved in a different way than the other layout parameters.
 */
static int storage_nand_get_oob_available(void *callback_data,
					  unsigned int *oob_availablep) {
	struct storage *storage = callback_data;
	char oobavail_str[16] = {0};
	int ret;

	ret = storage_nand_get_oob_available_string(storage, oobavail_str);
	if (ret < 0) {
		return ret;
	}

	ret = util_parse_number(oobavail_str, 10, oob_availablep);
	if (ret < 0) {
		return ret;
	}

	log_debug("detected available OOB data size: %u bytes",
		  *oob_availablep);

	return 0;
}

static const struct layout_callbacks storage_nand_layout_callbacks = {
	.get_total_size = storage_nand_get_total_size,
	.get_block_size = storage_nand_get_block_size,
	.get_chunk_size = storage_nand_get_chunk_size,
	.get_oob_size = storage_nand_get_oob_size,
	.get_oob_available = storage_nand_get_oob_available,
};

static const struct ydriver_callbacks storage_nand_ydriver_callbacks = {
	.check_bad = ydriver_ioctl_check_bad,
	.erase_block = ydriver_ioctl_erase_block,
	.mark_bad = ydriver_ioctl_mark_bad,
	.read_chunk = ydriver_ioctl_read_chunk,
	.write_chunk = ydriver_ioctl_write_chunk,
};

const struct storage_driver storage_driver_nand = {
	.name = "NAND",
	.match = storage_nand_match,
	.layout_callbacks = &storage_nand_layout_callbacks,
	.ydriver_callbacks = &storage_nand_ydriver_callbacks,
};
