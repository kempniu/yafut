// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <stdio.h>

#include <yaffs_guts.h>
#include <yportenv.h>

#include "log.h"
#include "ydriver.h"

/*
 * Helper macro to reduce code repetition in ydriver_debug_hexdump_location().
 */
#define HEXDUMP_APPEND(fmt, ...)                                               \
	{                                                                      \
		int ret = snprintf(hex + hex_pos, sizeof(hex) - hex_pos, fmt,  \
				   ##__VA_ARGS__);                             \
		if (ret < 0 || (unsigned int)ret >= sizeof(hex) - hex_pos) {   \
			return;                                                \
		}                                                              \
		hex_pos += ret;                                                \
	}

/*
 * Print a hex dump of up to the first 32 bytes of a chunk read or written by a
 * Yaffs driver.  Only used for debugging; requires -v -v to be specified on
 * the command line in order to do anything.
 */
void ydriver_debug_hexdump_location(const char *file, int line,
				    const char *func, const u8 *buf,
				    int buf_len, const char *description) {
	unsigned char hex_pos = 0;
	char hex[128];

	if (log_level < 2 || !buf || buf_len < 1) {
		return;
	}

	for (int i = 0; i < (buf_len < 32 ? buf_len : 32); i++) {
		if (i % 16 == 0) {
			HEXDUMP_APPEND("    ");
		}

		HEXDUMP_APPEND("%02x ", buf[i]);

		if (i % 16 == 15) {
			HEXDUMP_APPEND("\n");
		} else if (i % 8 == 7) {
			HEXDUMP_APPEND(" ");
		}
	}

	log_location(file, line, func, 2, "%s:\n%s%s", description, hex,
		     buf_len > 32 ? "    ..." : "");
}

/*
 * Get the offset at which data starts for the given Yaffs 'chunk', based on
 * the layout information provided in 'ydriver_data'.  This routine is more
 * than a simple multiplication so that it can handle Yaffs layouts in which
 * the block size is not a multiple of the chunk size (with padding between the
 * last chunk in a block and the first chunk of the following block).
 */
long long ydriver_get_data_offset(const struct ydriver_data *ydriver_data,
				  int chunk) {
	unsigned int block_size;
	unsigned int chunk_size;
	unsigned int chunks_per_block;
	unsigned int block;
	unsigned int chunk_in_block;

	block_size = ydriver_data->block_size;
	chunk_size = ydriver_data->chunk_size;

	chunks_per_block = block_size / chunk_size;

	block = chunk / chunks_per_block;
	chunk_in_block = chunk % chunks_per_block;

	return (block * block_size) + (chunk_in_block * chunk_size);
}

/*
 * Helper function for the 'read_chunk' callback of a Yaffs driver that
 * translates the result code of a system call into an <ECC result, Yaffs
 * result code> tuple.  Yaffs uses these values to properly handle deficiencies
 * in flash memory.
 */
int ydriver_get_ecc_result(int read_result, enum yaffs_ecc_result *ecc_result) {
	switch (read_result) {
#if !defined(NO_MTD_DEVICE)
	case -EUCLEAN:
		*ecc_result = YAFFS_ECC_RESULT_FIXED;
		return YAFFS_OK;
	case -EBADMSG:
		*ecc_result = YAFFS_ECC_RESULT_UNFIXED;
		return YAFFS_FAIL;
#endif
	case 0:
		*ecc_result = YAFFS_ECC_RESULT_NO_ERROR;
		return YAFFS_OK;
	default:
		*ecc_result = YAFFS_ECC_RESULT_UNKNOWN;
		return YAFFS_FAIL;
	}
}

static int ydriver_check_bad(struct yaffs_dev *yaffs_device, int block_no) {
	struct ydriver_data *ydriver_data = yaffs_device->driver_context;

	if (block_no < 0) {
		log_debug("block_no=%d", block_no);
		return YAFFS_FAIL;
	}

	return ydriver_data->callbacks->check_bad(ydriver_data, block_no);
}

static int ydriver_erase_block(struct yaffs_dev *yaffs_device, int block_no) {
	struct ydriver_data *ydriver_data = yaffs_device->driver_context;

	if (block_no < 0) {
		log_debug("block_no=%d", block_no);
		return YAFFS_FAIL;
	}

	return ydriver_data->callbacks->erase_block(ydriver_data, block_no);
}

static int ydriver_mark_bad(struct yaffs_dev *yaffs_device, int block_no) {
	struct ydriver_data *ydriver_data = yaffs_device->driver_context;

	if (block_no < 0) {
		log_debug("block_no=%d", block_no);
		return YAFFS_FAIL;
	}

	return ydriver_data->callbacks->mark_bad(ydriver_data, block_no);
}

static int ydriver_read_chunk(struct yaffs_dev *yaffs_device, int chunk,
			      u8 *data, int data_len, u8 *oob, int oob_len,
			      enum yaffs_ecc_result *ecc_result_out) {
	struct ydriver_data *ydriver_data = yaffs_device->driver_context;

	if (chunk < 0 || data_len < 0 || oob_len < 0) {
		log_debug("chunk=%d, data_len=%d, oob_len=%d", chunk, data_len,
			  oob_len);
		return YAFFS_FAIL;
	}

	return ydriver_data->callbacks->read_chunk(ydriver_data, chunk, data,
						   data_len, oob, oob_len,
						   ecc_result_out);
}

static int ydriver_write_chunk(struct yaffs_dev *yaffs_device, int chunk,
			       const u8 *data, int data_len, const u8 *oob,
			       int oob_len) {
	struct ydriver_data *ydriver_data = yaffs_device->driver_context;

	if (chunk < 0 || data_len < 0 || oob_len < 0) {
		log_debug("chunk=%d, data_len=%d, oob_len=%d", chunk, data_len,
			  oob_len);
		return YAFFS_FAIL;
	}

	return ydriver_data->callbacks->write_chunk(ydriver_data, chunk, data,
						    data_len, oob, oob_len);
}

const struct yaffs_driver ydriver = {
	.drv_check_bad_fn = ydriver_check_bad,
	.drv_erase_fn = ydriver_erase_block,
	.drv_mark_bad_fn = ydriver_mark_bad,
	.drv_read_chunk_fn = ydriver_read_chunk,
	.drv_write_chunk_fn = ydriver_write_chunk,
};
