// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <yaffs_guts.h>

#include "options.h"
#include "ydriver.h"

struct layout;

struct layout_callbacks {
	int (*get_total_size)(void *callback_data, unsigned int *total_sizep);
	int (*get_block_size)(void *callback_data, unsigned int *block_sizep);
	int (*get_chunk_size)(void *callback_data, unsigned int *chunk_sizep);
	int (*get_oob_size)(void *callback_data, unsigned int *oob_sizep);
	int (*get_oob_available)(void *callback_data,
				 unsigned int *oob_availablep);
};

int layout_create(struct layout **layoutp);
void layout_destroy(struct layout **layoutp);

int layout_prepare(struct layout *layout,
		   const struct layout_callbacks *callbacks,
		   void *callback_data, const struct opts *opts);

void layout_to_yaffs_parameters(const struct layout *layout,
				struct yaffs_param *yaffs_parameters);
void layout_to_ydriver_data(const struct layout *layout,
			    struct ydriver_data *ydriver_data);
