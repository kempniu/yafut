// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include <yaffs_guts.h>
#include <yaffs_packedtags2.h>

#include "layout.h"
#include "log.h"
#include "options.h"

/*
 * The "workspace" for this module.  It encompasses all parameters necessary to
 * describe any storage layout on top of which a Yaffs file system can be
 * built.  Once ready, the structure is used as a source of information for
 * preparing other data structures necessary to set up Yaffs code for operating
 * on a file system.
 *
 * The structure is split up into several parts, corresponding to the
 * stages in which a complete set of layout parameters is arrived at:
 *
 *   - 'constants' are fixed, predefined values that remain unchanged after
 *     being assigned during structure initialization,
 *
 *   - 'variables' are values that are assigned some defaults during structure
 *     initialization, but can be overridden by callbacks provided by storage
 *     drivers,
 *
 *   - 'derived' are values that are computed from other values, provided by
 *     'constants', 'variables', and command-line options.
 */
struct layout {
	struct layout_constants {
		unsigned int start_block;
		unsigned int reserved_blocks;
	} constants;
	struct layout_variables {
		struct layout_variables_values {
			unsigned int total_size;
			unsigned int block_size;
			unsigned int chunk_size;
			unsigned int oob_size;
			unsigned int oob_available;
		} values;
		const struct layout_callbacks *callbacks;
		void *callback_data;
	} variables;
	struct layout_derived {
		unsigned int chunks_per_block;
		unsigned int end_block;
		bool is_yaffs2;
		bool inband_tags;
	} derived;
	const struct opts *opts;
};

static const struct layout_constants layout_constants
	= {.reserved_blocks = 2, .start_block = 0};

static const struct layout_variables_values layout_variables_default = {
	.total_size = 0,
	.block_size = 2048 * 64,
	.chunk_size = 2048,
	.oob_size = 0,
	.oob_available = 0,
};

int layout_create(struct layout **layoutp) {
	struct layout *layout;

	layout = calloc(1, sizeof(*layout));
	if (!layout) {
		return -ENOMEM;
	}

	*layoutp = layout;

	return 0;
}

void layout_destroy(struct layout **layoutp) {
	struct layout *layout = *layoutp;

	*layoutp = NULL;

	free(layout);
}

static void layout_init(struct layout *layout,
			const struct layout_callbacks *callbacks,
			void *callback_data, const struct opts *opts) {
	*layout = (struct layout){
		.constants = layout_constants,
		.variables = { .values = layout_variables_default,
			       .callbacks = callbacks,
			       .callback_data = callback_data, },
		.opts = opts,
	};
}

static int layout_variables_set_total_size(struct layout_variables *variables) {
	return variables->callbacks->get_total_size(
		variables->callback_data, &variables->values.total_size);
}

static int layout_variables_set_block_size(struct layout_variables *variables) {
	if (!variables->callbacks->get_block_size) {
		log_debug("using default block size (%u bytes)",
			  variables->values.block_size);
		return 0;
	}

	return variables->callbacks->get_block_size(
		variables->callback_data, &variables->values.block_size);
}

static int layout_variables_set_chunk_size(struct layout_variables *variables) {
	if (!variables->callbacks->get_chunk_size) {
		log_debug("using default chunk size (%u bytes)",
			  variables->values.chunk_size);
		return 0;
	}

	return variables->callbacks->get_chunk_size(
		variables->callback_data, &variables->values.chunk_size);
}

static int layout_variables_set_oob_size(struct layout_variables *variables) {
	if (!variables->callbacks->get_oob_size) {
		log_debug("using default OOB data size (%u bytes)",
			  variables->values.oob_size);
		return 0;
	}

	return variables->callbacks->get_oob_size(variables->callback_data,
						  &variables->values.oob_size);
}

static int
layout_variables_set_oob_available(struct layout_variables *variables) {
	if (!variables->callbacks->get_oob_available) {
		log_debug("using default available OOB data size (%u bytes)",
			  variables->values.oob_available);
		return 0;
	}

	return variables->callbacks->get_oob_available(
		variables->callback_data, &variables->values.oob_available);
}

static int
layout_variables_set_from_callbacks(struct layout_variables *variables) {
	int ret;

	ret = layout_variables_set_total_size(variables);
	if (ret < 0) {
		return ret;
	}

	ret = layout_variables_set_block_size(variables);
	if (ret < 0) {
		return ret;
	}

	ret = layout_variables_set_chunk_size(variables);
	if (ret < 0) {
		return ret;
	}

	ret = layout_variables_set_oob_size(variables);
	if (ret < 0) {
		return ret;
	}

	return layout_variables_set_oob_available(variables);
}

static void layout_variables_force_block_size(struct layout *layout) {
	if (layout->opts->block_size == SIZE_UNSPECIFIED) {
		return;
	}

	layout->variables.values.block_size = layout->opts->block_size;
	log_debug("block size forced to %u bytes",
		  layout->variables.values.block_size);
}

static void layout_variables_force_chunk_size(struct layout *layout) {
	if (layout->opts->chunk_size == SIZE_UNSPECIFIED) {
		return;
	}

	layout->variables.values.chunk_size = layout->opts->chunk_size;
	log_debug("chunk size forced to %u bytes",
		  layout->variables.values.chunk_size);
}

static void layout_variables_force_from_options(struct layout *layout) {
	layout_variables_force_block_size(layout);
	layout_variables_force_chunk_size(layout);
}

static unsigned int
layout_derive_chunks_per_block(const struct layout_variables *variables) {
	return variables->values.block_size / variables->values.chunk_size;
}

static unsigned int
layout_derive_end_block(const struct layout_variables *variables) {
	return variables->values.total_size / variables->values.block_size - 1;
}

static bool layout_derive_is_yaffs2(const struct layout_variables *variables) {
	return variables->values.chunk_size >= 1024;
}

static bool layout_derive_inband_tags(const struct layout_variables *variables,
				      const struct opts *opts) {
	struct yaffs_packed_tags2 tags;

	if (!layout_derive_is_yaffs2(variables)) {
		return false;
	}

	if (opts->force_inband_tags) {
		return true;
	}

	if (opts->disable_ecc_for_tags) {
		return (variables->values.oob_available < sizeof(tags.t));
	}

	return (variables->values.oob_available < sizeof(tags));
}

static void layout_derived_prepare(struct layout *layout) {
	const struct layout_variables *variables = &layout->variables;
	const struct opts *opts = layout->opts;

	layout->derived = (struct layout_derived){
		.chunks_per_block = layout_derive_chunks_per_block(variables),
		.end_block = layout_derive_end_block(variables),
		.is_yaffs2 = layout_derive_is_yaffs2(variables),
		.inband_tags = layout_derive_inband_tags(variables, opts),
	};
}

int layout_prepare(struct layout *layout,
		   const struct layout_callbacks *callbacks,
		   void *callback_data, const struct opts *opts) {
	int ret;

	layout_init(layout, callbacks, callback_data, opts);

	ret = layout_variables_set_from_callbacks(&layout->variables);
	if (ret < 0) {
		return ret;
	}

	layout_variables_force_from_options(layout);
	layout_derived_prepare(layout);

	return 0;
}

void layout_to_yaffs_parameters(const struct layout *layout,
				struct yaffs_param *yaffs_parameters) {
	const struct layout_constants *constants = &layout->constants;
	const struct layout_variables *variables = &layout->variables;
	const struct layout_derived *derived = &layout->derived;
	const struct opts *opts = layout->opts;

	*yaffs_parameters = (struct yaffs_param){
		.total_bytes_per_chunk = variables->values.chunk_size,
		.chunks_per_block = derived->chunks_per_block,
		.spare_bytes_per_chunk = variables->values.oob_size,
		.start_block = constants->start_block,
		.end_block = derived->end_block,
		.n_reserved_blocks = constants->reserved_blocks,
		.is_yaffs2 = derived->is_yaffs2,
		.inband_tags = derived->inband_tags,
		.no_tags_ecc = opts->disable_ecc_for_tags,
		.skip_checkpt_rd = opts->disable_checkpoints,
		.skip_checkpt_wr = opts->disable_checkpoints,
		.disable_summary = opts->disable_summaries,
		.stored_endian = opts->byte_order,
	};

	log_debug("total_bytes_per_chunk=%d, chunks_per_block=%d, "
		  "spare_bytes_per_chunk=%d, end_block=%d, is_yaffs2=%d, "
		  "inband_tags=%d, no_tags_ecc=%d, skip_checkpt_rd=%d, "
		  "skip_checkpt_wr=%d, disable_summary=%d, stored_endian=%d",
		  yaffs_parameters->total_bytes_per_chunk,
		  yaffs_parameters->chunks_per_block,
		  yaffs_parameters->spare_bytes_per_chunk,
		  yaffs_parameters->end_block, yaffs_parameters->is_yaffs2,
		  yaffs_parameters->inband_tags, yaffs_parameters->no_tags_ecc,
		  yaffs_parameters->skip_checkpt_rd,
		  yaffs_parameters->skip_checkpt_wr,
		  yaffs_parameters->disable_summary,
		  yaffs_parameters->stored_endian);
}

void layout_to_ydriver_data(const struct layout *layout,
			    struct ydriver_data *ydriver_data) {
	ydriver_data->block_size = layout->variables.values.block_size;
	ydriver_data->chunk_size = layout->variables.values.chunk_size;
	ydriver_data->is_yaffs2 = layout->derived.is_yaffs2;
}
