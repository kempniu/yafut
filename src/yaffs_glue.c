// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <yportenv.h>

#include "log.h"

static int yaffs_err;

/*
 * This file contains the RTOS Integration Interface functions whose
 * implementation is required by the Yaffs Direct Interface (YDI).
 *
 * See https://yaffs.net/documents/yaffs-direct-interface for more information.
 */

void yaffsfs_Lock(void) {
}

void yaffsfs_Unlock(void) {
}

u32 yaffsfs_CurrentTime(void) {
	return time(NULL);
}

void yaffsfs_SetError(int err) {
	yaffs_err = err;
}

/*
 * Sanity check the error code set by Yaffs code and then return it.  This
 * function is similar in spirit to util_get_errno_location().
 */
int yaffsfs_GetLastError(void) {
	if (yaffs_err >= 0) {
		log_error(yaffs_err, "unexpected Yaffs error code");
		abort();
	}

	return yaffs_err;
}

void *yaffsfs_malloc(size_t size) {
	return malloc(size);
}

void yaffsfs_free(void *ptr) {
	free(ptr);
}

int yaffsfs_CheckMemRegion(const void *addr, size_t size, int write_request) {
	(void)size;
	(void)write_request;

	return (addr ? 0 : -1);
}

void yaffs_bug_fn(const char *file_name, int line_no) {
	fprintf(stderr, "Yaffs bug at %s:%d, aborting\n", file_name, line_no);
	abort();
}
