// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "util.h"

/*
 * A helper function that should always be used instead of accessing 'errno'
 * directly.  See the corresponding comment in src/util.h for context.
 */
int util_get_errno_location(const char *file, int line, const char *func) {
	if (errno <= 0) {
		log_location(file, line, func,
			     "errno unexpectedly set to %d, aborting", errno);
		abort();
	}

	return -errno;
}

/*
 * Return a textual representation of the error provided in 'err'.
 */
char *util_get_error(int err) {
	return strerror(-err);
}
