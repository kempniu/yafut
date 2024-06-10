// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <limits.h>
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
		log_location(file, line, func, 0,
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

/*
 * Convert the provided 'string' to an unsigned integer value according to the
 * given 'base', storing the result in 'result'.  The number represented by
 * 'string' is expected to be non-negative and not greater than UINT_MAX, in
 * which case this function returns 0; otherwise, it returns -1, which
 * indicates an error.
 */
int util_parse_number(const char *string, int base, unsigned int *result) {
	char *first_bad_char = NULL;
	long long ret;

	if (!string) {
		return -1;
	}

	ret = strtoll(string, &first_bad_char, base);
	if (first_bad_char && *first_bad_char != '\0') {
		log("unable to parse '%s' as a number (base %d)", string, base);
		return -1;
	}

	if (ret < 0 || ret > UINT_MAX) {
		log("number '%s' (base %d) is out of range (0 <= number <= %u)",
		    string, base, UINT_MAX);
		return -1;
	}

	*result = ret;

	return 0;
}
