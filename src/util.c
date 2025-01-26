// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
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

/*
 * Extract substrings delimited by any of the characters in 'delimiters' from
 * the string pointed to by 'stringp'.  Stop after extracting 'max_tokens'
 * substrings or reaching the end of the processed string, whichever happens
 * first.  Update 'stringp' to point past the last extracted substring, so that
 * this function can be conveniently used in a loop.  Variadic arguments are
 * <char *, size_t> tuples describing the target buffers that the substrings
 * should be copied to.
 */
int util_get_tokens(const char **stringp, const char *delimiters,
		    unsigned int max_tokens, ...) {
	const char *string = *stringp;
	unsigned int tokens_found = 0;
	va_list args;
	int ret = 0;

	if (string[0] == '\0') {
		return -EPIPE;
	}

	va_start(args, max_tokens);
	while (tokens_found < max_tokens) {
		char *buf;
		size_t buf_size;
		size_t token_length;

		if (string[0] == '\0') {
			ret = -EINTR;
			break;
		}

		buf = va_arg(args, char *);
		buf_size = va_arg(args, size_t);

		token_length = strcspn(string, delimiters);
		if (token_length + 1 > buf_size) {
			ret = -ENOSPC;
			break;
		}

		memmove(buf, string, token_length);
		buf[token_length] = '\0';

		string += token_length;
		if (string[0] != '\0') {
			string++;
		}

		tokens_found++;
	}
	va_end(args);

	*stringp = string;

	return ret;
}
