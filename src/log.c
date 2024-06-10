// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "util.h"

unsigned int yaffs_trace_mask;
int log_level;

/*
 * Format a log message using the format string provided in 'fmt' (and any
 * optional arguments following it); store the result into 'buf', which is
 * 'buf_size' bytes long.  This function does not print anything by itself.
 */
static int log_format(char *buf, size_t buf_size, const char *fmt, ...) {
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vsnprintf(buf, buf_size, fmt, args);
	va_end(args);

	if (ret < 0 || (unsigned int)ret >= buf_size) {
		return -1;
	}

	return 0;
}

/*
 * Print the message provided in 'fmt' (and a va_list of optional arguments
 * prepared by the caller) to stderr, prefixing it with the provided
 * file/line/function information.
 */
static void log_location_varargs(const char *file, int line, const char *func,
				 const char *fmt, va_list args) {
	const char *relative_file = strrchr(file, '/');
	char format[1024];
	int ret;

	ret = log_format(format, sizeof(format), "%s:%d: %s: %s\n",
			 relative_file ? relative_file + 1 : file, line, func,
			 fmt);
	if (ret < 0) {
		return;
	}

	vfprintf(stderr, format, args);
}

/*
 * Print the message provided in 'fmt' (and any optional arguments following
 * it) to stderr, prefixing it with the provided file/line/function
 * information.  For logging specific error codes (e.g. errno values), use
 * log_error_location() instead.
 */
void log_location(const char *file, int line, const char *func,
		  int message_log_level, const char *fmt, ...) {
	va_list args;

	if (log_level < message_log_level) {
		return;
	}

	va_start(args, fmt);
	log_location_varargs(file, line, func, fmt, args);
	va_end(args);
}

/*
 * Print the message provided in 'fmt' (and any optional arguments following
 * it) to stderr, prefixing it with the provided file/line/function information
 * and suffixing it with the textual representation of the error code provided
 * in 'err'.  For logging non-error messages and error messages not accompanied
 * by a specific error code, use log_location() or log_location_varargs()
 * instead.
 */
void log_error_location(const char *file, int line, const char *func, int err,
			const char *fmt, ...) {
	char format[1024];
	va_list args;
	int ret;

	ret = log_format(format, sizeof(format), "%s: error %d (%s)", fmt, err,
			 util_get_error(err));
	if (ret < 0) {
		return;
	}

	va_start(args, fmt);
	log_location_varargs(file, line, func, format, args);
	va_end(args);
}

/*
 * Set the Yaffs tracing mask.  Yaffs code uses the value stored in the
 * 'yaffs_trace_mask' symbol for determining whether to produce debug messages.
 * It prints the latter on stdout, which makes it hard to capture combined
 * Yafut (stderr) + Yaffs (stdout) debugging information because the two types
 * of messages are not intertwined properly when output is redirected (since
 * stdout is buffered by default while stderr is not).  Disable stdout
 * buffering when Yaffs tracing is enabled to work around that problem.
 */
void log_set_yaffs_trace_mask(unsigned int mask) {
	yaffs_trace_mask = mask;
	if (yaffs_trace_mask) {
		setbuf(stdout, NULL);
	}
}
