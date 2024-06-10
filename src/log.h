// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#define log(fmt, ...)                                                          \
	log_location(__FILE__, __LINE__, __func__, 0, fmt, ##__VA_ARGS__)

#define log_debug(fmt, ...)                                                    \
	log_location(__FILE__, __LINE__, __func__, 1, fmt, ##__VA_ARGS__)

#define log_error(err, fmt, ...)                                               \
	log_error_location(__FILE__, __LINE__, __func__, err, fmt,             \
			   ##__VA_ARGS__)

extern int log_level;

void log_location(const char *file, int line, const char *func,
		  int message_log_level, const char *fmt, ...);
void log_error_location(const char *file, int line, const char *func, int err,
			const char *fmt, ...);

void log_set_yaffs_trace_mask(unsigned int mask);
