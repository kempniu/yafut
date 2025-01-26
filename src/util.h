// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#if defined(__clang_analyzer__) || defined(__gcc_analyzer__)

/*
 * Make functions retrieving error codes always return -1 when Clang Static
 * Analyzer or GCC Static Analyzer is in use.  This silences the warnings
 * triggered by these codes possibly being zero on errors, which should never
 * be the case.  However...
 */
#define util_get_errno() -1
#define util_get_yaffs_errno() -1

#else /* defined(__clang_analyzer__) || defined(__gcc_analyzer__) */

/*
 * ...rather than assume things, when Clang Static Analyzer or GCC Static
 * Analyzer is _not_ in use, employ helper functions to actually check whether
 * the error codes live up to their promises at run time (and call abort() if
 * they do not).
 */
#define util_get_errno() util_get_errno_location(__FILE__, __LINE__, __func__)
int util_get_errno_location(const char *file, int line, const char *func);

#define util_get_yaffs_errno() yaffsfs_GetLastError()

#endif /* defined(__clang_analyzer__) || defined(__gcc_analyzer__) */

char *util_get_error(int err);
int util_parse_number(const char *string, int base, unsigned int *result);
