// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#ifdef __clang_analyzer__

/*
 * Make util_get_errno() always return -1 when Clang Static Analyzer is in use.
 * This silences its warnings triggered by 'errno' possibly being zero on
 * errors, which should never be the case.  However...
 */
#define util_get_errno() -1

#else /* __clang_analyzer__ */

/*
 * ...rather than assume things, when Clang Static Analyzer is _not_ in use,
 * instead of accessing 'errno' directly, use a helper function that actually
 * checks whether 'errno' lives up to its promise at run time (and call abort()
 * if it does not).
 */
#define util_get_errno() util_get_errno_location(__FILE__, __LINE__, __func__)
int util_get_errno_location(const char *file, int line, const char *func);

#endif /* __clang_analyzer__ */

char *util_get_error(int err);
int util_parse_number(const char *string, int base, unsigned int *result);
