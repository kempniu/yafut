// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#include <sys/syscall.h>
#include <unistd.h>

#include "ioctl.h"

/*
 * The POSIX prototype for the ioctl() interface is:
 *
 *     int ioctl(int fd, int request, ...);
 *
 * Meanwhile, the corresponding Linux prototype is:
 *
 *     int ioctl(int fd, unsigned long request, ...);
 *
 * The linux_ioctl() function directly issues the requested ioctl() syscall,
 * bypassing the libc ioctl() wrapper.  This prevents compiler warnings about
 * integer overflow when building against e.g. musl.
 */
int linux_ioctl(int fd, unsigned long request, void *ptr) {
	return syscall(SYS_ioctl, fd, request, ptr);
}
