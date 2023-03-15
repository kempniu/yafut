// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

int linux_ioctl(int fd, unsigned long request, void *ptr);

/*
 * Provide a definition of the MEMREAD ioctl in case the kernel headers do not
 * yet contain it.  This "local" definition is going to become redundant over
 * time, as the definition of the MEMREAD ioctl trickles down into kernel
 * headers distributed out there.
 */
#include <mtd/mtd-user.h>
#ifndef MEMREAD
#include <sys/ioctl.h>

struct mtd_read_req_ecc_stats {
	__u32 uncorrectable_errors;
	__u32 corrected_bitflips;
	__u32 max_bitflips;
};

struct mtd_read_req {
	__u64 start;
	__u64 len;
	__u64 ooblen;
	__u64 usr_data;
	__u64 usr_oob;
	__u8 mode;
	__u8 padding[7];
	struct mtd_read_req_ecc_stats ecc_stats;
};

#define MEMREAD _IOWR('M', 26, struct mtd_read_req)
#endif /* MEMREAD */
