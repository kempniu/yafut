<!--
SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>

SPDX-License-Identifier: GPL-2.0-only
-->

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/kempniu/yafut/code.yml)](https://github.com/kempniu/yafut/actions/workflows/code.yml)
[![License](https://img.shields.io/github/license/kempniu/yafut)](https://github.com/kempniu/yafut/blob/main/LICENSE)

# Yafut (Yet Another File UTility)

## Overview

Yafut is a basic file copying utility for the Linux operating system
that employs [Yaffs Direct Interface (YDI)][YDI] and Linux [Memory
Technology Devices (MTD)][MTD] ioctls to interact with Yaffs file
systems from userspace.  It enables copying files from/to Yaffs file
systems even if the kernel does not have native support for the Yaffs
file system compiled in.

## Requirements

### Build Requirements

 - C compiler (C99-compliant; Yafut is tested with GCC & Clang)
 - CMake 3.16+ (with a CMake-supported build tool, e.g. GNU Make, Ninja)
 - Yaffs source code (included as a Git submodule)
 - C standard library header files
 - Linux kernel header files

### Runtime Requirements

 - Linux kernel 6.1+ with MTD support enabled
 - glibc or musl libc (other C standard libraries should also work, but
   have not been tested)

## Building

    cmake -B builddir
    cmake --build builddir

## Usage Examples

To copy a file called `foo` from the MTD partition represented by the
character device `/dev/mtd1` to a local file called `bar`, run:

    yafut -d /dev/mtd1 -r -i foo -o bar

(Run `cat /proc/mtd` to list all available MTD partitions.)

To copy a local file called `baz` to a file called `qux` on the MTD
partition represented by the character device `/dev/mtd2`, run:

    yafut -d /dev/mtd2 -w -i baz -o qux

Pass `-` to `-i`/`-o` to read from/write to stdin/stdout.  For example,
the first command above could also be written as:

    yafut -d /dev/mtd1 -r -i foo -o - > bar

while the second command above could also be written as:

    cat baz | yafut -d /dev/mtd2 -w -i - -o qux

Run `yafut -h` for further usage instructions.

## FAQ

### Which Yaffs file system versions does this tool work with?

Yaffs code that Yafut builds upon supports both Yaffs1 and Yaffs2 file
systems.  Yafut assumes that MTD devices with 512-byte pages use Yaffs1
while those with 1024-byte or larger pages use Yaffs2.  There is
currently no way to override this assumption other than by modifying the
source code.

### Do I need to manually set any Yaffs parameters?

Yafut tries to make reasonable assumptions about most Yaffs parameters
to use for a given MTD, so that its use remains as simple as possible.
However, not all Yaffs parameters can be discovered deterministically,
in which case the educated guess attempted by Yafut may turn out to be
wrong and specific values for certain Yaffs options will need to be
forced by the user via command-line options.

The Yaffs parameters that can currently be controlled using command-line
options are:

  - Chunk size (`-C`) and block size (`-B`).  Yafut uses autodetected
    MTD parameters for these parameters by default, but they can be
    forced to specific values if necessary.

  - Use of inband tags (`-T`).  Yafut assumes that inband tags are only
    necessary if the MTD does not have enough available bytes in the OOB
    area to store a full Yaffs2 tag structure (including tags ECC data).
    However, some file systems may use inband tags despite being stored
    on an MTD that does have enough available space in the OOB area to
    fit a full Yaffs2 tag structure.  For such file systems, the `-T`
    command-line option can be used to force use of inband tags.

### Does this tool really only work with Linux kernel 6.1+?

Linux kernel version 6.1 is the first one that implements all the MTD
ioctls that Yafut needs to do its job - specifically, it is the first
kernel version that supports the MEMREAD ioctl, which enables userspace
applications to use the Linux kernel's OOB autoplacement mechanism while
reading data from NAND devices (see also the next question).

While Yafut can be *built* on hosts on which the Linux kernel headers do
not include the definition of the MEMREAD ioctl, it needs Linux kernel
version 6.1+ to actually *work*.  (An older, custom kernel version with
a backported implementation of the MEMREAD ioctl can also be used).

### Do I need to know the OOB (spare) area layout of my NAND device?

No.  Here is why:

  - **Yaffs2:** Yafut relies on the Linux kernel's autoplacement
    mechanism for reading/writing Yaffs2 metadata from/to the OOB area
    of the NAND device.  This enables Yafut to work transparently with
    any NAND device supported by the Linux kernel, without requiring the
    user to provide the OOB layout details, which simplifies Yafut's
    source code and usage.  However, the downside of this approach is
    that if one wanted to read data from an MTD partition that uses a
    different OOB layout than the one assumed by the Linux kernel, there
    is currently no way to make Yafut do that.

  - **Yaffs1:** Yaffs1 code assumes that each page of the NAND device
    has a 16-byte spare area.  Yaffs assumes full control over the
    layout of that area.  For that reason, Yaffs1 metadata is written to
    the NAND device in raw mode (i.e. without using the Linux kernel's
    autoplacement mechanism for writing to the OOB area) and the concept
    of customizing the OOB layout does not really apply for Yaffs1.

## Troubleshooting & Debugging

If Yafut fails to do what you expect it to and the error messages it
reports back do not directly indicate the failure reason (or are
downright confusing), it might be useful to run it again with the `-v`
command-line option, which enables verbose output that includes
potentially useful information, e.g. the executed `ioctl()` system calls
and their return codes.  Verbose output is printed to stderr.  If
`err=-25 (Inappropriate ioctl for device)` lines are present in the
verbose output, it means that the running kernel does not support the
`ioctl()` commands that Yafut relies on.  Specifying `-v` twice also
causes (truncated) hex dumps of the data passed around to be included in
the output.

Yaffs tracing (implemented in Yaffs code itself) can be enabled by
setting the `YAFFS_TRACE_MASK` environment variable to the desired
value.  For example, to enable full Yaffs tracing, run Yafut like this:

    YAFFS_TRACE_MASK=0xffffffff yafut [...options-here...]

See the `yaffs_trace.h` file in the Yaffs source tree for what each bit
in the tracing mask means.  Note that Yaffs tracing code prints its
messages to stdout, not stderr, so setting `YAFFS_TRACE_MASK` while
copying the contents of a file from an MTD to stdout (`-r -o -`) is not
a good idea.  Setting `YAFFS_TRACE_MASK` can be combined with `-v`, but
since the former prints to stdout while the latter prints to stderr, use
something like this to collect both types of tracing information to a
common location:

    YAFFS_TRACE_MASK=0xffffffff yafut [...options-here...] >trace 2>&1

## License

Yafut source code is released under GNU General Public License (GPL),
version 2.

[YDI]: https://yaffs.net/documents/yaffs-direct-interface
[MTD]: https://en.wikipedia.org/wiki/Memory_Technology_Device
