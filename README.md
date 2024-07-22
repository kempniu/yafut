<!--
SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>

SPDX-License-Identifier: GPL-2.0-only
-->

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/kempniu/yafut/code.yml)](https://github.com/kempniu/yafut/actions/workflows/code.yml)
[![License](https://img.shields.io/github/license/kempniu/yafut)](https://github.com/kempniu/yafut/blob/main/LICENSE)

# Yafut (Yet Another File UTility)

## Overview

Yafut is a basic file copying utility for Unix-like operating systems
that employs [Yaffs Direct Interface (YDI)][YDI] to interact with Yaffs
file systems from userspace.  It enables copying files from/to Yaffs
file systems even if the kernel does not have native support for the
Yaffs file system compiled in.  Yafut also has limited support for
copying files from/to Yaffs file system images stored in regular files.

## Requirements

### Build Requirements

 - C compiler (C99-compliant; Yafut is tested with GCC & Clang)
 - CMake 3.16+ (with a CMake-supported build tool, e.g. GNU Make, Ninja)
 - Yaffs source code (included as a Git submodule)
 - C standard library header files
 - for NAND/NOR flash support (Linux only): Linux kernel header files

### Runtime Requirements

 - POSIX-compatible C standard library
 - for NAND/NOR flash support (Linux only):
    - Linux kernel 6.1 or newer for NAND flash
    - Linux kernel 3.2 or newer for NOR flash

## Supported Yaffs File System Storage Types

### Linux

 - NAND flash
 - NOR flash
 - regular files (file system images)

### macOS

 - regular files (file system images)

## Building

    cmake -B builddir
    cmake --build builddir

## Usage Examples

To copy a file called `foo` from the flash partition represented by the
character device `/dev/mtd1` to a local file called `bar`, run:

    yafut -d /dev/mtd1 -r -i foo -o bar

(Run `cat /proc/mtd` on Linux to list all available flash partitions.)

To copy a local file called `baz` to a file called `qux` on the flash
partition represented by the character device `/dev/mtd2`, run:

    yafut -d /dev/mtd2 -w -i baz -o qux

Pass `-` to `-i`/`-o` to read from/write to stdin/stdout.  For example,
the first command above could also be written as:

    yafut -d /dev/mtd1 -r -i foo -o - > bar

while the second command above could also be written as:

    cat baz | yafut -d /dev/mtd2 -w -i - -o qux

To use a Yaffs file system image instead of a flash partition, replace
`/dev/mtdX` with the path to the regular file containing the image.

Run `yafut -h` for further usage instructions.

## FAQ

### Which flash memory types does this tool work with?

On Linux, Yafut supports both NAND flash and NOR flash, which are
collectively referred to below as MTDs ([Memory Technology
Devices][MTD]).  However, while most parameters for an existing Yaffs
file system stored on NAND flash can be autodetected, the Yaffs layout
used on NOR flash can be fairly arbitrary and therefore Yaffs parameters
for such a file system will likely need to be provided manually (see the
next question below).

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
    area to store a Yaffs2 tag structure (whether that includes ECC data
    for tags or not depends on whether the `-E` option is used, see
    below).  However, some file systems may use inband tags despite
    being stored on an MTD that does have enough available space in the
    OOB area to fit a Yaffs2 tag structure.  For such file systems, the
    `-T` command-line option can be used to force use of inband tags.

  - Use of ECC for tags (`-E`).  Yafut assumes that Yaffs2 tag
    structures include ECC data for tags by default.  If a given file
    system does not use ECC for tags, the `-E` command-line option can
    be used to tell Yafut to act accordingly.

  - Use of Yaffs2 checkpoints (`-P` to disable).  By default, Yaffs2
    code stores a snapshot of its runtime state (called a "checkpoint")
    in the file system when the latter gets unmounted or `sync()`'d.
    Using these checkpoints speeds up file system mounting, but occupies
    extra storage space.  If desired, reading and writing checkpoints
    can be disabled using the `-P` command-line option.

  - Writing Yaffs2 summaries (`-S` to disable).  By default, Yaffs2
    code stores a so-called summary at the end of each block.  Using
    these summaries speeds up file system scanning, but occupies extra
    storage space.  If desired, writing summaries can be disabled using
    the `-S` command-line option.

  - Byte order (`-L` to force little-endian byte order, `-M` to force
    big-endian byte order).  By default, Yafut assumes that the byte
    order used on the MTD is the same as the byte order used by the host
    CPU.  This can be overridden if necessary, allowing little-endian
    hosts to operate on big-endian file systems and vice versa.

### Which Yaffs file system versions does this tool work with?

Yaffs code that Yafut builds upon supports both Yaffs1 and Yaffs2 file
systems.  Yafut assumes that NAND devices with 512-byte pages use Yaffs1
while those with 1024-byte or larger pages use Yaffs2.  All NOR devices
and Yaffs file system images are assumed to use Yaffs2 by default.
While the autodetected Yaffs layout can be tweaked using the `-C` and
`-B` command-line options (see above), there is currently no way to
override the chunk size threshold used for autodetecting the Yaffs file
system version used.

### What's the deal with the Linux kernel version requirements?

Linux kernel version 6.1 is the first one that implements all the MTD
ioctls that Yafut needs to do its job on NAND flash - specifically, it
is the first kernel version that supports the MEMREAD ioctl, which
enables userspace applications to use the Linux kernel's OOB
autoplacement mechanism while reading data from NAND devices (see also
the next question).

While Yafut can be *built* on hosts on which the Linux kernel headers do
not include the definition of the MEMREAD ioctl, it needs Linux kernel
version 6.1+ to actually *work* on NAND flash.  (An older, custom kernel
version with a backported implementation of the MEMREAD ioctl can also
be used).

As Yafut does not need the MEMREAD ioctl to handle NOR flash, only Linux
kernel 3.2 or newer is necessary for Yafut to work on that type of flash
memory.

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

### Is this tool also able to work with Yaffs file system images?

Yes, to an extent.  The argument passed via the `-d` command-line option
can be a path to either an MTD character device representing NAND/NOR
flash memory or a regular file containing a Yaffs file system image.
However, there is currently no support for working with file system
images that include OOB data (e.g. NAND flash dumps).  Like for NOR
flash, the Yaffs layout used for a given file system image can be fairly
arbitrary and therefore Yaffs parameters for such a file system will
likely need to be provided manually (see above).

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
