# SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
#
# SPDX-License-Identifier: GPL-2.0-only

cmake_minimum_required(VERSION 3.16)

include(CMakeDependentOption)
include(CMakePushCheckState)
include(CheckTypeSize)

project(
	yafut
	LANGUAGES C
)

check_type_size(loff_t LOFF_T)
if(NOT HAVE_LOFF_T)
	add_definitions(-DY_LOFF_T=off_t)
endif()

cmake_push_check_state()
set(CMAKE_EXTRA_INCLUDE_FILES mtd/mtd-user.h)
check_type_size(mtd_info_t MTD_INFO_T)
cmake_pop_check_state()
cmake_dependent_option(
	WITH_MTD_DEVICE "Include support for MTD devices" ON HAVE_MTD_INFO_T OFF)
if(NOT WITH_MTD_DEVICE)
	add_definitions(-DNO_MTD_DEVICE)
endif()

execute_process(
	COMMAND sh handle_common.sh copy
	WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/lib/yaffs2/direct/
)

add_library(
	yaffs2
	OBJECT
	lib/yaffs2/direct/yaffs_allocator.c
	lib/yaffs2/direct/yaffs_attribs.c
	lib/yaffs2/direct/yaffs_bitmap.c
	lib/yaffs2/direct/yaffs_cache.c
	lib/yaffs2/direct/yaffs_checkptrw.c
	lib/yaffs2/direct/yaffs_ecc.c
	lib/yaffs2/direct/yaffs_endian.c
	lib/yaffs2/direct/yaffs_error.c
	lib/yaffs2/direct/yaffsfs.c
	lib/yaffs2/direct/yaffs_guts.c
	lib/yaffs2/direct/yaffs_hweight.c
	lib/yaffs2/direct/yaffs_nameval.c
	lib/yaffs2/direct/yaffs_nand.c
	lib/yaffs2/direct/yaffs_packedtags1.c
	lib/yaffs2/direct/yaffs_packedtags2.c
	lib/yaffs2/direct/yaffs_summary.c
	lib/yaffs2/direct/yaffs_tagscompat.c
	lib/yaffs2/direct/yaffs_tagsmarshall.c
	lib/yaffs2/direct/yaffs_verify.c
	lib/yaffs2/direct/yaffs_yaffs1.c
	lib/yaffs2/direct/yaffs_yaffs2.c
)

target_compile_definitions(
	yaffs2
	PUBLIC
	CONFIG_YAFFS_DEFINES_TYPES
	CONFIG_YAFFS_DIRECT
	CONFIG_YAFFS_PROVIDE_DEFS
	_GNU_SOURCE
)

target_include_directories(
	yaffs2
	INTERFACE
	${PROJECT_SOURCE_DIR}/lib/yaffs2/direct
)

add_executable(
	yafut
	src/copy.c
	src/file.c
	src/file_driver_posix.c
	src/file_driver_yaffs.c
	src/layout.c
	src/log.c
	src/main.c
	src/options.c
	src/storage.c
	src/storage_driver_image.c
	src/util.c
	src/yaffs_glue.c
	src/ydriver.c
	src/ydriver_posix.c
)

if(WITH_MTD_DEVICE)
	target_sources(yafut PRIVATE
		src/ioctl.c
		src/storage_driver_nand.c
		src/storage_driver_nor.c
		src/ydriver_ioctl.c
		)
endif()

set_target_properties(
	yafut
	PROPERTIES
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
)

if (${ENABLE_ALL_WARNINGS})
	target_compile_options(
		yafut
		PRIVATE
		-Wall
		-Werror
		-Wextra
	)
endif()

target_link_libraries(
	yafut
	yaffs2
)

install(TARGETS yafut)
