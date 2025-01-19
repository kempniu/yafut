// SPDX-FileCopyrightText: Michał Kępień <yafut@kempniu.pl>
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

extern const struct storage_driver *storage_platform_drivers[];

int storage_platform_probe(struct storage *storage);
void storage_platform_destroy(struct storage *storage);
