/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2019 Benjamin Warnke
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <julea-config.h>

#include <glib.h>

#include <julea.h>

#include <julea-internal.h>
#include <julea-smd.h>

#include "test.h"

void test_smd_space(void);
void test_smd_type(void);
void test_smd_file(void);
void test_smd_dataset(void);
void test_smd_attribute(void);
void
test_smd(void)
{
	test_smd_space();
	test_smd_type();
	test_smd_file();
	test_smd_dataset();
	test_smd_attribute();
}
