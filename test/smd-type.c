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
static void
test_type_create0(void)
{
	gboolean ret;
	int n = 1000;
	int i;
	void* type;

	for (i = 0; i < n; i++)
	{
		type = j_smd_type_create();
		g_assert_nonnull(type);
		ret = j_smd_type_free(type);
		g_assert_cmpuint(ret, !=, FALSE);
	}
}

static void
test_type_create1(void)
{
	guint one = 1;
	gboolean ret;
	void* type;

	type = j_smd_type_create();
	g_assert_nonnull(type);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 0);
	ret = j_smd_type_add_atomic_type(type, "a", 0, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 1);
	ret = j_smd_type_free(type);
	g_assert_cmpuint(ret, !=, FALSE);
}
static void
test_type_create2(void)
{
	guint one = 1;
	gboolean ret;
	void* type;

	type = j_smd_type_create();
	g_assert_nonnull(type);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 0);
	ret = j_smd_type_add_atomic_type(type, "a", 0, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 1);
	ret = j_smd_type_add_atomic_type(type, "b", 4, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 2);
	ret = j_smd_type_free(type);
	g_assert_cmpuint(ret, !=, FALSE);
}
static void
test_type_delete0(void)
{
	guint one = 1;
	gboolean ret;
	void* type;

	type = j_smd_type_create();
	g_assert_nonnull(type);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 0);
	ret = j_smd_type_add_atomic_type(type, "a", 0, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 1);
	ret = j_smd_type_add_atomic_type(type, "b", 4, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 2);
	ret = j_smd_type_add_atomic_type(type, "c", 8, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 3);
	ret = j_smd_type_remove_variable(type, "a");
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 2);
	ret = j_smd_type_free(type);
	g_assert_cmpuint(ret, !=, FALSE);
}
static void
test_type_delete1(void)
{
	guint one = 1;
	gboolean ret;
	void* type;

	type = j_smd_type_create();
	g_assert_nonnull(type);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 0);
	ret = j_smd_type_add_atomic_type(type, "a", 0, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 1);
	ret = j_smd_type_add_atomic_type(type, "b", 4, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 2);
	ret = j_smd_type_add_atomic_type(type, "c", 8, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 3);
	ret = j_smd_type_remove_variable(type, "b");
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 2);
	ret = j_smd_type_free(type);
	g_assert_cmpuint(ret, !=, FALSE);
}
static void
test_type_delete2(void)
{
	guint one = 1;
	gboolean ret;
	void* type;

	type = j_smd_type_create();
	g_assert_nonnull(type);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 0);
	ret = j_smd_type_add_atomic_type(type, "a", 0, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 1);
	ret = j_smd_type_add_atomic_type(type, "b", 4, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 2);
	ret = j_smd_type_add_atomic_type(type, "c", 8, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 3);
	ret = j_smd_type_remove_variable(type, "c");
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 2);
	ret = j_smd_type_free(type);
	g_assert_cmpuint(ret, !=, FALSE);
}
static void
test_type_delete3(void)
{
	guint one = 1;
	gboolean ret;
	void* type;

	type = j_smd_type_create();
	g_assert_nonnull(type);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 0);
	ret = j_smd_type_add_atomic_type(type, "a", 0, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 1);
	ret = j_smd_type_add_atomic_type(type, "b", 4, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 2);
	ret = j_smd_type_add_atomic_type(type, "c", 8, 4, SMD_TYPE_INT, one, &one);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 3);
	ret = j_smd_type_remove_variable(type, "d");
	g_assert_cmpuint(ret, ==, FALSE);
	g_assert_cmpuint(j_smd_type_get_variable_count(type), ==, 3);
	ret = j_smd_type_free(type);
	g_assert_cmpuint(ret, !=, FALSE);
}

void test_smd_type(void);
void
test_smd_type(void)
{
	g_test_add_func("/smd/type/create0", test_type_create0);
	g_test_add_func("/smd/type/create1", test_type_create1);
	g_test_add_func("/smd/type/create2", test_type_create2);
	g_test_add_func("/smd/type/delete0", test_type_delete0);
	g_test_add_func("/smd/type/delete1", test_type_delete1);
	g_test_add_func("/smd/type/delete2", test_type_delete2);
	g_test_add_func("/smd/type/delete3", test_type_delete3);
}
