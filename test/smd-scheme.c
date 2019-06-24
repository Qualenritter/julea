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
#include "smd-type-helper.h"
static void
test_scheme_create_destroy_single(void)
{
	gboolean ret;
	int n = 10;
	int i;
	const char* filename = "filename";
	const char* schemename = "schemename";
	void* file;
	void* type;
	void* space;
	void* scheme;
	guint one = 1;
	g_autoptr(JBatch) batch = NULL;
	type = j_smd_type_create();
	J_SMD_TYPE_ADD_ATOMIC(type, struct test_type_0, a);
	g_assert_nonnull(type);
	space = j_smd_space_create(one, &one);
	g_assert_nonnull(space);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	file = j_smd_file_create(filename, batch);
	j_batch_execute(batch);
	g_assert_nonnull(file);
	g_assert_cmpuint(j_smd_is_initialized(file), !=, FALSE);
	for (i = 0; i < n; i++)
	{
		scheme = j_smd_scheme_create(schemename, file, type, space, J_DISTRIBUTION_DATABASE, batch);
		j_batch_execute(batch);
		g_assert_nonnull(scheme);
		g_assert_cmpuint(j_smd_is_initialized(scheme), !=, FALSE);
		ret = j_smd_scheme_unref(scheme);
		g_assert_cmpuint(ret, ==, FALSE);
		scheme = j_smd_scheme_open(schemename, file, batch);
		j_batch_execute(batch);
		g_assert_nonnull(scheme);
		g_assert_cmpuint(j_smd_is_initialized(scheme), !=, FALSE);
		ret = j_smd_scheme_unref(scheme);
		g_assert_cmpuint(ret, ==, FALSE);
		ret = j_smd_scheme_delete(schemename, file, batch);
		g_assert_cmpuint(ret, !=, FALSE);
		j_batch_execute(batch);
		scheme = j_smd_scheme_open(schemename, file, batch);
		j_batch_execute(batch);
		g_assert_nonnull(scheme);
		g_assert_cmpuint(j_smd_is_initialized(scheme), ==, FALSE);
		ret = j_smd_scheme_unref(scheme);
		g_assert_cmpuint(ret, ==, FALSE);
	}
	ret = j_smd_file_unref(file);
	g_assert_cmpuint(ret, ==, FALSE);
	ret = j_smd_file_delete(filename, batch);
	g_assert_cmpuint(ret, !=, FALSE);
	j_batch_execute(batch);
	ret = j_smd_space_unref(space);
	g_assert_cmpuint(ret, ==, FALSE);
	ret = j_smd_type_unref(type);
	g_assert_cmpuint(ret, ==, FALSE);
}
static void
test_scheme_create_conflict(void)
{
	gboolean ret;
	const char* filename = "filename";
	const char* schemename = "schemename";
	void* file;
	void* type;
	void* space;
	void* scheme;
	guint one = 1;
	g_autoptr(JBatch) batch = NULL;
	type = j_smd_type_create();
	J_SMD_TYPE_ADD_ATOMIC(type, struct test_type_0, a);
	g_assert_nonnull(type);
	space = j_smd_space_create(one, &one);
	g_assert_nonnull(space);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	file = j_smd_file_create(filename, batch);
	j_batch_execute(batch);
	g_assert_nonnull(file);
	g_assert_cmpuint(j_smd_is_initialized(file), !=, FALSE);
	scheme = j_smd_scheme_create(schemename, file, type, space, J_DISTRIBUTION_DATABASE, batch);
	j_batch_execute(batch);
	g_assert_nonnull(scheme);
	g_assert_cmpuint(j_smd_is_initialized(scheme), !=, FALSE);
	ret = j_smd_scheme_unref(scheme);
	g_assert_cmpuint(ret, ==, FALSE);
	scheme = j_smd_scheme_open(schemename, file, batch);
	j_batch_execute(batch);
	g_assert_nonnull(scheme);
	g_assert_cmpuint(j_smd_is_initialized(scheme), !=, FALSE);
	ret = j_smd_scheme_unref(scheme);
	g_assert_cmpuint(ret, ==, FALSE);
	scheme = j_smd_scheme_create(schemename, file, type, space, J_DISTRIBUTION_DATABASE, batch);
	j_batch_execute(batch);
	g_assert_nonnull(scheme);
	g_assert_cmpuint(j_smd_is_initialized(scheme), ==, FALSE);
	ret = j_smd_scheme_unref(scheme);
	g_assert_cmpuint(ret, ==, FALSE);
	scheme = j_smd_scheme_open(schemename, file, batch);
	j_batch_execute(batch);
	g_assert_nonnull(scheme);
	g_assert_cmpuint(j_smd_is_initialized(scheme), !=, FALSE);
	ret = j_smd_scheme_unref(scheme);
	g_assert_cmpuint(ret, ==, FALSE);
	ret = j_smd_file_unref(file);
	g_assert_cmpuint(ret, ==, FALSE);
	ret = j_smd_file_delete(filename, batch);
	g_assert_cmpuint(ret, !=, FALSE);
	j_batch_execute(batch);
	ret = j_smd_space_unref(space);
	g_assert_cmpuint(ret, ==, FALSE);
	ret = j_smd_type_unref(type);
	g_assert_cmpuint(ret, ==, FALSE);
}
static void
test_scheme_create_destroy_many(void)
{
	gboolean ret;
	const char* filename = "filename";
	char schemename[50];
	int n = 10;
	int i;
	void* file;
	void* type;
	void* space;
	void* scheme;
	guint one = 1;
	g_autoptr(JBatch) batch = NULL;
	type = j_smd_type_create();
	J_SMD_TYPE_ADD_ATOMIC(type, struct test_type_0, a);
	g_assert_nonnull(type);
	space = j_smd_space_create(one, &one);
	g_assert_nonnull(space);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	file = j_smd_file_create(filename, batch);
	j_batch_execute(batch);
	g_assert_nonnull(file);
	g_assert_cmpuint(j_smd_is_initialized(file), !=, FALSE);
	for (i = 0; i < n; i++)
	{
		sprintf(schemename, "schemename_%d", i);
		scheme = j_smd_scheme_create(schemename, file, type, space, J_DISTRIBUTION_DATABASE, batch);
		j_batch_execute(batch);
		g_assert_nonnull(scheme);
		ret = j_smd_scheme_unref(scheme);
		g_assert_cmpuint(ret, ==, FALSE);
		j_batch_execute(batch);
		scheme = j_smd_scheme_open(schemename, file, batch);
		j_batch_execute(batch);
		g_assert_nonnull(scheme);
		g_assert_cmpuint(j_smd_is_initialized(scheme), !=, FALSE);
		ret = j_smd_scheme_unref(scheme);
		g_assert_cmpuint(ret, ==, FALSE);
	}
	for (i = 0; i < n; i++)
	{
		sprintf(schemename, "schemename_%d", i);
		j_smd_scheme_delete(schemename, file, batch);
		j_batch_execute(batch);
		scheme = j_smd_scheme_open(schemename, file, batch);
		j_batch_execute(batch);
		g_assert_nonnull(scheme);
		g_assert_cmpuint(j_smd_is_initialized(scheme), ==, FALSE);
		ret = j_smd_scheme_unref(scheme);
		g_assert_cmpuint(ret, ==, FALSE);
	}
	ret = j_smd_file_unref(file);
	g_assert_cmpuint(ret, ==, FALSE);
	ret = j_smd_file_delete(filename, batch);
	g_assert_cmpuint(ret, !=, FALSE);
	j_batch_execute(batch);
	j_smd_space_unref(space);
	j_smd_type_unref(type);
}
static void
_create_test_spaces(void*** _spaces, guint* count)
{
	guint one[] = { 1 };
	guint two[] = { 1, 2 };
	guint three[] = { 1, 2, 3 };
	void** spaces;
	*count = 3;
	*_spaces = g_new(void*, *count);
	spaces = *_spaces;
	spaces[0] = j_smd_space_create(1, one);
	spaces[1] = j_smd_space_create(2, two);
	spaces[2] = j_smd_space_create(3, three);
}
static void
test_scheme_datatypes(void)
{
	gboolean ret;
	guint i, j;
	const char* filename = "filename";
	const char* schemename = "schemename";
	void* file;
	void** types;
	guint types_count;
	void** spaces;
	guint spaces_count;
	void* scheme;
	void* space;
	void* type;
	g_autoptr(JBatch) batch = NULL;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	file = j_smd_file_create(filename, batch);
	j_batch_execute(batch);
	g_assert_nonnull(file);
	g_assert_cmpuint(j_smd_is_initialized(file), !=, FALSE);
	_create_test_types(&types, &types_count);
	_create_test_spaces(&spaces, &spaces_count);
	///
	for (i = 0; i < types_count; i++)
	{
		for (j = 0; j < spaces_count; j++)
		{
			scheme = j_smd_scheme_create(schemename, file, types[i], spaces[j], J_DISTRIBUTION_DATABASE, batch);
			j_batch_execute(batch);
			g_assert_nonnull(scheme);
			g_assert_cmpuint(j_smd_is_initialized(scheme), !=, FALSE);
			type = j_smd_scheme_get_type(scheme);
			g_assert_cmpuint(j_smd_type_equals(types[i], type), !=, FALSE);
			j_smd_type_unref(type);
			space = j_smd_scheme_get_space(scheme);
			g_assert_cmpuint(j_smd_space_equals(spaces[j], space), !=, FALSE);
			j_smd_space_unref(space);
			ret = j_smd_scheme_unref(scheme);
			g_assert_cmpuint(ret, ==, FALSE);
			scheme = j_smd_scheme_open(schemename, file, batch);
			j_batch_execute(batch);
			type = j_smd_scheme_get_type(scheme);
			g_assert_cmpuint(j_smd_type_equals(types[i], type), !=, FALSE);
			j_smd_type_unref(type);
			space = j_smd_scheme_get_space(scheme);
			g_assert_cmpuint(j_smd_space_equals(spaces[j], space), !=, FALSE);
			j_smd_space_unref(space);
			g_assert_nonnull(scheme);
			g_assert_cmpuint(j_smd_is_initialized(scheme), !=, FALSE);
			ret = j_smd_scheme_unref(scheme);
			g_assert_cmpuint(ret, ==, FALSE);
			ret = j_smd_scheme_delete(schemename, file, batch);
			g_assert_cmpuint(ret, !=, FALSE);
			j_batch_execute(batch);
		}
	}
	for (i = 0; i < types_count; i++)
	{
		ret = j_smd_type_unref(types[i]);
		g_assert_cmpuint(ret, ==, FALSE);
	}
	for (j = 0; j < spaces_count; j++)
	{
		ret = j_smd_space_unref(spaces[j]);
		g_assert_cmpuint(ret, ==, FALSE);
	}
	///
	ret = j_smd_file_unref(file);
	g_assert_cmpuint(ret, ==, FALSE);
	ret = j_smd_file_delete(filename, batch);
	g_assert_cmpuint(ret, !=, FALSE);
	j_batch_execute(batch);
	g_free(types);
	g_free(spaces);
}
void test_smd_scheme(void);
void
test_smd_scheme(void)
{
	g_test_add_func("/smd/scheme/create_conflict", test_scheme_create_conflict);
	g_test_add_func("/smd/scheme/create_destroy_single", test_scheme_create_destroy_single);
	g_test_add_func("/smd/scheme/create_destroy_many", test_scheme_create_destroy_many);
	g_test_add_func("/smd/scheme/datatypes", test_scheme_datatypes);
}
