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
test_file_create_destroy_single(void)
{
	gboolean ret;
	int n = 10;
	int i;
	const char* filename = "filename";
	void* file;

	g_autoptr(JBatch) batch = NULL;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	for (i = 0; i < n; i++)
	{
		file = j_smd_file_create(filename, batch);
		j_batch_execute(batch);
		g_assert_nonnull(file);
		ret = j_smd_file_close(file);
		g_assert_cmpuint(ret, !=, FALSE);
		file = j_smd_file_open(filename, batch);
		j_batch_execute(batch);
		g_assert_nonnull(file);
		g_assert_cmpuint(j_smd_is_initialized(file), !=, FALSE);
		ret = j_smd_file_close(file);
		g_assert_cmpuint(ret, !=, FALSE);
		ret = j_smd_file_delete(filename, batch);
		g_assert_cmpuint(ret, !=, FALSE);
		j_batch_execute(batch);
		file = j_smd_file_open(filename, batch);
		j_batch_execute(batch);
		g_assert_nonnull(file);
		g_assert_cmpuint(j_smd_is_initialized(file), ==, FALSE);
		ret = j_smd_file_close(file);
		g_assert_cmpuint(ret, !=, FALSE);
	}
}
static void
test_file_create_destroy_many(void)
{
	gboolean ret;
	char filename[50];
	int n = 10;
	int i;
	void* file;

	g_autoptr(JBatch) batch = NULL;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	for (i = 0; i < n; i++)
	{
		sprintf(filename, "filename_%d", i);
		file = j_smd_file_create(filename, batch);
		j_batch_execute(batch);
		g_assert_nonnull(file);
		ret = j_smd_file_close(file);
		g_assert_cmpuint(ret, !=, FALSE);
		j_batch_execute(batch);
		file = j_smd_file_open(filename, batch);
		j_batch_execute(batch);
		g_assert_nonnull(file);
		g_assert_cmpuint(j_smd_is_initialized(file), !=, FALSE);
		ret = j_smd_file_close(file);
		g_assert_cmpuint(ret, !=, FALSE);
	}
	for (i = 0; i < n; i++)
	{
		sprintf(filename, "filename_%d", i);
		ret = j_smd_file_delete(filename, batch);
		g_assert_cmpuint(ret, !=, FALSE);
		j_batch_execute(batch);
		file = j_smd_file_open(filename, batch);
		j_batch_execute(batch);
		g_assert_nonnull(file);
		g_assert_cmpuint(j_smd_is_initialized(file), ==, FALSE);
		ret = j_smd_file_close(file);
		g_assert_cmpuint(ret, !=, FALSE);
	}
}
void test_smd_file(void);
void
test_smd_file(void)
{
	g_test_add_func("/smd/file/create_destroy_single", test_file_create_destroy_single);
	g_test_add_func("/smd/file/create_destroy_many", test_file_create_destroy_many);
}
