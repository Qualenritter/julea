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
test_space_create_destroy(void)
{
	gboolean ret;
	guint one = 1;
	int n = 1000;
	int i;
	void* space;
	for (i = 0; i < n; i++)
	{
		space = j_smd_space_create(one, &one);
		g_assert_nonnull(space);
		ret = j_smd_space_unref(space);
		g_assert_cmpuint(ret, ==, FALSE);
	}
}
static void
test_space_read(void)
{
	gboolean ret;
	guint in_ndims = 4;
	guint in_dims[] = { 2, 3, 6, 5 };
	guint out_ndims = 0;
	guint* out_dims = NULL;
	guint i;
	void* space;
	space = j_smd_space_create(in_ndims, in_dims);
	ret = j_smd_space_get(space, &out_ndims, &out_dims);
	g_assert_cmpuint(ret, !=, FALSE);
	g_assert_cmpuint(in_ndims, ==, out_ndims);
	for (i = 0; i < in_ndims && i < out_ndims; i++)
		g_assert_cmpuint(in_dims[i], ==, out_dims[i]);
	g_free(out_dims);
	ret = j_smd_space_unref(space);
	g_assert_cmpuint(ret, ==, FALSE);
}
void test_smd_space(void);
void
test_smd_space(void)
{
	g_test_add_func("/smd/space/create_destroy", test_space_create_destroy);
	g_test_add_func("/smd/space/read", test_space_read);
}
