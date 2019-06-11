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
/*http://mongoc.org/libbson/current/bson_t.html*/
/**
 * \file
 **/

#include <julea-config.h>

#include <glib.h>

#include <string.h>

#include <bson.h>

#include <julea.h>

#include <julea-internal.h>
#include <julea-smd.h>

bson_t*
j_smd_space_to_bson(void* _space)
{
	J_SMD_Space_t* space = _space;
	char key_buf[16];
	const char* key;
	bson_t* b_attr_space;
	bson_t b_attr_space_dims[1];

	guint i;

	j_trace_enter(G_STRFUNC, NULL);
	b_attr_space = g_new(bson_t, 1);
	bson_init(b_attr_space);

	bson_append_int32(b_attr_space, "ndims", -1, space->ndims);

	bson_append_array_begin(b_attr_space, "dims", -1, b_attr_space_dims);
	for (i = 0; i < space->ndims; i++)
	{
		bson_uint32_to_string(i, &key, key_buf, sizeof(key_buf));
		bson_append_int32(b_attr_space_dims, key, -1, space->dims[i]);
	}
	bson_append_array_end(b_attr_space, b_attr_space_dims);
	bson_destroy(b_attr_space_dims);
	j_trace_leave(G_STRFUNC);
	return b_attr_space;
}
void*
j_smd_space_from_bson(bson_iter_t* bson)
{
	J_SMD_Space_t* space;

	bson_iter_t iter;
	bson_iter_t b_ndims;
	bson_iter_t b_dims;

	space = g_new(J_SMD_Space_t, 1);

	j_trace_enter(G_STRFUNC, NULL);
	J_INFO("j_smd_space_from_bson");
	if (bson_iter_recurse(bson, &iter) && bson_iter_find_descendant(&iter, "ndims", &b_ndims) && BSON_ITER_HOLDS_INT32(&b_ndims))
	{
		space->ndims = bson_iter_int32(&b_ndims);
		J_INFO("j_smd_space_from_bson %d", space->ndims);
		space->dims = g_new(guint, space->ndims);
	}
	else
	{
		j_trace_leave(G_STRFUNC);
		g_free(space);
		return NULL;
	}
	if (bson_iter_recurse(bson, &iter) && bson_iter_find_descendant(&iter, "dims", &b_ndims) && BSON_ITER_HOLDS_ARRAY(&b_ndims))
	{
		bson_iter_recurse(&b_ndims, &b_dims);
		for (guint i = 0; bson_iter_next(&b_dims) && i < space->ndims; i++)
		{
			space->dims[i] = bson_iter_int32(&b_dims);
			J_INFO("j_smd_space_from_bson %d %d", i, space->dims[i]);
		}
	}
	else
	{
		j_trace_leave(G_STRFUNC);
		g_free(space->dims);
		g_free(space);
		return NULL;
	}
	j_trace_leave(G_STRFUNC);
	return space;
}

void*
j_smd_space_create(guint ndims, guint* dims)
{
	J_SMD_Space_t* space;

	space = g_new(J_SMD_Space_t, 1);
	space->ndims = ndims;
	space->dims = g_new(guint, ndims);
	memcpy(space->dims, dims, sizeof(*space->dims) * ndims);
	return space;
}
gboolean
j_smd_space_get(void* _space, guint* ndims, guint** dims)
{
	J_SMD_Space_t* space = _space;
	*ndims = space->ndims;
	*dims = g_new(guint, *ndims);
	memcpy(*dims, space->dims, sizeof(*space->dims) * *ndims);
	return TRUE;
}
gboolean
j_smd_space_free(void* _space)
{
	J_SMD_Space_t* space = _space;

	g_free(space->dims);
	g_free(space);
	return TRUE;
}
gboolean
j_smd_space_equals(void* _space1, void* _space2)
{
	J_SMD_Space_t* space1 = _space1;
	J_SMD_Space_t* space2 = _space2;
	guint i;

	if (space1 == NULL && space2 == NULL)
		return TRUE;
	if (space1 == NULL || space2 == NULL)
		return FALSE;

	if (space1->ndims != space2->ndims)
		return FALSE;
	for (i = 0; i < space1->ndims; i++)
	{
		if (space1->dims[i] != space2->dims[i])
			return FALSE;
	}
	return TRUE;
}
