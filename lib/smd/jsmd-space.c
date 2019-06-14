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
void*
j_smd_space_create(guint ndims, guint* dims)
{
	guint i;
	J_SMD_Space_t* space;
	if (ndims > SMD_MAX_NDIMS)
	{
		J_CRITICAL("ndims > %d not supported", SMD_MAX_NDIMS);
		return NULL;
	}
	space = g_new(J_SMD_Space_t, 1);
	space->ref_count = 1;
	space->ndims = ndims;
	for (i = 0; i < ndims; i++)
		space->dims[i] = dims[i];
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
void*
j_smd_space_ref(void* _space)
{
	J_SMD_Space_t* space = _space;
	g_atomic_int_inc(&(space->ref_count));
	return space;
}
gboolean
j_smd_space_unref(void* _space)
{
	J_SMD_Space_t* space = _space;
	if (space && g_atomic_int_dec_and_test(&(space->ref_count)))
	{
		g_free(_space);
	}
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
bson_t*
j_smd_space_to_bson(void* _space)
{
	J_SMD_Space_t* space = _space;
	char key_buf[16];
	const char* key;
	bson_t* b_space;
	bson_t b_space_dims[1];
	guint i;
	b_space = g_new(bson_t, 1);
	bson_init(b_space);
	bson_append_int32(b_space, "ndims", -1, space->ndims);
	bson_append_array_begin(b_space, "dims", -1, b_space_dims);
	for (i = 0; i < space->ndims; i++)
	{
		bson_uint32_to_string(i, &key, key_buf, sizeof(key_buf));
		bson_append_int32(b_space_dims, key, -1, space->dims[i]);
	}
	bson_append_array_end(b_space, b_space_dims);
	bson_destroy(b_space_dims);
	return b_space;
}
void*
j_smd_space_from_bson(bson_iter_t* bson)
{
	J_SMD_Space_t* space;
	bson_iter_t iter;
	bson_iter_t b_ndims;
	bson_iter_t b_dims;
	space = g_new(J_SMD_Space_t, 1);
	space->ref_count = 1;
	if (bson_iter_recurse(bson, &iter) && bson_iter_find_descendant(&iter, "ndims", &b_ndims) && BSON_ITER_HOLDS_INT32(&b_ndims))
		space->ndims = bson_iter_int32(&b_ndims);
	else
	{
		g_free(space);
		return NULL;
	}
	if (bson_iter_recurse(bson, &iter) && bson_iter_find_descendant(&iter, "dims", &b_ndims) && BSON_ITER_HOLDS_ARRAY(&b_ndims))
	{
		bson_iter_recurse(&b_ndims, &b_dims);
		for (guint i = 0; bson_iter_next(&b_dims) && i < space->ndims; i++)
			space->dims[i] = bson_iter_int32(&b_dims);
	}
	else
	{
		g_free(space->dims);
		g_free(space);
		return NULL;
	}
	return space;
}
