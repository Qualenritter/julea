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
/**
* \return a new space or NULL if parameters are invalid
*/
void*
j_smd_space_create(guint ndims, guint* dims)
{
	guint i;
	J_SMD_Space_t* space;
	if (ndims > SMD_MAX_NDIMS || ndims == 0)
	{
		J_DEBUG("(0 < ndims) && (ndims <= %d)", SMD_MAX_NDIMS);
		return NULL;
	}
	if (!dims)
	{
		J_DEBUG("dims must be allocated and contain %d-elements", ndims);
		return NULL;
	}
	space = g_new(J_SMD_Space_t, 1);
	space->ref_count = 1;
	space->ndims = ndims;
	for (i = 0; i < ndims; i++)
		space->dims[i] = dims[i];
	return space;
}
/**
* \param _space IN the type to extract from
* \param ndims OUT the number of dimensions
* \return success
*/
gboolean
j_smd_space_get(void* _space, guint* ndims, guint** dims)
{
	J_SMD_Space_t* space = _space;
	if (!_space || !ndims || !dims)
	{
		J_DEBUG("parameters must not be NULL %p %p %p", (void*)_space, (void*)ndims, (void*)dims);
		return FALSE;
	}
	if (*dims)
	{
		J_DEBUG("dims output will be allocated within this function - memory will leak %p", (void*)*dims);
		return FALSE;
	}
	*ndims = space->ndims;
	*dims = g_new(guint, *ndims);
	memcpy(*dims, space->dims, sizeof(*space->dims) * *ndims);
	return TRUE;
}
/**
*\return _space
*/
void*
j_smd_space_ref(void* _space)
{
	J_SMD_Space_t* space = _space;
	if (space)
		g_atomic_int_inc(&(space->ref_count));
	return space;
}
/**
* \return TRUE if _space is still referenced somewhere, and FALSE if memory is released
*/
gboolean
j_smd_space_unref(void* _space)
{
	J_SMD_Space_t* space = _space;
	if (space && g_atomic_int_dec_and_test(&(space->ref_count)))
	{
		g_free(_space);
		return FALSE;
	}
	return space != NULL;
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
		if (space1->dims[i] != space2->dims[i])
			return FALSE;
	return TRUE;
}
