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
gboolean
j_is_key_initialized(const char* const key)
{
	int i;

	for (i = 0; i < SMD_KEY_LENGTH; i++)
	{
		if (key[i] != 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}
gboolean
j_smd_is_initialized(void* data)
{
	J_Metadata_t* mdata = data;

	return j_is_key_initialized(mdata->key);
}

void*
_j_smd_get_type(void* _dataset)
{
	J_Metadata_t* dataset = _dataset;
	bson_iter_t b_iter;
	bson_iter_t b_dataset;

	if (bson_iter_init(&b_iter, dataset->bson) && bson_iter_find_descendant(&b_iter, "data_type", &b_dataset) && BSON_ITER_HOLDS_DOCUMENT(&b_dataset))
	{
		return j_smd_type_from_bson(&b_dataset);
	}
	return NULL;
}

void*
_j_smd_get_space(void* _dataset)
{
	J_Metadata_t* dataset = _dataset;
	bson_iter_t b_iter;
	bson_iter_t b_dataset;

	if (bson_iter_init(&b_iter, dataset->bson) && bson_iter_find_descendant(&b_iter, "space_type", &b_dataset) && BSON_ITER_HOLDS_DOCUMENT(&b_dataset))
	{
		return j_smd_space_from_bson(&b_dataset);
	}
	return NULL;
}
