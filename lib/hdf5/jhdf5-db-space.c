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

/**
 * \file
 **/

#include <julea-config.h>
#include <julea.h>
#include <julea-db.h>
#include <julea-object.h>
#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#ifdef JULEA_HDF_COMPILES
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "jhdf5-db.h"

#define _GNU_SOURCE

static JDBSchema* julea_db_schema_space = NULL;

static herr_t
H5VL_julea_db_space_init(hid_t vipl_id)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(JBatch) batch = NULL;
	g_autoptr(GError) error = NULL;

	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);

	if (!(julea_db_schema_space = j_db_schema_new("hdf5", "space", NULL)))
		goto _error;
	if (!(j_db_schema_get(julea_db_schema_space, batch, &error) && j_batch_execute(batch)))
	{
		if (error)
		{
			if (error->code == J_BACKEND_DB_ERROR_SCHEMA_NOT_FOUND)
			{
				j_db_schema_unref(julea_db_schema_space);
				if (!(julea_db_schema_space = j_db_schema_new("hdf5", "space", NULL)))
					goto _error;
				if (!j_db_schema_add_field(julea_db_schema_space, "data", J_DB_TYPE_BLOB, &error))
					goto _error;
				if (!j_db_schema_create(julea_db_schema_space, batch, &error))
					goto _error;
				if (!j_batch_execute(batch))
					goto _error;
			}
			else
			{
				g_assert_not_reached();
				goto _error;
			}
		}
		else
		{
			g_assert_not_reached();
			goto _error;
		}
	}
	return 0;
_error:
	H5VL_julea_db_error_handler(error);
	H5VL_julea_db_space_term();
	return 1;
}
herr_t
H5VL_julea_db_space_term(void)
{
	J_TRACE_FUNCTION(NULL);

	j_db_schema_unref(julea_db_schema_space);
	julea_db_schema_space = NULL;
	return 0;
}

static JHDF5Object_t*
H5VL_julea_db_space_decode(void* backend_id, guint64 backend_id_len)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(JDBIterator) iterator = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JDBSelector) selector = NULL;
	JHDF5Object_t* object = NULL;
	JDBType type;
	guint64 length;

	object = H5VL_julea_db_object_new(J_HDF5_OBJECT_TYPE_SPACE);
	object->space.data = NULL;
	object->backend_id = g_new(char, backend_id_len);
	memcpy(object->backend_id, backend_id, backend_id_len);
	object->backend_id_len = backend_id_len;

	if (!(selector = j_db_selector_new(julea_db_schema_space, J_DB_SELECTOR_MODE_AND, &error)))
		goto _error;
	G_DEBUG_HERE();
	if (!j_db_selector_add_field(selector, "_id", J_DB_SELECTOR_OPERATOR_EQ, &object->backend_id, object->backend_id_len, &error))
		goto _error;
if (!(iterator = j_db_iterator_new(julea_db_schema_space, selector, &error)))
                goto _error;
	G_DEBUG_HERE();
	if (!j_db_iterator_next(iterator, NULL))
		goto _error;
	G_DEBUG_HERE();
	if (!j_db_iterator_get_field(iterator, "data", &type, &object->space.data, &length, &error))
		goto _error;
	G_DEBUG_HERE();
	g_assert(!j_db_iterator_next(iterator, NULL));
	object->space.hdf5_id = H5Sdecode(object->space.data);
	return object;
_error:
	H5VL_julea_db_error_handler(error);
	H5VL_julea_db_object_unref(object);
	return NULL;
}

static JHDF5Object_t*
H5VL_julea_db_space_encode(hid_t* type_id)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(JDBEntry) entry = NULL;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(JDBIterator) iterator = NULL;
	g_autoptr(JDBSelector) selector = NULL;
	gboolean loop = FALSE;
	JHDF5Object_t* object = NULL;
	JDBType type;
	size_t size;

	g_return_val_if_fail(type_id != NULL, NULL);
	g_return_val_if_fail(*type_id != -1, NULL);

	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);

	//transform to binary
	object = H5VL_julea_db_object_new(J_HDF5_OBJECT_TYPE_SPACE);
	H5Sencode(*type_id, NULL, &size);
	object->space.data = g_new(char, size);
	H5Sencode(*type_id, object->space.data, &size);
	object->space.hdf5_id = *type_id;

_check_type_exist:
	//check if this space exists
	if (!(selector = j_db_selector_new(julea_db_schema_space, J_DB_SELECTOR_MODE_AND, &error)))
		goto _error;
	G_DEBUG_HERE();
	if (!j_db_selector_add_field(selector, "data", J_DB_SELECTOR_OPERATOR_EQ, object->space.data, size, &error))
		goto _error;if (!(iterator = j_db_iterator_new(julea_db_schema_space, selector, &error)))
                goto _error;
	G_DEBUG_HERE();
	if (j_db_iterator_next(iterator, NULL))
	{
		G_DEBUG_HERE();
		if (!j_db_iterator_get_field(iterator, "_id", &type, &object->backend_id, &object->backend_id_len, &error))
			goto _error;
		G_DEBUG_HERE();
		g_assert(!j_db_iterator_next(iterator, NULL));
		goto _done;
	}

	g_return_val_if_fail(loop == FALSE, NULL);

	//create new space if it did not exist before
	if (!(entry = j_db_entry_new(julea_db_schema_space, &error)))
		goto _error;
	G_DEBUG_HERE();
	if (!j_db_entry_set_field(entry, "data", object->space.data, size, &error))
		goto _error;
	if (!j_db_entry_insert(entry, batch, &error))
		goto _error;
	if (!j_batch_execute(batch))
		goto _error;
	loop = TRUE;
	goto _check_type_exist;
_done:
	return object;
_error:
	H5VL_julea_db_error_handler(error);
	H5VL_julea_db_object_unref(object);
	return NULL;
}

#pragma GCC diagnostic pop
#endif
