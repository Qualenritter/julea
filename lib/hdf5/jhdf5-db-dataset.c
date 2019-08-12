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

static JDBSchema* julea_db_schema_dataset = NULL;
static herr_t
H5VL_julea_db_dataset_init(hid_t vipl_id)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(JBatch) batch = NULL;
	g_autoptr(GError) error = NULL;

	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);

	if (!(julea_db_schema_dataset = j_db_schema_new("hdf5", "dataset", NULL)))
		goto _error;
	if (!(j_db_schema_get(julea_db_schema_dataset, batch, &error) && j_batch_execute(batch)))
	{
		if (error)
		{
			if (error->code == J_BACKEND_DB_ERROR_SCHEMA_NOT_FOUND)
			{
				j_db_schema_unref(julea_db_schema_dataset);
				if (!(julea_db_schema_dataset = j_db_schema_new("hdf5", "dataset", NULL)))
					goto _error;
				if (!j_db_schema_add_field(julea_db_schema_dataset, "file", J_DB_TYPE_STRING, &error))
					goto _error;
				if (!j_db_schema_add_field(julea_db_schema_dataset, "name", J_DB_TYPE_STRING, &error))
					goto _error;
				if (!j_db_schema_create(julea_db_schema_dataset, batch, &error))
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
	return 1;
}
static herr_t
H5VL_julea_db_dataset_term(void)
{
	J_TRACE_FUNCTION(NULL);

	j_db_schema_unref(julea_db_schema_dataset);
	julea_db_schema_dataset = NULL;
	return 0;
}

static JHDF5Dataset_t*
H5VL_julea_db_dataset_ref(JHDF5Dataset_t* dataset)
{
	J_TRACE_FUNCTION(NULL);

	g_return_val_if_fail(dataset != NULL, NULL);

	g_atomic_int_inc(&dataset->ref_count);
	return dataset;
}
static void
H5VL_julea_db_dataset_unref(JHDF5Dataset_t* dataset)
{
	J_TRACE_FUNCTION(NULL);

	if (dataset && g_atomic_int_dec_and_test(&dataset->ref_count))
	{
		H5VL_julea_db_file_unref(dataset->file);
		g_free(dataset->name);
		g_free(dataset);
	}
}
static void*
H5VL_julea_db_dataset_create(void* obj, const H5VL_loc_params_t* loc_params, const char* name,
	hid_t lcpl_id, hid_t type_id, hid_t space_id, hid_t dcpl_id,
	hid_t dapl_id, hid_t dxpl_id, void** req)
{
	/*        J_TRACE_FUNCTION(NULL);

        g_autoptr(GError) error = NULL;
        g_autoptr(JBatch) batch = NULL;
        g_autoptr(JDBEntry) entry = NULL;
        JHDF5Dataset_t* dataset = NULL;
        JHDF5File_t* file=obj;

        g_return_val_if_fail(name != NULL, NULL);
        g_return_val_if_fail(file != NULL, NULL);

        batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);

        if (!(entry = j_db_entry_new(julea_db_schema_dataset, &error)))
                goto _error;
        if (!j_db_entry_set_field(entry, "file", file->name, strlen(name), &error))
                goto _error;
        if (!j_db_entry_set_field(entry, "name", name, strlen(name), &error))
                goto _error;
        if (!j_db_entry_insert(entry, batch, &error))
                goto _error;
        dataset = g_new(JHDF5Dataset_t, 1);
        dataset->ref_count=1;
        dataset->name = g_strdup(name);
        dataset->file = H5VL_julea_db_file_ref(file);
        return dataset;
_error:
        H5VL_julea_db_dataset_unref(dataset);
        H5VL_julea_db_error_handler(error);
        return NULL;
*/
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static void*
H5VL_julea_db_dataset_open(void* obj, const H5VL_loc_params_t* loc_params, const char* name,
	hid_t dapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_dataset_read(void* dset, hid_t mem_type_id, hid_t mem_space_id, hid_t file_space_id,
	hid_t xfer_plist_id, void* buf, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_dataset_write(void* dset, hid_t mem_type_id, hid_t mem_space_id, hid_t file_space_id,
	hid_t xfer_plist_id, const void* buf, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_dataset_get(void* obj, H5VL_dataset_get_t get_type, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_dataset_specific(void* obj, H5VL_dataset_specific_t specific_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_dataset_optional(void* obj, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_dataset_close(void* dset, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
#pragma GCC diagnostic pop
#endif
