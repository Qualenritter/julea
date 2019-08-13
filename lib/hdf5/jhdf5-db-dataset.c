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

	if (!(julea_db_schema_dataset = j_db_schema_new(JULEA_HDF5_DB_NAMESPACE, "dataset", NULL)))
		goto _error;
	if (!(j_db_schema_get(julea_db_schema_dataset, batch, &error) && j_batch_execute(batch)))
	{
		if (error)
		{
			if (error->code == J_BACKEND_DB_ERROR_SCHEMA_NOT_FOUND)
			{
				j_db_schema_unref(julea_db_schema_dataset);
				if (!(julea_db_schema_dataset = j_db_schema_new(JULEA_HDF5_DB_NAMESPACE, "dataset", NULL)))
					goto _error;
				if (!j_db_schema_add_field(julea_db_schema_dataset, "file", J_DB_TYPE_STRING, &error))
					goto _error;
				if (!j_db_schema_add_field(julea_db_schema_dataset, "name", J_DB_TYPE_STRING, &error))
					goto _error;
				if (!j_db_schema_add_field(julea_db_schema_dataset, "datatype", J_DB_TYPE_BLOB, &error))
					goto _error;
				if (!j_db_schema_add_field(julea_db_schema_dataset, "space", J_DB_TYPE_BLOB, &error))
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

static void*
H5VL_julea_db_dataset_create(void* obj, const H5VL_loc_params_t* loc_params, const char* name,
	hid_t lcpl_id, hid_t type_id, hid_t space_id, hid_t dcpl_id,
	hid_t dapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(GError) error = NULL;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JDBEntry) entry = NULL;
	g_autoptr(JDBIterator) iterator = NULL;
	g_autoptr(JDBSelector) selector = NULL;
	g_autofree char* hex_buf = NULL;
	JHDF5Object_t* object = NULL;
	JHDF5Object_t* parent = obj;
	JHDF5Object_t* file;
	JDBType type;

	g_return_val_if_fail(name != NULL, NULL);
	g_return_val_if_fail(parent != NULL, NULL);

	switch (parent->type)
	{
	case J_HDF5_OBJECT_TYPE_FILE:
		file = parent;
		break;
	case J_HDF5_OBJECT_TYPE_DATASET:
		file = parent->dataset.file;
		break;
	case J_HDF5_OBJECT_TYPE_ATTR:
		file = parent->attr.file;
		break;
	case J_HDF5_OBJECT_TYPE_DATATYPE:
	case J_HDF5_OBJECT_TYPE_SPACE:
	case _J_HDF5_OBJECT_TYPE_COUNT:
	default:
		g_assert_not_reached();
		goto _error;
	}

	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);

	object = H5VL_julea_db_object_new(J_HDF5_OBJECT_TYPE_DATASET);
	object->dataset.name = g_strdup(name);
	object->dataset.file = H5VL_julea_db_object_ref(file);
	object->dataset.datatype = H5VL_julea_db_datatype_encode(&type_id);
	object->dataset.space = H5VL_julea_db_space_encode(&space_id);
	object->dataset.distribution = NULL;
	object->dataset.object = NULL;

	if (!(entry = j_db_entry_new(julea_db_schema_dataset, &error)))
		goto _error;
	if (!j_db_entry_set_field(entry, "file", file->backend_id, file->backend_id_len, &error))
		goto _error;
	if (!j_db_entry_set_field(entry, "name", name, strlen(name), &error))
		goto _error;
	if (!j_db_entry_set_field(entry, "datatype", object->dataset.datatype->backend_id, object->dataset.datatype->backend_id_len, &error))
		goto _error;
	if (!j_db_entry_set_field(entry, "space", object->dataset.space->backend_id, object->dataset.space->backend_id_len, &error))
		goto _error;
	if (!j_db_entry_insert(entry, batch, &error))
		goto _error;
	if (!j_batch_execute(batch))
		goto _error;
	if (!(selector = j_db_selector_new(julea_db_schema_dataset, J_DB_SELECTOR_MODE_AND, &error)))
		goto _error;
	if (!j_db_selector_add_field(selector, "file", J_DB_SELECTOR_OPERATOR_EQ, file->backend_id, file->backend_id_len, &error))
		goto _error;
	if (!j_db_selector_add_field(selector, "name", J_DB_SELECTOR_OPERATOR_EQ, name, strlen(name), &error))
		goto _error;
	if (!(iterator = j_db_iterator_new(julea_db_schema_dataset, selector, &error)))
		goto _error;
	if (!j_db_iterator_next(iterator, &error))
		goto _error;
	if (!j_db_iterator_get_field(iterator, "_id", &type, &object->backend_id, &object->backend_id_len, &error))
		goto _error;
	g_assert(!j_db_iterator_next(iterator, NULL));
	object->dataset.distribution = j_distribution_new(J_DISTRIBUTION_ROUND_ROBIN);
	hex_buf = H5VL_julea_db_buf_to_hex(object->backend_id, object->backend_id_len);
	object->dataset.object = j_distributed_object_new(JULEA_HDF5_DB_NAMESPACE, hex_buf, object->dataset.distribution);
	g_debug("hex_buf %s", hex_buf);
	j_distributed_object_create(object->dataset.object, batch);
	if (!j_batch_execute(batch))
		goto _error;
	return object;
_error:
	H5VL_julea_db_error_handler(error);
	H5VL_julea_db_object_unref(object);
	return NULL;
}
static void*
H5VL_julea_db_dataset_open(void* obj, const H5VL_loc_params_t* loc_params, const char* name,
	hid_t dapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(GError) error = NULL;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JDBIterator) iterator = NULL;
	g_autoptr(JDBSelector) selector = NULL;
	g_autofree char* hex_buf = NULL;
	g_autofree void* space_id_buf = NULL;
	g_autofree void* datatype_id_buf = NULL;
	JHDF5Object_t* object = NULL;
	JHDF5Object_t* parent = obj;
	JHDF5Object_t* file;
	JDBType type;
	guint64 space_id_buf_len;
	guint64 datatype_id_buf_len;

	g_return_val_if_fail(name != NULL, NULL);
	g_return_val_if_fail(parent != NULL, NULL);

	switch (parent->type)
	{
	case J_HDF5_OBJECT_TYPE_FILE:
		file = parent;
		break;
	case J_HDF5_OBJECT_TYPE_DATASET:
		file = parent->dataset.file;
		break;
	case J_HDF5_OBJECT_TYPE_ATTR:
		file = parent->attr.file;
		break;
	case J_HDF5_OBJECT_TYPE_DATATYPE:
	case J_HDF5_OBJECT_TYPE_SPACE:
	case _J_HDF5_OBJECT_TYPE_COUNT:
	default:
		g_assert_not_reached();
		goto _error;
	}

	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);

	object = H5VL_julea_db_object_new(J_HDF5_OBJECT_TYPE_DATASET);
	object->dataset.name = g_strdup(name);
	object->dataset.file = H5VL_julea_db_object_ref(file);
	object->dataset.distribution = NULL;
	object->dataset.object = NULL;

	G_DEBUG_HERE();
	if (!(selector = j_db_selector_new(julea_db_schema_dataset, J_DB_SELECTOR_MODE_AND, &error)))
		goto _error;
	G_DEBUG_HERE();
	if (!j_db_selector_add_field(selector, "file", J_DB_SELECTOR_OPERATOR_EQ, file->backend_id, file->backend_id_len, &error))
		goto _error;
	G_DEBUG_HERE();
	if (!j_db_selector_add_field(selector, "name", J_DB_SELECTOR_OPERATOR_EQ, name, strlen(name), &error))
		goto _error;
	G_DEBUG_HERE();
	if (!(iterator = j_db_iterator_new(julea_db_schema_dataset, selector, &error)))
		goto _error;
	G_DEBUG_HERE();
	if (!j_db_iterator_next(iterator, &error))
		goto _error;
	G_DEBUG_HERE();
	if (!j_db_iterator_get_field(iterator, "_id", &type, &object->backend_id, &object->backend_id_len, &error))
		goto _error;
	G_DEBUG_HERE();
	if (!j_db_iterator_get_field(iterator, "space", &type, &space_id_buf, &space_id_buf_len, &error))
		goto _error;
g_assert(type==J_DB_TYPE_BLOB);
	if (!(object->dataset.space = H5VL_julea_db_space_decode(space_id_buf, space_id_buf_len)))
		goto _error;
	G_DEBUG_HERE();
	if (!j_db_iterator_get_field(iterator, "datatype", &type, &datatype_id_buf, &datatype_id_buf_len, &error))
		goto _error;
g_assert(type==J_DB_TYPE_BLOB);
	if (!(object->dataset.datatype = H5VL_julea_db_datatype_decode(datatype_id_buf, datatype_id_buf_len)))
		goto _error;
	G_DEBUG_HERE();
	g_assert(!j_db_iterator_next(iterator, NULL));
	G_DEBUG_HERE();
	object->dataset.distribution = j_distribution_new(J_DISTRIBUTION_ROUND_ROBIN);
	G_DEBUG_HERE();
	hex_buf = H5VL_julea_db_buf_to_hex(object->backend_id, object->backend_id_len);
	G_DEBUG_HERE();
	object->dataset.object = j_distributed_object_new(JULEA_HDF5_DB_NAMESPACE, hex_buf, object->dataset.distribution);
	g_debug("hex_buf %s", hex_buf);
	G_DEBUG_HERE();
	return object;
_error:
	G_DEBUG_HERE();
	H5VL_julea_db_error_handler(error);
	G_DEBUG_HERE();
	H5VL_julea_db_object_unref(object);
	G_DEBUG_HERE();
	return NULL;
}
static herr_t
H5VL_julea_db_dataset_read(void* obj, hid_t mem_type_id, hid_t mem_space_id, hid_t file_space_id,
	hid_t xfer_plist_id, void* buf, void** req)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(JBatch) batch = NULL;
	guint64 bytes_read;
	gsize data_size;
	JHDF5Object_t* object = obj;
	hsize_t* dims;
	gint ndims;

	g_return_val_if_fail(buf != NULL, 1);
	g_return_val_if_fail(object->type == J_HDF5_OBJECT_TYPE_DATASET, 1);
	g_return_val_if_fail(file_space_id == H5S_ALL, 1); //read entire dataset
	g_return_val_if_fail(mem_space_id == H5S_ALL, 1); //read entire dataset
	//TODO compare mem_type_id with stored type

	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	bytes_read = 0;
	data_size = H5Tget_size(object->dataset.datatype->datatype.hdf5_id);
	ndims = H5Sget_simple_extent_ndims(object->dataset.space->space.hdf5_id);
	dims = g_new(hsize_t, ndims);
	H5Sget_simple_extent_dims(object->dataset.space->space.hdf5_id, dims, NULL);

	for (gint i = 0; i < ndims; i++)
	{
		data_size *= dims[i];
	}
	j_distributed_object_read(object->dataset.object, buf, data_size, 0, &bytes_read, batch);
	if (!j_batch_execute(batch))
		goto _error;
	g_free(dims);
	return 0;
_error:
	g_free(dims);
	return 1;
}
static herr_t
H5VL_julea_db_dataset_write(void* obj, hid_t mem_type_id, hid_t mem_space_id, hid_t file_space_id,
	hid_t xfer_plist_id, const void* buf, void** req)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(JBatch) batch = NULL;
	guint64 bytes_written;
	gsize data_size;
	JHDF5Object_t* object = obj;
	hsize_t* dims;
	gint ndims;

	g_return_val_if_fail(buf != NULL, 1);
	g_return_val_if_fail(object->type == J_HDF5_OBJECT_TYPE_DATASET, 1);
	g_return_val_if_fail(file_space_id == H5S_ALL, 1); //write entire dataset
	g_return_val_if_fail(mem_space_id == H5S_ALL, 1); //write entire dataset
	//TODO compare mem_type_id with stored type

	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	bytes_written = 0;
	data_size = H5Tget_size(object->dataset.datatype->datatype.hdf5_id);
	ndims = H5Sget_simple_extent_ndims(object->dataset.space->space.hdf5_id);
	dims = g_new(hsize_t, ndims);
	H5Sget_simple_extent_dims(object->dataset.space->space.hdf5_id, dims, NULL);

	for (gint i = 0; i < ndims; i++)
	{
		data_size *= dims[i];
	}
	j_distributed_object_write(object->dataset.object, buf, data_size, 0, &bytes_written, batch);
	if (!j_batch_execute(batch))
		goto _error;
	g_free(dims);
	return 0;
_error:
	g_free(dims);
	return 1;
}
static herr_t
H5VL_julea_db_dataset_get(void* obj, H5VL_dataset_get_t get_type, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);

	JHDF5Object_t* object = obj;

	g_return_val_if_fail(object->type == J_HDF5_OBJECT_TYPE_DATASET, 1);

	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_dataset_specific(void* obj, H5VL_dataset_specific_t specific_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);

	JHDF5Object_t* object = obj;

	g_return_val_if_fail(object->type == J_HDF5_OBJECT_TYPE_DATASET, 1);

	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_dataset_optional(void* obj, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);

	JHDF5Object_t* object = obj;

	g_return_val_if_fail(object->type == J_HDF5_OBJECT_TYPE_DATASET, 1);

	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_dataset_close(void* obj, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);

	JHDF5Object_t* object = obj;

	g_return_val_if_fail(object->type == J_HDF5_OBJECT_TYPE_DATASET, 1);

	H5VL_julea_db_object_unref(object);
	return 0;
}
#pragma GCC diagnostic pop
#endif
