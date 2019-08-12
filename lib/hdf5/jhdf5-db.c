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

#define _GNU_SOURCE

#define JULEA_DB 530

#ifdef JULEA_HDF_COMPILES
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

struct JHDF5File_t
{
	char* name;
};
typedef struct JHDF5File_t JHDF5File_t;

static JDBSchema* julea_db_schema_file = NULL;

static void
H5VL_julea_db_file_free(JHDF5File_t* file)
{
	if (file)
	{
		g_free(file->name);
		g_free(file);
	}
}
static void
H5VL_julea_db_error_handler(GError* error)
{
	J_TRACE_FUNCTION(NULL);

	if (error)
	{
		g_debug("%s %d %s", g_quark_to_string(error->domain), error->code, error->message);
	}
}

static herr_t
H5VL_julea_db_init(hid_t vipl_id)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(JBatch) batch = NULL;
	g_autoptr(GError) error = NULL;

	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);

	if (!(julea_db_schema_file = j_db_schema_new("hdf5", "file", NULL)))
		goto _error_file;
	if (!(j_db_schema_get(julea_db_schema_file, batch, &error) && j_batch_execute(batch)))
	{
		if (error)
		{
			if (error->code == J_BACKEND_DB_ERROR_SCHEMA_NOT_FOUND)
			{
				j_db_schema_unref(julea_db_schema_file);
				if (!(julea_db_schema_file = j_db_schema_new("hdf5", "file", NULL)))
					goto _error_file;
				if (!j_db_schema_add_field(julea_db_schema_file, "name", J_DB_TYPE_STRING, &error))
					goto _error_file;
				if (!j_db_schema_create(julea_db_schema_file, batch, &error))
					goto _error_file;
				if (!j_batch_execute(batch))
					goto _error_file;
			}
			else
			{
				g_assert_not_reached();
				goto _error_file;
			}
		}
		else
		{
			g_assert_not_reached();
			goto _error_file;
		}
	}

	return 0;
_error_file:
	j_db_schema_unref(julea_db_schema_file);
	julea_db_schema_file = NULL;
	H5VL_julea_db_error_handler(error);
	return 1;
}
static herr_t
H5VL_julea_db_term(void)
{
	J_TRACE_FUNCTION(NULL);

	j_db_schema_unref(julea_db_schema_file);
	return 0;
}
static void*
H5VL_julea_db_attr_create(void* obj, const H5VL_loc_params_t* loc_params, const char* attr_name,
	hid_t type_id, hid_t space_id, hid_t acpl_id, hid_t aapl_id,
	hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static void*
H5VL_julea_db_attr_open(void* obj, const H5VL_loc_params_t* loc_params, const char* attr_name,
	hid_t aapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_attr_read(void* attr, hid_t mem_type_id, void* buf, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_attr_write(void* attr, hid_t mem_type_id, const void* buf, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_attr_get(void* obj, H5VL_attr_get_t get_type, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_attr_specific(void* obj, const H5VL_loc_params_t* loc_params, H5VL_attr_specific_t specific_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_attr_optional(void* obj, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_attr_close(void* attr, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static void*
H5VL_julea_db_dataset_create(void* obj, const H5VL_loc_params_t* loc_params, const char* name,
	hid_t lcpl_id, hid_t type_id, hid_t space_id, hid_t dcpl_id,
	hid_t dapl_id, hid_t dxpl_id, void** req)
{
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
static void*
H5VL_julea_db_datatype_commit(void* obj, const H5VL_loc_params_t* loc_params, const char* name, hid_t type_id,
	hid_t lcpl_id, hid_t tcpl_id, hid_t tapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static void*
H5VL_julea_db_datatype_open(void* obj, const H5VL_loc_params_t* loc_params, const char* name,
	hid_t tapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_datatype_get(void* obj, H5VL_datatype_get_t get_type, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_datatype_specific(void* obj, H5VL_datatype_specific_t specific_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_datatype_optional(void* obj, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_datatype_close(void* dt, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static void*
H5VL_julea_db_file_create(const char* name, unsigned flags, hid_t fcpl_id,
	hid_t fapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(GError) error = NULL;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JDBEntry) entry = NULL;
	JHDF5File_t* file = NULL;

	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);

	if (!(entry = j_db_entry_new(julea_db_schema_file, &error)))
		goto _error;
	if (!j_db_entry_set_field(entry, "name", name, strlen(name), &error))
		goto _error;
	if (!j_db_entry_insert(entry, batch, &error))
		goto _error;
	file = g_new(JHDF5File_t, 1);
	file->name = g_strdup(name);
	return file;
_error:
	H5VL_julea_db_file_free(file);
	H5VL_julea_db_error_handler(error);
	return NULL;
}
static void*
H5VL_julea_db_file_open(const char* name, unsigned flags, hid_t fapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);

	g_autoptr(GError) error = NULL;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JDBIterator) iterator = NULL;
	g_autoptr(JDBSelector) selector = NULL;
	JHDF5File_t* file = NULL;
	JDBType type;
	guint64 length;
	void* value;

	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);

	if (!(selector = j_db_selector_new(julea_db_schema_file, J_DB_SELECTOR_MODE_AND, &error)))
		goto _error;
	if (!j_db_selector_add_field(selector, "name", J_DB_SELECTOR_OPERATOR_EQ, name, strlen(name), &error))
		goto _error;
	if (!(iterator = j_db_iterator_new(julea_db_schema_file, selector, &error)))
		goto _error;
	if (!j_db_iterator_next(iterator, &error))
		goto _error;
	if (!j_db_iterator_get_field(iterator, "name", &type, &value, &length, &error))
		goto _error;
	if (g_strcmp0(value, name))
		goto _error;
	if (j_db_iterator_next(iterator, &error))
		goto _error;
	file = g_new(JHDF5File_t, 1);
	file->name = g_strdup(name);
	return file;
_error:
	H5VL_julea_db_file_free(file);
	H5VL_julea_db_error_handler(error);
	return NULL;
}
static herr_t
H5VL_julea_db_file_get(void* obj, H5VL_file_get_t get_type, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_file_specific(void* obj, H5VL_file_specific_t specific_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_file_optional(void* obj, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_file_close(void* file, hid_t dxpl_id, void** req)
{
	H5VL_julea_db_file_free(file);
	return 0;
}
static void*
H5VL_julea_db_group_create(void* obj, const H5VL_loc_params_t* loc_params, const char* name,
	hid_t lcpl_id, hid_t gcpl_id, hid_t gapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static void*
H5VL_julea_db_group_open(void* obj, const H5VL_loc_params_t* loc_params, const char* name,
	hid_t gapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_group_get(void* obj, H5VL_group_get_t get_type, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_group_specific(void* obj, H5VL_group_specific_t specific_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_group_optional(void* obj, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_group_close(void* grp, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_link_create(H5VL_link_create_type_t create_type, void* obj, const H5VL_loc_params_t* loc_params,
	hid_t lcpl_id, hid_t lapl_id, hid_t dxpl_id, void** req, va_list argumenmts)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_link_copy(void* src_obj, const H5VL_loc_params_t* loc_params1,
	void* dst_obj, const H5VL_loc_params_t* loc_params2,
	hid_t lcpl, hid_t lapl, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_link_move(void* src_obj, const H5VL_loc_params_t* loc_params1,
	void* dst_obj, const H5VL_loc_params_t* loc_params2,
	hid_t lcpl, hid_t lapl, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_link_get(void* obj, const H5VL_loc_params_t* loc_params, H5VL_link_get_t get_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_link_specific(void* obj, const H5VL_loc_params_t* loc_params, H5VL_link_specific_t specific_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_link_optional(void* obj, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static void*
H5VL_julea_db_object_open(void* obj, const H5VL_loc_params_t* loc_params, H5I_type_t* opened_type,
	hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_object_copy(void* src_obj, const H5VL_loc_params_t* loc_params1, const char* src_name,
	void* dst_obj, const H5VL_loc_params_t* loc_params2, const char* dst_name,
	hid_t ocpypl_id, hid_t lcpl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_object_get(void* obj, const H5VL_loc_params_t* loc_params, H5VL_object_get_t get_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_object_specific(void* obj, const H5VL_loc_params_t* loc_params, H5VL_object_specific_t specific_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_object_optional(void* obj, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_request_wait(void* req, uint64_t timeout, H5ES_status_t* status)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_request_notify(void* req, H5VL_request_notify_t cb, void* ctx)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_request_cancel(void* req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_request_specific(void* req, H5VL_request_specific_t specific_type, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_request_optional(void* req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_request_free(void* req)
{
	J_TRACE_FUNCTION(NULL);
	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}

/**
 * The class providing the functions to HDF5
 **/
static const H5VL_class_t H5VL_julea_db_g = {
	.version = 0,
	.value = JULEA_DB,
	.name = "julea",
	.cap_flags = 0,
	.initialize = H5VL_julea_db_init,
	.terminate = H5VL_julea_db_term,
	.info_cls = {
		.size = 0,
		.copy = NULL,
		.cmp = NULL,
		.free = NULL,
		.to_str = NULL,
		.from_str = NULL,
	},
	.wrap_cls = {
		.get_object = NULL,
		.get_wrap_ctx = NULL,
		.wrap_object = NULL,
		.unwrap_object = NULL,
		.free_wrap_ctx = NULL,
	},
	.attr_cls = {
		.create = H5VL_julea_db_attr_create,
		.open = H5VL_julea_db_attr_open,
		.read = H5VL_julea_db_attr_read,
		.write = H5VL_julea_db_attr_write,
		.get = H5VL_julea_db_attr_get,
		.specific = H5VL_julea_db_attr_specific,
		.optional = H5VL_julea_db_attr_optional,
		.close = H5VL_julea_db_attr_close,
	},
	.dataset_cls = {
		.create = H5VL_julea_db_dataset_create,
		.open = H5VL_julea_db_dataset_open,
		.read = H5VL_julea_db_dataset_read,
		.write = H5VL_julea_db_dataset_write,
		.get = H5VL_julea_db_dataset_get,
		.specific = H5VL_julea_db_dataset_specific,
		.optional = H5VL_julea_db_dataset_optional,
		.close = H5VL_julea_db_dataset_close,
	},
	.datatype_cls = {
		.commit = H5VL_julea_db_datatype_commit,
		.open = H5VL_julea_db_datatype_open,
		.get = H5VL_julea_db_datatype_get,
		.specific = H5VL_julea_db_datatype_specific,
		.optional = H5VL_julea_db_datatype_optional,
		.close = H5VL_julea_db_datatype_close,
	},
	.file_cls = {
		.create = H5VL_julea_db_file_create,
		.open = H5VL_julea_db_file_open,
		.get = H5VL_julea_db_file_get,
		.specific = H5VL_julea_db_file_specific,
		.optional = H5VL_julea_db_file_optional,
		.close = H5VL_julea_db_file_close,
	},
	.group_cls = {
		.create = H5VL_julea_db_group_create,
		.open = H5VL_julea_db_group_open,
		.get = H5VL_julea_db_group_get,
		.specific = H5VL_julea_db_group_specific,
		.optional = H5VL_julea_db_group_optional,
		.close = H5VL_julea_db_group_close,
	},
	.link_cls = {
		.create = H5VL_julea_db_link_create,
		.copy = H5VL_julea_db_link_copy,
		.move = H5VL_julea_db_link_move,
		.get = H5VL_julea_db_link_get,
		.specific = H5VL_julea_db_link_specific,
		.optional = H5VL_julea_db_link_optional,
	},
	.object_cls = {
		.open = H5VL_julea_db_object_open,
		.copy = H5VL_julea_db_object_copy,
		.get = H5VL_julea_db_object_get,
		.specific = H5VL_julea_db_object_specific,
		.optional = H5VL_julea_db_object_optional,
	},
	.request_cls = {
		.wait = H5VL_julea_db_request_wait,
		.notify = H5VL_julea_db_request_notify,
		.cancel = H5VL_julea_db_request_cancel,
		.specific = H5VL_julea_db_request_specific,
		.optional = H5VL_julea_db_request_optional,
		.free = H5VL_julea_db_request_free,
	},
	.optional = NULL
};
#pragma GCC diagnostic pop
#endif
