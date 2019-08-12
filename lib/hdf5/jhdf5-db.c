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
#include "jhdf5-db-file.c"
#include "jhdf5-db-dataset.c"
#include "jhdf5-db-attr.c"
#include "jhdf5-db-group.c"
#include "jhdf5-db-datatype.c"

#define _GNU_SOURCE

#define JULEA_DB 530

static void
H5VL_julea_db_error_handler(GError* error)
{
	J_TRACE_FUNCTION(NULL);

	if (error)
	{
		g_debug("%s %d %s", g_quark_to_string(error->domain), error->code, error->message);
	}
}

static JHDF5Object_t*
H5VL_julea_db_object_ref(JHDF5Object_t* object)
{
	J_TRACE_FUNCTION(NULL);

	g_return_val_if_fail(object != NULL, NULL);

	g_atomic_int_inc(&object->ref_count);
	return object;
}
static JHDF5Object_t*
H5VL_julea_db_object_new(JHDF5ObjectType type)
{
	J_TRACE_FUNCTION(NULL);

	JHDF5Object_t* object;

	g_return_val_if_fail(type < _J_HDF5_OBJECT_TYPE_COUNT, NULL);

	object = g_new(JHDF5Object_t, 1);
	object->ref_count = 1;
	object->type = type;
	return object;
}
static void
H5VL_julea_db_object_unref(JHDF5Object_t* object)
{
	J_TRACE_FUNCTION(NULL);

	if (object && g_atomic_int_dec_and_test(&object->ref_count))
	{
		switch (object->type)
		{
		case J_HDF5_OBJECT_TYPE_FILE:
			g_free(object->file.name);
			break;
		case J_HDF5_OBJECT_TYPE_DATASET:
			H5VL_julea_db_object_unref(object->dataset.file);
			g_free(object->dataset.name);
			break;
		case _J_HDF5_OBJECT_TYPE_COUNT:
		default:
			g_assert_not_reached();
		}
		g_free(object);
	}
}

static herr_t
H5VL_julea_db_init(hid_t vipl_id)
{
	J_TRACE_FUNCTION(NULL);

	if (H5VL_julea_db_file_init(vipl_id))
		goto _error_file;
	if (H5VL_julea_db_dataset_init(vipl_id))
		goto _error_dataset;
	if (H5VL_julea_db_attr_init(vipl_id))
		goto _error_attr;
	if (H5VL_julea_db_datatype_init(vipl_id))
		goto _error_datatype;
	if (H5VL_julea_db_group_init(vipl_id))
		goto _error_group;
	return 0;
_error_group:
	H5VL_julea_db_group_term();
_error_datatype:
	H5VL_julea_db_datatype_term();
_error_attr:
	H5VL_julea_db_attr_term();
_error_dataset:
	H5VL_julea_db_dataset_term();
_error_file:
	H5VL_julea_db_file_term();
	return 1;
}
static herr_t
H5VL_julea_db_term(void)
{
	J_TRACE_FUNCTION(NULL);

	if (H5VL_julea_db_group_term())
		goto _error;
	if (H5VL_julea_db_datatype_term())
		goto _error;
	if (H5VL_julea_db_attr_term())
		goto _error;
	if (H5VL_julea_db_dataset_term())
		goto _error;
	if (H5VL_julea_db_file_term())
		goto _error;
	return 0;
_error:
	return 1;
}

/**
 * The class providing the functions to HDF5
 * @see dependencies/opt/spack/linux-ubuntu19.04-x86_64/gcc-8.3.0/hdf5-develop-4iami4kalqj7xgv2x2uv25dnzvz4xzwf/include/H5VLconnector.h
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
		.create = NULL,
		.copy = NULL,
		.move = NULL,
		.get = NULL,
		.specific = NULL,
		.optional = NULL,
	},
	.object_cls = {
		.open = NULL,
		.copy = NULL,
		.get = NULL,
		.specific = NULL,
		.optional = NULL,
	},
	.request_cls = {
		.wait = NULL,
		.notify = NULL,
		.cancel = NULL,
		.specific = NULL,
		.optional = NULL,
		.free = NULL,
	},
	.optional = NULL
};
#pragma GCC diagnostic pop
#endif
