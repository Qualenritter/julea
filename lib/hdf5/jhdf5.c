/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2017 Olga Perevalova
 * Copyright (C) 2017 Eugen Betke
 * Copyright (C) 2018-2019 Johannes Coym
 * Copyright (C) 2019 Michael Kuhn
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

// FIXME check whether version is up to date: https://github.com/Olgasnezh/hdf5-vol-sqlite-plugin

#define H5Sencode_vers 1

#include <bson.h>
#include <glib.h>

#include <julea.h>

#include <julea-config.h>
#include <julea-internal.h>
#include <julea-object.h>
#include <julea-smd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <H5PLextern.h>
#include <hdf5.h>

#define _GNU_SOURCE

#define JULEA 520

/**
 * Initializes the plugin
 *
 * \return err Error
 **/
static herr_t
H5VL_julea_init(hid_t vipl_id __attribute__((unused)))
{
	return 0;
}

/**
 * Terminates the plugin
 *
 * \return err Error
 **/
static herr_t
H5VL_julea_term(void)
{
	return 0;
}

static J_SMD_Space_t*
hdf5_space_export(hid_t space_id __attribute__((unused)))
{
	void* space;
	guint ndims;
	hsize_t* dims1;
	guint* dims2;
	guint i;
	ndims = H5Sget_simple_extent_ndims(space_id);
	dims1 = g_new(hsize_t, ndims);
	dims2 = g_new(guint, ndims);
	H5Sget_simple_extent_dims(space_id, dims1, NULL);
	for (i = 0; i < ndims; i++)
	{
		dims2[i] = dims1[i];
	}
	space = j_smd_space_create(ndims, dims2);
	g_free(dims1);
	g_free(dims2);
	return space;
}
static J_SMD_Type_t*
hdf5_type_export(hid_t type_id __attribute__((unused)))
{
	void* type;
	type = j_smd_type_create();
	/*TODO type data*/
	return type;
}
static int
hdf5_space_import(J_SMD_Space_t* space __attribute__((unused)), hid_t* type_id __attribute__((unused)))
{
	return FALSE; /*TODO*/
}
static int
hdf5_type_import(J_SMD_Type_t* type __attribute__((unused)), hid_t* type_id __attribute__((unused)))
{
	return FALSE; /*TODO*/
}
static void*
H5VL_julea_attr_create(void* _parent __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	const char* name __attribute__((unused)), //
	hid_t type_id __attribute__((unused)), //
	hid_t space_id __attribute__((unused)), //
	hid_t acpl_id __attribute__((unused)), //
	hid_t aapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	void* type;
	void* space;
	J_Scheme_t* parent = (J_Scheme_t*)_parent;
	J_Scheme_t* attr;
	g_autoptr(JBatch) batch = NULL;
	if (!j_is_key_initialized(parent->key))
		return 0;
	type = hdf5_type_export(type_id);
	space = hdf5_space_export(space_id);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	attr = j_smd_scheme_create(name, parent, type, space, J_DISTRIBUTION_DATABASE, batch);
	j_batch_execute(batch);
	j_smd_type_unref(type);
	j_smd_space_unref(space);
	return attr;
}
static herr_t
H5VL_julea_attr_read(void* _scheme __attribute__((unused)), //
	hid_t dtype_id __attribute__((unused)), //
	void* buf __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* scheme = (J_Scheme_t*)_scheme;
	guint size = 0; /*TODO calculate it correctly*/
	if (!j_is_key_initialized(scheme->key))
		return 1;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	j_smd_scheme_read(scheme, buf, 0, size, batch);
	j_batch_execute(batch);
	return 0;
}
static herr_t
H5VL_julea_attr_write(void* _scheme __attribute__((unused)), //
	hid_t dtype_id __attribute__((unused)), //
	const void* buf __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* scheme = (J_Scheme_t*)_scheme;
	guint size = 0; /*TODO calculate it correctly*/
	if (!j_is_key_initialized(scheme->key))
		return 1;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	j_smd_scheme_write(scheme, buf, 0, size, batch);
	j_batch_execute(batch);
	return 0;
}
static herr_t
H5VL_julea_scheme_get(void* _scheme __attribute__((unused)), //
	H5VL_attr_get_t get_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_Scheme_t* scheme = (J_Scheme_t*)_scheme;
	if (!j_is_key_initialized(scheme->key))
		return 1;
	switch (get_type)
	{
	case H5VL_ATTR_GET_ACPL:
		break;
	case H5VL_ATTR_GET_INFO:
		break;
	case H5VL_ATTR_GET_NAME:
		break;
	case H5VL_ATTR_GET_SPACE:
		hdf5_space_import(scheme->space, va_arg(arguments, hid_t*));
		break;
	case H5VL_ATTR_GET_STORAGE_SIZE:
		break;
	case H5VL_ATTR_GET_TYPE:
		hdf5_type_import(scheme->type, va_arg(arguments, hid_t*));
		break;
	default:
		printf("ERROR: unsupported type %s:%d\n", __FILE__, __LINE__);
		exit(1);
	}
	return 0;
}
static herr_t
H5VL_julea_scheme_close(void* scheme __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	j_smd_scheme_unref(scheme);
	return 0;
}
static void*
H5VL_julea_file_create(const char* name __attribute__((unused)), //
	unsigned flags __attribute__((unused)), //
	hid_t fcpl_id __attribute__((unused)), //
	hid_t fapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_Scheme_t* scheme;
	g_autoptr(JBatch) batch = NULL;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	scheme = j_smd_file_create(name, batch);
	j_batch_execute(batch);
	return scheme;
}
static void*
H5VL_julea_file_open(const char* name __attribute__((unused)),
	unsigned flags __attribute__((unused)),
	hid_t fapl_id __attribute__((unused)),
	hid_t dxpl_id __attribute__((unused)),
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* scheme;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	scheme = j_smd_file_open(name, batch);
	j_batch_execute(batch);
	return scheme;
}
static herr_t
H5VL_julea_file_close(void* _scheme __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	j_smd_file_unref(_scheme);
	return 0;
}
static void*
H5VL_julea_group_create(void* _parent __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	const char* name __attribute__((unused)), //
	hid_t lcpl_id __attribute__((unused)), //
	hid_t gcpl_id __attribute__((unused)), //
	hid_t gapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* parent = (J_Scheme_t*)_parent;
	J_Scheme_t* scheme;
	if (!j_is_key_initialized(parent->key))
		return 0;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	scheme = j_smd_scheme_create(name, parent, NULL, NULL, J_DISTRIBUTION_DATABASE, batch);
	j_batch_execute(batch);

	return scheme;
}
static void*
H5VL_julea_dataset_create(void* _parent __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	const char* name __attribute__((unused)), //
	hid_t lcpl_id __attribute__((unused)), //
	hid_t type_id __attribute__((unused)), //
	hid_t space_id __attribute__((unused)), //
	hid_t dcpl_id __attribute__((unused)), //
	hid_t dapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	void* type;
	void* space;
	J_Scheme_t* parent = (J_Scheme_t*)_parent;
	J_Scheme_t* dataset;
	if (!j_is_key_initialized(parent->key))
		return 0;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	type = hdf5_type_export(type_id);
	space = hdf5_space_export(space_id);
	dataset = j_smd_scheme_create(name, parent, type, space, J_DISTRIBUTION_ROUND_ROBIN, batch);
	j_batch_execute(batch);
	j_smd_type_unref(type);
	j_smd_space_unref(space);

	return dataset;
}
static void*
H5VL_julea_scheme_open(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	const char* name __attribute__((unused)), //
	hid_t dapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* parent = (J_Scheme_t*)obj;
	J_Scheme_t* dataset;
	if (!j_is_key_initialized(parent->key))
		return 0;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	dataset = j_smd_scheme_open(name, parent, batch);
	j_batch_execute(batch);
	return dataset;
}
static herr_t
H5VL_julea_dataset_read(void* _dataset __attribute__((unused)), //
	hid_t mem_type_id __attribute__((unused)), //
	hid_t mem_space_id __attribute__((unused)), //
	hid_t file_space_id __attribute__((unused)), //
	hid_t plist_id __attribute__((unused)), //
	void* buf __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* dataset = (J_Scheme_t*)_dataset;
	guint64 bytes_read;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	bytes_read = 0;
	g_assert(buf != NULL);
	g_assert(dataset->object != NULL);
	int len_to_read = 4096; /*TODO specify which data and offset?*/
	int off_to_read = 0; /*TODO specify which data and offset?*/
	j_distributed_object_read(dataset->object, buf, len_to_read, off_to_read, &bytes_read, batch);
	j_batch_execute(batch);
	return 0;
}
static herr_t
H5VL_julea_dataset_write(void* dset __attribute__((unused)), //
	hid_t mem_type_id __attribute__((unused)), //
	hid_t mem_space_id __attribute__((unused)), //
	hid_t file_space_id __attribute__((unused)), //
	hid_t plist_id __attribute__((unused)), //
	const void* buf __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* dataset = (J_Scheme_t*)dset;
	guint64 bytes_written;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	bytes_written = 0;
	int len_to_read = 4096; /*TODO specify which data and offset?*/
	int off_to_read = 0; /*TODO specify which data and offset?*/
	j_distributed_object_write(dataset->object, buf, len_to_read, off_to_read, &bytes_written, batch);
	j_batch_execute(batch);
	return 0;
}
static const H5VL_class_t H5VL_julea_g = { 0,
	JULEA,
	"julea", /* name */
	0,
	H5VL_julea_init, /* initialize */
	H5VL_julea_term, /* terminate */
	{ 0, NULL, NULL, NULL, NULL, NULL },
	{ NULL, NULL, NULL, NULL, NULL },
	{
		/* attribute_cls */
		H5VL_julea_attr_create, /* create */
		H5VL_julea_scheme_open, /* open */
		H5VL_julea_attr_read, /* read */
		H5VL_julea_attr_write, /* write */
		H5VL_julea_scheme_get, /* get */
		NULL, // H5VL_julea_attr_specific,              /* specific */
		NULL, // H5VL_julea_attr_optional,              /* optional */
		H5VL_julea_scheme_close /* close */
	},
	{
		/* dataset_cls */
		H5VL_julea_dataset_create, /* create */
		H5VL_julea_scheme_open, /* open */
		H5VL_julea_dataset_read, /* read */
		H5VL_julea_dataset_write, /* write */
		H5VL_julea_scheme_get, /* get */
		NULL, // H5VL_julea_dataset_specific,          /* specific */
		NULL, // H5VL_julea_dataset_optional,          /* optional */
		H5VL_julea_scheme_close /* close */
	},
	{
		/* datatype_cls */
		NULL, // H5VL_julea_datatype_commit, /* commit */
		NULL, // H5VL_julea_datatype_open,   /* open */
		NULL, // H5VL_julea_datatype_get,	/* get_size */
		NULL, // H5VL_julea_datatype_specific,         /* specific */
		NULL, // H5VL_julea_datatype_optional,         /* optional */
		NULL, // H5VL_julea_datatype_close   /* close */
	},
	{
		/* file_cls */
		H5VL_julea_file_create, /* create */
		H5VL_julea_file_open, /* open */
		NULL, // H5VL_julea_file_get,	/* get */
		NULL, // H5VL_julea_file_specific,            /* specific */
		NULL, // H5VL_julea_file_optional,            /* optional */
		H5VL_julea_file_close /* close */
	},
	{
		/* group_cls */
		H5VL_julea_group_create, /* create */
		H5VL_julea_scheme_open, /* open */
		NULL, // H5VL_julea_group_get,	/* get */
		NULL, // H5VL_julea_group_specific,           /* specific */
		NULL, // H5VL_julea_group_optional,           /* optional */
		H5VL_julea_scheme_close /* close */
	},
	{
		/* link_cls */
		NULL, // H5VL_julea_link_create,                /* create */
		NULL, // H5VL_julea_link_copy,                  /* copy */
		NULL, // H5VL_julea_link_move,                  /* move */
		NULL, // H5VL_julea_link_get,                   /* get */
		NULL, // H5VL_julea_link_specific,              /* specific */
		NULL, // H5VL_julea_link_optional,              /* optional */
	},
	{
		/* object_cls */
		NULL, // H5VL_julea_object_open,                        /* open */
		NULL, // H5VL_julea_object_copy,                /* copy */
		NULL, // H5VL_julea_object_get,                 /* get */
		NULL, // H5VL_julea_object_specific,                    /* specific */
		NULL, // H5VL_julea_object_optional,            /* optional */
	},
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	NULL };

/**
 * Provides the plugin type
 **/
H5PL_type_t
H5PLget_plugin_type(void)
{
	return H5PL_TYPE_VOL;
}

/**
 * Provides a pointer to the plugin structure
 **/
const void*
H5PLget_plugin_info(void)
{
	return &H5VL_julea_g;
}
