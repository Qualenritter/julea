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
#include <julea.h>

#include <bson.h>
#include <glib.h>

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

#define SUCCEED 0
#define FAIL -1

struct J_HDF_Scheme_t
{
	hid_t type_id;
	hid_t space_id;
	guint type_size;
};
typedef struct J_HDF_Scheme_t J_HDF_Scheme_t;

/**
 * Initializes the plugin
 *
 * \return err Error
 **/
static herr_t
H5VL_julea_init(hid_t vipl_id __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
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
	J_CRITICAL("DEBUG start%d", 0);
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
static gboolean
hdf5_type_export_recourse(hid_t type_id __attribute__((unused)), const char* name, guint offset, void* parent, guint ndims, guint* dims)
{
	void* type;
	int i;
	guint dims2[SMD_MAX_NDIMS];
	hsize_t dims3[SMD_MAX_NDIMS];
	guint one = 1;
	if (parent == NULL)
		parent = j_smd_type_create();
	switch (H5Tget_class(type_id))
	{
	case H5T_INTEGER:
		j_smd_type_add_atomic_type(parent, name, offset, H5Tget_size(type_id), SMD_TYPE_INT, ndims, dims);
		break;
	case H5T_FLOAT:
		j_smd_type_add_atomic_type(parent, name, offset, H5Tget_size(type_id), SMD_TYPE_FLOAT, ndims, dims);
		break;
	case H5T_COMPOUND:
		for (i = 0; i < H5Tget_nmembers(type_id); i++)
		{
			type = j_smd_type_create();
			hdf5_type_export_recourse(H5Tget_member_type(type_id, i), H5Tget_member_name(type_id, i), H5Tget_member_offset(type_id, i), type, one, &one);
			j_smd_type_add_compound_type(parent, name, offset, H5Tget_size(type_id), type, ndims, dims);
			j_smd_type_unref(type);
		}
		break;
	case H5T_ARRAY:
		ndims = H5Tget_array_ndims(type_id);
		H5Tget_array_dims2(type_id, dims3);
		for (i = 0; i < SMD_MAX_NDIMS; i++)
			dims2[i] = dims3[i];
		hdf5_type_export_recourse(H5Tget_member_type(type_id, 0), name, offset, parent, ndims, dims2);
		break;
	case H5T_STRING:
	case H5T_BITFIELD:
	case H5T_OPAQUE:
	case H5T_REFERENCE:
	case H5T_ENUM:
	case H5T_VLEN:
	case H5T_NO_CLASS:
	case H5T_TIME:
	case H5T_NCLASSES:
	default:
		J_CRITICAL("unsupported class type=%d", H5Tget_class(type_id));
		exit(1);
	}
	return TRUE;
}
static void*
hdf5_type_export(hid_t type_id __attribute__((unused)))
{
	void* type;
	guint one = 1;
	type = j_smd_type_create();
	hdf5_type_export_recourse(type_id, "_", 0, type, one, &one);
	return type;
}

static gboolean
hdf5_space_import(J_SMD_Space_t* space __attribute__((unused)), hid_t* space_id __attribute__((unused)))
{
	hsize_t dims[SMD_MAX_NDIMS];
	guint i;
	for (i = 0; i < space->ndims && i < SMD_MAX_NDIMS; i++)
	{
		dims[i] = space->dims[i];
	}
	*space_id = H5Screate_simple(space->ndims, dims, NULL);
	return TRUE;
}

static hid_t
hdf5_type_import_base(J_SMD_Variable_t* var)
{
	switch (var->type)
	{
	case SMD_TYPE_INT:
		switch (var->size)
		{ /*TODO signed|unsigned*/
		case 8:
			return H5T_NATIVE_LLONG;
		case 4:
			return H5T_NATIVE_INT;
		case 2:
			return H5T_NATIVE_SHORT;
		case 1:
			return H5T_NATIVE_CHAR;
		default:
			J_CRITICAL("this should never happen type=%d", var->type);
		}
		break;
	case SMD_TYPE_FLOAT:
		switch (var->size)
		{ /*TODO signed|unsigned*/
		case 8:
			return H5T_NATIVE_DOUBLE;
		case 4:
			return H5T_NATIVE_FLOAT;
		default:
			J_CRITICAL("this should never happen type=%d", var->type);
		}
		break;
	case SMD_TYPE_BLOB:
		return H5T_NATIVE_CHAR;
	case SMD_TYPE_SUB_TYPE:
	case _SMD_TYPE_COUNT:
	default:
		J_CRITICAL("this should never happen%d", 0);
	}
	J_CRITICAL("this should never happen%d", 0);
	return 0;
}
static hid_t
hdf5_type_import_array(J_SMD_Variable_t* var, hid_t base_type)
{
	hsize_t dims[SMD_MAX_NDIMS];
	guint i;
	if (var->space.ndims == 1 && var->space.dims[0] == 1)
		return base_type;
	for (i = 0; i < SMD_MAX_NDIMS; i++)
	{
		dims[i] = var->space.dims[i];
	}
	return H5Tarray_create(base_type, var->space.ndims, dims);
}
static gboolean
hdf5_type_import(void* _type __attribute__((unused)), hid_t* type_id __attribute__((unused)))
{
	J_SMD_Type_t* type = _type;
	J_SMD_Variable_t* var;
	hid_t base_type;
	guint i;
	if (type->element_count > 0)
	{
		var = &g_array_index(type->arr, J_SMD_Variable_t, type->first_index);
		base_type = hdf5_type_import_base(var);
		if (type->arr->len == 1 || var->type == SMD_TYPE_SUB_TYPE)
			*type_id = hdf5_type_import_array(var, base_type);
		else
		{
			*type_id = H5Tcreate(H5T_COMPOUND, var->size);
			for (i = 0; i < type->arr->len; i++)
			{
				var = g_array_index(type->arr, J_SMD_Variable_t*, i);
				H5Tinsert(*type_id, var->name, var->offset, hdf5_type_import_array(var, base_type));
			}
		}
	}
	else
	{
		J_CRITICAL("array length invalid %d", type->arr->len);
	}
	return TRUE;
}
static gboolean
calculate_constants(J_Scheme_t* scheme)
{
	guint i, j;
	guint type_size = 0;
	J_SMD_Variable_t* var;
	J_HDF_Scheme_t* user_data = scheme->user_data;
	user_data->type_size = 0;
	for (j = 0; j < scheme->type->arr->len; j++)
	{
		var = g_array_index(scheme->type->arr, J_SMD_Variable_t*, j);
		type_size = var->size;
		for (i = 0; i < var->space.ndims; i++)
			type_size *= var->space.dims[i];
		type_size += var->offset;
		user_data->type_size = user_data->type_size < type_size ? type_size : user_data->type_size;
	}
	return TRUE;
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
	J_Scheme_t* scheme;
	g_autoptr(JBatch) batch = NULL;
	J_CRITICAL("DEBUG start%d", 0);
	if (!j_is_key_initialized(parent->key))
		return 0;
	type = hdf5_type_export(type_id);
	space = hdf5_space_export(space_id);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	scheme = j_smd_scheme_create(name, parent, type, space, J_DISTRIBUTION_DATABASE, batch);
	j_batch_execute(batch);
	scheme->user_data = g_new(J_HDF_Scheme_t, 1);
	((J_HDF_Scheme_t*)scheme->user_data)->type_id = type_id;
	((J_HDF_Scheme_t*)scheme->user_data)->space_id = space_id;
	calculate_constants(scheme);
	j_smd_type_unref(type);
	j_smd_space_unref(space);
	return scheme;
}
static herr_t
H5VL_julea_attr_read(void* _scheme __attribute__((unused)), //
	hid_t dtype_id __attribute__((unused)), //
	void* buf __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	guint len;
	guint i;
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* scheme = (J_Scheme_t*)_scheme;
	J_CRITICAL("DEBUG start%d", 0);
	if (!j_is_key_initialized(scheme->key))
		return 1;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	len = 1;
	for (i = 0; i < scheme->space->ndims; i++)
		len *= scheme->space->dims[i];
	j_smd_scheme_read(scheme, buf, 0, len, batch);
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
	guint len;
	guint i;
	J_Scheme_t* scheme = (J_Scheme_t*)_scheme;
	J_CRITICAL("DEBUG start%d", 0);
	if (!j_is_key_initialized(scheme->key))
		return 1;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	len = 1;
	for (i = 0; i < scheme->space->ndims; i++)
	{
		len *= scheme->space->dims[i];
	}
	j_smd_scheme_write(scheme, buf, 0, len, batch);
	j_batch_execute(batch);
	return 0;
}
static herr_t
H5VL_julea_dataset_get(void* _scheme, //
	H5VL_dataset_get_t get_type, //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments)
{
	J_Scheme_t* scheme = (J_Scheme_t*)_scheme;
	J_CRITICAL("DEBUG start%d", 0);
	if (!j_is_key_initialized(scheme->key))
		return 1;
	switch (get_type)
	{
	case H5VL_DATASET_GET_SPACE:
		hdf5_space_import(scheme->space, va_arg(arguments, hid_t*));
		break;
	case H5VL_DATASET_GET_TYPE:
		hdf5_type_import(scheme->type, va_arg(arguments, hid_t*));
		break;
	case H5VL_DATASET_GET_DCPL:
	case H5VL_DATASET_GET_STORAGE_SIZE:
	case H5VL_DATASET_GET_OFFSET:
	case H5VL_DATASET_GET_SPACE_STATUS:
	case H5VL_DATASET_GET_DAPL:
	default:
		J_CRITICAL("unsupported get_type %d", get_type);
		exit(1);
	}
	return 0;
}
static herr_t
H5VL_julea_attr_get(void* _scheme __attribute__((unused)), //
	H5VL_attr_get_t get_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_Scheme_t* scheme = (J_Scheme_t*)_scheme;
	J_CRITICAL("DEBUG start%d", 0);
	if (!j_is_key_initialized(scheme->key))
		return 1;
	switch (get_type)
	{
	case H5VL_ATTR_GET_SPACE:
		hdf5_space_import(scheme->space, va_arg(arguments, hid_t*));
		break;
	case H5VL_ATTR_GET_TYPE:
		hdf5_type_import(scheme->type, va_arg(arguments, hid_t*));
		break;
	case H5VL_ATTR_GET_ACPL:
	case H5VL_ATTR_GET_INFO:
	case H5VL_ATTR_GET_NAME:
	case H5VL_ATTR_GET_STORAGE_SIZE:
	default:
		J_CRITICAL("unsupported get_type %d", get_type);
		exit(1);
	}
	return 0;
}
static herr_t
H5VL_julea_attr_close(void* scheme __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	g_free(((J_Scheme_t*)scheme)->user_data);
	j_smd_scheme_unref(scheme);
	return 0;
}
static herr_t
H5VL_julea_group_close(void* scheme __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	g_free(((J_Scheme_t*)scheme)->user_data);
	j_smd_scheme_unref(scheme);
	return 0;
}
static herr_t
H5VL_julea_dataset_close(void* scheme __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	g_free(((J_Scheme_t*)scheme)->user_data);
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
	J_CRITICAL("DEBUG start%d", 0);
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
	J_CRITICAL("DEBUG start%d", 0);
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
	J_CRITICAL("DEBUG start%d", 0);
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
	J_CRITICAL("DEBUG start%d", 0);
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
	J_Scheme_t* scheme;
	J_CRITICAL("DEBUG start%d", 0);
	if (!j_is_key_initialized(parent->key))
		return 0;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	type = hdf5_type_export(type_id);
	space = hdf5_space_export(space_id);
	scheme = j_smd_scheme_create(name, parent, type, space, J_DISTRIBUTION_ROUND_ROBIN, batch);
	j_batch_execute(batch);
	scheme->user_data = g_new(J_HDF_Scheme_t, 1);
	((J_HDF_Scheme_t*)scheme->user_data)->type_id = type_id;
	((J_HDF_Scheme_t*)scheme->user_data)->space_id = space_id;
	calculate_constants(scheme);
	j_smd_type_unref(type);
	j_smd_space_unref(space);

	return scheme;
}
static void*
H5VL_julea_attr_open(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	const char* name __attribute__((unused)), //
	hid_t dapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* parent = (J_Scheme_t*)obj;
	J_Scheme_t* scheme;
	J_CRITICAL("DEBUG start%d", 0);
	if (!j_is_key_initialized(parent->key))
		return 0;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	scheme = j_smd_scheme_open(name, parent, batch);
	j_batch_execute(batch);
	if (!j_is_key_initialized(scheme->key))
	{
		j_smd_scheme_unref(scheme);
		return NULL;
	}
	scheme->user_data = g_new(J_HDF_Scheme_t, 1);
	calculate_constants(scheme);
	hdf5_space_import(scheme->space, &((J_HDF_Scheme_t*)scheme->user_data)->space_id);
	hdf5_type_import(scheme->type, &((J_HDF_Scheme_t*)scheme->user_data)->type_id);
	return scheme;
}
static void*
H5VL_julea_group_open(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	const char* name __attribute__((unused)), //
	hid_t dapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* parent = (J_Scheme_t*)obj;
	J_Scheme_t* scheme;
	J_CRITICAL("DEBUG start%d", 0);
	if (!j_is_key_initialized(parent->key))
		return 0;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	scheme = j_smd_scheme_open(name, parent, batch);
	j_batch_execute(batch);
	if (!j_is_key_initialized(scheme->key))
	{
		j_smd_scheme_unref(scheme);
		return NULL;
	}
	scheme->user_data = g_new(J_HDF_Scheme_t, 1);
	calculate_constants(scheme);
	hdf5_space_import(scheme->space, &((J_HDF_Scheme_t*)scheme->user_data)->space_id);
	hdf5_type_import(scheme->type, &((J_HDF_Scheme_t*)scheme->user_data)->type_id);
	return scheme;
}
static void*
H5VL_julea_dataset_open(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	const char* name __attribute__((unused)), //
	hid_t dapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* parent = (J_Scheme_t*)obj;
	J_Scheme_t* scheme;
	J_CRITICAL("DEBUG start%d", 0);
	if (!j_is_key_initialized(parent->key))
		return 0;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	scheme = j_smd_scheme_open(name, parent, batch);
	j_batch_execute(batch);
	if (!j_is_key_initialized(scheme->key))
	{
		j_smd_scheme_unref(scheme);
		return NULL;
	}
	scheme->user_data = g_new(J_HDF_Scheme_t, 1);
	calculate_constants(scheme);
	hdf5_space_import(scheme->space, &((J_HDF_Scheme_t*)scheme->user_data)->space_id);
	hdf5_type_import(scheme->type, &((J_HDF_Scheme_t*)scheme->user_data)->type_id);
	return scheme;
}
static herr_t
H5VL_julea_dataset_read(void* _scheme __attribute__((unused)), //
	hid_t mem_type_id __attribute__((unused)), //
	hid_t mem_space_id __attribute__((unused)), //
	hid_t file_space_id __attribute__((unused)), //
	hid_t plist_id __attribute__((unused)), //
	void* buf __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* scheme = (J_Scheme_t*)_scheme;
	guint i, j, k, l;
	gint m;
	guint len;
	hsize_t dims_start[SMD_MAX_NDIMS];
	hsize_t dims_end[SMD_MAX_NDIMS];
	guint off_layer[SMD_MAX_NDIMS];
	guint size_layer[SMD_MAX_NDIMS];
	J_CRITICAL("DEBUG start%d", 0);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	g_assert(buf != NULL);
	g_assert(scheme->object != NULL);
	if (H5Tequal(mem_type_id, ((J_HDF_Scheme_t*)scheme->user_data)->type_id))
	{
		if (file_space_id != H5S_ALL)
		{
			J_CRITICAL("must read entire dataset currently %ld %ld", mem_space_id, file_space_id);
			exit(1);
		}
		if (mem_space_id == H5S_ALL)
		{
			len = 1;
			for (i = 0; i < scheme->space->ndims; i++)
				len *= scheme->space->dims[i];
			j_smd_scheme_read(scheme, buf, 0, len, batch);
		}
		else
		{
			H5Sget_select_bounds(mem_space_id, dims_start, dims_end);
			for (i = scheme->space->ndims; i < SMD_MAX_NDIMS; i++)
			{
				dims_start[i] = 0;
				dims_end[i] = 1;
			}
			size_layer[SMD_MAX_NDIMS - 1] = 1;
			for (m = SMD_MAX_NDIMS - 2; m >= 0; m--)
			{
				if ((guint)m > scheme->space->ndims)
					size_layer[m] = size_layer[m + 1];
				else
					size_layer[m] = size_layer[m + 1] * scheme->space->dims[m];
			}
			for (i = dims_start[0]; i < dims_end[0]; i++)
			{
				off_layer[0] = size_layer[0] * i;
				for (j = dims_start[1]; j < dims_end[1]; j++)
				{
					off_layer[1] = off_layer[0] + size_layer[1] * j;
					for (k = dims_start[2]; k < dims_end[2]; k++)
					{
						off_layer[2] = off_layer[1] + size_layer[2] * k;
						for (l = dims_start[3]; l < dims_end[3]; l++)
						{
							off_layer[3] = off_layer[2] + size_layer[3] * l;
							j_smd_scheme_read(scheme, buf, off_layer[3], size_layer[3], batch);
						}
					}
				}
			}
		}
	}
	else
	{
		J_CRITICAL("memory and database type must match %d", 0);
		exit(1);
	}
	j_batch_execute(batch);
	return 0;
}
static herr_t
H5VL_julea_dataset_write(void* _scheme __attribute__((unused)), //
	hid_t mem_type_id __attribute__((unused)), //
	hid_t mem_space_id __attribute__((unused)), //
	hid_t file_space_id __attribute__((unused)), //
	hid_t plist_id __attribute__((unused)), //
	const void* buf __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	g_autoptr(JBatch) batch = NULL;
	J_Scheme_t* scheme = (J_Scheme_t*)_scheme;
	guint i, j, k, l;
	gint m;
	guint len;
	hsize_t dims_start[SMD_MAX_NDIMS];
	hsize_t dims_end[SMD_MAX_NDIMS];
	guint off_layer[SMD_MAX_NDIMS];
	guint size_layer[SMD_MAX_NDIMS];
	J_CRITICAL("DEBUG start%d", 0);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	g_assert(buf != NULL);
	g_assert(scheme->object != NULL);
	if (H5Tequal(mem_type_id, ((J_HDF_Scheme_t*)scheme->user_data)->type_id))
	{
		if (file_space_id != H5S_ALL)
		{
			J_CRITICAL("must read entire dataset currently %ld %ld", mem_space_id, file_space_id);
			exit(1);
		}
		if (mem_space_id == H5S_ALL)
		{
			len = 1;
			for (i = 0; i < scheme->space->ndims; i++)
				len *= scheme->space->dims[i];
			j_smd_scheme_write(scheme, buf, 0, len, batch);
		}
		else
		{
			H5Sget_select_bounds(mem_space_id, dims_start, dims_end);
			for (i = scheme->space->ndims; i < SMD_MAX_NDIMS; i++)
			{
				dims_start[i] = 0;
				dims_end[i] = 1;
			}
			size_layer[SMD_MAX_NDIMS - 1] = 1;
			for (m = SMD_MAX_NDIMS - 2; m >= 0; m--)
			{
				if ((guint)m > scheme->space->ndims)
					size_layer[m] = size_layer[m + 1];
				else
					size_layer[m] = size_layer[m + 1] * scheme->space->dims[m];
			}
			for (i = dims_start[0]; i < dims_end[0]; i++)
			{
				off_layer[0] = size_layer[0] * i;
				for (j = dims_start[1]; j < dims_end[1]; j++)
				{
					off_layer[1] = off_layer[0] + size_layer[1] * j;
					for (k = dims_start[2]; k < dims_end[2]; k++)
					{
						off_layer[2] = off_layer[1] + size_layer[2] * k;
						for (l = dims_start[3]; l < dims_end[3]; l++)
						{
							off_layer[3] = off_layer[2] + size_layer[3] * l;
							j_smd_scheme_write(scheme, buf, off_layer[3], size_layer[3], batch);
						}
					}
				}
			}
		}
	}
	else
	{
		J_CRITICAL("memory and database type must match %d", 0);
		exit(1);
	}
	j_batch_execute(batch);
	return 0;
}
static herr_t
H5VL_julea_attr_specific(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	H5VL_attr_specific_t specific_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_attr_optional(void* obj __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_dataset_specific(void* obj __attribute__((unused)), //
	H5VL_dataset_specific_t specific_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_dataset_optional(void* obj __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static void*
H5VL_julea_datatype_commit(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	const char* name __attribute__((unused)), //
	hid_t type_id __attribute__((unused)), //
	hid_t lcpl_id __attribute__((unused)), //
	hid_t tcpl_id __attribute__((unused)), //
	hid_t tapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static void*
H5VL_julea_datatype_open(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	const char* name __attribute__((unused)), //
	hid_t tapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_datatype_get(void* obj __attribute__((unused)), //
	H5VL_datatype_get_t get_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_datatype_specific(void* obj __attribute__((unused)), //
	H5VL_datatype_specific_t specific_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_datatype_close(void* dt __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_file_get(void* _obj __attribute__((unused)), //
	H5VL_file_get_t get_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_Scheme_t* file = (J_Scheme_t*)_obj;
	J_CRITICAL("DEBUG start%d", 0);
	switch (get_type)
	{
	case H5VL_FILE_GET_NAME:
	{
		H5I_type_t type = (H5I_type_t)va_arg(arguments, int);
		size_t size = va_arg(arguments, size_t);
		char* name = va_arg(arguments, char*);
		ssize_t* ret = va_arg(arguments, ssize_t*);
		size_t len;
		len = strlen(file->name) + 1;
		if (name)
			memcpy(name, file->name, len < size ? len : size);
		if (len >= size)
			name[size - 1] = '\0';
		*ret = (ssize_t)len;
		(void)type;
		break;
	}
	case H5VL_FILE_GET_OBJ_COUNT:{
		unsigned    types = HDva_arg(arguments, unsigned);
		ssize_t    *ret = HDva_arg(arguments, ssize_t *);
		size_t      obj_count = 0;

		J_CRITICAL("count objects !! %d", get_type);
		exit(1);

		//count only where types == H5F_OBJ_FILE|H5F_OBJ_DATASET|H5F_OBJ_GROUP|H5F_OBJ_DATATYPE|H5F_OBJ_ATTR
		*ret = (ssize_t)obj_count;
		break;
	}
	case H5VL_FILE_GET_FAPL:
	case H5VL_FILE_GET_FCPL:
	case H5VL_FILE_GET_INTENT:
	case H5VL_FILE_GET_FILENO:
	case H5VL_FILE_GET_OBJ_IDS:
	default:
		J_CRITICAL("unsupported get_type %d", get_type);
		exit(1);
	}
	return SUCCEED;
}
static herr_t
H5VL_julea_file_specific(void* obj __attribute__((unused)), //
	H5VL_file_specific_t specific_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_file_optional(void* obj __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_group_get(void* obj __attribute__((unused)), //
	H5VL_group_get_t get_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_group_specific(void* obj __attribute__((unused)), //
	H5VL_group_specific_t specific_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_group_optional(void* obj __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_link_create(H5VL_link_create_type_t create_type __attribute__((unused)), //
	void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	hid_t lcpl_id __attribute__((unused)), //
	hid_t lapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_link_copy(void* src_obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params1 __attribute__((unused)), //
	void* dst_obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params2 __attribute__((unused)), //
	hid_t lcpl_id __attribute__((unused)), //
	hid_t lapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_link_move(void* src_obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params1 __attribute__((unused)), //
	void* dst_obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params2 __attribute__((unused)), //
	hid_t lcpl_id __attribute__((unused)), //
	hid_t lapl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_link_get(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	H5VL_link_get_t get_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_link_specific(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	H5VL_link_specific_t specific_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static void*
H5VL_julea_object_open(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	H5I_type_t* opened_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_object_copy(void* src_obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params1 __attribute__((unused)), //
	const char* src_name __attribute__((unused)), //
	void* dst_obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params2 __attribute__((unused)), //
	const char* dst_name __attribute__((unused)), //
	hid_t ocpypl_id __attribute__((unused)), //
	hid_t lcpl_id __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_object_get(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	H5VL_object_get_t get_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_object_specific(void* obj __attribute__((unused)), //
	const H5VL_loc_params_t* loc_params __attribute__((unused)), //
	H5VL_object_specific_t specific_type __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}
static herr_t
H5VL_julea_object_optional(void* obj __attribute__((unused)), //
	hid_t dxpl_id __attribute__((unused)), //
	void** req __attribute__((unused)), //
	va_list arguments __attribute__((unused)))
{
	J_CRITICAL("DEBUG start%d", 0);
	J_CRITICAL("not implemented %d", 0);
	exit(1);
}

const H5VL_class_t H5VL_julea_g = {
	//
	0,
	JULEA,
	"julea", /* name */
	0,
	H5VL_julea_init, /* initialize */
	H5VL_julea_term, /* terminate */
	{
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		/* attribute_cls */
		H5VL_julea_attr_create, /* create */
		H5VL_julea_attr_open, /* open */
		H5VL_julea_attr_read, /* read */
		H5VL_julea_attr_write, /* write */
		H5VL_julea_attr_get, /* get */
		H5VL_julea_attr_specific, // H5VL_julea_attr_specific,              /* specific */
		H5VL_julea_attr_optional, // H5VL_julea_attr_optional,              /* optional */
		H5VL_julea_attr_close /* close */
	},
	{
		/* dataset_cls */
		H5VL_julea_dataset_create, /* create */
		H5VL_julea_dataset_open, /* open */
		H5VL_julea_dataset_read, /* read */
		H5VL_julea_dataset_write, /* write */
		H5VL_julea_dataset_get, /* get */
		H5VL_julea_dataset_specific, /* specific */
		H5VL_julea_dataset_optional, /* optional */
		H5VL_julea_dataset_close /* close */
	},
	{
		/* datatype_cls */
		H5VL_julea_datatype_commit, /* commit */
		H5VL_julea_datatype_open, /* open */
		H5VL_julea_datatype_get, /* get_size */
		H5VL_julea_datatype_specific, /* specific */
		NULL, //H5VL_julea_datatype_optional,/* optional */
		H5VL_julea_datatype_close, /* close */
	},
	{
		/* file_cls */
		H5VL_julea_file_create, /* create */
		H5VL_julea_file_open, /* open */
		H5VL_julea_file_get, /* get */
		H5VL_julea_file_specific, /* specific */
		H5VL_julea_file_optional, /* optional */
		H5VL_julea_file_close /* close */
	},
	{
		/* group_cls */
		H5VL_julea_group_create, /* create */
		H5VL_julea_group_open, /* open */
		H5VL_julea_group_get, /* get */
		H5VL_julea_group_specific, /* specific */
		H5VL_julea_group_optional, /* optional */
		H5VL_julea_group_close /* close */
	},
	{
		/* link_cls */
		H5VL_julea_link_create, /* create */
		H5VL_julea_link_copy, /* copy */
		H5VL_julea_link_move, /* move */
		H5VL_julea_link_get, /* get */
		H5VL_julea_link_specific, /* specific */
		NULL, //H5VL_julea_link_optional, /* optional */
	},
	{
		/* object_cls */
		H5VL_julea_object_open, /* open */
		H5VL_julea_object_copy, /* copy */
		H5VL_julea_object_get, /* get */
		H5VL_julea_object_specific, /* specific */
		H5VL_julea_object_optional, /* optional */
	},
	{
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	NULL,
};

/**
 * Provides the plugin type
 **/
H5PL_type_t
H5PLget_plugin_type(void)
{
	J_CRITICAL("DEBUG start%d", 0);
	return H5PL_TYPE_VOL;
}

/**
 * Provides a pointer to the plugin structure
 **/
const void*
H5PLget_plugin_info(void)
{
	J_CRITICAL("DEBUG start%d", 0);
	return &H5VL_julea_g;
}
