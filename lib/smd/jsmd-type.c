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
j_smd_type_equals(void* _type1, void* _type2)
{
	struct J_SMD_Type_t* type1 = _type1;
	struct J_SMD_Type_t* type2 = _type2;
	guint i, j;
	gboolean ret;
	J_SMD_Variable_t* var1;
	J_SMD_Variable_t* var2;
	g_return_val_if_fail(type1 != NULL, FALSE);
	g_return_val_if_fail(type2 != NULL, FALSE);
	g_return_val_if_fail(type1->arr->len == type2->arr->len, FALSE);
	for (i = 0; i < type1->arr->len; i++)
	{
		var1 = g_array_index(type1->arr, J_SMD_Variable_t*, i);
		var2 = g_array_index(type2->arr, J_SMD_Variable_t*, i);
		ret = (var1->offset == var2->offset);
		if (!ret)
		{
			J_DEBUG("%d", i);
			return FALSE;
		}
		ret = (var1->size == var2->size);
		if (!ret)
		{
			J_DEBUG("%d", i);
			return FALSE;
		}
		ret = (var1->type == var2->type);
		if (!ret)
		{
			J_DEBUG("%d %d %d", i, var1->type, var2->type);
			return FALSE;
		}
		ret = (strcmp(var1->name, var2->name) == 0);
		if (!ret)
		{
			J_DEBUG("%d", i);
			return FALSE;
		}
		ret = (var1->space.ndims == var2->space.ndims);
		if (!ret)
		{
			J_DEBUG("%d", i);
			return FALSE;
		}
		for (j = 0; j < var1->space.ndims; j++)
			ret = ret && var1->space.dims[j] == var2->space.dims[j];
		if (!ret)
		{
			J_DEBUG("%d", i);
			return FALSE;
		}
		if (var1->type == SMD_TYPE_SUB_TYPE)
		{
			ret = j_smd_type_equals(var1->sub_type, var2->sub_type);
			if (!ret)
			{
				J_DEBUG("%d", i);
				return FALSE;
			}
		}
	}
	return TRUE;
}
void*
j_smd_type_create(void)
{
	J_SMD_Type_t* type;
	type = g_new(J_SMD_Type_t, 1);
	type->ref_count = 1;
	type->arr = g_array_new(FALSE, TRUE, sizeof(J_SMD_Variable_t*));
	return type;
}
gboolean
j_smd_type_add_atomic_type(void* _type, const char* var_name, int var_offset, int var_size, JSMDType var_type, guint var_ndims, guint* var_dims)
{
	struct J_SMD_Type_t* type = _type;
	J_SMD_Variable_t* variable;
	guint i;
	if (var_ndims > SMD_MAX_NDIMS)
	{
		J_CRITICAL("var_ndims > %d not supported", SMD_MAX_NDIMS);
		return FALSE;
	}
	if (strlen(var_name) > SMD_MAX_NAME_LENGTH)
	{
		J_CRITICAL("var_names longer than  %d not supported", SMD_MAX_NAME_LENGTH);
		return FALSE;
	}
	for (i = 0; i < var_ndims; i++)
	{
		if (var_dims[i] == 0)
		{
			J_CRITICAL("variable array length not supported here var_dims[%d]", i);
			return FALSE;
		}
	}
	variable = g_new(J_SMD_Variable_t, 1);
	variable->ref_count = 1;
	variable->offset = var_offset;
	variable->size = var_size;
	variable->type = var_type;
	variable->sub_type = NULL;
	memcpy(variable->name, var_name, strlen(var_name));
	variable->name[strlen(var_name)] = 0;
	variable->space.ndims = var_ndims;
	for (i = 0; i < var_ndims; i++)
		variable->space.dims[i] = var_dims[i];
	g_array_append_val(type->arr, variable);
	/*TODO check conflicting other variables*/
	return TRUE;
}
gboolean
j_smd_type_add_compound_type(void* _type, const char* var_name, int var_offset, int var_size, void* var_type, guint var_ndims, guint* var_dims)
{
	struct J_SMD_Type_t* type = _type;
	J_SMD_Variable_t* variable;
	guint i;
	if (var_ndims > SMD_MAX_NDIMS)
	{
		J_CRITICAL("var_ndims > %d not supported", SMD_MAX_NDIMS);
		return FALSE;
	}
	if (strlen(var_name) > SMD_MAX_NAME_LENGTH)
	{
		J_CRITICAL("var_names longer than  %d not supported", SMD_MAX_NAME_LENGTH);
		return FALSE;
	}
	for (i = 0; i < var_ndims; i++)
		if (var_dims[i] == 0)
		{
			J_CRITICAL("variable array length not supported here var_dims[%d]", i);
			return FALSE;
		}
	variable = g_new(J_SMD_Variable_t, 1);
	variable->ref_count = 1;
	variable->offset = var_offset;
	variable->size = var_size;
	variable->type = SMD_TYPE_SUB_TYPE;
	variable->sub_type = j_smd_type_ref(var_type);
	memcpy(variable->name, var_name, strlen(var_name));
	variable->name[strlen(var_name)] = 0;
	variable->space.ndims = var_ndims;
	for (i = 0; i < var_ndims; i++)
		variable->space.dims[i] = var_dims[i];
	g_array_append_val(type->arr, variable);
	return TRUE;
}
guint
j_smd_type_get_variable_count(void* _type)
{
	struct J_SMD_Type_t* type = _type;
	return type->arr->len;
}
void*
j_smd_variable_ref(void* _variable)
{
	J_SMD_Variable_t* variable = _variable;
	g_atomic_int_inc(&(variable->ref_count));
	return variable;
}
gboolean
j_smd_variable_unref(void* _variable)
{
	J_SMD_Variable_t* variable = _variable;
	if (variable && g_atomic_int_dec_and_test(&(variable->ref_count)))
	{
		j_smd_type_unref(variable->sub_type);
		g_free(_variable);
	}
	return TRUE;
}
void*
j_smd_type_ref(void* _type)
{
	J_SMD_Type_t* type = _type;
	g_atomic_int_inc(&(type->ref_count));
	return type;
}
gboolean
j_smd_type_unref(void* _type)
{
	guint i;
	J_SMD_Type_t* type = _type;
	if (type && g_atomic_int_dec_and_test(&(type->ref_count)))
	{
		for (i = 0; i < type->arr->len; i++)
			j_smd_variable_unref(g_array_index(type->arr, J_SMD_Variable_t*, i));
		g_free(type);
	}
	return TRUE;
}

gboolean
j_smd_type_remove_variable(void* _type, const char* name)
{
	struct J_SMD_Type_t* type = _type;
	guint i;
	for (i = 0; i < type->arr->len; i++)
	{
		if (strcmp(name, g_array_index(type->arr, J_SMD_Variable_t*, i)->name) == 0)
		{
			j_smd_variable_unref(g_array_index(type->arr, J_SMD_Variable_t*, i));
			g_array_remove_index(type->arr, i);
			return TRUE;
		}
	}
	return FALSE;
}
bson_t*
j_smd_type_to_bson(void* _type)
{
	struct J_SMD_Type_t* type = _type;
	guint i, j;
	J_SMD_Variable_t* var;
	char key_buf[16];
	const char* key;
	bson_t* bson;
	bson_t* bson_subtype;
	bson_t b_arr[1];
	bson_t b_var[1];
	bson_t b_dims[1];
	bson = g_new(bson_t, 1);
	bson_init(bson);
	bson_append_array_begin(bson, "arr", -1, b_arr);
	for (i = 0; i < type->arr->len; i++)
	{
		bson_uint32_to_string(i, &key, key_buf, sizeof(key_buf));
		var = g_array_index(type->arr, J_SMD_Variable_t*, i);
		bson_append_document_begin(b_arr, key, -1, b_var);
		bson_append_int32(b_var, "offset", -1, var->offset);
		bson_append_int32(b_var, "size", -1, var->size);
		bson_append_int32(b_var, "type", -1, var->type);
		bson_append_utf8(b_var, "name", -1, var->name, -1);
		bson_append_int32(b_var, "ndims", -1, var->space.ndims);
		bson_append_array_begin(b_var, "dims", -1, b_dims);
		for (j = 0; j < var->space.ndims; j++)
		{
			bson_uint32_to_string(j, &key, key_buf, sizeof(key_buf));
			bson_append_int32(b_dims, key, -1, var->space.dims[j]);
		}
		bson_append_array_end(b_var, b_dims);
		if (var->type == SMD_TYPE_SUB_TYPE)
		{
			bson_subtype = j_smd_type_to_bson(var->sub_type);
			bson_append_document(b_var, "subtype", -1, bson_subtype);
			bson_destroy(bson_subtype);
			g_free(bson_subtype);
		}
		bson_append_document_end(b_arr, b_var);
	}
	bson_append_array_end(bson, b_arr);
	return bson;
}
void*
j_smd_type_from_bson(bson_iter_t* iter_arr)
{
	struct J_SMD_Type_t* type;
	guint i;
	bson_iter_t iter_loc;
	bson_iter_t iter_loc2;
	bson_iter_t iter;
	bson_iter_t iter_var;
	bson_iter_t iter_val;
	bson_iter_t iter_dims;
	J_SMD_Variable_t var;
	uint32_t len;
	const char* tmp;
	gchar const* key;
	type = j_smd_type_create();
	bson_iter_recurse(iter_arr, &iter_loc2);
	while (bson_iter_next(&iter_loc2))
	{
		key = bson_iter_key(&iter_loc2);
		if (g_strcmp0("arr", key) == 0)
		{
			bson_iter_recurse(&iter_loc2, &iter);
			while (bson_iter_next(&iter))
			{
				var.offset = 0;
				var.size = 0;
				var.type = 0;
				var.name[0] = 0;
				var.space.ndims = 0;
				var.space.dims[0] = 0;
				var.sub_type = NULL;
				bson_iter_recurse(&iter, &iter_val);
				while (bson_iter_next(&iter_val))
				{
					key = bson_iter_key(&iter_val);
					if (g_strcmp0("offset", key) == 0)
						var.offset = bson_iter_int32(&iter_val);
					if (g_strcmp0("size", key) == 0)
						var.size = bson_iter_int32(&iter_val);
					if (g_strcmp0("type", key) == 0)
						var.type = bson_iter_int32(&iter_val);
					if (g_strcmp0("name", key) == 0)
					{
						tmp = bson_iter_utf8(&iter_val, &len);
						memcpy(var.name, tmp, len);
						var.name[len] = 0;
					}
					if (g_strcmp0("ndims", key) == 0)
						var.space.ndims = bson_iter_int32(&iter_val);
					if (g_strcmp0("subtype", key) == 0)
						var.sub_type = j_smd_type_from_bson(&iter_val);
					if (g_strcmp0("dims", key) == 0)
					{
						bson_iter_recurse(&iter_val, &iter_dims);
						i = 0;
						while (bson_iter_next(&iter_dims) && i < var.space.ndims)
						{
							if (BSON_ITER_HOLDS_INT32(&iter_dims))
							{
								var.space.dims[i] = bson_iter_int32(&iter_dims);
								i++;
							}
						}
					}
				}
				if (var.type == SMD_TYPE_SUB_TYPE)
				{
					j_smd_type_add_compound_type(type, var.name, var.offset, var.size, var.sub_type, var.space.ndims, var.space.dims);
					j_smd_type_unref(var.sub_type);
				}
				else
					j_smd_type_add_atomic_type(type, var.name, var.offset, var.size, var.type, var.space.ndims, var.space.dims);
			}
		}
	}
	return type;
}
