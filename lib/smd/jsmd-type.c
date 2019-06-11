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
		ret = (var1->offset == var2->offset) && (var1->size == var2->size) && (var1->type == var2->type) && (strcmp(var1->name, var2->name) == 0) && (var1->space.ndims == var2->space.ndims);
		if (!ret)
		{
			return FALSE;
		}
		for (j = 0; j < var1->space.ndims; j++)
		{
			ret = ret && var1->space.dims[j] == var2->space.dims[j];
		}
		if (!ret)
		{
			return FALSE;
		}
	}

	return TRUE;
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

	type = j_smd_type_create();

	if (bson_iter_recurse(iter_arr, &iter_loc) && bson_iter_find_descendant(&iter_loc, "arr", &iter_loc2) && BSON_ITER_HOLDS_ARRAY(&iter_loc2))
	{
		bson_iter_recurse(&iter_loc2, &iter);

		while (bson_iter_next(&iter))
		{
			var.offset = 0;
			var.size = 0;
			var.type = 0;
			var.name = NULL;
			var.space.ndims = 0;
			var.space.dims = NULL;
			if (bson_iter_recurse(&iter, &iter_var) && bson_iter_find_descendant(&iter_var, "offset", &iter_val) && BSON_ITER_HOLDS_INT32(&iter_val))
			{
				var.offset = bson_iter_int32(&iter_val);
			}
			if (bson_iter_recurse(&iter, &iter_var) && bson_iter_find_descendant(&iter_var, "size", &iter_val) && BSON_ITER_HOLDS_INT32(&iter_val))
			{
				var.size = bson_iter_int32(&iter_val);
			}
			if (bson_iter_recurse(&iter, &iter_var) && bson_iter_find_descendant(&iter_var, "type", &iter_val) && BSON_ITER_HOLDS_INT32(&iter_val))
			{
				var.type = bson_iter_int32(&iter_val);
			}
			if (bson_iter_recurse(&iter, &iter_var) && bson_iter_find_descendant(&iter_var, "name", &iter_val) && BSON_ITER_HOLDS_UTF8(&iter_val))
			{
				var.name = g_strdup(bson_iter_utf8(&iter_val, NULL));
			}
			if (bson_iter_recurse(&iter, &iter_var) && bson_iter_find_descendant(&iter_var, "ndims", &iter_val) && BSON_ITER_HOLDS_INT32(&iter_val))
			{
				var.space.ndims = bson_iter_int32(&iter_val);
			}
			if (bson_iter_recurse(&iter, &iter_var) && bson_iter_find_descendant(&iter_var, "dims", &iter_val) && BSON_ITER_HOLDS_ARRAY(&iter_val))
			{
				var.space.dims = g_new(guint, var.space.ndims);
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

			j_smd_type_add_variable(type, var.name, var.offset, var.size, var.type, var.space.ndims, var.space.dims);
			g_free(var.space.dims);
			g_free(var.name);
		}
	}

	return type;
}

void*
j_smd_type_create(void)
{
	J_SMD_Type_t* type;

	type = g_new(J_SMD_Type_t, 1);
	type->arr = g_array_new(FALSE, TRUE, sizeof(J_SMD_Variable_t*));
	return type;
}
gboolean
j_smd_type_add_variable(void* _type, const char* var_name, int var_offset, int var_size, JSMDType var_type, guint var_ndims, guint* var_dims)
{
	struct J_SMD_Type_t* type = _type;
	J_SMD_Variable_t* variable;

	variable = g_new(J_SMD_Variable_t, 1);
	variable->offset = var_offset;
	variable->size = var_size;
	variable->type = var_type;
	variable->name = g_strdup(var_name);
	variable->space.ndims = var_ndims;
	if (var_ndims > 0)
	{
		variable->space.dims = g_new(guint, var_ndims);
		memcpy(variable->space.dims, var_dims, sizeof(*var_dims) * var_ndims);
	}
	g_array_append_val(type->arr, variable);
	/*TODO check conflicting other variables*/
	return TRUE;
}

guint
j_smd_type_get_variable_count(void* _type)
{
	struct J_SMD_Type_t* type = _type;

	return type->arr->len;
}
gboolean
j_smd_type_free(void* _type)
{
	guint i;
	struct J_SMD_Type_t* type = _type;

	for (i = 0; i < type->arr->len; i++)
	{
		g_free(g_array_index(type->arr, J_SMD_Variable_t*, i)->space.dims);
		g_free(g_array_index(type->arr, J_SMD_Variable_t*, i)->name);
		g_free(g_array_index(type->arr, J_SMD_Variable_t*, i));
	}
	g_free(type);
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
			g_free(g_array_index(type->arr, J_SMD_Variable_t*, i)->space.dims);
			g_free(g_array_index(type->arr, J_SMD_Variable_t*, i)->name);
			g_free(g_array_index(type->arr, J_SMD_Variable_t*, i));
			g_array_remove_index(type->arr, i);
			return TRUE;
		}
	}
	return FALSE;
}