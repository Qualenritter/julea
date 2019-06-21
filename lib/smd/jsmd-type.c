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
static gboolean
_j_smd_variable_equals(J_SMD_Variable_t* var1, J_SMD_Variable_t* var2)
{
	gboolean ret = TRUE;
	guint i;
start:
	ret = ret && ((var1->nextindex == 0) == (var2->nextindex == 0)); //beide oder keiner hat einen Nachfolger
	ret = ret && (var1->offset == var2->offset);
	ret = ret && (var1->size == var2->size);
	ret = ret && (var1->type == var2->type);
	ret = ret && (var1->space.ndims == var2->space.ndims);
	if (!ret)
	{
		return FALSE;
	}
	ret = ret && (strcmp(var1->name, var2->name) == 0);
	if (!ret)
	{
		return FALSE;
	}
	for (i = 0; i < var1->space.ndims; i++)
		ret = ret && (var1->space.dims[i] == var2->space.dims[i]);
	if (!ret)
	{
		return FALSE;
	}
	if (var1->type == SMD_TYPE_SUB_TYPE)
		ret = ret && _j_smd_variable_equals(var1 + var1->subtypeindex, var2 + var2->subtypeindex);
	if (!ret)
	{
		return FALSE;
	}

	if (var1->nextindex == 0)
		return TRUE;
	var1 += var1->nextindex;
	var2 += var2->nextindex;
	goto start;
}
gboolean
j_smd_type_equals(void* _type1, void* _type)
{
	J_SMD_Type_t* type1 = _type1;
	J_SMD_Type_t* type = _type;
	J_SMD_Variable_t* var1;
	J_SMD_Variable_t* var2;
	if (type1 == NULL || type == NULL)
	{
		return FALSE;
	}
	if (type1->arr->len == 0 && type->arr->len == 0)
	{
		return TRUE;
	}
	var1 = &g_array_index(type1->arr, J_SMD_Variable_t, type1->first_index);
	var2 = &g_array_index(type->arr, J_SMD_Variable_t, type->first_index);
	return _j_smd_variable_equals(var1, var2);
}
/**
\return a new created type
*/
void*
j_smd_type_create(void)
{
	J_SMD_Type_t* type;
	type = g_new(J_SMD_Type_t, 1);
	type->ref_count = 1;
	type->arr = g_array_new(FALSE, TRUE, sizeof(J_SMD_Variable_t));
	type->last_index = 0;
	type->first_index = 0;
	return type;
}
gboolean
j_smd_type_add_atomic_type(void* _type, const char* var_name, int var_offset, int var_size, J_SMD_Atomic_Type_t var_type, guint var_ndims, guint* var_dims)
{
	J_SMD_Type_t* type = _type;
	J_SMD_Variable_t variable;
	guint i;
	guint my_idx;
	if (!type)
	{
		J_DEBUG("type is %p", _type);
		return FALSE;
	}
	if (var_ndims > SMD_MAX_NDIMS || var_ndims == 0)
	{
		J_DEBUG("(0 < ndims) && (ndims <= %d)", SMD_MAX_NDIMS);
		return FALSE;
	}
	if (strlen(var_name) > SMD_MAX_NAME_LENGTH)
	{
		J_DEBUG("var_names longer than  %d not supported", SMD_MAX_NAME_LENGTH);
		return FALSE;
	}
	if (var_type == SMD_TYPE_SUB_TYPE)
	{
		J_DEBUG("vartype SMD_TYPE_SUB_TYPE %d not supportet here", var_type);
		return FALSE;
	}
	for (i = 0; i < var_ndims; i++)
	{
		if (var_dims[i] == 0)
		{
			J_DEBUG("variable array length not supported here var_dims[%d]", i);
			return FALSE;
		}
	}
	variable.nextindex = 0;
	variable.subtypeindex = 0;
	variable.offset = var_offset;
	variable.size = var_size;
	variable.type = var_type;
	memcpy(variable.name, var_name, strlen(var_name));
	variable.name[strlen(var_name)] = 0;
	variable.space.ndims = var_ndims;
	for (i = 0; i < var_ndims; i++)
		variable.space.dims[i] = var_dims[i];
	my_idx = type->arr->len;
	g_array_append_val(type->arr, variable);
	if (my_idx)
		g_array_index(type->arr, J_SMD_Variable_t, type->last_index).nextindex = my_idx - type->last_index;
	type->last_index = my_idx;
	/*TODO check conflicting other variables*/
	return TRUE;
}
gboolean
j_smd_type_add_compound_type(void* _type, const char* var_name, int var_offset, int var_size, void* _var_type, guint var_ndims, guint* var_dims)
{
	J_SMD_Type_t* type = _type;
	J_SMD_Type_t* var_type = _var_type;
	J_SMD_Variable_t variable;
	guint my_idx;
	guint i;
	if (!type)
	{
		J_DEBUG("type is %p", _type);
		return FALSE;
	}
	if (!_var_type)
	{
		J_DEBUG("_var_type is %p", _type);
		return FALSE;
	}
	if (var_ndims > SMD_MAX_NDIMS || var_ndims == 0)
	{
		J_DEBUG("(0 < ndims) && (ndims <= %d)", SMD_MAX_NDIMS);
		return FALSE;
	}
	if (strlen(var_name) > SMD_MAX_NAME_LENGTH)
	{
		J_DEBUG("var_names longer than  %d not supported", SMD_MAX_NAME_LENGTH);
		return FALSE;
	}
	for (i = 0; i < var_ndims; i++)
		if (var_dims[i] == 0)
		{
			J_DEBUG("variable array length not supported here var_dims[%d]", i);
			return FALSE;
		}
	if (var_type->arr->len == 0)
	{
		J_DEBUG("adding empty subtype not allowed - since subtypes are not modifyable curerntly %d", 0);
		return FALSE;
	}
	if (type == _var_type)
	{
		J_DEBUG("recoursive definition not allowed %p %p", _type, _var_type);
		return FALSE;
	}
	variable.subtypeindex = 1; //appended directly afterwards
	variable.nextindex = 0; //this is last element
	variable.type = SMD_TYPE_SUB_TYPE;
	variable.offset = var_offset;
	variable.size = var_size;
	memcpy(variable.name, var_name, strlen(var_name));
	variable.name[strlen(var_name)] = 0;
	variable.space.ndims = var_ndims;
	for (i = 0; i < var_ndims; i++)
		variable.space.dims[i] = var_dims[i];
	my_idx = type->arr->len;
	g_array_append_val(type->arr, variable);
	if (my_idx)
		g_array_index(type->arr, J_SMD_Variable_t, type->last_index).nextindex = my_idx - type->last_index;
	type->last_index = my_idx;
	g_array_append_vals(type->arr, var_type->arr->data, var_type->arr->len);
	return TRUE;
}
guint
j_smd_type_get_variable_count(void* _type)
{
	J_SMD_Type_t* type = _type;
	J_SMD_Variable_t* var;
	guint count = 0;
	if (!type || type->arr->len == 0)
		return 0;
	var = &g_array_index(type->arr, J_SMD_Variable_t, type->first_index);
	count++;
	while (var->nextindex)
	{
		var += var->nextindex;
		count++;
	}
	return count;
}
void*
j_smd_type_ref(void* _type)
{
	J_SMD_Type_t* type = _type;
	if (type)
	{
		g_atomic_int_inc(&(type->ref_count));
	}
	return type;
}
void*
j_smd_type_copy(void* _type)
{
	J_SMD_Type_t* type = _type;
	J_SMD_Type_t* type2 = NULL;
	if (type)
	{
		type2 = j_smd_type_create();
		type2->last_index = type->last_index;
		type2->first_index = type->first_index;
		g_array_append_vals(type2->arr, type->arr->data, type->arr->len);
	}
	return type2;
}
/**
* \return TRUE if _type is still referenced somewhere, and FALSE if memory is released
*/
gboolean
j_smd_type_unref(void* _type)
{
	J_SMD_Type_t* type = _type;
	if (type)
	{
	}
	if (type && g_atomic_int_dec_and_test(&(type->ref_count)))
	{
		g_array_free(type->arr, TRUE);
		g_free(type);
		return FALSE;
	}
	return type != NULL;
}
gboolean
j_smd_type_remove_variable(void* _type, const char* name)
{
	J_SMD_Type_t* type = _type;
	J_SMD_Variable_t* var;
	J_SMD_Variable_t* var_prev;
	if (!type || !name || type->arr->len == 0)
		return FALSE;
	var = &g_array_index(type->arr, J_SMD_Variable_t, type->first_index);
	var_prev = var;
start:
	if (strcmp(name, var->name) == 0)
	{
		if (var == var_prev)
		{
			if (var->nextindex) //remove first element
			{
				type->first_index += var->nextindex;
			}
			else
			{ //remove first AND last element -> ALL
				g_array_free(type->arr, TRUE);
				type->arr = g_array_new(FALSE, FALSE, sizeof(J_SMD_Variable_t));
				type->last_index = 0;
				type->first_index = 0;
			}
		}
		else
		{ //deletes not the first element
			if (var->nextindex == 0)
				var_prev->nextindex = 0;
			else
				var_prev->nextindex += var->nextindex;
		}
		return TRUE;
	}
	if (var->nextindex)
	{
		var_prev = var;
		var += var->nextindex;
		goto start;
	}
	return FALSE;
}

/*bson_t*
j_smd_type_to_bson(void* _type)
{
	 J_SMD_Type_t* type = _type;
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
	 J_SMD_Type_t* type;
	guint i;
	bson_iter_t iter_val;
	bson_iter_t iter_loc2;
	bson_iter_t iter;
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
*/
