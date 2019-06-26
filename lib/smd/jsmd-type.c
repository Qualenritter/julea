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
	if (type1->element_count == 0 && type->element_count == 0)
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
	type->element_count = 0;
	type->last_index = 0;
	type->first_index = 0;
	return type;
}
gboolean
j_smd_type_add_atomic_type(void* _type, const char* var_name, int var_offset, int var_size, J_SMD_Atomic_Type_t var_type, guint var_ndims, guint* var_dims)
{
	J_SMD_Type_t* type = _type;
	guint i;
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
	if (j_smd_type_get_member(type, var_name))
	{
		J_DEBUG("type already contains a variable named '%s'", var_name);
		return FALSE;
	}
	return j_smd_type_add_atomic_type_internal(type, var_name, var_offset, var_size, var_type, var_ndims, var_dims);
}
gboolean
j_smd_type_add_atomic_type_internal(J_SMD_Type_t* type, const char* var_name, int var_offset, int var_size, J_SMD_Atomic_Type_t var_type, guint var_ndims, guint* var_dims)
{
	J_SMD_Variable_t variable;
	guint i;
	guint my_idx;
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
	if (type->element_count == 0)
		type->first_index = my_idx;
	type->last_index = my_idx;
	type->element_count++;
	return TRUE;
}
gboolean
j_smd_type_add_compound_type(void* _type, const char* var_name, int var_offset, int var_size, void* _var_type, guint var_ndims, guint* var_dims)
{
	J_SMD_Type_t* type = _type;
	guint i;
	gboolean tmp;
	J_SMD_Type_t* var_type = _var_type;
	if (!type)
	{
		J_DEBUG("type is %p", _type);
		return FALSE;
	}
	if (!_var_type)
	{
		J_DEBUG("_var_type is %p", _var_type);
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
	if (type == _var_type)
	{
		J_DEBUG("recoursive definition not allowed %p %p", _type, _var_type);
		return FALSE;
	}
	if (j_smd_type_get_member(type, var_name))
	{
		J_DEBUG("type already contains a variable named '%s'", var_name);
		return FALSE;
	}
	tmp = j_smd_type_calc_metadata(_var_type);
	if ((var_type->arr->len == 0) || (!tmp))
	{
		J_DEBUG("adding empty subtype not allowed - since subtypes are not modifyable curerntly %d", 0);
		return FALSE;
	}
	return j_smd_type_add_compound_type_internal(type, var_name, var_offset, var_size, _var_type, var_ndims, var_dims);
}
gboolean
j_smd_type_add_compound_type_internal(J_SMD_Type_t* type, const char* var_name, int var_offset, int var_size, void* _var_type, guint var_ndims, guint* var_dims)
{
	J_SMD_Type_t* var_type = _var_type;
	J_SMD_Variable_t variable;
	guint my_idx;
	guint i;
	variable.subtypeindex = 1 + var_type->first_index; //!! subtype may have deleted data at front!!
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
	if (type->element_count == 0)
		type->first_index = my_idx;
	type->last_index = my_idx;
	g_array_append_vals(type->arr, var_type->arr->data, var_type->arr->len);
	type->element_count++;
	return TRUE;
}
guint
j_smd_type_get_variable_count(void* _type)
{
	J_SMD_Type_t* type = _type;
	if (!type)
		return 0;
	return type->element_count;
}
void*
j_smd_type_ref(void* _type)
{
	J_SMD_Type_t* type = _type;
	if (type)
		g_atomic_int_inc(&(type->ref_count));
	return type;
}
void
j_smd_type_copy2(void* target, void* source)
{
	J_SMD_Type_t* type = source;
	J_SMD_Type_t* type2 = target;
	if (source && target)
	{
		type2->last_index = type->last_index;
		type2->first_index = type->first_index;
		type2->element_count = type->element_count;
		g_array_append_vals(type2->arr, type->arr->data, type->arr->len);
	}
}
void*
j_smd_type_copy(void* type)
{
	J_SMD_Type_t* type2 = NULL;
	if (type)
	{
		type2 = j_smd_type_create();
		j_smd_type_copy2(type2, type);
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
	if (type && g_atomic_int_dec_and_test(&(type->ref_count)))
	{
		g_array_unref(type->arr);
		g_free(type);
		return FALSE;
	}
	return type != NULL;
}
static guint
j_smd_variable_calc_size(J_SMD_Variable_t* var)
{
	guint size = 0;
	guint tmp = 0;
	guint i;
start:
	if (var->type == SMD_TYPE_SUB_TYPE)
		var->size = j_smd_variable_calc_size(var + var->subtypeindex);
	tmp = var->size;
	for (i = 0; i < var->space.ndims; i++)
		tmp *= var->space.dims[i];
	tmp += var->offset;
	if (tmp > size)
		size = tmp;
	if (var->nextindex)
	{
		var += var->nextindex;
		goto start;
	}
	return size;
}
gboolean
j_smd_type_calc_metadata(void* _type)
{
	J_SMD_Type_t* type = _type;
	J_SMD_Variable_t* var;
	guint tmp;
	guint i;
	if (!type || (type->element_count == 0))
		return FALSE;
	var = &g_array_index(type->arr, J_SMD_Variable_t, type->first_index);
	type->element_count = 0;
	type->total_size = 0;
	type->last_index = type->first_index;
start:
	type->element_count++;
	if (var->type == SMD_TYPE_SUB_TYPE)
		var->size = j_smd_variable_calc_size(var + var->subtypeindex);
	tmp = var->size;
	for (i = 0; i < var->space.ndims; i++)
		tmp *= var->space.dims[i];
	tmp += var->offset;
	if (tmp > type->total_size)
		type->total_size = tmp;
	if (var->nextindex)
	{
		type->last_index += var->nextindex;
		var += var->nextindex;
		goto start;
	}
	return TRUE;
}
const J_SMD_Variable_t*
j_smd_type_get_member(void* _type, const char* var_name)
{
	J_SMD_Variable_t* var;
	J_SMD_Type_t* type = _type;
	if (!type || !var_name || (type->element_count == 0))
		return NULL;
	var = &g_array_index(type->arr, J_SMD_Variable_t, type->first_index);
start:
	if (strcmp(var_name, var->name) == 0)
		return var;
	if (var->nextindex)
	{
		var += var->nextindex;
		goto start;
	}
	return NULL;
}
gboolean
j_smd_type_remove_variable(void* _type, const char* name)
{
	J_SMD_Type_t* type = _type;
	J_SMD_Variable_t* var;
	J_SMD_Variable_t* var_prev;
	if (!type || !name || (type->element_count == 0))
		return FALSE;
	var = &g_array_index(type->arr, J_SMD_Variable_t, type->first_index);
	var_prev = var;
start:
	if (strcmp(name, var->name) == 0)
	{
		if (var == var_prev)
		{
			if (var->nextindex)
			{ //remove first element
				type->first_index += var->nextindex;
			}
			else
			{ //remove first AND last element -> ALL
				g_array_remove_range(type->arr, 0, type->arr->len);
				type->last_index = 0;
				type->first_index = 0;
			}
		}
		else
		{
			if (var->nextindex == 0)
			{ //last element
				type->last_index -= var_prev->nextindex;
				var_prev->nextindex = 0;
			}
			else
			{ //middle element
				var_prev->nextindex += var->nextindex;
			}
		}
		type->element_count--;
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
