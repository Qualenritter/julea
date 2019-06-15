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

#ifndef JULEA_SMD_H
#define JULEA_SMD_H

#include <bson.h>
#include <glib.h>

#include <julea.h>

#include <julea-object.h>

#define SMD_KEY_LENGTH 32
#define SMD_MAX_NAME_LENGTH 30
#define SMD_MAX_NDIMS 4

enum JSMDType
{
	SMD_TYPE_INT,
	SMD_TYPE_FLOAT,
	SMD_TYPE_BLOB,
	SMD_TYPE_SUB_TYPE,
};
typedef enum JSMDType JSMDType;

/*helper makro to obtain the type of a given variable*/
#define J_SMD_GET_TYPE_HELPER(a) _Generic((a),              \
					  int               \
					  : SMD_TYPE_INT,   \
					  float             \
					  : SMD_TYPE_FLOAT, \
					  default           \
					  : SMD_TYPE_BLOB)

/*TODO make all structs internal*/
struct J_SMD_Space_t
{
	guint ndims;
	guint dims[SMD_MAX_NDIMS];
	gint ref_count;
};
typedef struct J_SMD_Space_t J_SMD_Space_t;
struct J_SMD_Type_t
{
	GArray* arr;
	gint ref_count;
};
typedef struct J_SMD_Type_t J_SMD_Type_t;
struct J_SMD_Variable_t
{
	int offset;
	int size;
	JSMDType type;
	char name[SMD_MAX_NAME_LENGTH + 1]; /*+1 for nulltermination*/
	J_SMD_Space_t space;
	union
	{
		J_SMD_Type_t* sub_type; /*client side*/
		char sub_type_key[SMD_KEY_LENGTH + 1]; /*server side*/
	};
	gint ref_count;
};
typedef struct J_SMD_Variable_t J_SMD_Variable_t;
struct J_Scheme_t
{
	char key[SMD_KEY_LENGTH + 1]; /*primary key in DB zero terminated - invalid if all 0 */
	J_SMD_Type_t* type;
	J_SMD_Space_t* space;
	JDistributionType distribution_type;
	JDistribution* distribution; /*only if scheme*/
	JDistributedObject* object; /*only if scheme*/
	gint ref_count;
	void* user_data; /*may be used by user application - this will be initialized to NULL but never freed or touched elsewhere*/
};
typedef struct J_Scheme_t J_Scheme_t;

/*files only required to detect fast what belongs together*/
void* j_smd_file_create(const char* name, JBatch* batch);
gboolean j_smd_file_delete(const char* name, JBatch* batch);
void* j_smd_file_open(const char* name, JBatch* batch);
void* j_smd_file_ref(void* _file);
gboolean j_smd_file_unref(void* file);
/*scheme structure*/
void* j_smd_scheme_create(const char* name, void* parent, void* data_type, void* space_type, JDistributionType distribution, JBatch* batch);
gboolean j_smd_scheme_delete(const char* name, void* parent, JBatch* batch);
void* j_smd_scheme_open(const char* name, void* parent, JBatch* batch);
void* j_smd_scheme_ref(void* _scheme);
gboolean j_smd_scheme_unref(void* _scheme);
void* j_smd_scheme_get_type(void* scheme);
void* j_smd_scheme_get_space(void* scheme);
/*read write to database*/
gboolean j_smd_scheme_read(void* scheme, void* buf, guint64 buf_offset, guint64 buf_size, JBatch* batch);
gboolean j_smd_scheme_write(void* scheme, const void* buf, guint64 buf_offset, guint64 buf_size, JBatch* batch);
/*read write to objectstore*/
gboolean j_smd_dataset_read(void* scheme, void* buf, guint64 len, guint64 off, guint64* bytes_read, JBatch* batch);
gboolean j_smd_dataset_write(void* scheme, const void* buf, guint64 len, guint64 off, guint64* bytes_written, JBatch* batch);

void* j_smd_space_create(guint ndims, guint* dims);
gboolean j_smd_space_get(void* space_type, guint* ndims, guint** dims);
gboolean j_smd_space_equals(void* space_type1, void* space_type2);
void* j_smd_space_ref(void* _space);
gboolean j_smd_space_unref(void* _space);

#define J_SMD_TYPE_ADD_COMPOUND(type, parent, var_name, var_subtype) \
	j_smd_type_add_compound_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(((parent*)0)->var_name), var_subtype, 1, &_one);
#define J_SMD_TYPE_ADD_COMPOUND_DIMS1(type, parent, var_name, var_dims, var_subtype) \
	j_smd_type_add_compound_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(*((parent*)0)->var_name), var_subtype, 1, var_dims);
#define J_SMD_TYPE_ADD_COMPOUND_DIMS2(type, parent, var_name, var_dims, var_subtype) \
	j_smd_type_add_compound_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(**((parent*)0)->var_name), var_subtype, 2, var_dims);
#define J_SMD_TYPE_ADD_COMPOUND_DIMS3(type, parent, var_name, var_dims, var_subtype) \
	j_smd_type_add_compound_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(***((parent*)0)->var_name), var_subtype, 3, var_dims);
#define J_SMD_TYPE_ADD_COMPOUND_DIMS4(type, parent, var_name, var_dims, var_subtype) \
	j_smd_type_add_compound_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(****((parent*)0)->var_name), var_subtype, 4, var_dims);

#define J_SMD_TYPE_ADD_ATOMIC(type, parent, var_name) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(((parent*)0)->var_name), J_SMD_GET_TYPE_HELPER(((parent*)0)->var_name), 1, &_one);
#define J_SMD_TYPE_ADD_ATOMIC_DIMS1(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(*((parent*)0)->var_name), J_SMD_GET_TYPE_HELPER(*((parent*)0)->var_name), 1, var_dims);
#define J_SMD_TYPE_ADD_ATOMIC_DIMS2(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(**((parent*)0)->var_name), J_SMD_GET_TYPE_HELPER(**((parent*)0)->var_name), 2, var_dims);
#define J_SMD_TYPE_ADD_ATOMIC_DIMS3(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(***((parent*)0)->var_name), J_SMD_GET_TYPE_HELPER(***((parent*)0)->var_name), 3, var_dims);
#define J_SMD_TYPE_ADD_ATOMIC_DIMS4(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(****((parent*)0)->var_name), J_SMD_GET_TYPE_HELPER(****((parent*)0)->var_name), 4, var_dims);

gboolean j_smd_type_equals(void* type1, void* type2);
void* j_smd_type_create(void);
guint j_smd_type_get_variable_count(void* type);
gboolean j_smd_type_remove_variable(void* type, const char* name);
void* j_smd_type_ref(void* _type);
gboolean j_smd_type_unref(void* _type);

void* j_smd_variable_ref(void* _variable); /*internal only?*/
gboolean j_smd_variable_unref(void* _variable); /*internal only?*/

/*not public interface functions below*/
/*TODO move to internal header file*/
gboolean j_smd_type_add_compound_type(void* type, const char* var_name, int var_offset, int var_size, void* var_type, guint var_ndims, guint* var_dims);
gboolean j_smd_type_add_atomic_type(void* type, const char* var_name, int var_offset, int var_size, JSMDType var_type, guint var_ndims, guint* var_dims);
gboolean j_is_key_initialized(const char* const key);
gboolean j_smd_is_initialized(void* data);

bson_t* j_smd_type_to_bson(void* _type);
void* j_smd_type_from_bson(bson_iter_t* iter_arr);
bson_t* j_smd_space_to_bson(void* _space);
void* j_smd_space_from_bson(bson_iter_t* bson);
#endif
