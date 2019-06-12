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
	SMD_TYPE_STRING,
	SMD_TYPE_BLOB,
	SMD_TYPE_SUB_TYPE,
};
typedef enum JSMDType JSMDType;
/*TODO make all structs internal*/
struct J_Metadata_t
{
	char key[SMD_KEY_LENGTH + 1]; /*primary key in DB zero terminated - invalid if all 0 */
	bson_t* bson;
	gboolean bson_requires_free; /*if bson requires gfree*/
	JDistribution* distribution; /*only if dataset*/
	JDistributedObject* object; /*only if dataset*/
};
typedef struct J_Metadata_t J_Metadata_t;
struct J_SMD_Space_t
{
	guint ndims;
	guint dims[SMD_MAX_NDIMS];
};
typedef struct J_SMD_Space_t J_SMD_Space_t;
struct J_SMD_Type_t
{
	GArray* arr;
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
	{ /*for serializing to buffer*/
		J_SMD_Type_t* sub_type;
		int sub_type_off;
	};
};
typedef struct J_SMD_Variable_t J_SMD_Variable_t;

void* j_smd_attr_create(const char* name, void* parent, void* data_type, void* space_type, JBatch* batch);
gboolean j_smd_attr_delete(const char* name, void* parent, JBatch* batch);
void* j_smd_attr_open(const char* name, void* parent, JBatch* batch);
gboolean j_smd_attr_read(void* attribute, char* buf, JBatch* batch);
gboolean j_smd_attr_write(void* attribute, const char* buf, JBatch* batch);
gboolean j_smd_attr_close(void* attribute);
void* j_smd_attr_get_type(void* attribute);
void* j_smd_attr_get_space(void* attribute);

void* j_smd_file_create(const char* name, JBatch* batch);
gboolean j_smd_file_delete(const char* name, JBatch* batch);
void* j_smd_file_open(const char* name, JBatch* batch);
gboolean j_smd_file_close(void* file);

void* j_smd_dataset_create(const char* name, void* parent, void* data_type, void* space_type, JDistributionType distribution, JBatch* batch);
gboolean j_smd_dataset_delete(const char* name, void* parent, JBatch* batch);
void* j_smd_dataset_open(const char* name, void* parent, JBatch* batch);
gboolean j_smd_dataset_read(void* dataset, char* buf, guint64 len, guint64 off, guint64* bytes_read, JBatch* batch);
gboolean j_smd_dataset_write(void* dataset, char* buf, guint64 len, guint64 off, guint64* bytes_written, JBatch* batch);
gboolean j_smd_dataset_close(void* dataset);
void* j_smd_dataset_get_type(void* dataset);
void* j_smd_dataset_get_space(void* dataset);

void* j_smd_space_create(guint ndims, guint* dims);
gboolean j_smd_space_get(void* space_type, guint* ndims, guint** dims);
gboolean j_smd_space_free(void* space_type);
gboolean j_smd_space_equals(void* space_type1, void* space_type2);

gboolean j_smd_type_equals(void* type1, void* type2);
void* j_smd_type_create(void);
gboolean j_smd_type_add_atomic_type(void* type, const char* var_name, int var_offset, int var_size, JSMDType var_type, guint var_ndims, guint* var_dims);
gboolean j_smd_type_add_compound_type(void* type, const char* var_name, int var_offset, int var_size, void* var_type, guint var_ndims, guint* var_dims);
guint j_smd_type_get_variable_count(void* type);
gboolean j_smd_type_free(void* type);
gboolean j_smd_type_remove_variable(void* type, const char* name);

/*not public interface functions below*/
/*TODO move to internal header file*/
gboolean j_is_key_initialized(const char* const key);
gboolean j_smd_is_initialized(void* data);
void* j_smd_get_type(void* matedata);
void* j_smd_get_space(void* metadata);
bson_t* j_smd_space_to_bson(void* space);
void* j_smd_space_from_bson(bson_iter_t* bson);
bson_t* j_smd_type_to_bson(void* type);
void* j_smd_type_from_bson(bson_iter_t* bson);
#endif
