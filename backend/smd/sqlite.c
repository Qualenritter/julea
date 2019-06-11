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

#include <glib.h>
#include <gmodule.h>

#include <sqlite3.h>

#include <julea.h>

#include <julea-internal.h>
#include <julea-smd.h>

enum J_SMD_Metadata_Type
{
	SMD_METATYPE_FILE,
	SMD_METATYPE_DATA
}; /*TODO change to boolean?*/
typedef enum J_SMD_Metadata_Type J_SMD_Metadata_Type;

static sqlite3* backend_db;

static gboolean
backend_init(gchar const* path)
{
	g_autofree gchar* dirname = NULL;
	J_CRITICAL("%s", path);

	g_return_val_if_fail(path != NULL, FALSE);

	dirname = g_path_get_dirname(path);
	g_mkdir_with_parents(dirname, 0700);

	if (sqlite3_open(path, &backend_db) != SQLITE_OK)
	{
		goto error;
	}

	if (sqlite3_exec(backend_db,
		    "CREATE TABLE IF NOT EXISTS smd (" //
		    "key INTEGER PRIMARY KEY AUTOINCREMENT, " //
		    "parent_key INTEGER, " // reference to parent
		    "file_key INTEGER, " // reference to file for fast delete|fetch
		    "name TEXT NOT NULL, " // name of attribute|file|dataset
		    "meta_type INTEGER," // file|dataset|attribute
		    "ndims INTEGER," // number of dimensions/*TODO allow larger dimensions - requires separate table?!?*/
		    "dims0 INTEGER," // number of dimension[0]
		    "dims1 INTEGER," // number of dimension[1]
		    "dims2 INTEGER," // number of dimension[2]
		    "dims3 INTEGER," // number of dimension[3]
		    "distribution INTEGER" // only valid for datasets
		    ");",
		    NULL,
		    NULL,
		    NULL) != SQLITE_OK)
	{
		goto error;
	}
	if (sqlite3_exec(backend_db,
		    "CREATE TABLE IF NOT EXISTS smd_types (" //
		    "key INTEGER PRIMARY KEY AUTOINCREMENT, " //
		    "meta_key INTEGER, " // reference to the attribute|dataset
		    "file_key INTEGER, " // reference to file for fast delete|fetch
		    "name TEXT NOT NULL, " // name of variable
		    "type INTEGER," // type of variable
		    "offset INTEGER," // offset within binary
		    "size INTEGER," // size of singleelement within binary
		    "count INTEGER," // element count within binary
		    "ndims INTEGER," // number of dimensions/*TODO allow larger dimensions - requires separate table?!?*/
		    "dims0 INTEGER," // number of dimension[0]
		    "dims1 INTEGER," // number of dimension[1]
		    "dims2 INTEGER," // number of dimension[2]
		    "dims3 INTEGER" // number of dimension[3]
		    ");",
		    NULL,
		    NULL,
		    NULL) != SQLITE_OK)
	{
		goto error;
	}
	J_CRITICAL("%s", path);
	return (backend_db != NULL);
error:
	sqlite3_close(backend_db);
	J_CRITICAL("%s", path);
	return FALSE;
}
static void
backend_fini(void)
{
	J_CRITICAL("%d", 0);
	if (backend_db != NULL)
	{
		sqlite3_close(backend_db);
	}
	J_CRITICAL("%d", 0);
}
static gboolean
backend_attr_delete(const char* name, char* parent)
{
	J_CRITICAL("%s %d", name, *((int*)parent));
	(void)name;
	(void)parent;
	return TRUE;
}
static gboolean
backend_attr_create(const char* name, char* parent, bson_t* bson, char* key)
{
	J_CRITICAL("%s %d %s", name, *((int*)parent), bson_as_json(bson, NULL));
	*key = 0;
	(void)name;
	(void)parent;
	(void)bson;
	return TRUE;
}
static gboolean
backend_attr_open(const char* name, char* parent, bson_t* bson, char* key)
{
	J_CRITICAL("%s %d", name, *((int*)parent));
	*key = 0;
	(void)name;
	(void)parent;
	bson_init(bson);
	J_CRITICAL("%s %d %s", name, *((int*)parent), bson_as_json(bson, NULL));
	return TRUE;
}
static gboolean
backend_attr_read(char* key, bson_t* bson)
{
	J_CRITICAL("%d", *((int*)key));
	(void)bson;
	(void)key;
	bson_init(bson);
	J_CRITICAL("%d %s", *((int*)key), bson_as_json(bson, NULL));
	return TRUE;
}
static gboolean
backend_attr_write(char* key, bson_t* bson)
{
	J_CRITICAL("%d %s", *((int*)key), bson_as_json(bson, NULL));
	(void)key;
	(void)bson;
	return TRUE;
}
static gboolean
backend_file_delete(const char* name)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;

	J_CRITICAL("%s", name);

	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND meta_type = ?;", -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, NULL);
	sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
	{
		result = sqlite3_column_int64(stmt, 0);
	}
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "DELETE FROM smd WHERE file_key = ?;", -1, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, result);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	J_CRITICAL("%s", name);
	/*TODO delete all datasets and attributes too*/
	return TRUE;
}
static gboolean
backend_file_create(const char* name, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;

	J_CRITICAL("%s %s", name, bson_as_json(bson, NULL));

	g_return_val_if_fail(name != NULL, FALSE);
	{ /*delete old file first*/
		sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND meta_type = ?;", -1, &stmt, NULL);
		sqlite3_bind_text(stmt, 1, name, -1, NULL);
		sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			backend_file_delete(name);
		}
		sqlite3_finalize(stmt);
	}
	{ // insert new file
		sqlite3_prepare_v2(backend_db, "INSERT INTO smd (name,meta_type) VALUES (?,?);", -1, &stmt, NULL);
		sqlite3_bind_text(stmt, 1, name, -1, NULL);
		sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}
	{ // extract the primary key
		sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND meta_type = ?;", -1, &stmt, NULL);
		sqlite3_bind_text(stmt, 1, name, -1, NULL);
		sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
		ret = sqlite3_step(stmt);
		memset(key, 0, SMD_KEY_LENGTH);
		if (ret == SQLITE_ROW)
		{
			result = sqlite3_column_int64(stmt, 0);
			memcpy(key, &result, sizeof(result));
		}
		sqlite3_finalize(stmt);
	}
	{ // set the parent pointers to this file
		sqlite3_prepare_v2(backend_db, "UPDATE smd SET parent_key = ?1, file_key = ?1 WHERE key = ?1;", -1, &stmt, NULL);
		sqlite3_bind_int64(stmt, 1, result);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}
	(void)bson;
	J_CRITICAL("%s", name);
	return TRUE;
}
static gboolean
backend_file_open(const char* name, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;

	J_CRITICAL("%s", name);

	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND meta_type = ?;", -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, NULL);
	sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
	ret = sqlite3_step(stmt);
	memset(key, 0, SMD_KEY_LENGTH);
	if (ret == SQLITE_ROW)
	{
		result = sqlite3_column_int64(stmt, 0);
		memcpy(key, &result, sizeof(result));
	}
	sqlite3_finalize(stmt);
	bson_init(bson);
	J_CRITICAL("%s %s", name, bson_as_json(bson, NULL));
	return TRUE;
}
static gboolean
backend_dataset_delete(const char* name, char* parent)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;

	J_CRITICAL("%s", name);

	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND parent_key = ?;", -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, NULL);
	sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
	{
		result = sqlite3_column_int64(stmt, 0);
	}
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "DELETE FROM smd WHERE key = ?;", -1, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, result);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	/*TODO delete everything below*/
	J_CRITICAL("%s", name);
	return TRUE;
}
static gboolean
backend_dataset_create(const char* name, char* parent, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;
	sqlite3_int64 dataset_key = 0;
	sqlite3_int64 file_key;
	bson_iter_t iter;
	bson_iter_t iter_space_type;
	guint var_ndims;
	guint var_dims[4];
	bson_iter_t iter_data_type;
	bson_iter_t iter_data_arr;
	bson_iter_t iter_data_var;
	bson_iter_t iter_data_dims;
	guint var_offset;
	guint var_size;
	guint var_type;
	guint var_count;
	const char* var_name;
	guint i;
	guint distribution;

	J_CRITICAL("%s %s", name, bson_as_json(bson, NULL));

	g_return_val_if_fail(name != NULL, FALSE);

	bson_iter_init(&iter, bson);

	var_ndims = 0;
	var_dims[0] = 0;
	var_dims[1] = 0;
	var_dims[2] = 0;
	var_dims[3] = 0;
	distribution = J_DISTRIBUTION_ROUND_ROBIN;
	{ // extract ndims,dims,distribution
		while (bson_iter_next(&iter))
		{
			if (strcmp("space_type", bson_iter_key(&iter)) == 0)
			{
				bson_iter_recurse(&iter, &iter_space_type);
				while (bson_iter_next(&iter_space_type))
				{
					if (strcmp("ndims", bson_iter_key(&iter_space_type)) == 0)
					{
						var_ndims = bson_iter_int32(&iter_space_type);
						if (var_ndims > 4)
						{
							return FALSE;
						}
					}
					else if (strcmp("dims", bson_iter_key(&iter_space_type)) == 0)
					{
						bson_iter_recurse(&iter_space_type, &iter_data_dims);
						i = 0;
						while (bson_iter_next(&iter_data_dims) && i < 4)
						{
							var_dims[i] = bson_iter_int32(&iter_data_dims);
							i++;
						}
					}
				}
			}
			else if (strcmp("distribution", bson_iter_key(&iter)) == 0)
			{
				distribution = bson_iter_int32(&iter);
			}
		}
	}
	{ // extract the file key
		sqlite3_prepare_v2(backend_db, "SELECT file_key FROM smd WHERE key = ?;", -1, &stmt, NULL);
		sqlite3_bind_int64(stmt, 1, *((sqlite3_int64*)parent));
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			file_key = sqlite3_column_int64(stmt, 0);
		}
		sqlite3_finalize(stmt);
	}
	{ /*delete old dataset first*/
		sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND parent_key = ? AND file_key = ?;", -1, &stmt, NULL);
		sqlite3_bind_text(stmt, 1, name, -1, NULL);
		sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
		sqlite3_bind_int64(stmt, 3, file_key);
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			backend_dataset_delete(name, parent);
		}
		sqlite3_finalize(stmt);
	}
	{ // insert new dataset
		sqlite3_prepare_v2(backend_db, "INSERT INTO smd (name,meta_type,parent_key,file_key,ndims,dims0,dims1,dims2,dims3,distribution) VALUES (?,?,?,?,?,?,?,?,?,?);", -1, &stmt, NULL);
		sqlite3_bind_text(stmt, 1, name, -1, NULL);
		sqlite3_bind_int(stmt, 2, SMD_METATYPE_DATA);
		sqlite3_bind_int64(stmt, 3, *((sqlite3_int64*)parent));
		sqlite3_bind_int64(stmt, 4, file_key);
		sqlite3_bind_int(stmt, 5, var_ndims);
		sqlite3_bind_int(stmt, 6, var_dims[0]);
		sqlite3_bind_int(stmt, 7, var_dims[1]);
		sqlite3_bind_int(stmt, 8, var_dims[2]);
		sqlite3_bind_int(stmt, 9, var_dims[3]);
		sqlite3_bind_int(stmt, 10, distribution);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}
	{ // extract the primary key
		sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND parent_key = ? AND file_key = ?;", -1, &stmt, NULL);
		sqlite3_bind_text(stmt, 1, name, -1, NULL);
		sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
		sqlite3_bind_int64(stmt, 3, file_key);
		ret = sqlite3_step(stmt);
		memset(key, 0, SMD_KEY_LENGTH);
		if (ret == SQLITE_ROW)
		{
			dataset_key = sqlite3_column_int64(stmt, 0);
			memcpy(key, &dataset_key, sizeof(dataset_key));
		}
		sqlite3_finalize(stmt);
	}
	{
		bson_iter_init(&iter, bson);

		while (bson_iter_next(&iter))
		{
			if (strcmp("data_type", bson_iter_key(&iter)) == 0)
			{
				bson_iter_recurse(&iter, &iter_data_type);
				while (bson_iter_next(&iter_data_type))
				{
					if (strcmp("arr", bson_iter_key(&iter_data_type)) == 0)
					{
						bson_iter_recurse(&iter_data_type, &iter_data_arr);
						while (bson_iter_next(&iter_data_arr))
						{
							var_offset = 0;
							var_size = 0;
							var_type = var_type;
							var_name = NULL;
							var_ndims = 0;
							var_dims[0] = 0;
							var_dims[1] = 0;
							var_dims[2] = 0;
							var_dims[3] = 0;
							var_count = 1;
							bson_iter_recurse(&iter_data_arr, &iter_data_var);
							while (bson_iter_next(&iter_data_var))
							{
								if (strcmp("offset", bson_iter_key(&iter_data_var)) == 0)
								{
									var_offset = bson_iter_int32(&iter_data_var);
								}
								else if (strcmp("size", bson_iter_key(&iter_data_var)) == 0)
								{
									var_size = bson_iter_int32(&iter_data_var);
								}
								else if (strcmp("type", bson_iter_key(&iter_data_var)) == 0)
								{
									var_type = bson_iter_int32(&iter_data_var);
								}
								else if (strcmp("ndims", bson_iter_key(&iter_data_var)) == 0)
								{
									var_ndims = bson_iter_int32(&iter_data_var);
								}
								else if (strcmp("name", bson_iter_key(&iter_data_var)) == 0)
								{
									var_name = bson_iter_utf8(&iter_data_var, NULL);
								}
								else if (strcmp("dims", bson_iter_key(&iter_data_var)) == 0)
								{
									bson_iter_recurse(&iter_data_var, &iter_data_dims);
									i = 0;
									while (bson_iter_next(&iter_data_dims) && i < 4)
									{
										var_dims[i] = bson_iter_int32(&iter_data_dims);
										var_count *= var_dims[i];
										i++;
									}
								}
							}
							sqlite3_prepare_v2(backend_db, "INSERT INTO smd_types ( meta_key, file_key, name, type, offset, size, count, ndims, dims0, dims1, dims2, dims3) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
							sqlite3_bind_int64(stmt, 1, dataset_key);
							sqlite3_bind_int64(stmt, 2, file_key);
							sqlite3_bind_text(stmt, 3, var_name, -1, NULL);
							sqlite3_bind_int(stmt, 4, var_type);
							sqlite3_bind_int(stmt, 5, var_offset);
							sqlite3_bind_int(stmt, 6, var_size);
							sqlite3_bind_int(stmt, 7, var_count);
							sqlite3_bind_int(stmt, 8, var_ndims);
							sqlite3_bind_int(stmt, 9, var_dims[0]);
							sqlite3_bind_int(stmt, 10, var_dims[1]);
							sqlite3_bind_int(stmt, 11, var_dims[2]);
							sqlite3_bind_int(stmt, 12, var_dims[3]);
							ret = sqlite3_step(stmt);
							sqlite3_finalize(stmt);
						}
					}
				}
			}
		}
	}
	J_CRITICAL("%s", name);
	return TRUE;
}
static gboolean
backend_dataset_open(const char* name, char* parent, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 dataset_key = 0;
	sqlite3_int64 result = 0;
	bson_t b_datatype[1];
	bson_t b_arr[1];
	bson_t b_var[1];
	bson_t b_dims[1];
	guint i, j;
	char key_buf[16];
	const char* _key;

	J_CRITICAL("%s", name);
	bson_init(bson);
	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key,distribution, ndims, dims0, dims1, dims2, dims3 FROM smd WHERE name = ? AND parent_key = ?;", -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, NULL);
	sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
	ret = sqlite3_step(stmt);
	memset(key, 0, SMD_KEY_LENGTH);
	if (ret == SQLITE_ROW)
	{
		dataset_key = sqlite3_column_int64(stmt, 0);
		bson_append_int32(bson, "distribution", -1, sqlite3_column_int(stmt, 1));
		memcpy(key, &dataset_key, sizeof(dataset_key));
		bson_append_document_begin(bson, "space_type", -1, b_datatype);
		bson_append_int32(b_datatype, "ndims", -1, sqlite3_column_int(stmt, 2));
		bson_append_array_begin(b_datatype, "dims", -1, b_arr);
		bson_uint32_to_string(0, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt, 3));
		bson_uint32_to_string(1, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt, 4));
		bson_uint32_to_string(2, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt, 5));
		bson_uint32_to_string(3, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt, 6));
		bson_append_array_end(b_datatype, b_arr);
		bson_append_document_end(bson, b_datatype);
	}
	sqlite3_finalize(stmt);

	sqlite3_prepare_v2(backend_db, "SELECT name, type, offset, size, ndims, dims0, dims1, dims2, dims3 FROM smd_types WHERE meta_key = ? AND file_key = ?;", -1, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, dataset_key);
	sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
	bson_append_document_begin(bson, "data_type", -1, b_datatype);
	bson_append_array_begin(b_datatype, "arr", -1, b_arr);
	i = 0;
	do
	{
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			bson_uint32_to_string(i, &_key, key_buf, sizeof(key_buf));
			bson_append_document_begin(b_arr, _key, -1, b_var);
			bson_append_int32(b_var, "offset", -1, sqlite3_column_int(stmt, 2));
			bson_append_int32(b_var, "size", -1, sqlite3_column_int(stmt, 3));
			bson_append_int32(b_var, "type", -1, sqlite3_column_int(stmt, 1));
			bson_append_utf8(b_var, "name", -1, (const char*)sqlite3_column_text(stmt, 0), -1);
			bson_append_int32(b_var, "ndims", -1, sqlite3_column_int(stmt, 4));
			bson_append_array_begin(b_var, "dims", -1, b_dims);
			for (j = 0; j < 4; j++)
			{
				bson_uint32_to_string(j, &_key, key_buf, sizeof(key_buf));
				bson_append_int32(b_dims, _key, -1, sqlite3_column_int(stmt, 5 + j));
			}
			bson_append_array_end(b_var, b_dims);
			bson_append_document_end(b_arr, b_var);
			i++;
		}
	} while (ret != SQLITE_DONE);
	bson_append_array_end(b_datatype, b_arr);
	bson_append_document_end(bson, b_datatype);

	sqlite3_finalize(stmt);

	J_CRITICAL("%s %s", name, bson_as_json(bson, NULL));
	return TRUE;
}

static JBackend sqlite_backend = { .type = J_BACKEND_TYPE_SMD, //
	.component = J_BACKEND_COMPONENT_SERVER, //
	.smd = { //
		.backend_init = backend_init, //
		.backend_fini = backend_fini, //
		.backend_attr_create = backend_attr_create, //
		.backend_attr_delete = backend_attr_delete, //
		.backend_attr_open = backend_attr_open, //
		.backend_attr_read = backend_attr_read, //
		.backend_attr_write = backend_attr_write, //
		.backend_file_create = backend_file_create, //
		.backend_file_delete = backend_file_delete, //
		.backend_file_open = backend_file_open, //
		.backend_dataset_create = backend_dataset_create, //
		.backend_dataset_delete = backend_dataset_delete, //
		.backend_dataset_open = backend_dataset_open } };
G_MODULE_EXPORT
JBackend*
backend_info(void)
{
	return &sqlite_backend;
}

/*{
	"space_type" :
		{
			"ndims" : 1,
			"dims" : [ 1 ]
		},
	"data_type" :
		{
			"arr" :
			[
				{
					"offset" : 0,
					"size" : 4,
					"type" : 0,
					"name" : "a",
					"ndims" : 1,
					"dims" : [ 1 ]
				}
			]
		}
}*/
// J_CRITICAL("sqliterr %s",sqlite3_errmsg(backend_db));
