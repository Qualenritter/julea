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

#define j_sqlite3_bind_null(stmt, idx)                                                                                       \
	do                                                                                                                   \
	{                                                                                                                    \
		gint _ret_ = sqlite3_bind_null(stmt, idx);                                                                   \
		if (_ret_ != SQLITE_OK)                                                                                      \
			J_CRITICAL("sqlite3_bind_null errorcode = %d, errorstring = %s", _ret_, sqlite3_errmsg(backend_db)); \
	} while (0)
#define j_sqlite3_bind_int64(stmt, idx, val)                                                                                  \
	do                                                                                                                    \
	{                                                                                                                     \
		gint _ret_ = sqlite3_bind_int64(stmt, idx, val);                                                              \
		if (_ret_ != SQLITE_OK)                                                                                       \
			J_CRITICAL("sqlite3_bind_int64 errorcode = %d, errorstring = %s", _ret_, sqlite3_errmsg(backend_db)); \
	} while (0)
#define j_sqlite3_bind_int(stmt, idx, val)                                                                                  \
	do                                                                                                                  \
	{                                                                                                                   \
		gint _ret_ = sqlite3_bind_int(stmt, idx, val);                                                              \
		if (_ret_ != SQLITE_OK)                                                                                     \
			J_CRITICAL("sqlite3_bind_int errorcode = %d, errorstring = %s", _ret_, sqlite3_errmsg(backend_db)); \
	} while (0)
#define j_sqlite3_bind_blob(stmt, idx, val, val_len)                                                                         \
	do                                                                                                                   \
	{                                                                                                                    \
		gint _ret_ = sqlite3_bind_blob(stmt, idx, val, val_len, NULL);                                               \
		if (_ret_ != SQLITE_OK)                                                                                      \
			J_CRITICAL("sqlite3_bind_blob errorcode = %d, errorstring = %s", _ret_, sqlite3_errmsg(backend_db)); \
	} while (0)
#define j_sqlite3_bind_double(stmt, idx, val)                                                                                  \
	do                                                                                                                     \
	{                                                                                                                      \
		gint _ret_ = sqlite3_bind_double(stmt, idx, val);                                                              \
		if (_ret_ != SQLITE_OK)                                                                                        \
			J_CRITICAL("sqlite3_bind_double errorcode = %d, errorstring = %s", _ret_, sqlite3_errmsg(backend_db)); \
	} while (0)
#define j_sqlite3_bind_text(stmt, idx, val, val_len)                                                                         \
	do                                                                                                                   \
	{                                                                                                                    \
		gint _ret_ = sqlite3_bind_text(stmt, idx, val, val_len, NULL);                                               \
		if (_ret_ != SQLITE_OK)                                                                                      \
			J_CRITICAL("sqlite3_bind_text errorcode = %d, errorstring = %s", _ret_, sqlite3_errmsg(backend_db)); \
	} while (0)

#include "sqlite-type.h"
#include "sqlite-file.h"
#include "sqlite-attribute.h"
#include "sqlite-dataset.h"

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
		    "meta_type BIGINT," // file|dataset|attribute
		    "type_key," //the key in the smd_type_header table
		    "ndims BIGINT," // number of dimensions/*TODO allow larger dimensions - requires separate table?!?*/
		    "dims0 BIGINT," // number of dimension[0]
		    "dims1 BIGINT," // number of dimension[1]
		    "dims2 BIGINT," // number of dimension[2]
		    "dims3 BIGINT," // number of dimension[3]
		    "distribution BIGINT" // only valid for datasets
		    ");",
		    NULL,
		    NULL,
		    NULL) != SQLITE_OK)
	{
		goto error;
	}
	if (sqlite3_exec(backend_db,
		    "CREATE TABLE IF NOT EXISTS smd_type_header (" //
		    "key INTEGER PRIMARY KEY AUTOINCREMENT, " //used to reserve unique ids for subtypes
		    "hash BIGINT" // for reuseing it
		    ");", /*TODO add hash or sth to reuse existing ones*/
		    NULL, /*TODO if last file using this is removed*/
		    NULL,
		    NULL) != SQLITE_OK)
	{
		goto error;
	}
	if (sqlite3_exec(backend_db,
		    "CREATE TABLE IF NOT EXISTS smd_types (" //
		    "key INTEGER PRIMARY KEY AUTOINCREMENT, " //
		    "header_key INTEGER, " // identify variables belonging together
		    "subtype_key INTEGER, " // reference to subtype if required
		    "name TEXT NOT NULL, " // name of variable
		    "type BIGINT," // type of variable
		    "offset BIGINT," // offset within binary
		    "size BIGINT," // size of singleelement within binary
		    "count BIGINT," // element count within binary
		    "ndims BIGINT," // number of dimensions/*TODO allow larger dimensions - requires separate table?!?*/
		    "dims0 BIGINT," // number of dimension[0]
		    "dims1 BIGINT," // number of dimension[1]
		    "dims2 BIGINT," // number of dimension[2]
		    "dims3 BIGINT" // number of dimension[3]
		    ");",
		    NULL,
		    NULL,
		    NULL) != SQLITE_OK)
	{
		goto error;
	}
	if (sqlite3_exec(backend_db,
		    "CREATE TABLE IF NOT EXISTS smd_attributes (" //
		    "attribute_key INTEGER, " //identiy which attribute belongs to this variable
		    "type_key INTEGER, " //identify the type whithin attribute
		    "offset BIGINT, " //offset within attribute
		    "value_int BIGINT, " //value
		    "value_float FLOAT, " //value
		    "value_text TEXT, " //value
		    "value_blob BLOB " //value
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
