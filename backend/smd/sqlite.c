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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

#ifdef JULEA_DEBUG
#define _j_done_check(ret)                                                              \
	do                                                                              \
	{                                                                               \
		if (ret != SQLITE_DONE)                                                 \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
	} while (0)
#define _j_ok_check(ret)                                                                \
	do                                                                              \
	{                                                                               \
		if (ret != SQLITE_OK)                                                   \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
	} while (0)
#else
#define _j_done_check(ret)
#define _j_ok_check(ret)
#endif

#define j_sqlite3_reset(stmt)                     \
	do                                        \
	{                                         \
		gint _ret_ = sqlite3_reset(stmt); \
		_j_ok_check(_ret_);               \
	} while (0)
#define j_sqlite3_step_and_reset_check_done(stmt) \
	do                                        \
	{                                         \
		gint _ret_ = sqlite3_step(stmt);  \
		_j_done_check(_ret_);             \
		_ret_ = sqlite3_reset(stmt);      \
		_j_ok_check(_ret_);               \
	} while (0)

#define j_sqlite3_transaction_begin() j_sqlite3_step_and_reset_check_done(stmt_transaction_begin)
#define j_sqlite3_transaction_commit() j_sqlite3_step_and_reset_check_done(stmt_transaction_commit)
#define j_sqlite3_transaction_abort() j_sqlite3_step_and_reset_check_done(stmt_transaction_abort)
#define j_sqlite3_bind_null(stmt, idx)                     \
	do                                                 \
	{                                                  \
		gint _ret_ = sqlite3_bind_null(stmt, idx); \
		_j_ok_check(_ret_);                        \
	} while (0)
#define j_sqlite3_bind_int64(stmt, idx, val)                     \
	do                                                       \
	{                                                        \
		gint _ret_ = sqlite3_bind_int64(stmt, idx, val); \
		_j_ok_check(_ret_);                              \
	} while (0)
#define j_sqlite3_bind_int(stmt, idx, val)                     \
	do                                                     \
	{                                                      \
		gint _ret_ = sqlite3_bind_int(stmt, idx, val); \
		_j_ok_check(_ret_);                            \
	} while (0)
#define j_sqlite3_bind_blob(stmt, idx, val, val_len)                           \
	do                                                                     \
	{                                                                      \
		gint _ret_ = sqlite3_bind_blob(stmt, idx, val, val_len, NULL); \
		_j_ok_check(_ret_);                                            \
	} while (0)
#define j_sqlite3_bind_double(stmt, idx, val)                     \
	do                                                        \
	{                                                         \
		gint _ret_ = sqlite3_bind_double(stmt, idx, val); \
		_j_ok_check(_ret_);                               \
	} while (0)
#define j_sqlite3_bind_text(stmt, idx, val, val_len)                           \
	do                                                                     \
	{                                                                      \
		gint _ret_ = sqlite3_bind_text(stmt, idx, val, val_len, NULL); \
		_j_ok_check(_ret_);                                            \
	} while (0)
#define j_sqlite3_prepare_v3(sql, stmt)                                                                      \
	do                                                                                                   \
	{                                                                                                    \
		gint _ret_ = sqlite3_prepare_v3(backend_db, sql, -1, SQLITE_PREPARE_PERSISTENT, stmt, NULL); \
		_j_ok_check(_ret_);                                                                          \
	} while (0)

static guint smd_schemes_primary_key;
static guint smd_scheme_type_primary_key;
static sqlite3_stmt* stmt_create_type;
static sqlite3_stmt* stmt_load_type;
static sqlite3_stmt* stmt_struct_size;
static sqlite3_stmt* stmt_write_structure;
static sqlite3_stmt* stmt_scheme_delete_0;
static sqlite3_stmt* stmt_scheme_delete_1;
static sqlite3_stmt* stmt_scheme_delete_2;
static sqlite3_stmt* stmt_scheme_delete_3;
static sqlite3_stmt* stmt_scheme_create;
static sqlite3_stmt* stmt_scheme_open;
static sqlite3_stmt* stmt_scheme_get_type_key;
static sqlite3_stmt* stmt_transaction_begin;
static sqlite3_stmt* stmt_transaction_commit;
static sqlite3_stmt* stmt_transaction_abort;

#include "sqlite-type.h"
#include "sqlite-file.h"
#include "sqlite-scheme.h"

static gboolean
backend_init(gchar const* path)
{
	sqlite3_stmt* stmt;
	guint ret;
	g_autofree gchar* dirname = NULL;
	J_CRITICAL("%s", path);
	g_return_val_if_fail(path != NULL, FALSE);
	dirname = g_path_get_dirname(path);
	g_mkdir_with_parents(dirname, 0700);
	if (sqlite3_open(path, &backend_db) != SQLITE_OK)
		goto error;
	if ((ret = sqlite3_exec(backend_db,
		     "CREATE TABLE IF NOT EXISTS smd_scheme_type (" //
		     "key INTEGER PRIMARY KEY AUTOINCREMENT, "
		     "header_key INTEGER, " // identify variables belonging together
		     "subtype_key INTEGER, " // reference to subtype if required
		     "name TEXT NOT NULL, " // name of variable
		     "type INTEGER, " // type of variable
		     "offset INTEGER, " // offset within binary
		     "size INTEGER, " // size of singleelement within binary
		     "count INTEGER, " // element count within binary
		     "ndims INTEGER, " // number of dimensions/*TODO allow larger dimensions - requires separate table?!?*/
		     "dims0 INTEGER, " // number of dimension[0]
		     "dims1 INTEGER, " // number of dimension[1]
		     "dims2 INTEGER, " // number of dimension[2]
		     "dims3 INTEGER, " // number of dimension[3]
		     "FOREIGN KEY(subtype_key) REFERENCES smd_scheme_type(header_key)" //
		     ");",
		     NULL,
		     NULL,
		     NULL)) != SQLITE_OK)
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		goto error;
	}
	if ((ret = sqlite3_exec(backend_db,
		     "CREATE TABLE IF NOT EXISTS smd_schemes (" //
		     "key INTEGER PRIMARY KEY, " //
		     "parent_key INTEGER, " // reference to parent
		     "file_key INTEGER, " // reference to file for fast delete|fetch
		     "name TEXT NOT NULL, " // name of |file|scheme
		     "meta_type INTEGER, " // file|scheme
		     "type_key INTEGER, " //the key in the smd_type_header table
		     "ndims INTEGER, " // number of dimensions/*TODO allow larger dimensions - requires separate table?!?*/
		     "dims0 INTEGER, " // number of dimension[0]
		     "dims1 INTEGER, " // number of dimension[1]
		     "dims2 INTEGER, " // number of dimension[2]
		     "dims3 INTEGER, " // number of dimension[3]
		     "distribution INTEGER, " //if this is stored within DB or the distribution in the object store
		     "FOREIGN KEY(parent_key) REFERENCES smd_schemes(key), "
		     "FOREIGN KEY(file_key) REFERENCES smd_schemes(key), "
		     "FOREIGN KEY(type_key) REFERENCES smd_scheme_type(header_key)"
		     ");",
		     NULL,
		     NULL,
		     NULL)) != SQLITE_OK)
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		goto error;
	}
	if ((ret = sqlite3_exec(backend_db,
		     "CREATE TABLE IF NOT EXISTS smd_scheme_data (" //
		     "scheme_key INTEGER, " //identiy which scheme belongs to this variable
		     "type_key INTEGER, " //identify the type whithin scheme
		     "offset INTEGER, " //offset within scheme
		     "value_int INTEGER, " //value
		     "value_float FLOAT, " //value
		     "value_text TEXT, " //value
		     "value_blob BLOB, " //value
		     "PRIMARY KEY(scheme_key, type_key, offset), " //
		     "FOREIGN KEY(scheme_key) REFERENCES smd_schemes(key), " //
		     "FOREIGN KEY(type_key) REFERENCES smd_scheme_type(key)" //
		     ");",
		     NULL,
		     NULL,
		     NULL)) != SQLITE_OK)
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		goto error;
	}
	sqlite3_prepare_v2(backend_db, "SELECT max(key) FROM smd_schemes", -1, &stmt, NULL);
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
		smd_schemes_primary_key = 1 + sqlite3_column_int64(stmt, 0);
	else if (ret == SQLITE_DONE)
		smd_schemes_primary_key = 1;
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "SELECT max(d.type_key, t.subtype_key) FROM smd_scheme_data d, smd_scheme_type t", -1, &stmt, NULL);
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
		smd_scheme_type_primary_key = 1 + sqlite3_column_int64(stmt, 0);
	else if (ret == SQLITE_DONE)
		smd_scheme_type_primary_key = 1;
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_scheme_type (" //
		"header_key, " //
		"name, " //
		"type, " //
		"offset, " //
		"size, " //
		"count, " //
		"ndims, " //
		"dims0, dims1, dims2, dims3, " //
		"subtype_key) " //
		"VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12);", //
		&stmt_create_type);
	j_sqlite3_prepare_v3(
		"SELECT name, type, offset, size, ndims, dims0, dims1, dims2, dims3, subtype_key " //
		"FROM smd_scheme_type " //
		"WHERE header_key = ?1 AND offset >= ?2" //
		"ORDER BY offset;",
		&stmt_load_type);
	j_sqlite3_prepare_v3(
		"SELECT t.size, t.offset, t.ndims, t.dims0, t.dims1, t.dims2, t.dims3 " //
		"FROM smd_scheme_type t " //
		"WHERE header_key = ?1 " //
		"ORDER BY t.offset DESC " //
		"LIMIT 1",
		&stmt_struct_size);
	j_sqlite3_prepare_v3(
		"SELECT t.type, t.offset, t.size, t.ndims, t.dims0, t.dims1, t.dims2, t.dims3, t.subtype_key, t.key " //
		"FROM smd_scheme_type t " //
		"WHERE header_key = ?1 " //
		"ORDER BY t.offset;",
		&stmt_write_structure);
	j_sqlite3_prepare_v3(
		"SELECT key, type_key FROM smd_schemes " //
		"WHERE name = ? AND parent_key = ?;",
		&stmt_scheme_delete_0);
	j_sqlite3_prepare_v3(
		"DELETE FROM smd_schemes " //
		"WHERE key = ?;",
		&stmt_scheme_delete_1);
	j_sqlite3_prepare_v3(
		"DELETE FROM smd_scheme_data " //
		"WHERE scheme_key = ?;",
		&stmt_scheme_delete_2);
	j_sqlite3_prepare_v3(
		"DELETE FROM smd_scheme_type " //
		"WHERE header_key = ?;",
		&stmt_scheme_delete_3);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_schemes (name, meta_type, parent_key, file_key, ndims, dims0, dims1, dims2, dims3, distribution, type_key, key) " //
		"VALUES (?1, ?2, ?3, (SELECT file_key FROM smd_schemes WHERE key = ?3), ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11);",
		&stmt_scheme_create);
	j_sqlite3_prepare_v3(
		"SELECT key, ndims, dims0, dims1, dims2, dims3, distribution, type_key " //
		"FROM smd_schemes " //
		"WHERE name = ? AND parent_key = ?;",
		&stmt_scheme_open);
	j_sqlite3_prepare_v3(
		"SELECT type_key " //
		"FROM smd_schemes " //
		"WHERE key = ?;",
		&stmt_scheme_get_type_key);
	j_sqlite3_prepare_v3("BEGIN TRANSACTION;", &stmt_transaction_begin);
	j_sqlite3_prepare_v3("COMMIT;", &stmt_transaction_commit);
	j_sqlite3_prepare_v3("ROLLBACK;", &stmt_transaction_abort);

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
		sqlite3_finalize(stmt_create_type);
		sqlite3_close(backend_db);
	}
	J_CRITICAL("%d", 0);
}
static JBackend sqlite_backend = { .type = J_BACKEND_TYPE_SMD, //
	.component = J_BACKEND_COMPONENT_SERVER, //
	.smd = { //
		.backend_init = backend_init, //
		.backend_fini = backend_fini, //
		.backend_scheme_read = backend_scheme_read, //
		.backend_scheme_write = backend_scheme_write, //
		.backend_file_create = backend_file_create, //
		.backend_file_delete = backend_file_delete, //
		.backend_file_open = backend_file_open, //
		.backend_scheme_create = backend_scheme_create, //
		.backend_scheme_delete = backend_scheme_delete, //
		.backend_scheme_open = backend_scheme_open } };
G_MODULE_EXPORT
JBackend*
backend_info(void)
{
	return &sqlite_backend;
}
