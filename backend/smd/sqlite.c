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
		{                                                                       \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
			exit(1);                                                        \
		}                                                                       \
	} while (0)
#define _j_done_constraint_check(ret)                                                   \
	do                                                                              \
	{                                                                               \
		if ((ret != SQLITE_DONE) && (ret != SQLITE_CONSTRAINT))                 \
		{                                                                       \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
			exit(1);                                                        \
		}                                                                       \
	} while (0)
#define _j_ok_check(ret)                                                                \
	do                                                                              \
	{                                                                               \
		if (ret != SQLITE_OK)                                                   \
		{                                                                       \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
			exit(1);                                                        \
		}                                                                       \
	} while (0)
#define _j_ok_constraint_check(ret)                                                     \
	do                                                                              \
	{                                                                               \
		if ((ret != SQLITE_OK) && (ret != SQLITE_CONSTRAINT))                   \
		{                                                                       \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
			exit(1);                                                        \
		}                                                                       \
	} while (0)
#else
#define _j_done_check(ret) (void)ret
#define _j_done_constraint_check(ret) (void)ret
#define _j_ok_check(ret) (void)ret
#define _j_ok_constraint_check(ret) (void)ret
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
#define j_sqlite3_step_and_reset_check_done_constraint(stmt) \
	do                                                   \
	{                                                    \
		gint _ret_ = sqlite3_step(stmt);             \
		_j_done_constraint_check(_ret_);             \
		_ret_ = sqlite3_reset(stmt);                 \
		_j_ok_constraint_check(_ret_);               \
	} while (0)
#define j_sqlite3_transaction_begin()                                        \
	do                                                                   \
	{                                                                    \
		j_sqlite3_step_and_reset_check_done(stmt_transaction_begin); \
	} while (0)
#define j_sqlite3_transaction_commit()                                        \
	do                                                                    \
	{                                                                     \
		j_sqlite3_step_and_reset_check_done(stmt_transaction_commit); \
	} while (0)
#define j_sqlite3_transaction_abort()                                        \
	do                                                                   \
	{                                                                    \
		j_sqlite3_step_and_reset_check_done(stmt_transaction_abort); \
	} while (0)
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
#define j_sqlite3_exec_done_or_error(sql)                                                   \
	do                                                                                  \
	{                                                                                   \
		sqlite3_stmt* _stmt_;                                                       \
		gint _ret_ = sqlite3_prepare_v3(backend_db, sql, -1, 0, &_stmt_, NULL);     \
		if (_ret_ != SQLITE_OK)                                                     \
		{                                                                           \
			J_CRITICAL("sql_error a %d %s", _ret_, sqlite3_errmsg(backend_db)); \
			sqlite3_finalize(_stmt_);                                           \
			goto error;                                                         \
		}                                                                           \
		_ret_ = sqlite3_step(_stmt_);                                               \
		if (_ret_ != SQLITE_DONE)                                                   \
		{                                                                           \
			J_CRITICAL("sql_error b %d %s", _ret_, sqlite3_errmsg(backend_db)); \
			sqlite3_finalize(_stmt_);                                           \
			goto error;                                                         \
		}                                                                           \
		sqlite3_finalize(_stmt_);                                                   \
	} while (0)
#define j_sqlite3_exec_ok_or_error(sql)                                                     \
	do                                                                                  \
	{                                                                                   \
		sqlite3_stmt* _stmt_;                                                       \
		gint _ret_ = sqlite3_prepare_v3(backend_db, sql, -1, 0, &_stmt_, NULL);     \
		if (_ret_ != SQLITE_OK)                                                     \
		{                                                                           \
			J_CRITICAL("sql_error a %d %s", _ret_, sqlite3_errmsg(backend_db)); \
			sqlite3_finalize(_stmt_);                                           \
			goto error;                                                         \
		}                                                                           \
		_ret_ = sqlite3_step(_stmt_);                                               \
		if (_ret_ != SQLITE_OK)                                                     \
		{                                                                           \
			J_CRITICAL("sql_error b %d %s", _ret_, sqlite3_errmsg(backend_db)); \
			sqlite3_finalize(_stmt_);                                           \
			goto error;                                                         \
		}                                                                           \
		sqlite3_finalize(_stmt_);                                                   \
	} while (0)
static guint smd_schemes_primary_key;
static guint smd_scheme_type_primary_key;
static sqlite3_stmt* stmt_type_create;
static sqlite3_stmt* stmt_type_create_header;
static sqlite3_stmt* stmt_type_load;
static sqlite3_stmt* stmt_type_write;
static sqlite3_stmt* stmt_type_read;
static sqlite3_stmt* stmt_type_struct_size;
static sqlite3_stmt* stmt_type_write_get_structure;
static sqlite3_stmt* stmt_file_create;
static sqlite3_stmt* stmt_file_open;
static sqlite3_stmt* stmt_file_delete0;
static sqlite3_stmt* stmt_file_delete1;
static sqlite3_stmt* stmt_type_delete;
static sqlite3_stmt* stmt_scheme_delete0;
static sqlite3_stmt* stmt_scheme_delete1;
static sqlite3_stmt* stmt_scheme_delete2;
static sqlite3_stmt* stmt_scheme_create;
static sqlite3_stmt* stmt_scheme_open;
static sqlite3_stmt* stmt_scheme_get_type_key;
static sqlite3_stmt* stmt_transaction_begin;
static sqlite3_stmt* stmt_transaction_commit;
static sqlite3_stmt* stmt_transaction_abort;
#ifdef JULEA_DEBUG
j_smd_timer_variables(backend_scheme_create);
j_smd_timer_variables(backend_scheme_delete);
j_smd_timer_variables(backend_scheme_open);
j_smd_timer_variables(backend_scheme_read);
j_smd_timer_variables(backend_scheme_write);
j_smd_timer_variables(calculate_struct_size);
j_smd_timer_variables(create_type);
j_smd_timer_variables(create_type_sql);
j_smd_timer_variables(get_type_structure);
j_smd_timer_variables(load_type);
j_smd_timer_variables(load_type_sql);
j_smd_timer_variables(read_type);
j_smd_timer_variables(write_type);
#endif
#include "sqlite-type.h"
#include "sqlite-file.h"
#include "sqlite-scheme.h"

static guint
backend_init_sql(void)
{
	sqlite3_stmt* stmt;
	guint ret;
	j_sqlite3_exec_done_or_error("PRAGMA foreign_keys = ON");
	j_sqlite3_prepare_v3("BEGIN TRANSACTION;", &stmt_transaction_begin);
	j_sqlite3_prepare_v3("COMMIT;", &stmt_transaction_commit);
	j_sqlite3_prepare_v3("ROLLBACK;", &stmt_transaction_abort);
	j_sqlite3_exec_done_or_error(
		"CREATE TABLE IF NOT EXISTS smd_scheme_type_header (" //
		"key INTEGER PRIMARY KEY"
		")");
	j_sqlite3_exec_done_or_error(
		"CREATE TABLE IF NOT EXISTS smd_scheme_type (" //
		"key INTEGER PRIMARY KEY AUTOINCREMENT, " //wird von den eigentlichen daten benutzt
		"header_key INTEGER, " // identify variables belonging together
		"subtype_key INTEGER, " // reference to subtype if required
		"name TEXT NOT NULL, " // name of variable
		"type INTEGER, " // type of variable
		"offset INTEGER, " // offset within binary
		"size INTEGER, " // size of singleelement within binary
		"ndims INTEGER, " // number of dimensions/*TODO allow larger dimensions - requires separate table?!?*/
		"dims0 INTEGER, " // number of dimension[0]
		"dims1 INTEGER, " // number of dimension[1]
		"dims2 INTEGER, " // number of dimension[2]
		"dims3 INTEGER, " // number of dimension[3]
		"UNIQUE(header_key, offset),"
		"UNIQUE(header_key, name),"
		"FOREIGN KEY(subtype_key) REFERENCES smd_scheme_type_header(key) ON DELETE RESTRICT, " //typen dürfen nicht gelöscht werden, wenn andere noch darauf zeigen
		"FOREIGN KEY(header_key) REFERENCES smd_scheme_type_header(key) ON DELETE CASCADE " //typen immer vollständig löschen
		");");
	j_sqlite3_exec_done_or_error("CREATE INDEX IF NOT EXISTS smd_scheme_type_idx ON smd_scheme_type(header_key)");
	j_sqlite3_exec_done_or_error(
		"CREATE TABLE IF NOT EXISTS smd_schemes (" //
		"key INTEGER UNIQUE NOT NULL, " //
		"parent_key INTEGER, " // reference to parent
		"file_key INTEGER, " // reference to file for fast delete|fetch
		"name TEXT NOT NULL, " // name of |file|scheme
		"type_key INTEGER, " //the key in the smd_type_header table
		"ndims INTEGER, " // number of dimensions/*TODO allow larger dimensions - requires separate table?!?*/
		"dims0 INTEGER, " // number of dimension[0]
		"dims1 INTEGER, " // number of dimension[1]
		"dims2 INTEGER, " // number of dimension[2]
		"dims3 INTEGER, " // number of dimension[3]
		"distribution INTEGER, " //if this is stored within DB or the distribution in the object store
		"FOREIGN KEY(parent_key) REFERENCES smd_schemes(key) ON DELETE CASCADE, " //unterstütze rekursives löschen
		"FOREIGN KEY(file_key) REFERENCES smd_schemes(key) ON DELETE CASCADE, " //löschen von kompletten datein auf einmal
		"FOREIGN KEY(type_key) REFERENCES smd_scheme_type_header(key) ON DELETE RESTRICT, " //blockiere das löschen von einem typen, wenn der noch benutzt wird
		"PRIMARY KEY(name, parent_key), "
		"UNIQUE(name, parent_key) "
		");");
	j_sqlite3_exec_done_or_error(
		"CREATE TABLE IF NOT EXISTS smd_scheme_data (" //
		"scheme_key INTEGER, " //identiy which scheme belongs to this variable
		"type_key INTEGER, " //identify the type whithin scheme
		"offset INTEGER, " //offset within scheme
		"value_int INTEGER, " //value
		"value_float FLOAT, " //value
		"value_text TEXT, " //value
		"value_blob BLOB, " //value
		"PRIMARY KEY(scheme_key, type_key, offset), " //
		"FOREIGN KEY(scheme_key) REFERENCES smd_schemes(key) ON DELETE CASCADE, " //wenn dass schema gelöscht wird - lösche auch die daten
		"FOREIGN KEY(type_key) REFERENCES smd_scheme_type(key) ON DELETE CASCADE" //wenn der datentyp gelöscht wird - lösche auch die daten. das löschen des typen wird ja sowiso verhin$
		");");
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_scheme_type (" //
		"header_key, " //
		"name, " //
		"type, " //
		"offset, " //
		"size, " //
		"ndims, " //
		"dims0, dims1, dims2, dims3, " //
		"subtype_key) " //
		"VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11);", //
		&stmt_type_create);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_scheme_type_header (" //
		"key " //
		") " //
		"VALUES (?1)", //
		&stmt_type_create_header);
	j_sqlite3_prepare_v3(
		"SELECT name, type, offset, size, ndims, dims0, dims1, dims2, dims3, subtype_key " //
		"FROM smd_scheme_type " //
		"WHERE header_key = ?1 AND offset >= ?2" //
		"ORDER BY offset;",
		&stmt_type_load);
	j_sqlite3_prepare_v3(
		"SELECT t.size, t.offset, t.ndims, t.dims0, t.dims1, t.dims2, t.dims3 " //
		"FROM smd_scheme_type t " //
		"WHERE header_key = ?1 " //
		"ORDER BY t.offset DESC " //
		"LIMIT 1",
		&stmt_type_struct_size);
	j_sqlite3_prepare_v3(
		"SELECT t.type, t.offset, t.size, t.ndims, t.dims0, t.dims1, t.dims2, t.dims3, t.subtype_key, t.key " //
		"FROM smd_scheme_type t " //
		"WHERE header_key = ?1 " //
		"ORDER BY t.offset;",
		&stmt_type_write_get_structure);
	j_sqlite3_prepare_v3(
		"DELETE FROM smd_scheme_type_header WHERE key = ?1",
		&stmt_type_delete);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_scheme_data (scheme_key, type_key, offset, value_int, value_float, value_text, value_blob) "
		"VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (scheme_key, type_key, offset) DO UPDATE SET value_int = ?4, value_float=?5,value_text=?6,value_blob=?7",
		&stmt_type_write);
	j_sqlite3_prepare_v3(
		"SELECT a.offset, a.value_int, a.value_float, a.value_blob, t.type, t.size " //
		"FROM smd_scheme_data a, smd_scheme_type t " //
		"WHERE a.scheme_key = ?1 AND t.key = a.type_key AND a.offset >= ?2 AND (a.offset + t.size) <= ?3",
		&stmt_type_read);

	j_sqlite3_prepare_v3(
		"DELETE FROM smd_schemes " //
		"WHERE name = ? AND parent_key = ?;",
		&stmt_scheme_delete1);
	j_sqlite3_prepare_v3(
		"WITH RECURSIVE "
		"subtypes(x) AS (SELECT type_key FROM smd_schemes WHERE name = ?1 AND parent_key = ?2 UNION SELECT subtype_key FROM smd_scheme_type t, subtypes s WHERE t.header_key = s.x) "
		"SELECT x FROM subtypes",
		&stmt_scheme_delete0);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_schemes (name, parent_key, file_key, ndims, dims0, dims1, dims2, dims3, distribution, type_key, key) " //
		"VALUES (?1, ?2, (SELECT file_key FROM smd_schemes WHERE key = ?2), ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);",
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

	j_sqlite3_prepare_v3(
		"DELETE FROM smd_schemes " //
		"WHERE name = ? AND parent_key = ?;",
		&stmt_scheme_delete1);
	j_sqlite3_prepare_v3(
		"WITH RECURSIVE "
		"subtypes(x) AS (SELECT type_key FROM smd_schemes WHERE name = ?1 AND parent_key = ?2 UNION SELECT subtype_key FROM smd_scheme_type t, subtypes s WHERE t.header_key = s.x) "
		"SELECT x FROM subtypes",
		&stmt_scheme_delete0);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_schemes (name, parent_key, file_key, ndims, dims0, dims1, dims2, dims3, distribution, type_key, key) " //
		"VALUES (?1, ?2, (SELECT file_key FROM smd_schemes WHERE key = ?2), ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);",
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

	j_sqlite3_prepare_v3(
		"WITH RECURSIVE " //
		"subtypes(x) AS (SELECT t.type_key " //
		"FROM smd_schemes t "
		"WHERE t.file_key = (SELECT t3.file_key FROM smd_schemes t3 WHERE t3.name = ?1 AND t3.file_key = t3.key) UNION SELECT subtype_key FROM smd_scheme_type t2, subtypes s WHERE t2.header_key = s.x) SELECT x FROM subtypes",
		&stmt_file_delete0);
	j_sqlite3_prepare_v3(
		"DELETE FROM smd_schemes WHERE name = ?1 AND file_key = key;",
		&stmt_file_delete1);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_schemes (key,parent_key,file_key,name) VALUES (?1,?1,?1,?2);",
		&stmt_file_create);
	j_sqlite3_prepare_v3(
		"SELECT key FROM smd_schemes WHERE name = ?1 AND file_key = key;",
		&stmt_file_open);

	j_sqlite3_prepare_v3("SELECT max(key) FROM smd_schemes", &stmt);
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
		smd_schemes_primary_key = 1 + sqlite3_column_int64(stmt, 0);
	else if (ret == SQLITE_DONE)
		smd_schemes_primary_key = 1;
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	j_sqlite3_prepare_v3("SELECT max(d.type_key, t.subtype_key) FROM smd_scheme_data d, smd_scheme_type t", &stmt);
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
		smd_scheme_type_primary_key = 1 + sqlite3_column_int64(stmt, 0);
	else if (ret == SQLITE_DONE)
		smd_scheme_type_primary_key = 1;
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);

	return TRUE;
error:
	return FALSE;
}
static void
backend_fini_sql(void)
{
	sqlite3_finalize(stmt_type_create);
	sqlite3_finalize(stmt_type_create_header);
	sqlite3_finalize(stmt_type_load);
	sqlite3_finalize(stmt_type_write);
	sqlite3_finalize(stmt_type_read);
	sqlite3_finalize(stmt_file_create);
	sqlite3_finalize(stmt_file_open);
	sqlite3_finalize(stmt_file_delete0);
	sqlite3_finalize(stmt_file_delete1);
	sqlite3_finalize(stmt_type_delete);
	sqlite3_finalize(stmt_scheme_create);
	sqlite3_finalize(stmt_scheme_delete0);
	sqlite3_finalize(stmt_scheme_delete1);
	sqlite3_finalize(stmt_scheme_delete2);
	sqlite3_finalize(stmt_scheme_get_type_key);
	sqlite3_finalize(stmt_scheme_open);
	sqlite3_finalize(stmt_type_struct_size);
	sqlite3_finalize(stmt_transaction_abort);
	sqlite3_finalize(stmt_transaction_begin);
	sqlite3_finalize(stmt_transaction_commit);
	sqlite3_finalize(stmt_type_write_get_structure);
}
static void
backend_reset(void)
{
	backend_fini_sql();
	j_sqlite3_exec_done_or_error("PRAGMA foreign_keys = OFF");
	j_sqlite3_exec_done_or_error("DROP INDEX smd_scheme_type_idx");
	j_sqlite3_exec_done_or_error("DROP TABLE smd_scheme_type_header");
	j_sqlite3_exec_done_or_error("DROP TABLE smd_scheme_type");
	j_sqlite3_exec_done_or_error("DROP TABLE smd_scheme_data");
	j_sqlite3_exec_done_or_error("DROP TABLE smd_schemes");
	backend_init_sql();
error:; /*makros jump here*/
}

static gboolean
backend_init(gchar const* path)
{
	g_autofree gchar* dirname = NULL;
	J_CRITICAL("%s", path);
	g_return_val_if_fail(path != NULL, FALSE);
	dirname = g_path_get_dirname(path);
	g_mkdir_with_parents(dirname, 0700);
	if (strncmp(":memory:", path, 7))
	{
		J_CRITICAL("useing path=%s", path);
		if (sqlite3_open(path, &backend_db) != SQLITE_OK)
			goto error;
	}
	else
	{
		J_CRITICAL("useing path=%s", ":memory:");
		if (sqlite3_open(":memory:", &backend_db) != SQLITE_OK)
			goto error;
	}
	if (!backend_init_sql())
		goto error;

#ifdef JULEA_DEBUG
	j_smd_timer_alloc(backend_scheme_create);
	j_smd_timer_alloc(backend_scheme_delete);
	j_smd_timer_alloc(backend_scheme_open);
	j_smd_timer_alloc(backend_scheme_read);
	j_smd_timer_alloc(backend_scheme_write);
	j_smd_timer_alloc(calculate_struct_size);
	j_smd_timer_alloc(create_type);
	j_smd_timer_alloc(create_type_sql);
	j_smd_timer_alloc(get_type_structure);
	j_smd_timer_alloc(load_type);
	j_smd_timer_alloc(load_type_sql);
	j_smd_timer_alloc(read_type);
	j_smd_timer_alloc(write_type);
#endif
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
		backend_fini_sql();
		sqlite3_close(backend_db);
#ifdef JULEA_DEBUG
		j_smd_timer_print(backend_scheme_create);
		j_smd_timer_print(backend_scheme_delete);
		j_smd_timer_print(backend_scheme_open);
		j_smd_timer_print(backend_scheme_read);
		j_smd_timer_print(backend_scheme_write);
		j_smd_timer_print(calculate_struct_size);
		j_smd_timer_print(create_type);
		j_smd_timer_print(create_type_sql);
		j_smd_timer_print(get_type_structure);
		j_smd_timer_print(load_type);
		j_smd_timer_print(load_type_sql);
		j_smd_timer_print(read_type);
		j_smd_timer_print(write_type);
		j_smd_timer_free(backend_scheme_create);
		j_smd_timer_free(backend_scheme_delete);
		j_smd_timer_free(backend_scheme_open);
		j_smd_timer_free(backend_scheme_read);
		j_smd_timer_free(backend_scheme_write);
		j_smd_timer_free(calculate_struct_size);
		j_smd_timer_free(create_type);
		j_smd_timer_free(create_type_sql);
		j_smd_timer_free(get_type_structure);
		j_smd_timer_free(load_type);
		j_smd_timer_free(load_type_sql);
		j_smd_timer_free(read_type);
		j_smd_timer_free(write_type);
#endif
	}
	J_CRITICAL("%d", 0);
}
static JBackend sqlite_backend = { .type = J_BACKEND_TYPE_SMD, //
	.component = J_BACKEND_COMPONENT_SERVER | J_BACKEND_COMPONENT_CLIENT, //
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
		.backend_scheme_open = backend_scheme_open, //
		.backend_reset = backend_reset } };
G_MODULE_EXPORT
JBackend*
backend_info(void)
{
	return &sqlite_backend;
}
