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

struct J_SMD_cache
{
	//type deletion:
	GHashTable* types_to_delete_keys; /*keys only - fast existence check*/
	GArray* types_to_delete; /*ordered list of types to delete to avoid reject because of dependencies deleted later*/
	GArray* types_to_delete_tmp;
	//type cache
	GHashTable* types_cached;
};
typedef struct J_SMD_cache J_SMD_cache;
static J_SMD_cache smd_cache;
static sqlite3* backend_db;

#ifdef JULEA_DEBUG
#define j_debug_check(ret, flag)                                                        \
	do                                                                              \
	{                                                                               \
		if (ret != flag)                                                        \
		{                                                                       \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
			abort();                                                        \
		}                                                                       \
	} while (0)
#define _j_done_constraint_check(ret)                                                   \
	do                                                                              \
	{                                                                               \
		if ((ret != SQLITE_DONE) && (ret != SQLITE_CONSTRAINT))                 \
		{                                                                       \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
			abort();                                                        \
		}                                                                       \
	} while (0)
#define _j_ok_constraint_check(ret)                                                     \
	do                                                                              \
	{                                                                               \
		if ((ret != SQLITE_OK) && (ret != SQLITE_CONSTRAINT))                   \
		{                                                                       \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
			abort();                                                        \
		}                                                                       \
	} while (0)
#else
#define j_debug_check(ret, flag) \
	do                       \
	{                        \
		(void)ret;       \
		(void)flag;      \
	} while (0)
#define _j_done_constraint_check(ret) (void)ret
#define _j_ok_constraint_check(ret) (void)ret
#endif
#define j_sqlite3_reset(stmt)                     \
	do                                        \
	{                                         \
		gint _ret_ = sqlite3_reset(stmt); \
		j_debug_check(_ret_, SQLITE_OK);  \
	} while (0)
#define j_sqlite3_reset_constraint(stmt)          \
	do                                        \
	{                                         \
		gint _ret_ = sqlite3_reset(stmt); \
		_j_ok_constraint_check(_ret_);    \
	} while (0)
#define j_sqlite3_step_and_reset_check_done(stmt)  \
	do                                         \
	{                                          \
		gint _ret_ = sqlite3_step(stmt);   \
		j_debug_check(_ret_, SQLITE_DONE); \
		_ret_ = sqlite3_reset(stmt);       \
		j_debug_check(_ret_, SQLITE_OK);   \
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
		j_debug_check(_ret_, SQLITE_OK);           \
	} while (0)
#define j_sqlite3_bind_int64(stmt, idx, val)                     \
	do                                                       \
	{                                                        \
		gint _ret_ = sqlite3_bind_int64(stmt, idx, val); \
		j_debug_check(_ret_, SQLITE_OK);                 \
	} while (0)
#define j_sqlite3_bind_int(stmt, idx, val)                     \
	do                                                     \
	{                                                      \
		gint _ret_ = sqlite3_bind_int(stmt, idx, val); \
		j_debug_check(_ret_, SQLITE_OK);               \
	} while (0)
#define j_sqlite3_bind_blob(stmt, idx, val, val_len)                           \
	do                                                                     \
	{                                                                      \
		gint _ret_ = sqlite3_bind_blob(stmt, idx, val, val_len, NULL); \
		j_debug_check(_ret_, SQLITE_OK);                               \
	} while (0)
#define j_sqlite3_bind_double(stmt, idx, val)                     \
	do                                                        \
	{                                                         \
		gint _ret_ = sqlite3_bind_double(stmt, idx, val); \
		j_debug_check(_ret_, SQLITE_OK);                  \
	} while (0)
#define j_sqlite3_bind_text(stmt, idx, val, val_len)                           \
	do                                                                     \
	{                                                                      \
		gint _ret_ = sqlite3_bind_text(stmt, idx, val, val_len, NULL); \
		j_debug_check(_ret_, SQLITE_OK);                               \
	} while (0)
#define j_sqlite3_prepare_v3(sql, stmt)                                                                      \
	do                                                                                                   \
	{                                                                                                    \
		gint _ret_ = sqlite3_prepare_v3(backend_db, sql, -1, SQLITE_PREPARE_PERSISTENT, stmt, NULL); \
		j_debug_check(_ret_, SQLITE_OK);                                                             \
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

#define j_sqlite3_exec_and_get_number(sql, number)                 \
	do                                                         \
	{                                                          \
		sqlite3_stmt* _stmt0_;                             \
		gint _ret0_;                                       \
		j_sqlite3_prepare_v3(sql, &_stmt0_);               \
		number = 0;                                        \
		_ret0_ = sqlite3_step(_stmt0_);                    \
		if (_ret0_ == SQLITE_ROW)                          \
			number = sqlite3_column_int64(_stmt0_, 0); \
		else                                               \
			j_debug_check(_ret0_, SQLITE_DONE);        \
	} while (0)

static guint smd_schemes_primary_key;
static guint smd_scheme_type_primary_key;
static sqlite3_stmt* stmt_type_create;
static sqlite3_stmt* stmt_type_create_header;
static sqlite3_stmt* stmt_type_get_header_by_hash;
static sqlite3_stmt* stmt_type_load;
static sqlite3_stmt* stmt_type_write;
static sqlite3_stmt* stmt_type_read;
static sqlite3_stmt* stmt_type_delete0;
static sqlite3_stmt* stmt_type_delete1;
static sqlite3_stmt* stmt_type_struct_size;
static sqlite3_stmt* stmt_type_write_get_structure;
static sqlite3_stmt* stmt_file_create0;
static sqlite3_stmt* stmt_file_create1;
static sqlite3_stmt* stmt_file_open;
static sqlite3_stmt* stmt_file_delete0;
static sqlite3_stmt* stmt_file_delete2;
static sqlite3_stmt* stmt_scheme_open_all_in_file;
static sqlite3_stmt* stmt_scheme_delete_valid;
static sqlite3_stmt* stmt_scheme_get_valid;
static sqlite3_stmt* stmt_scheme_get_valid_max;
static sqlite3_stmt* stmt_scheme_set_valid;
static sqlite3_stmt* stmt_scheme_update_valid;
static sqlite3_stmt* stmt_scheme_delete0;
static sqlite3_stmt* stmt_scheme_delete1;
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
	j_sqlite3_exec_done_or_error("PRAGMA foreign_keys = ON");
	j_sqlite3_prepare_v3("BEGIN TRANSACTION", &stmt_transaction_begin);
	j_sqlite3_prepare_v3("COMMIT", &stmt_transaction_commit);
	j_sqlite3_prepare_v3("ROLLBACK", &stmt_transaction_abort);
	j_sqlite3_exec_done_or_error(
		"CREATE TABLE IF NOT EXISTS smd_scheme_type_header (" //
		"key INTEGER PRIMARY KEY, "
		"hash INTEGER, "
		"var_count INTEGER "
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
		")");
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
		")");
	j_sqlite3_exec_done_or_error(
		"CREATE TABLE IF NOT EXISTS smd_scheme_file ("
		"key INTEGER UNIQUE NOT NULL, "
		"name TEXT NOT NULL PRIMARY KEY, "
		"UNIQUE(name), "
		"FOREIGN KEY(key) REFERENCES smd_schemes(key) ON DELETE CASCADE "
		")");
	j_sqlite3_exec_done_or_error(
		"CREATE TABLE IF NOT EXISTS smd_scheme_data (" //table for storing the file-data inside the DB
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
		")");
	j_sqlite3_exec_done_or_error(
		"CREATE TABLE IF NOT EXISTS smd_scheme_data_range (" //table for stoing the valid range of data if data is stored in object store -> used to identify which data should be repalced with fill values
		"scheme_key INTEGER, " //identiy which scheme belongs to this variable
		"range_start INTEGER, " //start index of valid data
		"range_end INTEGER, " //end index of valid data
		"PRIMARY KEY(scheme_key, range_start), " //
		"FOREIGN KEY(scheme_key) REFERENCES smd_schemes(key) ON DELETE CASCADE" //wenn dass schema gelöscht wird - lösche auch die daten
		")");
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
		"VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)", //
		&stmt_type_create);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_scheme_type_header (" //
		"key,hash,var_count " //
		") " //
		"VALUES (?1,?2,?3)", //
		&stmt_type_create_header);
	j_sqlite3_prepare_v3(
		"SELECT key FROM smd_scheme_type_header WHERE hash = ?1 AND var_count = ?2", //
		&stmt_type_get_header_by_hash);
	j_sqlite3_prepare_v3(
		"SELECT name, type, offset, size, ndims, dims0, dims1, dims2, dims3, subtype_key " //
		"FROM smd_scheme_type " //
		"WHERE header_key = ?1 AND offset >= ?2" //
		"ORDER BY offset",
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
		"ORDER BY t.offset",
		&stmt_type_write_get_structure);
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
		"WITH RECURSIVE "
		"subtypes(x) AS (VALUES(?1) UNION SELECT subtype_key FROM smd_scheme_type t, subtypes s WHERE t.header_key = s.x) "
		"SELECT x FROM subtypes",
		&stmt_type_delete0);
	j_sqlite3_prepare_v3(
		"DELETE FROM smd_scheme_type_header WHERE key = ?1",
		&stmt_type_delete1);

	j_sqlite3_prepare_v3(
		"SELECT range_start, range_end FROM smd_scheme_data_range WHERE "
		"scheme_key = ?1 AND range_start <= ?2 AND range_end >= ?3 ORDER BY range_start ASC",
		&stmt_scheme_get_valid);
	j_sqlite3_prepare_v3(
		"DELETE FROM smd_scheme_data_range WHERE "
		"scheme_key = ?1 AND range_start <= ?2 AND range_end >= ?3",
		&stmt_scheme_delete_valid);
	j_sqlite3_prepare_v3(
		"SELECT MIN(range_start), MAX(range_end), COUNT(*) FROM smd_scheme_data_range WHERE "
		"scheme_key = ?1 AND range_start <= ?2 AND range_end >= ?3",
		&stmt_scheme_get_valid_max);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_scheme_data_range ("
		"scheme_key,range_start,range_end"
		") VALUES (?1, ?2, ?3)",
		&stmt_scheme_set_valid);
	j_sqlite3_prepare_v3(
		"UPDATE smd_scheme_data_range SET range_start = ?4, range_end = ?5 "
		"WHERE scheme_key = ?1 AND range_start = ?2 AND range_end = ?3",
		&stmt_scheme_update_valid);
	j_sqlite3_prepare_v3(
		"SELECT type_key FROM smd_schemes WHERE name = ?1 AND parent_key = ?2",
		&stmt_scheme_delete0);
	j_sqlite3_prepare_v3(
		"DELETE FROM smd_schemes " //
		"WHERE name = ? AND parent_key = ?",
		&stmt_scheme_delete1);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_schemes (name, parent_key, file_key, ndims, dims0, dims1, dims2, dims3, distribution, type_key, key) " //
		"VALUES (?1, ?2, (SELECT file_key FROM smd_schemes WHERE key = ?2), ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
		&stmt_scheme_create);
	j_sqlite3_prepare_v3(
		"SELECT key, ndims, dims0, dims1, dims2, dims3, distribution, type_key " //
		"FROM smd_schemes " //
		"WHERE name = ? AND parent_key = ?",
		&stmt_scheme_open);
	j_sqlite3_prepare_v3(
		"SELECT type_key " //
		"FROM smd_schemes " //
		"WHERE key = ?",
		&stmt_scheme_get_type_key);
	j_sqlite3_prepare_v3(
		"SELECT key, ndims, dims0, dims1, dims2, dims3, distribution, type_key " //
		"FROM smd_schemes " //
		"WHERE file_key = (SELECT key FROM smd_schemes WHERE name = ?1 AND key = file_key LIMIT 1) AND key != file_key",
		&stmt_scheme_open_all_in_file);

	j_sqlite3_prepare_v3(
		"SELECT t.type_key "
		"FROM smd_schemes t "
		"WHERE t.file_key = (SELECT t3.file_key FROM smd_schemes t3 WHERE t3.name = ?1 AND t3.file_key = t3.key)",
		&stmt_file_delete0);
	j_sqlite3_prepare_v3(
		"DELETE FROM smd_schemes WHERE name = ?1 AND file_key = key",
		&stmt_file_delete2);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_schemes (key,parent_key,file_key,name) VALUES (?1, NULL, ?1, ?2)",
		&stmt_file_create0);
	j_sqlite3_prepare_v3(
		"INSERT INTO smd_scheme_file (key,name) VALUES (?1, ?2)",
		&stmt_file_create1);
	j_sqlite3_prepare_v3(
		"SELECT key FROM smd_schemes WHERE name = ?1 AND file_key = key",
		&stmt_file_open);

	j_sqlite3_exec_and_get_number("SELECT max(key) FROM smd_schemes", smd_schemes_primary_key);
	smd_schemes_primary_key++;
	j_sqlite3_exec_and_get_number("SELECT max(d.type_key, t.subtype_key) FROM smd_scheme_data d, smd_scheme_type t", smd_scheme_type_primary_key);
	smd_scheme_type_primary_key++;

	return TRUE;
error:
	abort();
	return FALSE;
}
static void
backend_fini_sql(void)
{
	sqlite3_finalize(stmt_type_create);
	sqlite3_finalize(stmt_type_create_header);
	sqlite3_finalize(stmt_type_get_header_by_hash);
	sqlite3_finalize(stmt_type_load);
	sqlite3_finalize(stmt_type_write);
	sqlite3_finalize(stmt_type_delete0);
	sqlite3_finalize(stmt_type_delete1);
	sqlite3_finalize(stmt_type_read);
	sqlite3_finalize(stmt_file_create0);
	sqlite3_finalize(stmt_file_create1);
	sqlite3_finalize(stmt_file_open);
	sqlite3_finalize(stmt_file_delete0);
	sqlite3_finalize(stmt_scheme_open_all_in_file);
	sqlite3_finalize(stmt_file_delete2);
	sqlite3_finalize(stmt_scheme_set_valid);
	sqlite3_finalize(stmt_scheme_update_valid);
	sqlite3_finalize(stmt_scheme_get_valid);
	sqlite3_finalize(stmt_scheme_delete_valid);
	sqlite3_finalize(stmt_scheme_get_valid_max);
	sqlite3_finalize(stmt_scheme_create);
	sqlite3_finalize(stmt_scheme_delete0);
	sqlite3_finalize(stmt_scheme_delete1);
	sqlite3_finalize(stmt_scheme_get_type_key);
	sqlite3_finalize(stmt_scheme_open);
	sqlite3_finalize(stmt_type_struct_size);
	sqlite3_finalize(stmt_transaction_abort);
	sqlite3_finalize(stmt_transaction_begin);
	sqlite3_finalize(stmt_transaction_commit);
	sqlite3_finalize(stmt_type_write_get_structure);
}
static gboolean
backend_reset(void)
{
	sqlite3_int64 tmp;
	gboolean result = TRUE;
	j_sqlite3_exec_and_get_number("SELECT COUNT (*) FROM smd_scheme_type_header", tmp);
	if (tmp)
	{
		J_DEBUG("smd_scheme_type_header contains %lld elements", tmp);
		result = FALSE;
	}
	j_sqlite3_exec_and_get_number("SELECT COUNT (*) FROM smd_scheme_type", tmp);
	if (tmp)
	{
		J_DEBUG("smd_scheme_type contains %lld elements", tmp);
		result = FALSE;
	}
	j_sqlite3_exec_and_get_number("SELECT COUNT (*) FROM smd_scheme_data", tmp);
	if (tmp)
	{
		J_DEBUG("smd_scheme_data contains %lld elements", tmp);
		result = FALSE;
	}
	j_sqlite3_exec_and_get_number("SELECT COUNT (*) FROM smd_schemes", tmp);
	if (tmp)
	{
		J_DEBUG("smd_schemes contains %lld elements", tmp);
		result = FALSE;
	}
	j_sqlite3_exec_and_get_number("SELECT COUNT (*) FROM smd_scheme_file", tmp);
	if (tmp)
	{
		J_DEBUG("smd_scheme_file contains %lld elements", tmp);
		result = FALSE;
	}
	j_sqlite3_exec_and_get_number("SELECT COUNT (*) FROM smd_scheme_data_range", tmp);
	if (tmp)
	{
		J_DEBUG("smd_scheme_data_range contains %lld elements", tmp);
		result = FALSE;
	}
	j_sqlite3_exec_done_or_error("PRAGMA foreign_keys = OFF");
	j_sqlite3_exec_done_or_error("DELETE FROM smd_scheme_type_header");
	j_sqlite3_exec_done_or_error("DELETE FROM smd_scheme_type");
	j_sqlite3_exec_done_or_error("DELETE FROM smd_scheme_data");
	j_sqlite3_exec_done_or_error("DELETE FROM smd_schemes");
	j_sqlite3_exec_done_or_error("DELETE FROM smd_scheme_file");
	j_sqlite3_exec_done_or_error("DELETE FROM smd_scheme_data_range");
	j_sqlite3_exec_done_or_error("PRAGMA foreign_keys = ON");
	smd_schemes_primary_key = 1;
	smd_scheme_type_primary_key = 1;
	J_DEBUG("reset smd %d", result);
	return result;
error:
	J_DEBUG("reset smd %d", FALSE);
	return FALSE;
}
static void
do_nothing(void* ptr)
{
	(void)ptr;
}
static void
j_smd_type_unref_wrapper(void* ptr)
{
	j_smd_type_unref(ptr); //casts away the return type of function
}
static gboolean
backend_init(gchar const* path)
{
	guint ret;
	g_autofree gchar* dirname = NULL;
	J_DEBUG("%s", path);
	g_return_val_if_fail(path != NULL, FALSE);
	dirname = g_path_get_dirname(path);
	g_mkdir_with_parents(dirname, 0700);
	if (strncmp(":memory:", path, 7))
	{
		J_DEBUG("useing path=%s", path);
		ret = sqlite3_open(path, &backend_db);
		if (ret != SQLITE_OK)
		{
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
			goto error;
		}
	}
	else
	{
		J_DEBUG("useing path=%s", ":memory:");
		ret = sqlite3_open(":memory:", &backend_db);
		if (ret != SQLITE_OK)
		{
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
			goto error;
		}
	}
	if (!backend_init_sql())
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		goto error;
	}
	smd_cache.types_to_delete_keys = g_hash_table_new(g_direct_hash, NULL);
	smd_cache.types_to_delete = g_array_new(FALSE, FALSE, sizeof(sqlite3_int64));
	smd_cache.types_to_delete_tmp = g_array_new(FALSE, FALSE, sizeof(sqlite3_int64));
	smd_cache.types_cached = g_hash_table_new_full(g_direct_hash, NULL, do_nothing, j_smd_type_unref_wrapper);
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
	J_DEBUG("%s", path);
	return (backend_db != NULL);
error:
	sqlite3_close(backend_db);
	J_DEBUG("%s", path);
	return FALSE;
}
static void
backend_sync(void)
{
	gint ret;
	guint i;
	guint delete_sth = 0;
	sqlite3_int64 tmp;
	sqlite3_int64* key = NULL;
	sqlite3_int64* key_end = NULL;
	j_sqlite3_transaction_begin();
	if (smd_cache.types_to_delete->len)
	{
		//recursively add all subtype definitions which may be deleted
		for (i = smd_cache.types_to_delete->len; i > 0; i--)
		{
			j_sqlite3_bind_int64(stmt_type_delete0, 1, g_array_index(smd_cache.types_to_delete, sqlite3_int64, i - 1));
			do
			{
				ret = sqlite3_step(stmt_type_delete0);
				if (ret == SQLITE_ROW)
				{
					tmp = sqlite3_column_int64(stmt_type_delete0, 0);
					if (g_hash_table_add(smd_cache.types_to_delete_keys, GINT_TO_POINTER(tmp)))
						g_array_append_val(smd_cache.types_to_delete, tmp);
				}
				else
					j_debug_check(ret, SQLITE_DONE);
			} while (ret != SQLITE_DONE);
			j_sqlite3_reset(stmt_type_delete0);
		}
		key = (sqlite3_int64*)smd_cache.types_to_delete->data;
		key_end = key + smd_cache.types_to_delete->len; //update the last key
	_delete_all_types:
		do
		{
			j_sqlite3_bind_int64(stmt_type_delete1, 1, *key);
			ret = sqlite3_step(stmt_type_delete1);
			if (ret == SQLITE_CONSTRAINT)
			{
				g_array_append_val(smd_cache.types_to_delete_tmp, *key);
			}
			else if (ret == SQLITE_DONE)
			{
				delete_sth = 1;
			}
			else
				j_debug_check(ret, SQLITE_DONE);
			j_sqlite3_reset(stmt_type_delete1);
			key++;
		} while (key < key_end);
		g_array_set_size(smd_cache.types_to_delete, 0);
		g_hash_table_remove_all(smd_cache.types_to_delete_keys);
		if (delete_sth && smd_cache.types_to_delete_tmp->len)
		{
			//while something is deleted successfully repeat deleteing the remaining types, because a constraint may not be blocking any more
			g_array_append_vals(smd_cache.types_to_delete, smd_cache.types_to_delete_tmp->data, smd_cache.types_to_delete_tmp->len);
			g_array_set_size(smd_cache.types_to_delete_tmp, 0);
			delete_sth = 0;
			goto _delete_all_types;
		}
		else
		{
			g_array_set_size(smd_cache.types_to_delete_tmp, 0);
		}
	}
	g_hash_table_remove_all(smd_cache.types_cached);
	J_DEBUG("sync complete %d", 0);
	j_sqlite3_transaction_commit();
}

static void
backend_fini(void)
{
	J_DEBUG("%d", 0);
	if (backend_db != NULL)
	{
		backend_sync();
		g_hash_table_unref(smd_cache.types_to_delete_keys);
		g_array_unref(smd_cache.types_to_delete);
		g_array_unref(smd_cache.types_to_delete_tmp);
		g_hash_table_unref(smd_cache.types_cached);
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
	J_DEBUG("%d", 0);
}
static JBackend sqlite_backend = { .type = J_BACKEND_TYPE_SMD, //
	.component = J_BACKEND_COMPONENT_SERVER | J_BACKEND_COMPONENT_CLIENT, //
	.smd = {
		//
		.backend_init = backend_init, //
		.backend_fini = backend_fini, //
		.backend_file_create = backend_file_create, //
		.backend_file_delete = backend_file_delete, //
		.backend_file_open = backend_file_open, //
		.backend_scheme_set_valid = backend_scheme_set_valid, //
		.backend_scheme_get_valid = backend_scheme_get_valid, //
		.backend_scheme_read = backend_scheme_read, //
		.backend_scheme_write = backend_scheme_write, //
		.backend_scheme_create = backend_scheme_create, //
		.backend_scheme_delete = backend_scheme_delete, //
		.backend_scheme_open = backend_scheme_open, //
		.backend_reset = backend_reset,
		.backend_sync = backend_sync,
	} };
G_MODULE_EXPORT
JBackend*
backend_info(void)
{
	return &sqlite_backend;
}
