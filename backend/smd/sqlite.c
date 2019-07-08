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

#include <julea-config.h>

#include <glib.h>
#include <gmodule.h>
#include <sqlite3.h>

#include <julea.h>
#include <julea-internal.h>
#include <julea-smd.h>

struct JSqlCacheNamespaces
{
	GHashTable* namespaces;
};
typedef struct JSqlCacheNamespaces JSqlCacheNamespaces;
struct JSqlCacheNames
{
	GHashTable* names;
};
typedef struct JSqlCacheNames JSqlCacheNames;
struct JSqlCacheSQLQueries
{
	GHashTable* queries;
};
typedef struct JSqlCacheSQLQueries JSqlCacheSQLQueries;
struct JSqlCacheSQLPrepared
{
	GString* sql;
	sqlite3_stmt* stmt;
	guint variables_count;
	GHashTable* variables_index;
	GHashTable* variables_type;
	gboolean initialized;
};
typedef struct JSqlCacheSQLPrepared JSqlCacheSQLPrepared;

static JSqlCacheNamespaces* cacheNamespaces = NULL;
static sqlite3* backend_db = NULL;
static sqlite3_stmt* stmt_schema_structure_create = NULL;
static sqlite3_stmt* stmt_schema_structure_get = NULL;
static sqlite3_stmt* stmt_schema_structure_delete = NULL;
static sqlite3_stmt* stmt_transaction_abort = NULL;
static sqlite3_stmt* stmt_transaction_begin = NULL;
static sqlite3_stmt* stmt_transaction_commit = NULL;

#ifdef JULEA_DEBUG
#define j_sql_check(ret, flag)                                                          \
	do                                                                              \
	{                                                                               \
		if (ret != flag)                                                        \
		{                                                                       \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
			abort();                                                        \
		}                                                                       \
	} while (0)
#define j_sql_constraint_check(ret, flag)                                               \
	do                                                                              \
	{                                                                               \
		if ((ret != flag) && (ret != SQLITE_CONSTRAINT))                        \
		{                                                                       \
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db)); \
			abort();                                                        \
		}                                                                       \
		if (ret == SQLITE_CONSTRAINT)                                           \
			goto constraint;                                                \
	} while (0)
#else
#define j_sql_check(ret, flag) \
	do                     \
	{                      \
		(void)ret;     \
		(void)flag;    \
	} while (0)
#define j_sql_constraint_check(ret, flag)     \
	do                                    \
	{                                     \
		if (ret == SQLITE_CONSTRAINT) \
			goto constraint;      \
	} while (0)
#endif
#define j_goto_error(val)                            \
	do                                           \
	{                                            \
		if (val)                             \
		{                                    \
			J_DEBUG("goto error %d", 0); \
			goto error;                  \
		}                                    \
	} while (0)
#define j_sql_reset(stmt)                         \
	do                                        \
	{                                         \
		gint _ret_ = sqlite3_reset(stmt); \
		j_sql_check(_ret_, SQLITE_OK);    \
	} while (0)
#define j_sql_reset_constraint(stmt)                      \
	do                                                \
	{                                                 \
		gint _ret_ = sqlite3_reset(stmt);         \
		j_sql_constraint_check(_ret_, SQLITE_OK); \
	} while (0)
#define j_sql_step_and_reset_check_done(stmt)    \
	do                                       \
	{                                        \
		gint _ret_ = sqlite3_step(stmt); \
		j_sql_check(_ret_, SQLITE_DONE); \
		_ret_ = sqlite3_reset(stmt);     \
		j_sql_check(_ret_, SQLITE_OK);   \
	} while (0)
#define j_sql_step_and_reset_check_done_constraint(stmt)    \
	do                                                  \
	{                                                   \
		gint _ret_ = sqlite3_step(stmt);            \
		gint _ret2_ = sqlite3_reset(stmt);          \
		j_sql_constraint_check(_ret_, SQLITE_DONE); \
		j_sql_constraint_check(_ret2_, SQLITE_OK);  \
	} while (0)
#define j_sql_transaction_begin()                                        \
	do                                                               \
	{                                                                \
		j_sql_step_and_reset_check_done(stmt_transaction_begin); \
	} while (0)
#define j_sql_transaction_commit()                                        \
	do                                                                \
	{                                                                 \
		j_sql_step_and_reset_check_done(stmt_transaction_commit); \
	} while (0)
#define j_sql_transaction_abort()                                        \
	do                                                               \
	{                                                                \
		j_sql_step_and_reset_check_done(stmt_transaction_abort); \
	} while (0)
#define j_sql_bind_null(stmt, idx)                         \
	do                                                 \
	{                                                  \
		gint _ret_ = sqlite3_bind_null(stmt, idx); \
		J_DEBUG("bind_null %d", idx);              \
		j_sql_check(_ret_, SQLITE_OK);             \
	} while (0)
#define j_sql_bind_int64(stmt, idx, val)                                         \
	do                                                                       \
	{                                                                        \
		gint _ret_ = sqlite3_bind_int64(stmt, idx, val);                 \
		J_DEBUG("bind_int64 %d %lld", idx, (long long unsigned int)val); \
		j_sql_check(_ret_, SQLITE_OK);                                   \
	} while (0)
#define j_sql_bind_int(stmt, idx, val)                             \
	do                                                         \
	{                                                          \
		gint _ret_ = sqlite3_bind_int(stmt, idx, val);     \
		J_DEBUG("bind_int %d %d", idx, (unsigned int)val); \
		j_sql_check(_ret_, SQLITE_OK);                     \
	} while (0)
#define j_sql_bind_blob(stmt, idx, val, val_len)                               \
	do                                                                     \
	{                                                                      \
		gint _ret_ = sqlite3_bind_blob(stmt, idx, val, val_len, NULL); \
		J_DEBUG("bind_blob %d %p", idx, val);                          \
		j_sql_check(_ret_, SQLITE_OK);                                 \
	} while (0)
#define j_sql_bind_double(stmt, idx, val)                         \
	do                                                        \
	{                                                         \
		gint _ret_ = sqlite3_bind_double(stmt, idx, val); \
		J_DEBUG("bind_double %d %f", idx, (double)val);   \
		j_sql_check(_ret_, SQLITE_OK);                    \
	} while (0)
#define j_sql_bind_text(stmt, idx, val, val_len)                               \
	do                                                                     \
	{                                                                      \
		gint _ret_ = sqlite3_bind_text(stmt, idx, val, val_len, NULL); \
		J_DEBUG("bind_text %d %s", idx, (const char*)val);             \
		j_sql_check(_ret_, SQLITE_OK);                                 \
	} while (0)
#define j_sql_prepare(sql, stmt)                                                                             \
	do                                                                                                   \
	{                                                                                                    \
		gint _ret_ = sqlite3_prepare_v3(backend_db, sql, -1, SQLITE_PREPARE_PERSISTENT, stmt, NULL); \
		j_sql_check(_ret_, SQLITE_OK);                                                               \
	} while (0)
#define j_sql_finalize(stmt)                           \
	do                                             \
	{                                              \
		gint __ret__ = sqlite3_finalize(stmt); \
		j_sql_check(__ret__, SQLITE_OK);       \
	} while (0)
#define j_sql_loop(stmt, ret)                                 \
	while (1)                                             \
		if ((ret = sqlite3_step(stmt)) != SQLITE_ROW) \
		{                                             \
			j_sql_check(ret, SQLITE_DONE);        \
			break;                                \
		}                                             \
		else
#define j_sql_step(stmt, ret)                         \
	if ((ret = sqlite3_step(stmt)) != SQLITE_ROW) \
		j_sql_check(ret, SQLITE_DONE);        \
	else
#define j_sql_step_constraint(stmt, ret)                  \
	if ((ret = sqlite3_step(stmt)) != SQLITE_ROW)     \
		j_sql_check_constraint(ret, SQLITE_DONE); \
	else
#define j_sql_exec_done_or_error(sql)                                                       \
	do                                                                                  \
	{                                                                                   \
		sqlite3_stmt* _stmt_;                                                       \
		gint _ret_ = sqlite3_prepare_v3(backend_db, sql, -1, 0, &_stmt_, NULL);     \
		if (_ret_ != SQLITE_OK)                                                     \
		{                                                                           \
			J_CRITICAL("sql_error a %d %s", _ret_, sqlite3_errmsg(backend_db)); \
			j_sql_finalize(_stmt_);                                             \
			j_goto_error(TRUE);                                                 \
		}                                                                           \
		_ret_ = sqlite3_step(_stmt_);                                               \
		if (_ret_ != SQLITE_DONE)                                                   \
		{                                                                           \
			J_CRITICAL("sql_error b %d %s", _ret_, sqlite3_errmsg(backend_db)); \
			j_sql_finalize(_stmt_);                                             \
			j_goto_error(TRUE);                                                 \
		}                                                                           \
		j_sql_finalize(_stmt_);                                                     \
	} while (0)
#define j_sql_exec_ok_or_error(sql)                                                         \
	do                                                                                  \
	{                                                                                   \
		sqlite3_stmt* _stmt_;                                                       \
		gint _ret_ = sqlite3_prepare_v3(backend_db, sql, -1, 0, &_stmt_, NULL);     \
		if (_ret_ != SQLITE_OK)                                                     \
		{                                                                           \
			J_CRITICAL("sql_error a %d %s", _ret_, sqlite3_errmsg(backend_db)); \
			j_sql_finalize(_stmt_);                                             \
			j_goto_error(TRUE);                                                 \
		}                                                                           \
		_ret_ = sqlite3_step(_stmt_);                                               \
		if (_ret_ != SQLITE_OK)                                                     \
		{                                                                           \
			J_CRITICAL("sql_error b %d %s", _ret_, sqlite3_errmsg(backend_db)); \
			j_sql_finalize(_stmt_);                                             \
			j_goto_error(TRUE);                                                 \
		}                                                                           \
		j_sql_finalize(_stmt_);                                                     \
	} while (0)
#define j_sql_exec_and_get_number(sql, number)                     \
	do                                                         \
	{                                                          \
		sqlite3_stmt* _stmt0_;                             \
		gint _ret0_;                                       \
		j_sql_prepare(sql, &_stmt0_);                      \
		number = 0;                                        \
		_ret0_ = sqlite3_step(_stmt0_);                    \
		if (_ret0_ == SQLITE_ROW)                          \
			number = sqlite3_column_int64(_stmt0_, 0); \
		else                                               \
			j_sql_check(_ret0_, SQLITE_DONE);          \
		j_sql_finalize(_stmt0_);                           \
	} while (0)
static void
freeJSqlCacheNamespaces(void* ptr)
{
	JSqlCacheNamespaces* p = ptr;
	if (ptr)
	{
		if (p->namespaces)
			g_hash_table_destroy(p->namespaces);
		g_free(p);
	}
}
static void
freeJSqlCacheNames(void* ptr)
{
	JSqlCacheNames* p = ptr;
	if (ptr)
	{
		if (p->names)
			g_hash_table_destroy(p->names);
		g_free(p);
	}
}
static void
freeJSqlCacheSQLQueries(void* ptr)
{
	JSqlCacheSQLQueries* p = ptr;
	if (ptr)
	{
		if (p->queries)
			g_hash_table_destroy(p->queries);
		g_free(p);
	}
}
static void
freeJSqlCacheSQLPrepared(void* ptr)
{
	JSqlCacheSQLPrepared* p = ptr;
	if (ptr)
	{
		if (p->variables_index)
			g_hash_table_destroy(p->variables_index);
		if (p->variables_type)
			g_hash_table_destroy(p->variables_type);
		if (p->sql)
			g_string_free(p->sql, TRUE);
		if (p->stmt)
			j_sql_finalize(p->stmt);
		g_free(p);
	}
}
static void
freeJSMDIterator(gpointer ptr)
{
	JSMDIterator* iter = ptr;
	if (ptr)
	{
		g_free(iter->namespace);
		g_free(iter->name);
		g_array_free(iter->arr, TRUE);
		g_free(iter);
	}
}
static JSqlCacheSQLPrepared*
getCachePrepared(gchar const* namespace, gchar const* name, gchar const* query)
{
	gint ret;
	JSqlCacheNames* cacheNames = NULL;
	JSqlCacheSQLQueries* cacheQueries = NULL;
	JSqlCacheSQLPrepared* cachePrepared = NULL;
	if (!cacheNamespaces)
	{
		cacheNamespaces = g_new0(JSqlCacheNamespaces, 1);
		cacheNamespaces->namespaces = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, freeJSqlCacheNames);
	}
	cacheNames = g_hash_table_lookup(cacheNamespaces->namespaces, namespace);
	if (!cacheNames)
	{
		cacheNames = g_new0(JSqlCacheNames, 1);
		cacheNames->names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, freeJSqlCacheSQLQueries);
		ret = g_hash_table_insert(cacheNamespaces->namespaces, g_strdup(namespace), cacheNames);
		j_goto_error(!ret);
	}
	cacheQueries = g_hash_table_lookup(cacheNames->names, name);
	if (!cacheQueries)
	{
		cacheQueries = g_new0(JSqlCacheSQLQueries, 1);
		cacheQueries->queries = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, freeJSqlCacheSQLPrepared);
		ret = g_hash_table_insert(cacheNames->names, g_strdup(name), cacheQueries);
		j_goto_error(!ret);
	}
	cachePrepared = g_hash_table_lookup(cacheQueries->queries, query);
	if (!cachePrepared)
	{
		cachePrepared = g_new0(JSqlCacheSQLPrepared, 1);
		ret = g_hash_table_insert(cacheQueries->queries, g_strdup(query), cachePrepared);
		j_goto_error(!ret);
	}
	return cachePrepared;
error:
	return NULL;
}
static void
deleteCachePrepared(gchar const* namespace, gchar const* name)
{
	gint ret;
	JSqlCacheNames* cacheNames = NULL;
	JSqlCacheSQLQueries* cacheQueries = NULL;
	JSqlCacheSQLPrepared* cachePrepared = NULL;
	if (!cacheNamespaces)
		return;
	cacheNames = g_hash_table_lookup(cacheNamespaces->namespaces, namespace);
	if (!cacheNames)
		return;
	g_hash_table_remove(cacheNames->names, name);
}
static gboolean
backend_init(gchar const* path)
{
	guint ret;
	g_autofree gchar* dirname = NULL;
	g_return_val_if_fail(path != NULL, FALSE);
	if (strncmp(":memory:", path, 7))
	{
		J_DEBUG("init useing path=%s", path);
		dirname = g_path_get_dirname(path);
		g_mkdir_with_parents(dirname, 0700);
		ret = sqlite3_open(path, &backend_db);
		if (ret != SQLITE_OK)
		{
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
			j_goto_error(TRUE);
		}
	}
	else
	{
		J_DEBUG("init useing path=%s", ":memory:");
		ret = sqlite3_open(":memory:", &backend_db);
		if (ret != SQLITE_OK)
		{
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
			j_goto_error(TRUE);
		}
	}
	j_sql_exec_done_or_error("PRAGMA foreign_keys = ON");
	j_sql_exec_done_or_error(
		"CREATE TABLE IF NOT EXISTS schema_structure ("
		"namespace TEXT,"
		"name TEXT,"
		"value TEXT,"
		"PRIMARY KEY (namespace, name)"
		")");
	j_sql_prepare("INSERT INTO schema_structure(namespace, name, value) VALUES (?1, ?2, ?3)", &stmt_schema_structure_create);
	j_sql_prepare("SELECT value FROM schema_structure WHERE namespace=?1 AND name=?2", &stmt_schema_structure_get);
	j_sql_prepare("DELETE FROM schema_structure WHERE namespace=?1 AND name=?2", &stmt_schema_structure_delete);
	j_sql_prepare("BEGIN TRANSACTION", &stmt_transaction_begin);
	j_sql_prepare("COMMIT", &stmt_transaction_commit);
	j_sql_prepare("ROLLBACK", &stmt_transaction_abort);
	return (backend_db != NULL);
error:
	sqlite3_close(backend_db);
	return FALSE;
}
static void
backend_fini(void)
{
	gint ret;
	freeJSqlCacheNamespaces(cacheNamespaces);
	j_sql_finalize(stmt_schema_structure_create);
	j_sql_finalize(stmt_schema_structure_get);
	j_sql_finalize(stmt_schema_structure_delete);
	j_sql_finalize(stmt_transaction_abort);
	j_sql_finalize(stmt_transaction_begin);
	j_sql_finalize(stmt_transaction_commit);
	ret = sqlite3_close(backend_db);
	j_sql_check(ret, SQLITE_OK);
}
static gboolean
backend_schema_create(gchar const* namespace, gchar const* name, bson_t const* schema)
{
	bson_iter_t iter;
	JSMDType type;
	guint counter = 0;
	char* json = NULL;
	GString* sql = g_string_new(NULL);
	j_sql_transaction_begin();
	g_string_append_printf(sql, "CREATE TABLE %s_%s ( _id INTEGER PRIMARY KEY", namespace, name);
	if (bson_iter_init(&iter, schema))
	{
		while (bson_iter_next(&iter))
		{
			counter++;
			g_string_append_printf(sql, ", %s", bson_iter_key(&iter));
			if (BSON_ITER_HOLDS_INT32(&iter))
			{
				type = bson_iter_int32(&iter);
				switch (type)
				{
				case J_SMD_TYPE_SINT32:
					g_string_append(sql, " INTEGER");
					break;
				case J_SMD_TYPE_UINT32:
					g_string_append(sql, " INTEGER");
					break;
				case J_SMD_TYPE_FLOAT32:
					g_string_append(sql, " REAL");
					break;
				case J_SMD_TYPE_SINT64:
					g_string_append(sql, " INTEGER");
					break;
				case J_SMD_TYPE_UINT64:
					g_string_append(sql, " UNSIGNED BIGINT");
					break;
				case J_SMD_TYPE_FLOAT64:
					g_string_append(sql, " REAL");
					break;
				case J_SMD_TYPE_STRING:
					g_string_append(sql, " TEXT");
					break;
				case J_SMD_TYPE_INVALID:
				case _J_SMD_TYPE_COUNT:
				default:
					j_goto_error(TRUE);
				}
			}
			else
				j_goto_error(TRUE);
		}
	}
	g_string_append(sql, " )");
	j_goto_error(!counter);
	json = bson_as_json(schema, NULL);
	j_sql_bind_text(stmt_schema_structure_create, 1, namespace, -1);
	j_sql_bind_text(stmt_schema_structure_create, 2, name, -1);
	j_sql_bind_text(stmt_schema_structure_create, 3, json, -1);
	j_sql_step_and_reset_check_done_constraint(stmt_schema_structure_create);
	J_DEBUG("%s", sql->str);
	j_sql_exec_done_or_error(sql->str);
	//TODO _index parse and create
	//TODO _unique parse and create
	j_sql_transaction_commit();
	bson_free(json);
	g_string_free(sql, TRUE);
	return TRUE;
error:
constraint:
	j_sql_transaction_abort();
	bson_free(json);
	g_string_free(sql, TRUE);
	return FALSE;
}
static gboolean
backend_schema_get(gchar const* namespace, gchar const* name, bson_t* schema)
{
	gint retsql;
	guint ret = FALSE;
	const char* json = NULL;
	j_sql_bind_text(stmt_schema_structure_get, 1, namespace, -1);
	j_sql_bind_text(stmt_schema_structure_get, 2, name, -1);
	j_sql_step(stmt_schema_structure_get, retsql)
	{
		if (schema)
		{
			json = (const char*)sqlite3_column_text(stmt_schema_structure_get, 0);
			j_goto_error(json == NULL);
			j_goto_error(!strlen(json));
			bson_init_from_json(schema, json, -1, NULL);
		}
		ret = TRUE;
	}
	j_sql_reset(stmt_schema_structure_get);
	return ret;
error:
	j_sql_reset(stmt_schema_structure_get);
	return FALSE;
}
static gboolean
backend_schema_delete(gchar const* namespace, gchar const* name)
{
	GString* sql = g_string_new(NULL);
	gint ret;
	deleteCachePrepared(namespace, name);
	j_sql_transaction_begin();
	ret = backend_schema_get(namespace, name, NULL);
	j_goto_error(!ret);
	g_string_append_printf(sql, "DROP TABLE %s_%s", namespace, name);
	j_sql_bind_text(stmt_schema_structure_delete, 1, namespace, -1);
	j_sql_bind_text(stmt_schema_structure_delete, 2, name, -1);
	j_sql_step_and_reset_check_done(stmt_schema_structure_delete);
	J_DEBUG("%s", sql->str);
	j_sql_exec_done_or_error(sql->str);
	j_sql_transaction_commit();
	g_string_free(sql, TRUE);
	return TRUE;
error:
	j_sql_transaction_abort();
	g_string_free(sql, TRUE);
	return false;
}
static gboolean
backend_insert(gchar const* namespace, gchar const* name, bson_t const* metadata)
{
	bson_type_t type;
	guint i, index;
	bson_iter_t iter;
	bson_t* schema = NULL;
	gboolean schema_initialized = FALSE;
	JSqlCacheSQLPrepared* prepared = NULL;
	j_sql_transaction_begin();
	prepared = getCachePrepared(namespace, name, "insert");
	j_goto_error(!prepared);
	if (!prepared->initialized)
	{
		schema = g_new0(bson_t, 1);
		schema_initialized = backend_schema_get(namespace, name, schema);
		j_goto_error(!schema_initialized);
		prepared->sql = g_string_new(NULL);
		prepared->variables_count = 0;
		prepared->variables_index = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
		g_string_append_printf(prepared->sql, "INSERT INTO %s_%s (", namespace, name);
		if (bson_iter_init(&iter, schema))
		{
			while (bson_iter_next(&iter))
			{
				if (BSON_ITER_HOLDS_INT32(&iter))
				{
					if (prepared->variables_count)
						g_string_append(prepared->sql, ", ");
					prepared->variables_count++;
					g_string_append_printf(prepared->sql, "%s", bson_iter_key(&iter));
					g_hash_table_insert(prepared->variables_index, g_strdup(bson_iter_key(&iter)), GINT_TO_POINTER(prepared->variables_count));
				}
				else
					j_goto_error(TRUE);
			}
		}
		g_string_append(prepared->sql, ") VALUES ( ?1");
		for (i = 1; i < prepared->variables_count; i++)
			g_string_append_printf(prepared->sql, ", ?%d", i + 1);
		g_string_append(prepared->sql, " )");
		J_DEBUG("%s %d", prepared->sql->str, prepared->variables_count);
		j_sql_prepare(prepared->sql->str, &prepared->stmt);
		prepared->initialized = TRUE;
	}
	for (i = 0; i < prepared->variables_count; i++)
		j_sql_bind_null(prepared->stmt, i + 1);
	if (bson_iter_init(&iter, metadata))
	{
		while (bson_iter_next(&iter))
		{
			type = bson_iter_type(&iter);
			J_DEBUG("%s", bson_iter_key(&iter));
			index = GPOINTER_TO_INT(g_hash_table_lookup(prepared->variables_index, bson_iter_key(&iter)));
			j_goto_error(!index);
			switch (type)
			{
			case BSON_TYPE_DOUBLE:
				j_sql_bind_double(prepared->stmt, index, bson_iter_double(&iter));
				break;
			case BSON_TYPE_UTF8:
				j_sql_bind_text(prepared->stmt, index, bson_iter_utf8(&iter, NULL), -1);
				break;
			case BSON_TYPE_INT32:
				j_sql_bind_int(prepared->stmt, index, bson_iter_int32(&iter));
				break;
			case BSON_TYPE_INT64:
				j_sql_bind_int64(prepared->stmt, index, bson_iter_int64(&iter));
				break;
			case BSON_TYPE_NULL:
				j_sql_bind_null(prepared->stmt, index);
				break;
			case BSON_TYPE_EOD:
			case BSON_TYPE_DOCUMENT:
			case BSON_TYPE_ARRAY:
			case BSON_TYPE_BINARY:
			case BSON_TYPE_UNDEFINED:
			case BSON_TYPE_OID:
			case BSON_TYPE_BOOL:
			case BSON_TYPE_DATE_TIME:
			case BSON_TYPE_REGEX:
			case BSON_TYPE_DBPOINTER:
			case BSON_TYPE_CODE:
			case BSON_TYPE_SYMBOL:
			case BSON_TYPE_CODEWSCOPE:
			case BSON_TYPE_TIMESTAMP:
			case BSON_TYPE_DECIMAL128:
			case BSON_TYPE_MAXKEY:
			case BSON_TYPE_MINKEY:
			default:
				j_goto_error(TRUE);
			}
		}
	}
	else
		j_goto_error(TRUE);
	j_sql_step_and_reset_check_done_constraint(prepared->stmt);
	if (schema)
	{
		if (schema_initialized)
			bson_destroy(schema);
		g_free(schema);
	}
	j_sql_transaction_commit();
	return TRUE;
error:
constraint:
	if (schema)
	{
		if (schema_initialized)
			bson_destroy(schema);
		g_free(schema);
	}
	j_sql_transaction_abort();
	return FALSE;
}
static gboolean
build_selector_query(bson_iter_t* iter, GString* sql, gboolean and_query, guint* variables_count)
{
	const char* query_op[] = { " AND ", " OR " };
	const char* query_subop[] = { "_or", "_and" };
	gint ret;
	JSMDOperator op;
	gboolean first = TRUE;
	bson_iter_t iterchild;
	g_string_append(sql, "( ");
	while (bson_iter_next(iter))
	{
		if (BSON_ITER_HOLDS_DOCUMENT(iter))
		{
			if (!g_strcmp0(bson_iter_key(iter), query_subop[and_query ? 0 : 1]))
			{
				ret = bson_iter_recurse(iter, &iterchild);
				j_goto_error(!ret);
				ret = build_selector_query(&iterchild, sql, !and_query, variables_count);
				j_goto_error(!ret);
			}
			else
			{
				(*variables_count)++;
				if (!first)
				{
					first = FALSE;
					g_string_append(sql, query_op[and_query ? 0 : 1]);
				}
				ret = bson_iter_recurse(iter, &iterchild);
				j_goto_error(!ret);
				ret = bson_iter_find(&iterchild, "operator");
				j_goto_error(!ret);
				op = bson_iter_int32(&iterchild);
				g_string_append_printf(sql, "%s ", bson_iter_key(iter));
				switch (op)
				{
				case J_SMD_OPERATOR_LT:
					g_string_append(sql, "<");
					break;
				case J_SMD_OPERATOR_LE:
					g_string_append(sql, "<=");
					break;
				case J_SMD_OPERATOR_GT:
					g_string_append(sql, ">");
					break;
				case J_SMD_OPERATOR_GE:
					g_string_append(sql, ">=");
					break;
				case J_SMD_OPERATOR_EQ:
					g_string_append(sql, "=");
					break;
				case J_SMD_OPERATOR_NE:
					g_string_append(sql, "!=");
					break;
				case _J_SMD_OPERATOR_COUNT:
				default:
					j_goto_error(TRUE);
				}
				g_string_append_printf(sql, " ?%d", *variables_count);
			}
		}
		else
			j_goto_error(TRUE);
	}
	g_string_append(sql, " )");
	return TRUE;
error:
	return FALSE;
}
static gboolean
bind_selector_query(bson_iter_t* iter, JSqlCacheSQLPrepared* prepared, gboolean and_query, guint* variables_count)
{
	const char* query_subop[] = { "_or", "_and" };
	bson_iter_t iterchild;
	gint ret;
	bson_type_t type;
	while (bson_iter_next(iter))
	{
		if (BSON_ITER_HOLDS_DOCUMENT(iter))
		{
			if (!g_strcmp0(bson_iter_key(iter), query_subop[and_query ? 0 : 1]))
			{
				ret = bson_iter_recurse(iter, &iterchild);
				j_goto_error(!ret);
				ret = bind_selector_query(&iterchild, prepared, !and_query, variables_count);
				j_goto_error(!ret);
			}
			else
			{
				(*variables_count)++;
				ret = bson_iter_recurse(iter, &iterchild);
				j_goto_error(!ret);
				ret = bson_iter_find(&iterchild, "value");
				j_goto_error(!ret);
				type = bson_iter_type(&iterchild);
				switch (type)
				{
				case BSON_TYPE_DOUBLE:
					j_sql_bind_double(prepared->stmt, *variables_count, bson_iter_double(&iterchild));
					break;
				case BSON_TYPE_UTF8:
					j_sql_bind_text(prepared->stmt, *variables_count, bson_iter_utf8(&iterchild, NULL), -1);
					break;
				case BSON_TYPE_INT32:
					j_sql_bind_int(prepared->stmt, *variables_count, bson_iter_int32(&iterchild));
					break;
				case BSON_TYPE_INT64:
					j_sql_bind_int64(prepared->stmt, *variables_count, bson_iter_int64(&iterchild));
					break;
				case BSON_TYPE_NULL:
					j_sql_bind_null(prepared->stmt, *variables_count);
					break;
				case BSON_TYPE_EOD:
				case BSON_TYPE_DOCUMENT:
				case BSON_TYPE_ARRAY:
				case BSON_TYPE_BINARY:
				case BSON_TYPE_UNDEFINED:
				case BSON_TYPE_OID:
				case BSON_TYPE_BOOL:
				case BSON_TYPE_DATE_TIME:
				case BSON_TYPE_REGEX:
				case BSON_TYPE_DBPOINTER:
				case BSON_TYPE_CODE:
				case BSON_TYPE_SYMBOL:
				case BSON_TYPE_CODEWSCOPE:
				case BSON_TYPE_TIMESTAMP:
				case BSON_TYPE_DECIMAL128:
				case BSON_TYPE_MAXKEY:
				case BSON_TYPE_MINKEY:
				default:
					j_goto_error(TRUE);
				}
			}
		}
		else
			j_goto_error(TRUE);
	}
	return TRUE;
error:
	return FALSE;
}

static gboolean
backend_query(gchar const* namespace, gchar const* name, bson_t const* selector, gpointer* iterator)
{
	guint64 tmp;
	gint ret;
	guint count = 0;
	bson_iter_t iter;
	guint variables_count;
	bson_t* schema = NULL;
	gboolean schema_initialized = FALSE;
	JSqlCacheSQLPrepared* prepared = NULL;
	GString* sql = g_string_new(NULL);
	JSMDIterator* iteratorOut;
	*iterator = NULL;
	iteratorOut = g_new(JSMDIterator, 1);
	iteratorOut->namespace = g_strdup(namespace);
	iteratorOut->name = g_strdup(name);
	iteratorOut->index = 0;
	iteratorOut->arr = g_array_new(FALSE, FALSE, sizeof(guint64));
	g_string_append_printf(sql, "SELECT DISTINCT _id FROM %s_%s", namespace, name);
	if (selector && bson_count_keys(selector))
	{
		g_string_append(sql, " WHERE ");
		if (bson_iter_init(&iter, selector))
		{
			variables_count = 0;
			ret = build_selector_query(&iter, sql, TRUE, &variables_count);
			j_goto_error(!ret);
		}
	}
	prepared = getCachePrepared(namespace, name, sql->str);
	j_goto_error(!prepared);
	if (!prepared->initialized)
	{
		schema = g_new0(bson_t, 1);
		schema_initialized = backend_schema_get(namespace, name, schema);
		j_goto_error(!schema_initialized);
		prepared->sql = g_string_new(sql->str);
		prepared->variables_count = variables_count;
		J_DEBUG("%s", prepared->sql->str);
		j_sql_prepare(prepared->sql->str, &prepared->stmt);
		prepared->initialized = TRUE;
	}
	if (selector && bson_count_keys(selector))
	{
		if (bson_iter_init(&iter, selector))
		{
			variables_count = 0;
			ret = bind_selector_query(&iter, prepared, TRUE, &variables_count);
			j_goto_error(!ret);
		}
	}
	J_DEBUG("%s", prepared->sql->str);
	j_sql_loop(prepared->stmt, ret)
	{
		count++;
		tmp = (guint64)sqlite3_column_int64(prepared->stmt, 0);
		g_array_append_val(iteratorOut->arr, tmp);
		J_DEBUG("index = %ld", tmp);
	}
	j_sql_reset(prepared->stmt);
	j_goto_error(!count);
	g_string_free(sql, TRUE);
	if (schema)
	{
		if (schema_initialized)
			bson_destroy(schema);
		g_free(schema);
	}
	*iterator = iteratorOut;
	return TRUE;
error:
	g_string_free(sql, TRUE);
	if (schema)
	{
		if (schema_initialized)
			bson_destroy(schema);
		g_free(schema);
	}
	freeJSMDIterator(iteratorOut);
	return FALSE;
}
static gboolean
backend_update(gchar const* namespace, gchar const* name, bson_t const* selector, bson_t const* metadata)
{
	bson_type_t type;
	JSMDIterator* iterator = NULL;
	bson_iter_t iter;
	guint index;
	gint ret;
	guint i, j;
	bson_t* schema = NULL;
	gboolean schema_initialized = FALSE;
	JSqlCacheSQLPrepared* prepared = NULL;
	j_sql_transaction_begin();
	prepared = getCachePrepared(namespace, name, "update");
	j_goto_error(!prepared);
	if (!prepared->initialized)
	{
		schema = g_new0(bson_t, 1);
		schema_initialized = backend_schema_get(namespace, name, schema);
		j_goto_error(!schema_initialized);
		prepared->sql = g_string_new(NULL);
		prepared->variables_count = 0;
		prepared->variables_index = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
		g_string_append_printf(prepared->sql, "UPDATE %s_%s SET ", namespace, name);
		if (bson_iter_init(&iter, schema))
		{
			while (bson_iter_next(&iter))
			{
				if (BSON_ITER_HOLDS_INT32(&iter))
				{
					if (prepared->variables_count)
						g_string_append(prepared->sql, ", ");
					prepared->variables_count++;
					g_string_append_printf(prepared->sql, "%s = ?%d", bson_iter_key(&iter), prepared->variables_count);
					g_hash_table_insert(prepared->variables_index, g_strdup(bson_iter_key(&iter)), GINT_TO_POINTER(prepared->variables_count));
				}
				else
					j_goto_error(TRUE);
			}
		}
		prepared->variables_count++;
		g_string_append_printf(prepared->sql, " WHERE _id = ?%d", prepared->variables_count);
		g_hash_table_insert(prepared->variables_index, g_strdup("_id"), GINT_TO_POINTER(prepared->variables_count));
		J_DEBUG("%s", prepared->sql->str);
		j_sql_prepare(prepared->sql->str, &prepared->stmt);
		prepared->initialized = TRUE;
	}
	ret = backend_query(namespace, name, selector, (gpointer*)&iterator);
	j_goto_error(!ret);
	for (j = 0; j < iterator->arr->len; j++)
	{
		for (i = 0; i < prepared->variables_count; i++)
			j_sql_bind_null(prepared->stmt, i + 1);
		index = GPOINTER_TO_INT(g_hash_table_lookup(prepared->variables_index, "_id"));
		j_goto_error(!index);
		j_sql_bind_int64(prepared->stmt, index, g_array_index(iterator->arr, guint64, j));
		if (bson_iter_init(&iter, metadata))
		{
			while (bson_iter_next(&iter))
			{
				type = bson_iter_type(&iter);
				index = GPOINTER_TO_INT(g_hash_table_lookup(prepared->variables_index, bson_iter_key(&iter)));
				J_DEBUG("%s", bson_iter_key(&iter));
				j_goto_error(!index);
				switch (type)
				{
				case BSON_TYPE_DOUBLE:
					j_sql_bind_double(prepared->stmt, index, bson_iter_double(&iter));
					break;
				case BSON_TYPE_UTF8:
					j_sql_bind_text(prepared->stmt, index, bson_iter_utf8(&iter, NULL), -1);
					break;
				case BSON_TYPE_INT32:
					j_sql_bind_int(prepared->stmt, index, bson_iter_int32(&iter));
					break;
				case BSON_TYPE_INT64:
					j_sql_bind_int64(prepared->stmt, index, bson_iter_int64(&iter));
					break;
				case BSON_TYPE_NULL:
					j_sql_bind_null(prepared->stmt, index);
					break;
				case BSON_TYPE_EOD:
				case BSON_TYPE_DOCUMENT:
				case BSON_TYPE_ARRAY:
				case BSON_TYPE_BINARY:
				case BSON_TYPE_UNDEFINED:
				case BSON_TYPE_OID:
				case BSON_TYPE_BOOL:
				case BSON_TYPE_DATE_TIME:
				case BSON_TYPE_REGEX:
				case BSON_TYPE_DBPOINTER:
				case BSON_TYPE_CODE:
				case BSON_TYPE_SYMBOL:
				case BSON_TYPE_CODEWSCOPE:
				case BSON_TYPE_TIMESTAMP:
				case BSON_TYPE_DECIMAL128:
				case BSON_TYPE_MAXKEY:
				case BSON_TYPE_MINKEY:
				default:
					j_goto_error(TRUE);
				}
			}
		}
		else
			j_goto_error(TRUE);
		j_sql_step_and_reset_check_done_constraint(prepared->stmt);
	}
	if (schema)
	{
		if (schema_initialized)
			bson_destroy(schema);
		g_free(schema);
	}
	freeJSMDIterator(iterator);
	j_sql_transaction_commit();
	return TRUE;
error:
constraint:
	if (schema)
	{
		if (schema_initialized)
			bson_destroy(schema);
		g_free(schema);
	}
	freeJSMDIterator(iterator);
	j_sql_transaction_abort();
	return FALSE;
}
static gboolean
backend_delete(gchar const* namespace, gchar const* name, bson_t const* selector)
{
	JSMDIterator* iterator = NULL;
	guint j;
	gint ret;
	JSqlCacheSQLPrepared* prepared = NULL;
	j_sql_transaction_begin();
	ret = backend_query(namespace, name, selector, (gpointer*)&iterator);
	j_goto_error(!ret);
	prepared = getCachePrepared(namespace, name, "delete");
	j_goto_error(!prepared);
	if (!prepared->initialized)
	{
		prepared->sql = g_string_new(NULL);
		prepared->variables_count = 1;
		g_string_append_printf(prepared->sql, "DELETE FROM %s_%s WHERE _id = ?1", namespace, name);
		J_DEBUG("%s", prepared->sql->str);
		j_sql_prepare(prepared->sql->str, &prepared->stmt);
		prepared->initialized = TRUE;
	}
	for (j = 0; j < iterator->arr->len; j++)
	{
		j_sql_bind_int64(prepared->stmt, 1, g_array_index(iterator->arr, guint64, j));
		j_sql_step_and_reset_check_done_constraint(prepared->stmt);
	}
	freeJSMDIterator(iterator);
	j_sql_transaction_commit();
	return TRUE;
error:
constraint:
	freeJSMDIterator(iterator);
	j_sql_transaction_abort();
	return FALSE;
}
static gboolean
backend_iterate(gpointer _iterator, bson_t* metadata)
{
	JSMDIterator* iterator = _iterator;
	bson_iter_t iter;
	const char* name;
	guint i;
	guint64 index;
	JSMDType type;
	gint ret;
	bson_t* schema = NULL;
	gboolean schema_initialized;
	JSqlCacheSQLPrepared* prepared = NULL;
	prepared = getCachePrepared(iterator->namespace, iterator->name, "select");
	j_goto_error(!prepared);
	if (!prepared->initialized)
	{
		schema = g_new0(bson_t, 1);
		schema_initialized = backend_schema_get(iterator->namespace, iterator->name, schema);
		j_goto_error(!schema_initialized);
		prepared->sql = g_string_new(NULL);
		prepared->variables_count = 0;
		prepared->variables_index = g_hash_table_new_full(g_direct_hash, NULL, NULL, g_free);
		prepared->variables_type = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
		g_string_append(prepared->sql, "SELECT ");
		if (bson_iter_init(&iter, schema))
		{
			while (bson_iter_next(&iter))
			{
				if (BSON_ITER_HOLDS_INT32(&iter))
				{
					if (prepared->variables_count)
						g_string_append(prepared->sql, ", ");
					g_string_append_printf(prepared->sql, "%s", bson_iter_key(&iter));
					g_hash_table_insert(prepared->variables_index, GINT_TO_POINTER(prepared->variables_count), g_strdup(bson_iter_key(&iter)));
					g_hash_table_insert(prepared->variables_type, g_strdup(bson_iter_key(&iter)), GINT_TO_POINTER(bson_iter_int32(&iter)));
					prepared->variables_count++;
				}
				else
					j_goto_error(TRUE);
			}
		}
		g_string_append_printf(prepared->sql, " FROM %s_%s WHERE _id = ?1", iterator->namespace, iterator->name);
		J_DEBUG("%s", prepared->sql->str);
		j_sql_prepare(prepared->sql->str, &prepared->stmt);
		prepared->initialized = TRUE;
	}
	j_sql_transaction_begin();
	j_goto_error(iterator->index >= iterator->arr->len);
	index = g_array_index(iterator->arr, guint64, iterator->index);
	J_DEBUG("index = %d", index);
	iterator->index++;
	j_sql_bind_int64(prepared->stmt, 1, index);
	j_sql_step(prepared->stmt, ret)
	{
		ret = bson_append_int64(metadata, "_id", -1, index);
		j_goto_error(!ret);
		for (i = 0; i < prepared->variables_count; i++)
		{
			name = g_hash_table_lookup(prepared->variables_index, GINT_TO_POINTER(i));
			type = GPOINTER_TO_INT(g_hash_table_lookup(prepared->variables_type, name));
			switch (type)
			{
			case J_SMD_TYPE_SINT32:
				ret = bson_append_int32(metadata, name, -1, sqlite3_column_int64(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_UINT32:
				ret = bson_append_int32(metadata, name, -1, sqlite3_column_int64(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_FLOAT32:
				ret = bson_append_double(metadata, name, -1, sqlite3_column_double(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_SINT64:
				ret = bson_append_int64(metadata, name, -1, sqlite3_column_int64(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_UINT64:
				ret = bson_append_int64(metadata, name, -1, sqlite3_column_int64(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_FLOAT64:
				ret = bson_append_double(metadata, name, -1, sqlite3_column_double(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_STRING:
				ret = bson_append_utf8(metadata, name, -1, (const char*)sqlite3_column_text(prepared->stmt, i), -1);
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_INVALID:
			case _J_SMD_TYPE_COUNT:
			default:
				j_goto_error(TRUE);
			}
		}
	}
	j_sql_reset(prepared->stmt);
	if (schema)
	{
		if (schema_initialized)
			bson_destroy(schema);
		g_free(schema);
	}
	j_sql_transaction_commit();
	return TRUE;
error:
	if (schema)
	{
		if (schema_initialized)
			bson_destroy(schema);
		g_free(schema);
	}
	j_sql_transaction_abort();
	return FALSE;
}
static JBackend sqlite_backend = {
	.type = J_BACKEND_TYPE_SMD,
	.component = J_BACKEND_COMPONENT_CLIENT | J_BACKEND_COMPONENT_SERVER,
	.smd = {
		.backend_init = backend_init,
		.backend_fini = backend_fini,
		.backend_schema_create = backend_schema_create,
		.backend_schema_get = backend_schema_get,
		.backend_schema_delete = backend_schema_delete,
		.backend_insert = backend_insert,
		.backend_update = backend_update,
		.backend_delete = backend_delete,
		.backend_query = backend_query,
		.backend_iterate = backend_iterate,
	},
};

G_MODULE_EXPORT
JBackend*
backend_info(void)
{
	return &sqlite_backend;
}
