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
#ifndef SQL_GENERIC_BACKEND_H
#define SQL_GENERIC_BACKEND_H
/*
 * this file does not care which sql-database is actually in use, and uses only defines sql-syntax to allow fast and easy implementations for any new sql-database backend
*/
#ifndef j_sql_bind_blob
#error "j_sql_bind_blob undefined"
#endif
#ifndef j_sql_bind_double
#error "j_sql_bind_double undefined"
#endif
#ifndef j_sql_bind_int
#error "j_sql_bind_int undefined"
#endif
#ifndef j_sql_bind_int64
#error "j_sql_bind_int64 undefined"
#endif
#ifndef j_sql_bind_null
#error "j_sql_bind_null undefined"
#endif
#ifndef j_sql_bind_text
#error "j_sql_bind_text undefined"
#endif
#ifndef j_sql_check
#error "j_sql_check undefined"
#endif
#ifndef j_sql_column_float32
#error "j_sql_column_float32 undefined"
#endif
#ifndef j_sql_column_float64
#error "j_sql_column_float64 undefined"
#endif
#ifndef j_sql_column_sint32
#error "j_sql_column_sint32 undefined"
#endif
#ifndef j_sql_column_sint64
#error "j_sql_column_sint64 undefined"
#endif
#ifndef j_sql_column_text
#error "j_sql_column_text undefined"
#endif
#ifndef j_sql_column_uint32
#error "j_sql_column_uint32 undefined"
#endif
#ifndef j_sql_column_uint64
#error "j_sql_column_uint64 undefined"
#endif
#ifndef j_sql_constraint_check
#error "j_sql_constraint_check undefined"
#endif
#ifndef j_sql_done
#error "j_sql_done undefined"
#endif
#ifndef j_sql_exec_and_get_number
#error "j_sql_exec_and_get_number undefined"
#endif
#ifndef j_sql_exec_or_error
#error "j_sql_exec_or_error undefined"
#endif
#ifndef j_sql_finalize
#error "j_sql_finalize undefined"
#endif
#ifndef j_sql_loop
#error "j_sql_loop undefined"
#endif
#ifndef j_sql_prepare
#error "j_sql_prepare undefined"
#endif
#ifndef j_sql_reset
#error "j_sql_reset undefined"
#endif
#ifndef j_sql_reset_constraint
#error "j_sql_reset_constraint undefined"
#endif
#ifndef j_sql_statement_type
#error "j_sql_statement_type undefined"
#endif
#ifndef j_sql_step
#error "j_sql_step undefined"
#endif
#ifndef j_sql_step_and_reset_check_done
#error "j_sql_step_and_reset_check_done undefined"
#endif
#ifndef j_sql_step_and_reset_check_done_constraint
#error "j_sql_step_and_reset_check_done_constraint undefined"
#endif
#ifndef j_sql_step_constraint
#error "j_sql_step_constraint undefined"
#endif
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
	j_sql_statement_type stmt;
	guint variables_count;
	GHashTable* variables_index;
	GHashTable* variables_type;
	gboolean initialized;
};
typedef struct JSqlCacheSQLPrepared JSqlCacheSQLPrepared;
struct JSqlBatch
{
	gchar* namespace;
};
typedef struct JSqlBatch JSqlBatch;
static gboolean
backend_batch_start(gchar const* namespace, JSemanticsSafety safety, gpointer* _batch)
{
	JSqlBatch* batch = *_batch = g_slice_new(JSqlBatch);
	batch->namespace = namespace;
	(void)safety;
	return TRUE;
}
static gboolean
backend_batch_execute(gpointer batch)
{
	g_slice_free(JSqlBatch, batch);
	return TRUE;
}
static JSqlCacheNamespaces* cacheNamespaces = NULL;
static j_sql_statement_type stmt_schema_structure_create = NULL;
static j_sql_statement_type stmt_schema_structure_get = NULL;
static j_sql_statement_type stmt_schema_structure_delete = NULL;
static j_sql_statement_type stmt_transaction_abort = NULL;
static j_sql_statement_type stmt_transaction_begin = NULL;
static j_sql_statement_type stmt_transaction_commit = NULL;
#define j_sql_transaction_begin() j_sql_step_and_reset_check_done(stmt_transaction_begin)
#define j_sql_transaction_commit() j_sql_step_and_reset_check_done(stmt_transaction_commit)
#define j_sql_transaction_abort() j_sql_step_and_reset_check_done(stmt_transaction_abort)
#define j_goto_error(val)                            \
	do                                           \
	{                                            \
		if (val)                             \
		{                                    \
			J_DEBUG("goto error %d", 0); \
			goto error;                  \
		}                                    \
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
error:;
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
	JSqlCacheNames* cacheNames = NULL;
	if (!cacheNamespaces)
		return;
	cacheNames = g_hash_table_lookup(cacheNamespaces->namespaces, namespace);
	if (!cacheNames)
		return;
	g_hash_table_remove(cacheNames->names, name);
}
static gboolean
init_sql(void)
{
	j_sql_exec_or_error(
		"CREATE TABLE IF NOT EXISTS schema_structure ("
		"namespace TEXT,"
		"name TEXT,"
		"value TEXT,"
		"PRIMARY KEY (namespace, name)"
		")",
		j_sql_done);
	j_sql_prepare("INSERT INTO schema_structure(namespace, name, value) VALUES (?1, ?2, ?3)", &stmt_schema_structure_create);
	j_sql_prepare("SELECT value FROM schema_structure WHERE namespace=?1 AND name=?2", &stmt_schema_structure_get);
	j_sql_prepare("DELETE FROM schema_structure WHERE namespace=?1 AND name=?2", &stmt_schema_structure_delete);
	j_sql_prepare("BEGIN TRANSACTION", &stmt_transaction_begin);
	j_sql_prepare("COMMIT", &stmt_transaction_commit);
	j_sql_prepare("ROLLBACK", &stmt_transaction_abort);
	return TRUE;
error:
	return FALSE;
}
static void
fini_sql(void)
{
	freeJSqlCacheNamespaces(cacheNamespaces);
	j_sql_finalize(stmt_schema_structure_create);
	j_sql_finalize(stmt_schema_structure_get);
	j_sql_finalize(stmt_schema_structure_delete);
	j_sql_finalize(stmt_transaction_abort);
	j_sql_finalize(stmt_transaction_begin);
	j_sql_finalize(stmt_transaction_commit);
error:;
}
static gboolean
backend_schema_create(gpointer _batch, gchar const* name, bson_t const* schema)
{
	JSqlBatch* batch = _batch;
	bson_iter_t iter;
	bson_iter_t iter_child;
	bson_iter_t iter_child2;
	JSMDType type;
	gboolean first;
	guint i;
	gint ret;
	guint counter = 0;
	gboolean found_index = FALSE;
	char* json = NULL;
	GString* sql = g_string_new(NULL);
	j_sql_transaction_begin();
	g_string_append_printf(sql, "CREATE TABLE %s_%s ( _id INTEGER PRIMARY KEY", batch->namespace, name);
	if (bson_iter_init(&iter, schema))
	{
		while (bson_iter_next(&iter))
		{
			if (!g_strcmp0(bson_iter_key(&iter), "_index"))
			{
				found_index = TRUE;
			}
			else
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
	}
	else
		j_goto_error(TRUE);
	g_string_append(sql, " )");
	j_goto_error(!counter);
	json = bson_as_json(schema, NULL);
	j_sql_bind_text(stmt_schema_structure_create, 1, batch->namespace, -1);
	j_sql_bind_text(stmt_schema_structure_create, 2, name, -1);
	j_sql_bind_text(stmt_schema_structure_create, 3, json, -1);
	j_sql_step_and_reset_check_done_constraint(stmt_schema_structure_create);
	J_DEBUG("%s", sql->str);
	j_sql_exec_or_error(sql->str, j_sql_done);
	bson_free(json);
	g_string_free(sql, TRUE);
	if (found_index)
	{
		i = 0;
		if (bson_iter_init(&iter, schema))
		{
			ret = bson_iter_find(&iter, "_arr");
			j_goto_error(!ret);
			ret = BSON_ITER_HOLDS_ARRAY(&iter);
			j_goto_error(!ret);
			ret = bson_iter_recurse(&iter, &iter_child);
			j_goto_error(!ret);
			while (bson_iter_next(&iter_child))
			{
				sql = g_string_new(NULL);
				first = TRUE;
				g_string_append_printf(sql, "CREATE INDEX %s_%s_%d ON %s_%s ( ", batch->namespace, name, i, batch->namespace, name);
				ret = BSON_ITER_HOLDS_ARRAY(&iter_child);
				j_goto_error(!ret);
				ret = bson_iter_recurse(&iter_child, &iter_child2);
				j_goto_error(!ret);
				while (bson_iter_next(&iter_child2))
				{
					if (first)
					{
						first = FALSE;
					}
					else
					{
						g_string_append(sql, ", ");
					}
					g_string_append_printf(sql, "%s", bson_iter_utf8(&iter_child2, NULL));
				}
				g_string_append(sql, " )");
				j_sql_exec_or_error(sql->str, j_sql_done);
				g_string_free(sql, TRUE);
				i++;
			}
		}
		else
			j_goto_error(TRUE);
	}
	j_sql_transaction_commit();
	return TRUE;
error:
constraint:
	j_sql_transaction_abort();
	bson_free(json);
	g_string_free(sql, TRUE);
	return FALSE;
}
static gboolean
backend_schema_get(gpointer _batch, gchar const* name, bson_t* schema)
{
	JSqlBatch* batch = _batch;
	gint retsql;
	guint ret = FALSE;
	const char* json = NULL;
	j_sql_bind_text(stmt_schema_structure_get, 1, batch->namespace, -1);
	j_sql_bind_text(stmt_schema_structure_get, 2, name, -1);
	j_sql_step(stmt_schema_structure_get, retsql)
	{
		if (schema)
		{
			json = j_sql_column_text(stmt_schema_structure_get, 0);
			j_goto_error(json == NULL);
			j_goto_error(!strlen(json));
			bson_init_from_json(schema, json, -1, NULL);
		}
		ret = TRUE;
	}
	j_sql_reset(stmt_schema_structure_get);
	J_DEBUG("ret %d", ret);
	return ret;
error:
	j_sql_reset(stmt_schema_structure_get);
	J_DEBUG("ret %d", FALSE);
	return FALSE;
}
static gboolean
backend_schema_delete(gpointer _batch, gchar const* name)
{
	JSqlBatch* batch = _batch;
	GString* sql = g_string_new(NULL);
	gint ret;
	deleteCachePrepared(batch->namespace, name);
	j_sql_transaction_begin();
	ret = backend_schema_get(batch->namespace, name, NULL);
	j_goto_error(!ret);
	g_string_append_printf(sql, "DROP TABLE %s_%s", batch->namespace, name);
	j_sql_bind_text(stmt_schema_structure_delete, 1, batch->namespace, -1);
	j_sql_bind_text(stmt_schema_structure_delete, 2, name, -1);
	j_sql_step_and_reset_check_done(stmt_schema_structure_delete);
	J_DEBUG("%s", sql->str);
	j_sql_exec_or_error(sql->str, j_sql_done);
	j_sql_transaction_commit();
	g_string_free(sql, TRUE);
	return TRUE;
error:
	j_sql_transaction_abort();
	g_string_free(sql, TRUE);
	return false;
}
static gboolean
insert_helper(JSqlCacheSQLPrepared* prepared, bson_iter_t* iter)
{
	bson_type_t type;
	guint i;
	guint index;
	guint count = 0;
	for (i = 0; i < prepared->variables_count; i++)
		j_sql_bind_null(prepared->stmt, i + 1);
	while (bson_iter_next(iter))
	{
		type = bson_iter_type(iter);
		J_DEBUG("%s", bson_iter_key(iter));
		index = GPOINTER_TO_INT(g_hash_table_lookup(prepared->variables_index, bson_iter_key(iter)));
		j_goto_error(!index);
		switch (type)
		{
		case BSON_TYPE_DOUBLE:
			count++;
			j_sql_bind_double(prepared->stmt, index, bson_iter_double(iter));
			break;
		case BSON_TYPE_UTF8:
			count++;
			j_sql_bind_text(prepared->stmt, index, bson_iter_utf8(iter, NULL), -1);
			break;
		case BSON_TYPE_INT32:
			count++;
			j_sql_bind_int(prepared->stmt, index, bson_iter_int32(iter));
			break;
		case BSON_TYPE_INT64:
			count++;
			j_sql_bind_int64(prepared->stmt, index, bson_iter_int64(iter));
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
	j_goto_error(!count);
	j_sql_step_and_reset_check_done_constraint(prepared->stmt);
	return TRUE;
constraint:
error:
	return FALSE;
}
static gboolean
backend_insert(gpointer _batch, gchar const* name, bson_t const* metadata)
{
	JSqlBatch* batch = _batch;
	guint i;
	guint ret;
	bson_iter_t iter;
	bson_iter_t iter_child;
	bson_iter_t iter_child2;
	bson_t* schema = NULL;
	gboolean schema_initialized = FALSE;
	JSqlCacheSQLPrepared* prepared = NULL;
	j_sql_transaction_begin();
	j_goto_error(!metadata);
	j_goto_error(!bson_count_keys(metadata));
	prepared = getCachePrepared(batch->namespace, name, "insert");
	j_goto_error(!prepared);
	if (!prepared->initialized)
	{
		schema = g_new0(bson_t, 1);
		schema_initialized = backend_schema_get(batch->namespace, name, schema);
		j_goto_error(!schema_initialized);
		prepared->sql = g_string_new(NULL);
		prepared->variables_count = 0;
		prepared->variables_index = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
		g_string_append_printf(prepared->sql, "INSERT INTO %s_%s (", batch->namespace, name);
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
	ret = bson_iter_init(&iter, metadata);
	j_goto_error(!ret);
	if ((bson_count_keys(metadata) == 1) && bson_iter_find(&iter, "_arr") && BSON_ITER_HOLDS_ARRAY(&iter) && bson_iter_recurse(&iter, &iter_child))
	{
		while (bson_iter_next(&iter_child))
		{
			ret = BSON_ITER_HOLDS_DOCUMENT(&iter_child);
			j_goto_error(!ret);
			ret = bson_iter_recurse(&iter_child, &iter_child2);
			j_goto_error(!ret);
			ret = insert_helper(prepared, &iter_child2);
			j_goto_error(!ret);
		}
	}
	else
	{
		bson_iter_init(&iter, metadata);
		ret = insert_helper(prepared, &iter);
		j_goto_error(!ret);
	}
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
				if (BSON_ITER_HOLDS_INT32(&iterchild))
				{
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
				else
				{
					j_goto_error(TRUE);
				}
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
backend_query(gpointer _batch, gchar const* name, bson_t const* selector, gpointer* iterator)
{
	JSqlBatch* batch = _batch;
	guint64 tmp;
	gint ret;
	guint count = 0;
	bson_iter_t iter;
	guint variables_count;
	JSqlCacheSQLPrepared* prepared = NULL;
	GString* sql = g_string_new(NULL);
	JSMDIterator* iteratorOut;
	*iterator = NULL;
	iteratorOut = g_new(JSMDIterator, 1);
	iteratorOut->namespace = g_strdup(batch->namespace);
	iteratorOut->name = g_strdup(name);
	iteratorOut->index = 0;
	iteratorOut->arr = g_array_new(FALSE, FALSE, sizeof(guint64));
	g_string_append_printf(sql, "SELECT DISTINCT _id FROM %s_%s", batch->namespace, name);
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
	prepared = getCachePrepared(batch->namespace, name, sql->str);
	j_goto_error(!prepared);
	if (!prepared->initialized)
	{
		ret = backend_schema_get(batch->namespace, name, NULL);
		j_goto_error(!ret);
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
		tmp = j_sql_column_uint64(prepared->stmt, 0);
		g_array_append_val(iteratorOut->arr, tmp);
		J_DEBUG("index = %ld", tmp);
	}
	j_sql_reset(prepared->stmt);
	j_goto_error(!count);
	g_string_free(sql, TRUE);
	*iterator = iteratorOut;
	return TRUE;
error:
	g_string_free(sql, TRUE);
	freeJSMDIterator(iteratorOut);
	return FALSE;
}
static gboolean
backend_update(gpointer _batch, gchar const* name, bson_t const* selector, bson_t const* metadata)
{
	JSqlBatch* batch = _batch;
	guint count;
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
	j_goto_error(!selector);
	j_goto_error(!bson_count_keys(selector));
	j_goto_error(!metadata);
	prepared = getCachePrepared(batch->namespace, name, "update");
	j_goto_error(!prepared);
	if (!prepared->initialized)
	{
		schema = g_new0(bson_t, 1);
		schema_initialized = backend_schema_get(batch->namespace, name, schema);
		j_goto_error(!schema_initialized);
		prepared->sql = g_string_new(NULL);
		prepared->variables_count = 0;
		prepared->variables_index = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
		g_string_append_printf(prepared->sql, "UPDATE %s_%s SET ", batch->namespace, name);
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
	ret = backend_query(batch->namespace, name, selector, (gpointer*)&iterator);
	j_goto_error(!ret);
	for (j = 0; j < iterator->arr->len; j++)
	{
		count = 0;
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
					count++;
					j_sql_bind_double(prepared->stmt, index, bson_iter_double(&iter));
					break;
				case BSON_TYPE_UTF8:
					count++;
					j_sql_bind_text(prepared->stmt, index, bson_iter_utf8(&iter, NULL), -1);
					break;
				case BSON_TYPE_INT32:
					count++;
					j_sql_bind_int(prepared->stmt, index, bson_iter_int32(&iter));
					break;
				case BSON_TYPE_INT64:
					count++;
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
		j_goto_error(!count);
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
backend_delete(gpointer _batch, gchar const* name, bson_t const* selector)
{
	JSqlBatch* batch = _batch;
	JSMDIterator* iterator = NULL;
	guint j;
	gint ret;
	JSqlCacheSQLPrepared* prepared = NULL;
	j_sql_transaction_begin();
	ret = backend_query(batch->namespace, name, selector, (gpointer*)&iterator);
	j_goto_error(!ret);
	prepared = getCachePrepared(batch->namespace, name, "delete");
	j_goto_error(!prepared);
	if (!prepared->initialized)
	{
		prepared->sql = g_string_new(NULL);
		prepared->variables_count = 1;
		g_string_append_printf(prepared->sql, "DELETE FROM %s_%s WHERE _id = ?1", batch->namespace, name);
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
	J_DEBUG("index = %ld", index);
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
				ret = bson_append_int32(metadata, name, -1, j_sql_column_sint32(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_UINT32:
				ret = bson_append_int32(metadata, name, -1, j_sql_column_uint32(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_FLOAT32:
				ret = bson_append_double(metadata, name, -1, j_sql_column_float32(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_SINT64:
				ret = bson_append_int64(metadata, name, -1, j_sql_column_sint64(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_UINT64:
				ret = bson_append_int64(metadata, name, -1, j_sql_column_uint64(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_FLOAT64:
				ret = bson_append_double(metadata, name, -1, j_sql_column_float64(prepared->stmt, i));
				j_goto_error(!ret);
				break;
			case J_SMD_TYPE_STRING:
				ret = bson_append_utf8(metadata, name, -1, j_sql_column_text(prepared->stmt, i), -1);
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
#endif
