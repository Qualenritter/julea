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

#include <mysql.h>

#include <julea.h>
#include <julea-db.h>

#include "jbson.c"

#define MAX_BUF_SIZE 4096

#define SQL_MODE_SINGLE_THREAD 0
#define SQL_MODE_MULTI_THREAD 1
#define SQL_MODE SQL_MODE_MULTI_THREAD

#define sql_autoincrement_string "NOT NULL AUTO_INCREMENT"

static gchar* path;
struct mysql_stmt_wrapper
{
	MYSQL_STMT* stmt;
	MYSQL_BIND* bind_in; //input
	MYSQL_BIND* bind_out; //output
	JDBTypeValue* buffer; //reused for in AND out
	bool* is_null; //reused for in AND out
	bool* is_error; //reused for in AND out
	unsigned long* length; //output
	gboolean active;
	guint param_count_in;
	guint param_count_out;
	guint param_count_total;
};
typedef struct mysql_stmt_wrapper mysql_stmt_wrapper;

static gboolean
j_sql_finalize(MYSQL* backend_db, void* _stmt, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	guint i;
	gint status;
	mysql_stmt_wrapper* wrapper = _stmt;

	//g_debug("%s %p", G_STRFUNC, wrapper);

	(void)backend_db;
	(void)error;

	if ((status = mysql_stmt_close(wrapper->stmt)))
	{
		g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_FINALIZE, "sql finalize failed error was  (%d):'%s'", status, mysql_stmt_error(wrapper->stmt));
		goto _error;
	}
	for (i = 0; i < wrapper->param_count_out; i++)
	{
		if (wrapper->bind_out[i].buffer_type == MYSQL_TYPE_STRING)
			g_free(wrapper->bind_out[i].buffer);
		if (wrapper->bind_out[i].buffer_type == MYSQL_TYPE_BLOB)
			g_free(wrapper->bind_out[i].buffer);
	}
	g_free(wrapper->bind_in);
	g_free(wrapper->bind_out);
	g_free(wrapper->buffer);
	g_free(wrapper->is_null);
	g_free(wrapper->is_error);
	g_free(wrapper->length);
	g_free(wrapper);
	return TRUE;
_error:
	return FALSE;
}

static gboolean
j_sql_prepare(MYSQL* backend_db, const char* sql, void* _stmt, GArray* types_in, GArray* types_out, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	guint i;
	JDBType type;
	gint status;
	mysql_stmt_wrapper** _wrapper = _stmt;
	mysql_stmt_wrapper* wrapper;

	wrapper = *_wrapper = g_new0(mysql_stmt_wrapper, 1);
	//g_debug("%s %p %s", G_STRFUNC, wrapper, sql);
	if (!(wrapper->stmt = mysql_stmt_init(backend_db)))
	{
		g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_PREPARE, "sql prepare failed error was '%s'", mysql_stmt_error(wrapper->stmt));
		goto _error;
	}
	if ((status = mysql_stmt_prepare(wrapper->stmt, sql, strlen(sql))))
	{
		g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_PREPARE, "sql prepare failed error was (%d):'%s'", status, mysql_stmt_error(wrapper->stmt));
		goto _error;
	}
	wrapper->param_count_in = types_in ? types_in->len : 0;
	wrapper->param_count_out = types_out ? types_out->len : 0;
	wrapper->param_count_total = wrapper->param_count_in > wrapper->param_count_out ? wrapper->param_count_in : wrapper->param_count_out;
	wrapper->bind_in = g_new0(MYSQL_BIND, wrapper->param_count_in);
	wrapper->bind_out = g_new0(MYSQL_BIND, wrapper->param_count_out);
	wrapper->buffer = g_new0(JDBTypeValue, wrapper->param_count_total);
	wrapper->is_null = g_new0(bool, wrapper->param_count_total);
	wrapper->is_error = g_new0(bool, wrapper->param_count_total);
	wrapper->length = g_new0(unsigned long, wrapper->param_count_total);
	wrapper->active = FALSE;
	for (i = 0; i < wrapper->param_count_in; i++)
	{
		wrapper->bind_in[i].is_null = &wrapper->is_null[i];
		wrapper->bind_in[i].error = &wrapper->is_error[i];
		type = g_array_index(types_in, JDBType, i);
		switch (type)
		{
		case J_DB_TYPE_SINT32:
			//g_debug("param_type_in[%d]=J_DB_TYPE_SINT32", i);
			wrapper->bind_in[i].buffer_type = MYSQL_TYPE_LONG;
			wrapper->bind_in[i].is_unsigned = 0;
			wrapper->bind_in[i].buffer = &wrapper->buffer[i].val_sint32;
			break;
		case J_DB_TYPE_UINT32:
			//g_debug("param_type_in[%d]=J_DB_TYPE_UINT32", i);
			wrapper->bind_in[i].buffer_type = MYSQL_TYPE_LONG;
			wrapper->bind_in[i].is_unsigned = 1;
			wrapper->bind_in[i].buffer = &wrapper->buffer[i].val_uint32;
			break;
		case J_DB_TYPE_SINT64:
			//g_debug("param_type_in[%d]=J_DB_TYPE_SINT64", i);
			wrapper->bind_in[i].buffer_type = MYSQL_TYPE_LONGLONG;
			wrapper->bind_in[i].is_unsigned = 0;
			wrapper->bind_in[i].buffer = &wrapper->buffer[i].val_sint64;
			break;
		case J_DB_TYPE_UINT64:
			//g_debug("param_type_in[%d]=J_DB_TYPE_UINT64", i);
			wrapper->bind_in[i].buffer_type = MYSQL_TYPE_LONGLONG;
			wrapper->bind_in[i].is_unsigned = 1;
			wrapper->bind_in[i].buffer = &wrapper->buffer[i].val_uint64;
			break;
		case J_DB_TYPE_FLOAT32:
			//g_debug("param_type_in[%d]=J_DB_TYPE_FLOAT32", i);
			wrapper->bind_in[i].buffer_type = MYSQL_TYPE_FLOAT;
			wrapper->bind_in[i].buffer = &wrapper->buffer[i].val_float32;
			break;
		case J_DB_TYPE_FLOAT64:
			//g_debug("param_type_in[%d]=J_DB_TYPE_FLOAT64", i);
			wrapper->bind_in[i].buffer_type = MYSQL_TYPE_DOUBLE;
			wrapper->bind_in[i].buffer = &wrapper->buffer[i].val_sint64;
			break;
		case J_DB_TYPE_STRING:
			//g_debug("param_type_in[%d]=J_DB_TYPE_STRING", i);
			wrapper->bind_in[i].buffer_type = MYSQL_TYPE_STRING;
			wrapper->bind_in[i].buffer = &wrapper->buffer[i].val_string;
			break;
		case J_DB_TYPE_BLOB:
			//g_debug("param_type_in[%d]=J_DB_TYPE_BLOB", i);
			wrapper->bind_in[i].buffer_type = MYSQL_TYPE_BLOB;
			wrapper->bind_in[i].buffer = &wrapper->buffer[i].val_blob;
			wrapper->bind_in[i].buffer_length = wrapper->buffer[i].val_blob_length;
			break;
		case J_DB_TYPE_ID:
		case _J_DB_TYPE_COUNT:
		default:
			g_set_error_literal(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_INVALID_TYPE, "sql invalid type");
			goto _error;
		}
	}
	for (i = 0; i < wrapper->param_count_out; i++)
	{
		wrapper->bind_out[i].is_null = &wrapper->is_null[i];
		wrapper->bind_out[i].error = &wrapper->is_error[i];
		wrapper->bind_out[i].length = &wrapper->length[i];
		type = g_array_index(types_out, JDBType, i);
		switch (type)
		{
		case J_DB_TYPE_SINT32:
			//g_debug("param_type_out[%d]=J_DB_TYPE_SINT32", i);
			wrapper->bind_out[i].buffer_type = MYSQL_TYPE_LONG;
			wrapper->bind_out[i].is_unsigned = 0;
			wrapper->bind_out[i].buffer = &wrapper->buffer[i].val_sint32;
			break;
		case J_DB_TYPE_UINT32:
			//g_debug("param_type_out[%d]=J_DB_TYPE_UINT32", i);
			wrapper->bind_out[i].buffer_type = MYSQL_TYPE_LONG;
			wrapper->bind_out[i].is_unsigned = 1;
			wrapper->bind_out[i].buffer = &wrapper->buffer[i].val_uint32;
			break;
		case J_DB_TYPE_SINT64:
			//g_debug("param_type_out[%d]=J_DB_TYPE_SINT64", i);
			wrapper->bind_out[i].buffer_type = MYSQL_TYPE_LONGLONG;
			wrapper->bind_out[i].is_unsigned = 0;
			wrapper->bind_out[i].buffer = &wrapper->buffer[i].val_sint64;
			break;
		case J_DB_TYPE_UINT64:
			//g_debug("param_type_out[%d]=J_DB_TYPE_UINT64", i);
			wrapper->bind_out[i].buffer_type = MYSQL_TYPE_LONGLONG;
			wrapper->bind_out[i].is_unsigned = 1;
			wrapper->bind_out[i].buffer = &wrapper->buffer[i].val_uint64;
			break;
		case J_DB_TYPE_FLOAT32:
			//g_debug("param_type_out[%d]=J_DB_TYPE_FLOAT32", i);
			wrapper->bind_out[i].buffer_type = MYSQL_TYPE_FLOAT;
			wrapper->bind_out[i].buffer = &wrapper->buffer[i].val_float32;
			break;
		case J_DB_TYPE_FLOAT64:
			//g_debug("param_type_out[%d]=J_DB_TYPE_FLOAT64", i);
			wrapper->bind_out[i].buffer_type = MYSQL_TYPE_DOUBLE;
			wrapper->bind_out[i].buffer = &wrapper->buffer[i].val_sint64;
			break;
		case J_DB_TYPE_STRING:
			//g_debug("param_type_out[%d]=J_DB_TYPE_STRING", i);
			wrapper->bind_out[i].buffer_type = MYSQL_TYPE_STRING;
			wrapper->bind_out[i].buffer_length = MAX_BUF_SIZE;
			wrapper->bind_out[i].buffer = g_new(char, MAX_BUF_SIZE);
			break;
		case J_DB_TYPE_BLOB:
			//g_debug("param_type_out[%d]=J_DB_TYPE_BLOB", i);
			wrapper->bind_out[i].buffer_type = MYSQL_TYPE_BLOB;
			wrapper->bind_out[i].buffer_length = MAX_BUF_SIZE;
			wrapper->bind_out[i].buffer = g_new(char, MAX_BUF_SIZE);
			break;
		case J_DB_TYPE_ID:
		case _J_DB_TYPE_COUNT:
		default:
			g_set_error_literal(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_INVALID_TYPE, "sql invalid type");
			goto _error;
		}
	}
	return TRUE;
_error:
	j_sql_finalize(backend_db, wrapper, NULL);
	return FALSE;
}

static gboolean
j_sql_bind_null(MYSQL* backend_db, void* _stmt, guint idx, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	mysql_stmt_wrapper* wrapper = _stmt;

	//g_debug("%s %p", G_STRFUNC, wrapper);
	(void)backend_db;
	(void)error;
	idx--; //sqlite index start with 1, mysql index start with 0
	wrapper->is_null[idx] = 1;

	return TRUE;
}

static gboolean
j_sql_column(MYSQL* backend_db, void* _stmt, guint idx, JDBType type, JDBTypeValue* value, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	mysql_stmt_wrapper* wrapper = _stmt;
	//g_debug("%s %p", G_STRFUNC, wrapper);
	(void)backend_db;
	memset(value, 0, sizeof(*value));
	switch (type)
	{
	case J_DB_TYPE_SINT32:
		value->val_sint32 = wrapper->buffer[idx].val_sint32;
		break;
	case J_DB_TYPE_UINT32:
		value->val_uint32 = wrapper->buffer[idx].val_uint32;
		break;
	case J_DB_TYPE_SINT64:
		value->val_sint64 = wrapper->buffer[idx].val_sint64;
		break;
	case J_DB_TYPE_UINT64:
		value->val_uint64 = wrapper->buffer[idx].val_uint64;
		break;
	case J_DB_TYPE_FLOAT32:
		value->val_float32 = wrapper->buffer[idx].val_float32;
		break;
	case J_DB_TYPE_FLOAT64:
		value->val_float64 = wrapper->buffer[idx].val_float64;
		break;
	case J_DB_TYPE_STRING:
		value->val_string = wrapper->bind_out[idx].buffer;
		break;
	case J_DB_TYPE_BLOB:
		value->val_blob = wrapper->bind_out[idx].buffer;
		value->val_blob_length = wrapper->length[idx];
		break;
	case J_DB_TYPE_ID:
	case _J_DB_TYPE_COUNT:
	default:
		g_set_error_literal(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_INVALID_TYPE, "sql invalid type");
		goto _error;
	}
	return TRUE;
_error:
	return FALSE;
}

static gboolean
j_sql_bind_value(MYSQL* backend_db, void* _stmt, guint idx, JDBType type, JDBTypeValue* value, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	mysql_stmt_wrapper* wrapper = _stmt;

	(void)backend_db;
	idx--; //sqlite index start with 1, mysql index start with 0
	wrapper->is_null[idx] = 0;
	//g_debug("%s %p", G_STRFUNC, wrapper);

	switch (type)
	{
	case J_DB_TYPE_SINT32:
		//g_debug("bind_param [%d]= %d", idx, value->val_sint32);
		wrapper->buffer[idx].val_sint32 = value->val_sint32;
		break;
	case J_DB_TYPE_UINT32:
		//g_debug("bind_param [%d]= %d", idx, value->val_uint32);
		wrapper->buffer[idx].val_uint32 = value->val_uint32;
		break;
	case J_DB_TYPE_SINT64:
		//g_debug("bind_param [%d]= %lld", idx, value->val_sint64);
		wrapper->buffer[idx].val_sint64 = value->val_sint64;
		break;
	case J_DB_TYPE_UINT64:
		//g_debug("bind_param [%d]= %lld", idx, value->val_uint64);
		wrapper->buffer[idx].val_uint64 = value->val_uint64;
		break;
	case J_DB_TYPE_FLOAT32:
		//g_debug("bind_param [%d]= %f", idx, value->val_float32);
		wrapper->buffer[idx].val_float32 = value->val_float32;
		break;
	case J_DB_TYPE_FLOAT64:
		//g_debug("bind_param [%d]= %f", idx, value->val_float64);
		wrapper->buffer[idx].val_float64 = value->val_float64;
		break;
	case J_DB_TYPE_STRING:
		//g_debug("bind_param [%d]= %s", idx, value->val_string);
		wrapper->is_null[idx] = value->val_string == NULL;
		wrapper->bind_in[idx].buffer = value->val_string;
		wrapper->bind_in[idx].buffer_length = value->val_string != 0 ? strlen(value->val_string) : 0;
		wrapper->length[idx] = wrapper->bind_in[idx].buffer_length;
		break;
	case J_DB_TYPE_BLOB:
		//g_debug("bind_param [%d]= %p", idx, value->val_blob);
		wrapper->is_null[idx] = value->val_blob == NULL;
		wrapper->bind_in[idx].buffer = value->val_blob;
		wrapper->bind_in[idx].buffer_length = value->val_blob_length;
		wrapper->length[idx] = wrapper->bind_in[idx].buffer_length;
		break;
	case J_DB_TYPE_ID:
	case _J_DB_TYPE_COUNT:
	default:
		g_set_error_literal(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_INVALID_TYPE, "sql invalid type");
		goto _error;
	}
	return TRUE;
_error:
	return FALSE;
}
static gboolean
j_sql_reset(MYSQL* backend_db, void* _stmt, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	mysql_stmt_wrapper* wrapper = _stmt;
	//g_debug("%s %p", G_STRFUNC, wrapper);
	(void)backend_db;
	(void)error;
	wrapper->active = FALSE;

	return TRUE;
}

static gboolean
j_sql_exec(MYSQL* backend_db, const char* sql, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	mysql_stmt_wrapper* stmt;
	gint status;
	//g_debug("%s", G_STRFUNC);
	(void)backend_db;
	(void)error;
	if (G_UNLIKELY(!j_sql_prepare(backend_db, sql, &stmt, NULL, NULL, error)))
	{
		goto _error;
	}
	if ((status = mysql_stmt_execute(stmt->stmt)))
	{
		g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_STEP, "sql step failed error was  (%d):'%s'", status, mysql_stmt_error(stmt->stmt));
		goto _error;
	}
	if (G_UNLIKELY(!j_sql_finalize(backend_db, stmt, error)))
	{
		goto _error2;
	}
	return TRUE;
_error:
	if (G_UNLIKELY(!j_sql_finalize(backend_db, stmt, NULL)))
	{
		goto _error2;
	}
	return FALSE;
_error2:
	/*something failed very hard*/
	return FALSE;
}
static gboolean
j_sql_step(MYSQL* backend_db, void* _stmt, gboolean* found, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	mysql_stmt_wrapper* wrapper = _stmt;
	gint status;
	//g_debug("%s %p", G_STRFUNC, wrapper);
	(void)backend_db;
	(void)error;
	if (!wrapper->active)
	{
		if (wrapper->param_count_in)
			if ((status = mysql_stmt_bind_param(wrapper->stmt, wrapper->bind_in)))
			{
				g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_STEP, "sql step failed error was  (%d):'%s'", status, mysql_stmt_error(wrapper->stmt));
				goto _error;
			}
		if (wrapper->param_count_out)
			if ((status = mysql_stmt_bind_result(wrapper->stmt, wrapper->bind_out)))
			{
				g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_STEP, "sql step failed error was  (%d):'%s'", status, mysql_stmt_error(wrapper->stmt));
				goto _error;
			}
		if ((status = mysql_stmt_execute(wrapper->stmt)))
		{
			g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_STEP, "sql step failed error was  (%d):'%s'", status, mysql_stmt_error(wrapper->stmt));
			goto _error;
		}
		if (wrapper->param_count_out)
			if ((status = mysql_stmt_store_result(wrapper->stmt)))
			{
				g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_STEP, "sql step failed error was  (%d):'%s'", status, mysql_stmt_error(wrapper->stmt));
				goto _error;
			}
		wrapper->active = TRUE;
	}
	if (wrapper->param_count_out)
		*found = mysql_stmt_fetch(wrapper->stmt) == 0;
	else
		*found = TRUE;
	return TRUE;
_error:
	return FALSE;
}
static gboolean
j_sql_step_and_reset_check_done(MYSQL* backend_db, void* _stmt, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	gboolean sql_found;
	//g_debug("%s %p", G_STRFUNC, _stmt);
	if (G_UNLIKELY(!j_sql_step(backend_db, _stmt, &sql_found, error)))
	{
		goto _error;
	}
	if (G_UNLIKELY(!j_sql_reset(backend_db, _stmt, error)))
	{
		goto _error;
	}
	return TRUE;
_error:
	if (G_UNLIKELY(!j_sql_reset(backend_db, _stmt, NULL)))
	{
		goto _error2;
	}
	return FALSE;
_error2:
	/*something failed very hard*/
	return FALSE;
}
static void*
j_sql_open(void)
{
	J_TRACE_FUNCTION(NULL);

	MYSQL* backend_db = NULL;
	g_autofree gchar* dirname = NULL;

	g_return_val_if_fail(path != NULL, FALSE);
	//g_debug("%s", G_STRFUNC);
	if (!(backend_db = mysql_init(NULL)))
		goto _error;

	//FIXME use the path variable
	if (!mysql_real_connect(backend_db,
		    "localhost", //hostname
		    "root", //username
		    "1234", //password
		    "julea", //database name
		    3306, //port number
		    "/var/run/mysqld/mysqld.sock", //unix socket
		    CLIENT_OPTIONAL_RESULTSET_METADATA //client flags
		    ))
	{
		//g_debug("%s", mysql_error(backend_db));
		goto _error;
	}
	return backend_db;
_error:
	mysql_close(backend_db);
	return NULL;
}
static void
j_sql_close(MYSQL* backend_db)
{
	J_TRACE_FUNCTION(NULL);
	//g_debug("%s", G_STRFUNC);
	mysql_close(backend_db);
}
static gboolean
j_sql_start_transaction(MYSQL* backend_db, GError** error)
{
	mysql_query(backend_db, "START TRANSACTION");
	return TRUE;
}
static gboolean
j_sql_commit_transaction(MYSQL* backend_db, GError** error)
{
	mysql_query(backend_db, "COMMIT");
	return TRUE;
}
static gboolean
j_sql_abort_transaction(MYSQL* backend_db, GError** error)
{
	mysql_query(backend_db, "ROLLBACK");
	return TRUE;
}
#include "sql-generic.c"
static gboolean
backend_init(gchar const* _path)
{
	J_TRACE_FUNCTION(NULL);

	//g_debug("db-backend-init %s", _path);

	path = g_strdup(_path);
	return TRUE;
}
static void
backend_fini(void)
{
	J_TRACE_FUNCTION(NULL);

	//g_debug("db-backend-fini");
	g_private_replace(&thread_variables_global, NULL);
	g_free(path);
}
static JBackend mysql_backend = {
	.type = J_BACKEND_TYPE_DB,
	.component = J_BACKEND_COMPONENT_SERVER | J_BACKEND_COMPONENT_CLIENT,
	.db = {
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
		.backend_batch_start = backend_batch_start,
		.backend_batch_execute = backend_batch_execute,
	},
};

G_MODULE_EXPORT
JBackend*
backend_info(void)
{
	return &mysql_backend;
}
