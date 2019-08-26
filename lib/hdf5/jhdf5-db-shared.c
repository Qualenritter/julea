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
#ifndef JULEA_DB_HDF5_SHARED_C
#define JULEA_DB_HDF5_SHARED_C
#include <julea-config.h>
#include <julea.h>
#include <julea-db.h>
#include <julea-object.h>
#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"

#include "jhdf5-db.h"

#define _GNU_SOURCE

#define JULEA_DB 530

static char*
H5VL_julea_db_buf_to_hex(const char* prefix, const char* buf, guint buf_len)
{
	J_TRACE_FUNCTION(NULL);

	const guint prefix_len = strlen(prefix);
	char* str = g_new(char, buf_len * 2 + 1 + prefix_len);
	unsigned const char* pin = (unsigned const char*)buf;
	unsigned const char* pin_end = pin + buf_len;
	const char* hex = "0123456789ABCDEF";
	char* pout = str;

	memcpy(str, prefix, prefix_len);
	pout += prefix_len;
	while (pin < pin_end)
	{
		*pout++ = hex[(*pin >> 4) & 0xF];
		*pout++ = hex[(*pin++) & 0xF];
	}
	*pout = 0;
	return str;
}

static void
H5VL_julea_db_error_handler(GError* error)
{
	J_TRACE_FUNCTION(NULL);

	if (error)
	{
		g_debug("%s %d %s", g_quark_to_string(error->domain), error->code, error->message);
	}
}

static JHDF5Object_t*
H5VL_julea_db_object_ref(JHDF5Object_t* object)
{
	J_TRACE_FUNCTION(NULL);

	g_return_val_if_fail(object != NULL, NULL);

	g_atomic_int_inc(&object->ref_count);
	return object;
}
static JHDF5Object_t*
H5VL_julea_db_object_new(JHDF5ObjectType type)
{
	J_TRACE_FUNCTION(NULL);

	JHDF5Object_t* object;

	g_return_val_if_fail(type < _J_HDF5_OBJECT_TYPE_COUNT, NULL);

	object = g_new0(JHDF5Object_t, 1);
	object->backend_id = NULL;
	object->backend_id_len = 0;
	object->ref_count = 1;
	object->type = type;
	return object;
}
static void
H5VL_julea_db_object_unref(JHDF5Object_t* object)
{
	J_TRACE_FUNCTION(NULL);

	if (object && g_atomic_int_dec_and_test(&object->ref_count))
	{
		switch (object->type)
		{
		case J_HDF5_OBJECT_TYPE_FILE:
			g_free(object->file.name);
			break;
		case J_HDF5_OBJECT_TYPE_DATASET:
			H5VL_julea_db_object_unref(object->dataset.file);
			g_free(object->dataset.name);
			j_distribution_unref(object->dataset.distribution);
			j_distributed_object_unref(object->dataset.object);
			break;
		case J_HDF5_OBJECT_TYPE_ATTR:
			H5VL_julea_db_object_unref(object->attr.file);
			g_free(object->attr.name);
			j_distribution_unref(object->attr.distribution);
			j_distributed_object_unref(object->attr.object);
			break;
		case J_HDF5_OBJECT_TYPE_GROUP:
			H5VL_julea_db_object_unref(object->group.file);
			g_free(object->group.name);
			break;
		case J_HDF5_OBJECT_TYPE_DATATYPE:
			g_free(object->datatype.data);
			break;
		case J_HDF5_OBJECT_TYPE_SPACE:
			g_free(object->space.data);
			break;
		case _J_HDF5_OBJECT_TYPE_COUNT:
		default:
			g_assert_not_reached();
		}
		g_free(object->backend_id);
		g_free(object);
	}
}

#include <sqlite3.h>
#include <sys/types.h>
#include <unistd.h>
static sqlite3* backend_db = NULL;
static gboolean
j_sql_finalize(void* _stmt, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	sqlite3_stmt* stmt = _stmt;

	if (G_UNLIKELY(sqlite3_finalize(stmt) != SQLITE_OK))
	{
		g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_FINALIZE, "sql finalize failed error was '%s'", sqlite3_errmsg(backend_db));
		j_goto_error();
	}
	return TRUE;
_error:
	return FALSE;
}

static gboolean
j_sql_prepare(const char* sql, void* _stmt, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	sqlite3_stmt** stmt = _stmt;

	if (G_UNLIKELY(sqlite3_prepare_v3(backend_db, sql, -1, SQLITE_PREPARE_PERSISTENT, stmt, NULL) != SQLITE_OK))
	{
		g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_PREPARE, "sql prepare failed error was '%s'", sqlite3_errmsg(backend_db));
		j_goto_error();
	}
	return TRUE;
_error:
	j_sql_finalize(*stmt, NULL);
	return FALSE;
}
static gboolean
j_sql_exec(const char* sql, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	sqlite3_stmt* stmt;

	if (G_UNLIKELY(!j_sql_prepare(sql, &stmt, error)))
	{
		j_goto_error();
	}
	if (G_UNLIKELY(sqlite3_step(stmt) != SQLITE_DONE))
	{
		g_debug("%s", sqlite3_errmsg(backend_db));
		g_set_error(error, J_BACKEND_SQL_ERROR, J_BACKEND_SQL_ERROR_STEP, "sql step failed error was '%s'", sqlite3_errmsg(backend_db));
		j_goto_error();
	}
	if (G_UNLIKELY(!j_sql_finalize(stmt, error)))
	{
		j_goto_error();
	}
	return TRUE;
_error:
	if (G_UNLIKELY(!j_sql_finalize(stmt, NULL)))
	{
		goto _error2;
	}
	return FALSE;
_error2:
	/*something failed very hard*/
	return FALSE;
}
enum H5VL_julea_db_timer_func_names
{
	H5VL_julea_db_attr_close_timers = 0,
	H5VL_julea_db_attr_create_timers,
	H5VL_julea_db_attr_get_timers,
	H5VL_julea_db_attr_open_timers,
	H5VL_julea_db_attr_optional_timers,
	H5VL_julea_db_attr_read_timers,
	H5VL_julea_db_attr_specific_timers,
	H5VL_julea_db_attr_write_timers,
	H5VL_julea_db_dataset_close_timers,
	H5VL_julea_db_dataset_create_timers,
	H5VL_julea_db_dataset_get_timers,
	H5VL_julea_db_dataset_open_timers,
	H5VL_julea_db_dataset_optional_timers,
	H5VL_julea_db_dataset_read_timers,
	H5VL_julea_db_dataset_specific_timers,
	H5VL_julea_db_dataset_write_timers,
	H5VL_julea_db_datatype_close_timers,
	H5VL_julea_db_datatype_commit_timers,
	H5VL_julea_db_datatype_get_timers,
	H5VL_julea_db_datatype_open_timers,
	H5VL_julea_db_datatype_optional_timers,
	H5VL_julea_db_datatype_specific_timers,
	H5VL_julea_db_file_close_timers,
	H5VL_julea_db_file_create_timers,
	H5VL_julea_db_file_get_timers,
	H5VL_julea_db_file_open_timers,
	H5VL_julea_db_file_optional_timers,
	H5VL_julea_db_file_specific_timers,
	H5VL_julea_db_group_close_timers,
	H5VL_julea_db_group_create_timers,
	H5VL_julea_db_group_get_timers,
	H5VL_julea_db_group_open_timers,
	H5VL_julea_db_group_optional_timers,
	H5VL_julea_db_group_specific_timers,
	H5VL_julea_db_link_copy_timers,
	H5VL_julea_db_link_create_timers,
	H5VL_julea_db_link_get_timers,
	H5VL_julea_db_link_move_timers,
	H5VL_julea_db_link_optional_timers,
	H5VL_julea_db_link_specific_timers,
	total_timers,
	_H5VL_julea_db_func_count
};
typedef enum H5VL_julea_db_timer_func_names H5VL_julea_db_timer_func_names;
struct H5VL_julea_db_timer
{
	GTimer* timer;
	H5VL_julea_db_timer_func_names func_name;
};
typedef struct H5VL_julea_db_timer H5VL_julea_db_timer;
static H5VL_julea_db_timer*
H5VL_julea_db_timer_new(H5VL_julea_db_timer_func_names func_name)
{
	H5VL_julea_db_timer* timer;
	timer = g_new(H5VL_julea_db_timer, 1);
	timer->timer = g_timer_new();
	timer->func_name = func_name;
	return timer;
}
static gdouble all_timers[_H5VL_julea_db_func_count];
static guint all_timers_counter[_H5VL_julea_db_func_count];
static H5VL_julea_db_timer* global_timer = NULL;
static void
H5VL_julea_db_timer_init(void)
{
	char buf[100];
	if (global_timer)
		return;
	snprintf(buf, sizeof(buf), "%s%d", g_getenv("J_TIMER_DB"), getpid());
	if (G_UNLIKELY(sqlite3_open(buf, &backend_db) != SQLITE_OK))
	{
		j_goto_error();
	}
	if (!j_sql_exec("CREATE TABLE IF NOT EXISTS tmp(name INTEGER UNIQUE, count INTEGER, timer REAL);", NULL))
	{
		j_goto_error();
	}
	global_timer = H5VL_julea_db_timer_new(total_timers);
	memset(all_timers, 0, sizeof(all_timers));
	memset(all_timers_counter, 0, sizeof(all_timers_counter));
	return;
_error:
	abort();
}
static void
H5VL_julea_db_timer_free(void* ptr)
{
	H5VL_julea_db_timer* timer = ptr;
	if (timer)
	{
		gdouble elapsed = g_timer_elapsed(timer->timer, NULL);
		all_timers[timer->func_name] += elapsed;
		all_timers_counter[timer->func_name]++;
		g_timer_destroy(timer->timer);
		g_free(timer);
	}
}
static void
H5VL_julea_db_timer_fini(void)
{
	char buffer[512];
	guint i;
	if (!global_timer)
		return;
	H5VL_julea_db_timer_free(global_timer);
	global_timer = NULL;
	for (i = 0; i < _H5VL_julea_db_func_count; i++)
	{
		snprintf(buffer, sizeof(buffer), "INSERT INTO tmp (name, count, timer) VALUES ('%d', %d, %f) ON CONFLICT (name) DO UPDATE SET count = count + %d, timer = timer + %f WHERE NAME = '%d';",
			i,
			all_timers_counter[i],
			all_timers[i],
			all_timers_counter[i],
			all_timers[i],
			i);
		j_sql_exec(buffer, NULL);
	}
	sqlite3_close(backend_db);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(H5VL_julea_db_timer, H5VL_julea_db_timer_free)
#define H5VL_JULEA_TIMER(func_name) g_autoptr(H5VL_julea_db_timer) H5VL_julea_db_timer_local = H5VL_julea_db_timer_new(func_name##_timers)

#pragma GCC diagnostic pop
#endif
