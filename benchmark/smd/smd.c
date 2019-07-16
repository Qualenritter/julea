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
#include <string.h>
#include <julea-smd.h>
#include <julea.h>
#include "benchmark.h"
#include <julea-internal.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef JULEA_DEBUG
#define ERROR_PARAM &error
#define CHECK_ERROR(_ret_)                                                       \
	do                                                                       \
	{                                                                        \
		if (error)                                                       \
		{                                                                \
			J_DEBUG("ERROR (%d) (%s)", error->code, error->message); \
			abort();                                                 \
		}                                                                \
		if (_ret_)                                                       \
		{                                                                \
			J_DEBUG("ret was %d", _ret_);                            \
			abort();                                                 \
		}                                                                \
	} while (0)
static gdouble target_time = 1;
#else
#define ERROR_PARAM NULL
#define CHECK_ERROR(_ret_)   \
	do                   \
	{                    \
		(void)error; \
		(void)_ret_; \
	} while (0)
static gdouble target_time = 60;
#endif

static guint n = 1;
static JSMDSchema** schema_array;

static void
_benchmark_smd_schema_create(BenchmarkResult* result, gboolean use_batch)
{
	GError* error = NULL;
	gboolean ret;
	const char* namespace = "namespace";
	char name[50];
	guint i;
	guint m = 0;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed = 0;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
start:
	m++;
	j_benchmark_timer_start();
	for (i = 0; i < n; i++)
	{
		sprintf(name, "name%d", i);
		schema_array[i] = j_smd_schema_new(namespace, name, ERROR_PARAM);
		CHECK_ERROR(!schema_array[i]);
		ret = j_smd_schema_add_field(schema_array[i], "name", J_SMD_TYPE_STRING, ERROR_PARAM);
		CHECK_ERROR(!ret);
		ret = j_smd_schema_add_field(schema_array[i], "loc", J_SMD_TYPE_UINT32, ERROR_PARAM);
		CHECK_ERROR(!ret);
		ret = j_smd_schema_add_field(schema_array[i], "coverage", J_SMD_TYPE_FLOAT32, ERROR_PARAM);
		CHECK_ERROR(!ret);
		ret = j_smd_schema_add_field(schema_array[i], "lastrun", J_SMD_TYPE_UINT32, ERROR_PARAM);
		CHECK_ERROR(!ret);
		ret = j_smd_schema_create(schema_array[i], batch, ERROR_PARAM);
		CHECK_ERROR(!ret);
		if (!use_batch)
		{
			ret = j_batch_execute(batch);
			CHECK_ERROR(!ret);
		}
	}
	if (use_batch)
	{
		ret = j_batch_execute(batch);
		CHECK_ERROR(!ret);
	}
	elapsed += j_benchmark_timer_elapsed();
	if (elapsed < target_time)
	{
		for (i = 0; i < n; i++)
		{
			ret = j_smd_schema_delete(schema_array[i], batch, ERROR_PARAM);
			CHECK_ERROR(!ret);
		}
		ret = j_batch_execute(batch);
		CHECK_ERROR(!ret);
		for (i = 0; i < n; i++)
			j_smd_schema_unref(schema_array[i]);
		goto start;
	}
	result->elapsed_time = elapsed;
	result->operations = n * m;
}
static void
_benchmark_smd_schema_delete(BenchmarkResult* result, gboolean use_batch)
{
	GError* error = NULL;
	gboolean ret;
	const char* namespace = "namespace";
	char name[50];
	guint i;
	guint m = 0;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed = 0;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
start:
	m++;
	j_benchmark_timer_start();
	for (i = 0; i < n; i++)
	{
		ret = j_smd_schema_delete(schema_array[i], batch, ERROR_PARAM);
		CHECK_ERROR(!ret);
		if (!use_batch)
		{
			ret = j_batch_execute(batch);
			CHECK_ERROR(!ret);
		}
	}
	if (use_batch)
	{
		ret = j_batch_execute(batch);
		CHECK_ERROR(!ret);
	}
	elapsed += j_benchmark_timer_elapsed();
	if (elapsed < target_time)
	{
		for (i = 0; i < n; i++)
		{
			j_smd_schema_unref(schema_array[i]);
			sprintf(name, "name%d", i);
			schema_array[i] = j_smd_schema_new(namespace, name, ERROR_PARAM);
			CHECK_ERROR(!schema_array[i]);
			ret = j_smd_schema_add_field(schema_array[i], "name", J_SMD_TYPE_STRING, ERROR_PARAM);
			CHECK_ERROR(!ret);
			ret = j_smd_schema_add_field(schema_array[i], "loc", J_SMD_TYPE_UINT32, ERROR_PARAM);
			CHECK_ERROR(!ret);
			ret = j_smd_schema_add_field(schema_array[i], "coverage", J_SMD_TYPE_FLOAT32, ERROR_PARAM);
			CHECK_ERROR(!ret);
			ret = j_smd_schema_add_field(schema_array[i], "lastrun", J_SMD_TYPE_UINT32, ERROR_PARAM);
			CHECK_ERROR(!ret);
			ret = j_smd_schema_create(schema_array[i], batch, ERROR_PARAM);
			CHECK_ERROR(!ret);
		}
		ret = j_batch_execute(batch);
		CHECK_ERROR(!ret);
		goto start;
	}
	for (i = 0; i < n; i++)
		j_smd_schema_unref(schema_array[i]);
	result->elapsed_time = elapsed;
	result->operations = n * m;
}
static void
_benchmark_smd_schema_get(BenchmarkResult* result, gboolean use_batch)
{
	GError* error = NULL;
	gboolean ret;
	const char* namespace = "namespace";
	char name[50];
	guint i;
	guint m = 0;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed = 0;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
start:
	for (i = 0; i < n; i++)
		j_smd_schema_unref(schema_array[i]);
	for (i = 0; i < n; i++)
	{
		sprintf(name, "name%d", i);
		schema_array[i] = j_smd_schema_new(namespace, name, ERROR_PARAM);
		CHECK_ERROR(!schema_array[i]);
	}
	m++;
	j_benchmark_timer_start();
	for (i = 0; i < n; i++)
	{
		ret = j_smd_schema_get(schema_array[i], batch, ERROR_PARAM);
		CHECK_ERROR(!ret);
		if (!use_batch)
		{
			ret = j_batch_execute(batch);
			CHECK_ERROR(!ret);
		}
	}
	if (use_batch)
	{
		ret = j_batch_execute(batch);
		CHECK_ERROR(!ret);
	}
	elapsed += j_benchmark_timer_elapsed();
	if (elapsed < target_time)
	{
		goto start;
	}
	result->elapsed_time = elapsed;
	result->operations = n * m;
}
static void
_benchmark_smd_entry_insert(BenchmarkResult* result, gboolean use_batch)
{
	GError* error = NULL;
	gboolean ret;
	const char* namespace = "namespace";
	const char* name = "name";
	guint array_length = 100;
	JSMDEntry* entry;
	JSMDSchema* schema;
	guint i;
	guint j;
	char varname[50];
	guint m = 0;
	g_autoptr(JBatch) batch = NULL;
	gdouble elapsed = 0;
	g_autoptr(JSemantics) semantics = NULL;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
start:
	schema = j_smd_schema_new(namespace, name, ERROR_PARAM);
	CHECK_ERROR(!schema);
	for (i = 0; i < array_length; i++)
	{
		sprintf(varname, "varname_%d", i);
		ret = j_smd_schema_add_field(schema, varname, J_SMD_TYPE_UINT32, ERROR_PARAM);
		CHECK_ERROR(!ret);
	}
	ret = j_smd_schema_create(schema_array[i], batch, ERROR_PARAM);
	CHECK_ERROR(!ret);
	ret = j_batch_execute(batch);
	CHECK_ERROR(!ret);
	m++;
	j_benchmark_timer_start();
	for (j = 0; j < n; j++)
	{
		entry = j_smd_entry_new(schema, ERROR_PARAM);
		CHECK_ERROR(!entry);
		for (i = 0; i < array_length; i++)
		{
			sprintf(varname, "varname_%d", i);
			ret = j_smd_entry_set_field(entry, varname, &j, 4, ERROR_PARAM);
			CHECK_ERROR(!ret);
		}
		ret = j_smd_entry_insert(entry, batch, ERROR_PARAM);
		CHECK_ERROR(!ret);
		if (!use_batch)
		{
			ret = j_batch_execute(batch);
			CHECK_ERROR(!ret);
		}
	}
	if (use_batch)
	{
		ret = j_batch_execute(batch);
		CHECK_ERROR(!ret);
	}
	elapsed += j_benchmark_timer_elapsed();
	ret = j_smd_schema_delete(schema, batch, ERROR_PARAM);
	CHECK_ERROR(!ret);
	ret = j_batch_execute(batch);
	CHECK_ERROR(!ret);
	j_smd_schema_unref(schema);
	if (elapsed < target_time)
		goto start;
	result->elapsed_time = elapsed;
	result->operations = n * m;
}
static void
benchmark_smd_schema_create(BenchmarkResult* result)
{
	_benchmark_smd_schema_create(result, FALSE);
}
static void
benchmark_smd_schema_create_batch(BenchmarkResult* result)
{
	_benchmark_smd_schema_create(result, TRUE);
}
static void
benchmark_smd_schema_delete(BenchmarkResult* result)
{
	_benchmark_smd_schema_delete(result, FALSE);
}
static void
benchmark_smd_schema_delete_batch(BenchmarkResult* result)
{
	_benchmark_smd_schema_delete(result, TRUE);
}
static void
benchmark_smd_schema_get(BenchmarkResult* result)
{
	_benchmark_smd_schema_get(result, FALSE);
}
static void
benchmark_smd_schema_get_batch(BenchmarkResult* result)
{
	_benchmark_smd_schema_get(result, TRUE);
}
static void
benchmark_smd_entry_insert(BenchmarkResult* result)
{
	_benchmark_smd_entry_insert(result, FALSE);
}
static void
benchmark_smd_entry_insert_batch(BenchmarkResult* result)
{
	_benchmark_smd_entry_insert(result, TRUE);
}
void
benchmark_smd(void)
{
	char cwd[PATH_MAX];
	guint n_values[] = {
		1, 5, //
#ifndef JULEA_DEBUG
		10, 50, //
		100, 500, //
		1000, 5000, //
		10000,
		50000, //
		100000, //
		1000000, //
#endif
	};
	guint i;
	guint res;
	char* res2;
	char testname[500 + PATH_MAX];
	res2 = getcwd(cwd, sizeof(cwd));
	for (i = 0; i < sizeof(n_values) / sizeof(*n_values); i++)
	{
		n = n_values[i];
		schema_array = g_new(JSMDSchema*, n);
		if (n < 1000)
		{
			sprintf(testname, "/smd/schema/create-%d", n);
			j_benchmark_run(testname, benchmark_smd_schema_create);
			sprintf(testname, "/smd/schema/get-%d", n);
			j_benchmark_run(testname, benchmark_smd_schema_get);
			sprintf(testname, "/smd/schema/delete-%d", n);
			j_benchmark_run(testname, benchmark_smd_schema_delete);
		}
		sprintf(testname, "/smd/schema/create-batch-%d", n);
		j_benchmark_run(testname, benchmark_smd_schema_create_batch);
		sprintf(testname, "/smd/schema/get-batch-%d", n);
		j_benchmark_run(testname, benchmark_smd_schema_get_batch);
		sprintf(testname, "/smd/schema/delete-batch-%d", n);
		j_benchmark_run(testname, benchmark_smd_schema_delete_batch);
		g_free(schema_array);
		sprintf(testname, "/smd/entry/insert-%d", n);
		j_benchmark_run(testname, benchmark_smd_entry_insert);
		sprintf(testname, "/smd/entry/insert-batch-%d", n);
		j_benchmark_run(testname, benchmark_smd_entry_insert_batch);
	}
	(void)res;
	(void)res2;
}
