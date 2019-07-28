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

#include "db.h"

static gdouble target_time = 0;
static guint n = 0;
//
static BenchmarkResult* benchmark_db_entry_new_executed = NULL; /*execute only once*/
static BenchmarkResult* benchmark_db_entry_free_executed = NULL; /*execute only once*/
//
static BenchmarkResult* benchmark_db_entry_ref_executed = NULL; /*execute only once*/
static BenchmarkResult* benchmark_db_entry_unref_executed = NULL; /*execute only once*/
//
static void
benchmark_db_entry_ref(BenchmarkResult* result)
{
	guint batch_count = 1000;
	GError* error = NULL;
	const char* namespace = "namespace";
	const char* name = "name";
	JDBSchema* schema;
	JDBEntry* entry;
	JDBEntry* entry2;
	gboolean ret;
	guint i;
	guint m = 0;
	gdouble elapsed_ref = 0;
	gdouble elapsed_unref = 0;
	if (benchmark_db_entry_ref_executed)
	{
		result->elapsed_time = benchmark_db_entry_ref_executed->elapsed_time;
		result->operations = benchmark_db_entry_ref_executed->operations;
		return;
	}
	schema = j_db_schema_new(namespace, name, ERROR_PARAM);
	CHECK_ERROR(!schema);
	entry = j_db_entry_new(schema, ERROR_PARAM);
	CHECK_ERROR(!entry);
start:
	m += batch_count;
	j_benchmark_timer_start();
	for (i = 0; i < batch_count; i++)
	{
		entry2 = j_db_entry_ref(entry, ERROR_PARAM);
		CHECK_ERROR(!entry2);
		ret = entry != entry2;
		CHECK_ERROR(ret);
	}
	elapsed_ref += j_benchmark_timer_elapsed();
	j_benchmark_timer_start();
	for (i = 0; i < batch_count; i++)
	{
		j_db_entry_unref(entry);
	}
	elapsed_unref += j_benchmark_timer_elapsed();
	if (elapsed_ref < target_time || elapsed_unref < target_time)
	{
		goto start;
	}
	j_db_entry_unref(entry);
	j_db_schema_unref(schema);
	benchmark_db_entry_ref_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_ref_executed->elapsed_time = elapsed_ref;
	benchmark_db_entry_ref_executed->operations = n * m;
	benchmark_db_entry_unref_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_unref_executed->elapsed_time = elapsed_unref;
	benchmark_db_entry_unref_executed->operations = n * m;
	result->elapsed_time = benchmark_db_entry_ref_executed->elapsed_time;
	result->operations = benchmark_db_entry_ref_executed->operations;
}
static void
benchmark_db_entry_unref(BenchmarkResult* result)
{
	BenchmarkResult b;
	if (!benchmark_db_entry_unref_executed)
	{
		benchmark_db_entry_ref(&b);
	}
	result->elapsed_time = benchmark_db_entry_unref_executed->elapsed_time;
	result->operations = benchmark_db_entry_unref_executed->operations;
}
static void
benchmark_db_entry_new(BenchmarkResult* result)
{
	guint batch_count = 1000;
	GError* error = NULL;
	const char* namespace = "namespace";
	const char* name = "name";
	guint i;
	JDBSchema* schema;
	JDBEntry** entry_array = NULL;
	guint m = 0;
	gdouble elapsed_new = 0;
	gdouble elapsed_free = 0;
	if (benchmark_db_entry_new_executed)
	{
		result->elapsed_time = benchmark_db_entry_new_executed->elapsed_time;
		result->operations = benchmark_db_entry_new_executed->operations;
		return;
	}
	entry_array = g_new(JDBEntry*, batch_count);
	schema = j_db_schema_new(namespace, name, ERROR_PARAM);
	CHECK_ERROR(!schema);
start:
	m += batch_count;
	j_benchmark_timer_start();
	for (i = 0; i < batch_count; i++)
	{
		entry_array[i] = j_db_entry_new(schema, ERROR_PARAM);
		CHECK_ERROR(!entry_array[i]);
	}
	elapsed_new += j_benchmark_timer_elapsed();
	j_benchmark_timer_start();
	for (i = 0; i < batch_count; i++)
	{
		j_db_entry_unref(entry_array[i]);
	}
	elapsed_free += j_benchmark_timer_elapsed();
	if (elapsed_new < target_time || elapsed_free < target_time)
	{
		goto start;
	}
	g_free(entry_array);
	j_db_schema_unref(schema);
	benchmark_db_entry_new_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_new_executed->elapsed_time = elapsed_new;
	benchmark_db_entry_new_executed->operations = n * m;
	benchmark_db_entry_free_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_free_executed->elapsed_time = elapsed_free;
	benchmark_db_entry_free_executed->operations = n * m;
	result->elapsed_time = benchmark_db_entry_new_executed->elapsed_time;
	result->operations = benchmark_db_entry_new_executed->operations;
}
static void
benchmark_db_entry_free(BenchmarkResult* result)
{
	BenchmarkResult b;
	if (!benchmark_db_entry_free_executed)
	{
		benchmark_db_entry_new(&b);
	}
	result->elapsed_time = benchmark_db_entry_free_executed->elapsed_time;
	result->operations = benchmark_db_entry_free_executed->operations;
}
static void
_benchmark_db_entry_insert(BenchmarkResult* result, gboolean use_batch)
{
	GError* error = NULL;
	gboolean ret;
	const char* namespace = "namespace";
	const char* name = "name";
	guint array_length = 100;
	JDBEntry** entry;
	JDBSchema* schema;
	guint i;
	guint j;
	char varname[50];
	guint m = 0;
	g_autoptr(JBatch) batch = NULL;
	gdouble elapsed = 0;
	g_autoptr(JSemantics) semantics = NULL;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	entry = g_new(JDBEntry*, n);
start:
	schema = j_db_schema_new(namespace, name, ERROR_PARAM);
	CHECK_ERROR(!schema);
	for (i = 0; i < array_length; i++)
	{
		sprintf(varname, "varname_%d", i);
		ret = j_db_schema_add_field(schema, varname, J_DB_TYPE_UINT32, ERROR_PARAM);
		CHECK_ERROR(!ret);
	}
	ret = j_db_schema_create(schema, batch, ERROR_PARAM);
	CHECK_ERROR(!ret);
	ret = j_batch_execute(batch);
	CHECK_ERROR(!ret);
	m++;
	j_benchmark_timer_start();
	for (j = 0; j < n; j++)
	{
		entry[j] = j_db_entry_new(schema, ERROR_PARAM);
		CHECK_ERROR(!entry);
		for (i = 0; i < array_length; i++)
		{
			sprintf(varname, "varname_%d", i);
			ret = j_db_entry_set_field(entry[j], varname, &j, 4, ERROR_PARAM);
			CHECK_ERROR(!ret);
		}
		ret = j_db_entry_insert(entry[j], batch, ERROR_PARAM);
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
	ret = j_db_schema_delete(schema, batch, ERROR_PARAM);
	CHECK_ERROR(!ret);
	ret = j_batch_execute(batch);
	CHECK_ERROR(!ret);
	j_db_schema_unref(schema);
	for (j = 0; j < n; j++)
		j_db_entry_unref(entry[j]);
	if (elapsed < target_time)
		goto start;
	result->elapsed_time = elapsed;
	result->operations = n * m;
	g_free(entry);
}

static void
benchmark_db_entry_insert(BenchmarkResult* result)
{
	_benchmark_db_entry_insert(result, FALSE);
}
static void
benchmark_db_entry_insert_batch(BenchmarkResult* result)
{
	_benchmark_db_entry_insert(result, TRUE);
}
void
benchmark_db_entry(gdouble _target_time, guint _n)
{
	char testname[500];
	target_time = _target_time;
	n = _n;
	if (n <= 1000)
	{
		//not using batches with more than 1000 same functions does not make sense
		sprintf(testname, "/db/%d/entry/insert", n);
		j_benchmark_run(testname, benchmark_db_entry_insert);
	}
	sprintf(testname, "/db/%d/entry/insert-batch", n);
	j_benchmark_run(testname, benchmark_db_entry_insert_batch);
	{
		//ref schema
		sprintf(testname, "/db/%d/entry/ref", n);
		j_benchmark_run(testname, benchmark_db_entry_ref);
		//unref, but not free entry
		sprintf(testname, "/db/%d/entry/unref", n);
		j_benchmark_run(testname, benchmark_db_entry_unref);
	}
	{
		//create empty entry
		sprintf(testname, "/db/%d/entry/new", n);
		j_benchmark_run(testname, benchmark_db_entry_new);
		//free empty entry
		sprintf(testname, "/db/%d/entry/free", n);
		j_benchmark_run(testname, benchmark_db_entry_free);
	}
	// j_db_entry_set_field n variables
	// j_db_entry_insert 5,50,500 variables, n entrys
	// j_db_entry_update 5,50,500 variables, n entrys
	// j_db_entry_delete 5,50,500 variables, n entrys
}
