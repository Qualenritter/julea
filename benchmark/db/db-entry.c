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
}
