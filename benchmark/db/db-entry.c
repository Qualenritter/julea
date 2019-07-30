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
static guint n2 = 0;
//
static BenchmarkResult* benchmark_db_entry_new_executed = NULL; /*execute only once*/
static BenchmarkResult* benchmark_db_entry_free_executed = NULL; /*execute only once*/
//
static BenchmarkResult* benchmark_db_entry_ref_executed = NULL; /*execute only once*/
static BenchmarkResult* benchmark_db_entry_unref_executed = NULL; /*execute only once*/
//
static BenchmarkResult* benchmark_db_entry_insert_executed = NULL; /*execute multiple benchmarks together*/
static BenchmarkResult* benchmark_db_entry_update_executed = NULL; /*execute multiple benchmarks together*/
static BenchmarkResult* benchmark_db_entry_delete_executed = NULL; /*execute multiple benchmarks together*/
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
	while (m == 0 || elapsed_ref < target_time || elapsed_unref < target_time)
	{
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
	while (m == 0 || elapsed_new < target_time || elapsed_free < target_time)
	{
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
benchmark_db_entry_set_field(BenchmarkResult* result)
{
	GError* error = NULL;
	gboolean ret;
	const char* namespace = "namespace";
	const char* name = "name";
	JDBEntry* entry;
	JDBSchema* schema;
	guint i;
	char varname[50];
	guint m = 0;
	gdouble elapsed = 0;
	schema = j_db_schema_new(namespace, name, ERROR_PARAM);
	CHECK_ERROR(!schema);
	for (i = 0; i < n; i++)
	{
		sprintf(varname, "varname_%d", i);
		ret = j_db_schema_add_field(schema, varname, J_DB_TYPE_UINT32, ERROR_PARAM);
		CHECK_ERROR(!ret);
	}
	while (m == 0 || elapsed < target_time)
	{
		m++;
		entry = j_db_entry_new(schema, ERROR_PARAM);
		CHECK_ERROR(!entry);
		j_benchmark_timer_start();
		for (i = 0; i < n; i++)
		{
			sprintf(varname, "varname_%d", i);
			ret = j_db_entry_set_field(entry, varname, &i, 4, ERROR_PARAM);
			CHECK_ERROR(!ret);
		}
		elapsed += j_benchmark_timer_elapsed();
		j_db_entry_unref(entry);
	}
	j_db_schema_unref(schema);
	result->elapsed_time = elapsed;
	result->operations = n * m;
}
static void
_benchmark_db_entry_insert(BenchmarkResult* result, gboolean use_batch)
{
	GError* error = NULL;
	gboolean ret;
	const char* namespace = "namespace";
	const char* name = "name";
	JDBEntry** entry;
	JDBSelector** selector;
	JDBSchema* schema;
	guint i;
	guint j;
	char varname[50];
	guint m = 0;
	guint m2 = 0;
	g_autoptr(JBatch) batch = NULL;
	gdouble elapsed_insert = 0;
	gdouble elapsed_update = 0;
	gdouble elapsed_delete = 0;
	g_autoptr(JSemantics) semantics = NULL;
	if (benchmark_db_entry_insert_executed)
	{
		result->elapsed_time = benchmark_db_entry_insert_executed->elapsed_time;
		result->operations = benchmark_db_entry_insert_executed->operations;
		return;
	}
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	entry = g_new(JDBEntry*, n);
	selector = g_new(JDBSelector*, n);
	while (m == 0 || elapsed_insert < target_time || elapsed_delete < target_time)
	{
		schema = j_db_schema_new(namespace, name, ERROR_PARAM);
		CHECK_ERROR(!schema);
		for (i = 0; i < n2; i++)
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
			CHECK_ERROR(!entry[j]);
			for (i = 0; i < n2; i++)
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
		for (j = 0; j < n; j++)
		{
			j_db_entry_unref(entry[j]);
		}
		elapsed_insert += j_benchmark_timer_elapsed();
		while (m2 == 0 || elapsed_update < target_time)
		{
			m2++;
			j_benchmark_timer_start();
			for (j = 0; j < n; j++)
			{
				entry[j] = j_db_entry_new(schema, ERROR_PARAM);
				CHECK_ERROR(!entry[j]);
				for (i = 0; i < n2; i++)
				{
					sprintf(varname, "varname_%d", i);
					ret = j_db_entry_set_field(entry[j], varname, &j, 4, ERROR_PARAM);
					CHECK_ERROR(!ret);
				}
				sprintf(varname, "varname_%d", 0);
				selector[j] = j_db_selector_new(schema, J_DB_SELECTOR_MODE_AND, ERROR_PARAM);
				CHECK_ERROR(!selector);
				ret = j_db_selector_add_field(selector[j], varname, J_DB_SELECTOR_OPERATOR_EQ, &j, 4, ERROR_PARAM);
				CHECK_ERROR(!ret);
				ret = j_db_entry_update(entry[j], selector[j], batch, ERROR_PARAM);
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
			for (j = 0; j < n; j++)
			{
				j_db_entry_unref(entry[j]);
				j_db_selector_unref(selector[j]);
			}
			elapsed_update += j_benchmark_timer_elapsed();
		}
		j_benchmark_timer_start();
		for (j = 0; j < n; j++)
		{
			CHECK_ERROR(!entry);
			selector[j] = j_db_selector_new(schema, J_DB_SELECTOR_MODE_AND, ERROR_PARAM);
			CHECK_ERROR(!selector[j]);
			ret = j_db_selector_add_field(selector[j], varname, J_DB_SELECTOR_OPERATOR_EQ, &j, 4, ERROR_PARAM);
			CHECK_ERROR(!ret);
			entry[j] = j_db_entry_new(schema, ERROR_PARAM);
			CHECK_ERROR(!entry[j]);
			ret = j_db_entry_delete(entry[j], selector[j], batch, ERROR_PARAM);
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
		for (j = 0; j < n; j++)
		{
			j_db_entry_unref(entry[j]);
			j_db_selector_unref(selector[j]);
		}
		elapsed_delete += j_benchmark_timer_elapsed();
		ret = j_db_schema_delete(schema, batch, ERROR_PARAM);
		CHECK_ERROR(!ret);
		ret = j_batch_execute(batch);
		CHECK_ERROR(!ret);
		j_db_schema_unref(schema);
	}
	benchmark_db_entry_insert_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_insert_executed->elapsed_time = elapsed_insert;
	benchmark_db_entry_insert_executed->operations = n * m;
	benchmark_db_entry_update_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_update_executed->elapsed_time = elapsed_update;
	benchmark_db_entry_update_executed->operations = n * m2;
	benchmark_db_entry_delete_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_delete_executed->elapsed_time = elapsed_delete;
	benchmark_db_entry_delete_executed->operations = n * m;
	result->elapsed_time = benchmark_db_entry_insert_executed->elapsed_time;
	result->operations = benchmark_db_entry_insert_executed->operations;
	g_free(entry);
	g_free(selector);
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
static void
_benchmark_db_entry_update(BenchmarkResult* result, gboolean use_batch)
{
	BenchmarkResult b;
	if (!benchmark_db_entry_update_executed)
	{
		_benchmark_db_entry_insert(&b, use_batch);
	}
	result->elapsed_time = benchmark_db_entry_update_executed->elapsed_time;
	result->operations = benchmark_db_entry_update_executed->operations;
}
static void
benchmark_db_entry_update(BenchmarkResult* result)
{
	_benchmark_db_entry_update(result, FALSE);
}
static void
benchmark_db_entry_update_batch(BenchmarkResult* result)
{
	_benchmark_db_entry_update(result, TRUE);
}
static void
_benchmark_db_entry_delete(BenchmarkResult* result, gboolean use_batch)
{
	BenchmarkResult b;
	if (!benchmark_db_entry_delete_executed)
	{
		_benchmark_db_entry_insert(&b, use_batch);
	}
	result->elapsed_time = benchmark_db_entry_delete_executed->elapsed_time;
	result->operations = benchmark_db_entry_delete_executed->operations;
}
static void
benchmark_db_entry_delete(BenchmarkResult* result)
{
	_benchmark_db_entry_delete(result, FALSE);
}
static void
benchmark_db_entry_delete_batch(BenchmarkResult* result)
{
	_benchmark_db_entry_delete(result, TRUE);
}
void
benchmark_db_entry(gdouble _target_time, guint _n)
{
	guint i;
	char testname[500];
	target_time = _target_time;
	n = _n;
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
	if (n < 500)
	{
		//more than 500 fields in a schema is not supported by backend - since entrys build on top of schema, entry does not support more than 500 fields too
		// j_db_entry_set_field n variables
		sprintf(testname, "/db/%d/entry/set_field", n);
		j_benchmark_run(testname, benchmark_db_entry_set_field);
	}
	for (i = 0; i < 3; i++)
	{
		switch (i)
		{
		case 2:
			n2 = 5;
			break;
		case 1:
			n2 = 50;
			break;
		case 0:
			n2 = 500;
			break;
		default:
			n2 = 1;
		}
		if (n <= 1000)
		{
			//not using batches with more than 1000 same functions does not make sense
			sprintf(testname, "/db/%d/%d/entry/insert", n, n2);
			j_benchmark_run(testname, benchmark_db_entry_insert);
			sprintf(testname, "/db/%d/%d/entry/update", n, n2);
			j_benchmark_run(testname, benchmark_db_entry_update);
			sprintf(testname, "/db/%d/%d/entry/delete", n, n2);
			j_benchmark_run(testname, benchmark_db_entry_delete);
			g_free(benchmark_db_entry_insert_executed);
			benchmark_db_entry_insert_executed = NULL;
			g_free(benchmark_db_entry_update_executed);
			benchmark_db_entry_update_executed = NULL;
			g_free(benchmark_db_entry_delete_executed);
			benchmark_db_entry_delete_executed = NULL;
		}
		{
			// j_db_entry_insert 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/insert-batch", n, n2);
			j_benchmark_run(testname, benchmark_db_entry_insert_batch);
			// j_db_entry_update 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/update-batch", n, n2);
			j_benchmark_run(testname, benchmark_db_entry_update_batch);
			// j_db_entry_delete 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/delete-batch", n, n2);
			j_benchmark_run(testname, benchmark_db_entry_delete_batch);
			g_free(benchmark_db_entry_insert_executed);
			benchmark_db_entry_insert_executed = NULL;
			g_free(benchmark_db_entry_update_executed);
			benchmark_db_entry_update_executed = NULL;
			g_free(benchmark_db_entry_delete_executed);
			benchmark_db_entry_delete_executed = NULL;
		}
	}
}
