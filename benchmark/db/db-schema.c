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
static guint global_n = 0;
//
static BenchmarkResult* benchmark_db_schema_new_executed = NULL; /*execute only once*/
static BenchmarkResult* benchmark_db_schema_free_executed = NULL; /*execute only once*/
//
static BenchmarkResult* benchmark_db_schema_ref_executed = NULL; /*execute only once*/
static BenchmarkResult* benchmark_db_schema_unref_executed = NULL; /*execute only once*/
//
static BenchmarkResult* benchmark_db_schema_equals_executed = NULL; /*execute multiple benchmarks together*/
static BenchmarkResult* benchmark_db_schema_add_field_executed = NULL; /*execute multiple benchmarks together*/
static BenchmarkResult* benchmark_db_schema_get_field_executed = NULL; /*execute multiple benchmarks together*/
static BenchmarkResult* benchmark_db_schema_get_fields_executed = NULL; /*execute multiple benchmarks together*/
//
static BenchmarkResult* benchmark_db_schema_create_executed = NULL; /*execute multiple benchmarks together*/
static BenchmarkResult* benchmark_db_schema_get_executed = NULL; /*execute multiple benchmarks together*/
static BenchmarkResult* benchmark_db_schema_delete_executed = NULL; /*execute multiple benchmarks together*/
//
static guint scale_factor = SCALE_FACTOR_HDD;
//
static void
_benchmark_db_schema_create(BenchmarkResult* result, gboolean use_batch, const guint n)
{
	JDBSchema** schema_array = NULL;
	GError* error = NULL;
	gboolean ret;
	const char* namespace = "namespace";
	char name[50];
	guint i;
	guint m = 0;
	guint m2 = 0;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed_create = 0;
	gdouble elapsed_get = 0;
	gdouble elapsed_delete = 0;

	j_trace_enter(G_STRFUNC, "(n=%d)", n);
	if (benchmark_db_schema_create_executed)
	{
		result->elapsed_time = benchmark_db_schema_create_executed->elapsed_time;
		result->operations = benchmark_db_schema_create_executed->operations;
		j_trace_leave(G_STRFUNC);
		return;
	}
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	schema_array = g_new0(JDBSchema*, n);
	for (i = 0; i < n; i++)
	{
		sprintf(name, "name%d", i);
		schema_array[i] = j_db_schema_new(namespace, name, ERROR_PARAM);
		CHECK_ERROR(!schema_array[i]);
		ret = j_db_schema_add_field(schema_array[i], "name", J_DB_TYPE_STRING, ERROR_PARAM);
		CHECK_ERROR(!ret);
		ret = j_db_schema_add_field(schema_array[i], "loc", J_DB_TYPE_UINT32, ERROR_PARAM);
		CHECK_ERROR(!ret);
		ret = j_db_schema_add_field(schema_array[i], "coverage", J_DB_TYPE_FLOAT32, ERROR_PARAM);
		CHECK_ERROR(!ret);
		ret = j_db_schema_add_field(schema_array[i], "lastrun", J_DB_TYPE_UINT32, ERROR_PARAM);
		CHECK_ERROR(!ret);
	}
start:
	m++;
	for (i = 0; i < n; i++)
	{
		schema_array[i]->server_side = FALSE;
	}
	j_benchmark_timer_start();
	for (i = 0; i < n; i++)
	{
		sprintf(name, "name%d", i);
		ret = j_db_schema_create(schema_array[i], batch, ERROR_PARAM);
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
	elapsed_create += j_benchmark_timer_elapsed();
	while (m2 == 0 || elapsed_get < target_time)
	{
		for (i = 0; i < n; i++)
		{
			j_db_schema_unref(schema_array[i]);
		}
		for (i = 0; i < n; i++)
		{
			sprintf(name, "name%d", i);
			schema_array[i] = j_db_schema_new(namespace, name, ERROR_PARAM);
			CHECK_ERROR(!schema_array[i]);
		}
		m2++;
		j_benchmark_timer_start();
		for (i = 0; i < n; i++)
		{
			ret = j_db_schema_get(schema_array[i], batch, ERROR_PARAM);
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
		elapsed_get += j_benchmark_timer_elapsed();
	}
	j_benchmark_timer_start();
	for (i = 0; i < n; i++)
	{
		ret = j_db_schema_delete(schema_array[i], batch, ERROR_PARAM);
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
	elapsed_delete += j_benchmark_timer_elapsed();
	if (elapsed_create < target_time && elapsed_delete < target_time)
	{
		goto start;
	}
	for (i = 0; i < n; i++)
	{
		j_db_schema_unref(schema_array[i]);
	}
	g_free(schema_array);
	benchmark_db_schema_create_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_create_executed->elapsed_time = elapsed_create;
	benchmark_db_schema_create_executed->operations = n * m;
	benchmark_db_schema_get_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_get_executed->elapsed_time = elapsed_get;
	benchmark_db_schema_get_executed->operations = n * m2;
	benchmark_db_schema_delete_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_delete_executed->elapsed_time = elapsed_delete;
	benchmark_db_schema_delete_executed->operations = n * m;
	result->elapsed_time = benchmark_db_schema_create_executed->elapsed_time;
	result->operations = benchmark_db_schema_create_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_create(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	_benchmark_db_schema_create(result, FALSE, global_n);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_create_batch(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	_benchmark_db_schema_create(result, TRUE, global_n);
	j_trace_leave(G_STRFUNC);
}
static void
_benchmark_db_schema_delete(BenchmarkResult* result, gboolean use_batch)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	if (!benchmark_db_schema_delete_executed)
	{
		_benchmark_db_schema_create(&b, use_batch, global_n);
	}
	result->elapsed_time = benchmark_db_schema_delete_executed->elapsed_time;
	result->operations = benchmark_db_schema_delete_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_delete(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	_benchmark_db_schema_delete(result, FALSE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_delete_batch(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	_benchmark_db_schema_delete(result, TRUE);
	j_trace_leave(G_STRFUNC);
}
static void
_benchmark_db_schema_get(BenchmarkResult* result, gboolean use_batch)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	if (!benchmark_db_schema_get_executed)
	{
		_benchmark_db_schema_create(&b, use_batch, global_n);
	}
	result->elapsed_time = benchmark_db_schema_get_executed->elapsed_time;
	result->operations = benchmark_db_schema_get_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_get(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	_benchmark_db_schema_get(result, FALSE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_get_batch(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	_benchmark_db_schema_get(result, TRUE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_ref(BenchmarkResult* result)
{
	guint batch_count = 1000;
	GError* error = NULL;
	const char* namespace = "namespace";
	const char* name = "name";
	JDBSchema* schema;
	JDBSchema* schema2;
	gboolean ret;
	guint i;
	guint m = 0;
	gdouble elapsed_ref = 0;
	gdouble elapsed_unref = 0;

	j_trace_enter(G_STRFUNC, NULL);
	if (benchmark_db_schema_ref_executed)
	{
		result->elapsed_time = benchmark_db_schema_ref_executed->elapsed_time;
		result->operations = benchmark_db_schema_ref_executed->operations;
		j_trace_leave(G_STRFUNC);
		return;
	}
	schema = j_db_schema_new(namespace, name, ERROR_PARAM);
	CHECK_ERROR(!schema);
start:
	m += batch_count;
	j_benchmark_timer_start();
	for (i = 0; i < batch_count; i++)
	{
		schema2 = j_db_schema_ref(schema, ERROR_PARAM);
		CHECK_ERROR(!schema2);
		ret = schema != schema2;
		CHECK_ERROR(ret);
	}
	elapsed_ref += j_benchmark_timer_elapsed();
	j_benchmark_timer_start();
	for (i = 0; i < batch_count; i++)
	{
		j_db_schema_unref(schema);
	}
	elapsed_unref += j_benchmark_timer_elapsed();
	if (elapsed_ref < target_time && elapsed_unref < target_time)
	{
		goto start;
	}
	j_db_schema_unref(schema);
	benchmark_db_schema_ref_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_ref_executed->elapsed_time = elapsed_ref;
	benchmark_db_schema_ref_executed->operations = m;
	benchmark_db_schema_unref_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_unref_executed->elapsed_time = elapsed_unref;
	benchmark_db_schema_unref_executed->operations = m;
	result->elapsed_time = benchmark_db_schema_ref_executed->elapsed_time;
	result->operations = benchmark_db_schema_ref_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_unref(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, NULL);
	if (!benchmark_db_schema_unref_executed)
	{
		benchmark_db_schema_ref(&b);
	}
	result->elapsed_time = benchmark_db_schema_unref_executed->elapsed_time;
	result->operations = benchmark_db_schema_unref_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_new(BenchmarkResult* result)
{
	guint batch_count = 1000;
	GError* error = NULL;
	const char* namespace = "namespace";
	const char* name = "name";
	guint i;
	JDBSchema** schema_array = NULL;
	guint m = 0;
	gdouble elapsed_new = 0;
	gdouble elapsed_free = 0;

	j_trace_enter(G_STRFUNC, NULL);
	if (benchmark_db_schema_new_executed)
	{
		result->elapsed_time = benchmark_db_schema_new_executed->elapsed_time;
		result->operations = benchmark_db_schema_new_executed->operations;
		j_trace_leave(G_STRFUNC);
		return;
	}
	schema_array = g_new(JDBSchema*, batch_count);
start:
	m += batch_count;
	j_benchmark_timer_start();
	for (i = 0; i < batch_count; i++)
	{
		schema_array[i] = j_db_schema_new(namespace, name, ERROR_PARAM);
		CHECK_ERROR(!schema_array[i]);
	}
	elapsed_new += j_benchmark_timer_elapsed();
	j_benchmark_timer_start();
	for (i = 0; i < batch_count; i++)
	{
		j_db_schema_unref(schema_array[i]);
	}
	elapsed_free += j_benchmark_timer_elapsed();
	if (elapsed_new < target_time && elapsed_free < target_time)
	{
		goto start;
	}
	g_free(schema_array);
	benchmark_db_schema_new_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_new_executed->elapsed_time = elapsed_new;
	benchmark_db_schema_new_executed->operations = m;
	benchmark_db_schema_free_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_free_executed->elapsed_time = elapsed_free;
	benchmark_db_schema_free_executed->operations = m;
	result->elapsed_time = benchmark_db_schema_new_executed->elapsed_time;
	result->operations = benchmark_db_schema_new_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_free(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, NULL);
	if (!benchmark_db_schema_free_executed)
	{
		benchmark_db_schema_new(&b);
	}
	result->elapsed_time = benchmark_db_schema_free_executed->elapsed_time;
	result->operations = benchmark_db_schema_free_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
_benchmark_db_schema_add_field(BenchmarkResult* result, const guint n)
{
	gchar** names;
	JDBType* types;
	char varname[50];
	GError* error = NULL;
	const char* namespace = "namespace";
	const char* name = "name";
	JDBSchema* schema = NULL;
	JDBSchema* schema2;
	gboolean equals;
	guint i;
	gboolean ret;
	guint m = 0;
	guint m2 = 0;
	guint m3 = 0;
	guint m4 = 0;
	JDBType type;
	gdouble elapsed_add_field = 0;
	gdouble elapsed_get_field = 0;
	gdouble elapsed_get_fields = 0;
	gdouble elapsed_equals = 0;

	j_trace_enter(G_STRFUNC, "(n=%d)", n);
	if (benchmark_db_schema_add_field_executed)
	{
		result->elapsed_time = benchmark_db_schema_add_field_executed->elapsed_time;
		result->operations = benchmark_db_schema_add_field_executed->operations;
		j_trace_leave(G_STRFUNC);
		return;
	}
	while (m == 0 || elapsed_add_field < target_time)
	{
		if (schema)
		{
			j_db_schema_unref(schema);
		}
		schema = j_db_schema_new(namespace, name, ERROR_PARAM);
		CHECK_ERROR(!schema);
		m++;
		j_benchmark_timer_start();
		for (i = 0; i < n; i++)
		{
			sprintf(varname, "varname_%d", i);
			ret = j_db_schema_add_field(schema, varname, J_DB_TYPE_UINT32, ERROR_PARAM);
			CHECK_ERROR(!ret);
		}
		elapsed_add_field += j_benchmark_timer_elapsed();
	}
	while (m2 == 0 || elapsed_get_field < target_time)
	{
		m2++;
		j_benchmark_timer_start();
		for (i = 0; i < n; i++)
		{
			sprintf(varname, "varname_%d", i);
			ret = j_db_schema_get_field(schema, varname, &type, ERROR_PARAM);
			CHECK_ERROR(!ret);
		}
		elapsed_get_field += j_benchmark_timer_elapsed();
	}
	while (m3 == 0 || elapsed_get_fields < target_time)
	{
		m3++;
		j_benchmark_timer_start();
		sprintf(varname, "varname_%d", i);
		ret = j_db_schema_get_all_fields(schema, &names, &types, ERROR_PARAM);
		CHECK_ERROR(!ret);
		elapsed_get_fields += j_benchmark_timer_elapsed();
		g_strfreev(names);
		g_free(types);
	}
	schema2 = j_db_schema_new(namespace, name, ERROR_PARAM);
	CHECK_ERROR(!schema2);
	m++;
	for (i = 0; i < n; i++)
	{
		sprintf(varname, "varname_%d", i);
		ret = j_db_schema_add_field(schema2, varname, J_DB_TYPE_UINT32, ERROR_PARAM);
		CHECK_ERROR(!ret);
	}
	while (m4 == 0 || elapsed_equals < target_time)
	{
		m4++;
		j_benchmark_timer_start();
		ret = j_db_schema_equals(schema, schema2, &equals, ERROR_PARAM);
		CHECK_ERROR(!ret);
		elapsed_equals += j_benchmark_timer_elapsed();
	}
	j_db_schema_unref(schema);
	j_db_schema_unref(schema2);
	benchmark_db_schema_add_field_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_add_field_executed->elapsed_time = elapsed_add_field;
	benchmark_db_schema_add_field_executed->operations = n * m;
	benchmark_db_schema_get_field_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_get_field_executed->elapsed_time = elapsed_get_field;
	benchmark_db_schema_get_field_executed->operations = n * m2;
	benchmark_db_schema_get_fields_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_get_fields_executed->elapsed_time = elapsed_get_fields;
	benchmark_db_schema_get_fields_executed->operations = n * m3;
	benchmark_db_schema_equals_executed = g_new(BenchmarkResult, 1);
	benchmark_db_schema_equals_executed->elapsed_time = elapsed_equals;
	benchmark_db_schema_equals_executed->operations = n * m4;
	result->elapsed_time = benchmark_db_schema_add_field_executed->elapsed_time;
	result->operations = benchmark_db_schema_add_field_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_add_field(BenchmarkResult* result)
{
	_benchmark_db_schema_add_field(result, global_n);
}
static void
benchmark_db_schema_get_field(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	if (!benchmark_db_schema_get_field_executed)
	{
		_benchmark_db_schema_add_field(&b, global_n);
	}
	result->elapsed_time = benchmark_db_schema_get_field_executed->elapsed_time;
	result->operations = benchmark_db_schema_get_field_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_get_fields(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	if (!benchmark_db_schema_get_fields_executed)
	{
		_benchmark_db_schema_add_field(&b, global_n);
	}
	result->elapsed_time = benchmark_db_schema_get_fields_executed->elapsed_time;
	result->operations = benchmark_db_schema_get_fields_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_schema_equals(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d)", global_n);
	if (!benchmark_db_schema_equals_executed)
	{
		_benchmark_db_schema_add_field(&b, global_n);
	}
	result->elapsed_time = benchmark_db_schema_equals_executed->elapsed_time;
	result->operations = benchmark_db_schema_equals_executed->operations;
	j_trace_leave(G_STRFUNC);
}
void
benchmark_db_schema(gdouble _target_time, guint _n,guint _scale_factor)
{
	char testname[500];
	const guint n = global_n = _n;
	scale_factor=_scale_factor;

	j_trace_enter(G_STRFUNC, "(n=%d)", n);
	target_time = _target_time;
	if (n * scale_factor < 500)
	{
		//more than 500 fields in a schema is not supported by backend
		//add n fields to a schema
		sprintf(testname, "/db/%d/schema/add_field", n);
		j_benchmark_run(testname, benchmark_db_schema_add_field);
		//get all n different fields from a schema
		sprintf(testname, "/db/%d/schema/get_field", n);
		j_benchmark_run(testname, benchmark_db_schema_get_field);
		//get all n fields at once from a schema
		sprintf(testname, "/db/%d/schema/get_fields", n);
		j_benchmark_run(testname, benchmark_db_schema_get_fields);
		//compare schema containing n variables
		sprintf(testname, "/db/%d/schema/equals", n);
		j_benchmark_run(testname, benchmark_db_schema_equals);
		g_free(benchmark_db_schema_add_field_executed);
		benchmark_db_schema_add_field_executed = NULL;
		g_free(benchmark_db_schema_get_field_executed);
		benchmark_db_schema_get_field_executed = NULL;
		g_free(benchmark_db_schema_get_fields_executed);
		benchmark_db_schema_get_fields_executed = NULL;
		g_free(benchmark_db_schema_equals_executed);
		benchmark_db_schema_equals_executed = NULL;
	}
	if (n * scale_factor <= 1000)
	{
		//not using batches with more than 1000 same functions does not make sense
		//create n schema at once
		sprintf(testname, "/db/%d/schema/create", n);
		j_benchmark_run(testname, benchmark_db_schema_create);
		//get n schema at once
		sprintf(testname, "/db/%d/schema/get", n);
		j_benchmark_run(testname, benchmark_db_schema_get);
		//delete n schema at once
		sprintf(testname, "/db/%d/schema/delete", n);
		j_benchmark_run(testname, benchmark_db_schema_delete);
		g_free(benchmark_db_schema_create_executed);
		benchmark_db_schema_create_executed = NULL;
		g_free(benchmark_db_schema_get_executed);
		benchmark_db_schema_get_executed = NULL;
		g_free(benchmark_db_schema_delete_executed);
		benchmark_db_schema_delete_executed = NULL;
	}
	if (n * scale_factor <= 100000)
	{
		//tests with more than 100000 schema does not make sense
		{
			//create n schema at once in a batch
			sprintf(testname, "/db/%d/schema/create-batch", n);
			j_benchmark_run(testname, benchmark_db_schema_create_batch);
			//get n schema at once in a batch
			sprintf(testname, "/db/%d/schema/get-batch", n);
			j_benchmark_run(testname, benchmark_db_schema_get_batch);
			//delete n schema at once in a batch
			sprintf(testname, "/db/%d/schema/delete-batch", n);
			j_benchmark_run(testname, benchmark_db_schema_delete_batch);
			g_free(benchmark_db_schema_create_executed);
			benchmark_db_schema_create_executed = NULL;
			g_free(benchmark_db_schema_get_executed);
			benchmark_db_schema_get_executed = NULL;
			g_free(benchmark_db_schema_delete_executed);
			benchmark_db_schema_delete_executed = NULL;
		}
	}
	{
		//ref schema
		sprintf(testname, "/db/%d/schema/ref", n);
		j_benchmark_run(testname, benchmark_db_schema_ref);
		//unref, but not free schema
		sprintf(testname, "/db/%d/schema/unref", n);
		j_benchmark_run(testname, benchmark_db_schema_unref);
	}
	{
		//create empty schema
		sprintf(testname, "/db/%d/schema/new", n);
		j_benchmark_run(testname, benchmark_db_schema_new);
		//free empty schema
		sprintf(testname, "/db/%d/schema/free", n);
		j_benchmark_run(testname, benchmark_db_schema_free);
	}
	j_trace_leave(G_STRFUNC);
}
