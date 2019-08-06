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
static guint global_n2 = 0;
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
static BenchmarkResult* benchmark_db_iterator_single_executed = NULL; /*execute multiple benchmarks together*/
static BenchmarkResult* benchmark_db_iterator_all_executed = NULL; /*execute multiple benchmarks together*/
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

	j_trace_enter(G_STRFUNC, NULL);
	if (benchmark_db_entry_ref_executed)
	{
		result->elapsed_time = benchmark_db_entry_ref_executed->elapsed_time;
		result->operations = benchmark_db_entry_ref_executed->operations;
		j_trace_leave(G_STRFUNC);
		return;
	}
	schema = j_db_schema_new(namespace, name, ERROR_PARAM);
	CHECK_ERROR(!schema);
	entry = j_db_entry_new(schema, ERROR_PARAM);
	CHECK_ERROR(!entry);
	while (m == 0 || (elapsed_ref < target_time && elapsed_unref < target_time))
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
	benchmark_db_entry_ref_executed->operations = m;
	benchmark_db_entry_unref_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_unref_executed->elapsed_time = elapsed_unref;
	benchmark_db_entry_unref_executed->operations = m;
	result->elapsed_time = benchmark_db_entry_ref_executed->elapsed_time;
	result->operations = benchmark_db_entry_ref_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_unref(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, NULL);
	if (!benchmark_db_entry_unref_executed)
	{
		benchmark_db_entry_ref(&b);
	}
	result->elapsed_time = benchmark_db_entry_unref_executed->elapsed_time;
	result->operations = benchmark_db_entry_unref_executed->operations;
	j_trace_leave(G_STRFUNC);
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

	j_trace_enter(G_STRFUNC, NULL);
	if (benchmark_db_entry_new_executed)
	{
		result->elapsed_time = benchmark_db_entry_new_executed->elapsed_time;
		result->operations = benchmark_db_entry_new_executed->operations;
		j_trace_leave(G_STRFUNC);
		return;
	}
	entry_array = g_new(JDBEntry*, batch_count);
	schema = j_db_schema_new(namespace, name, ERROR_PARAM);
	CHECK_ERROR(!schema);
	while (m == 0 || (elapsed_new < target_time && elapsed_free < target_time))
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
	benchmark_db_entry_new_executed->operations = m;
	benchmark_db_entry_free_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_free_executed->elapsed_time = elapsed_free;
	benchmark_db_entry_free_executed->operations = m;
	result->elapsed_time = benchmark_db_entry_new_executed->elapsed_time;
	result->operations = benchmark_db_entry_new_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_free(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, NULL);
	if (!benchmark_db_entry_free_executed)
	{
		benchmark_db_entry_new(&b);
	}
	result->elapsed_time = benchmark_db_entry_free_executed->elapsed_time;
	result->operations = benchmark_db_entry_free_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
_benchmark_db_entry_set_field(BenchmarkResult* result, const guint n)
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

	j_trace_enter(G_STRFUNC, "(n=%d)", n);
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
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_set_field(BenchmarkResult* result)
{
	_benchmark_db_entry_set_field(result, global_n);
}
static void
_benchmark_db_entry_insert(BenchmarkResult* result, gboolean use_batch, gboolean use_index, const guint n, JSemanticsAtomicity atomicity)
{
	GError* error = NULL;
	gboolean ret;
	gpointer iter_ptr;
	JDBType iter_type;
	guint64 iter_length;
	const char* namespace = "namespace";
	const char* name = "name";
	JDBEntry** entry;
	JDBSelector** selector;
	JDBSchema* schema;
	JDBIterator* iterator;
	guint i;
	guint j;
	gchar const** names;
	char varname[50];
	guint m = 0;
	guint m2 = 0;
	guint m3 = 0;
	guint m4 = 0;
	g_autoptr(JBatch) batch = NULL;
	gdouble elapsed_entry_insert = 0;
	gdouble elapsed_entry_update = 0;
	gdouble elapsed_entry_delete = 0;
	gdouble elapsed_iterator_single = 0;
	gdouble elapsed_iterator_all = 0;
	g_autoptr(JSemantics) semantics = NULL;

	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", n, global_n2);
	if (benchmark_db_entry_insert_executed)
	{
		result->elapsed_time = benchmark_db_entry_insert_executed->elapsed_time;
		result->operations = benchmark_db_entry_insert_executed->operations;
		j_trace_leave(G_STRFUNC);
		return;
	}
	semantics = j_semantics_new(J_SEMANTICS_TEMPLATE_DEFAULT);
	j_semantics_set(semantics, J_SEMANTICS_ATOMICITY, atomicity);
	batch = j_batch_new(semantics);
	entry = g_new(JDBEntry*, n);
	selector = g_new(JDBSelector*, n);
	names = g_new(gchar const*, 2);
	names[0] = "varname_0";
	names[1] = NULL;
	while (m == 0 || (elapsed_entry_insert < target_time && elapsed_entry_delete < target_time))
	{
		schema = j_db_schema_new(namespace, name, ERROR_PARAM);
		CHECK_ERROR(!schema);
		for (i = 0; i < global_n2; i++)
		{
			sprintf(varname, "varname_%d", i);
			ret = j_db_schema_add_field(schema, varname, J_DB_TYPE_UINT32, ERROR_PARAM);
			CHECK_ERROR(!ret);
		}
		if (use_index)
		{
			ret = j_db_schema_add_index(schema, names, ERROR_PARAM);
			CHECK_ERROR(!ret);
		}
		ret = j_db_schema_create(schema, batch, ERROR_PARAM);
		CHECK_ERROR(!ret);
		ret = j_batch_execute(batch);
		CHECK_ERROR(!ret);
		m++;
		//insert
		j_benchmark_timer_start();
		for (j = 0; j < n; j++)
		{
			entry[j] = j_db_entry_new(schema, ERROR_PARAM);
			CHECK_ERROR(!entry[j]);
			for (i = 0; i < global_n2; i++)
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
		elapsed_entry_insert += j_benchmark_timer_elapsed();
		//selector single
		while (m3 == 0 || elapsed_iterator_single < target_time)
		{
			m3++;
			j_benchmark_timer_start();
			for (j = 0; j < n; j++)
			{
				selector[j] = j_db_selector_new(schema, J_DB_SELECTOR_MODE_AND, ERROR_PARAM);
				CHECK_ERROR(!selector);
				ret = j_db_selector_add_field(selector[j], varname, J_DB_SELECTOR_OPERATOR_EQ, &j, 4, ERROR_PARAM);
				CHECK_ERROR(!ret);
				iterator = j_db_iterator_new(schema, selector[j], ERROR_PARAM);
				CHECK_ERROR(!iterator);
				ret = j_db_iterator_next(iterator, ERROR_PARAM);
				CHECK_ERROR(!ret);
				for (i = 0; i < global_n2; i++)
				{
					sprintf(varname, "varname_%d", i);
					ret = j_db_iterator_get_field(iterator, varname, &iter_type, &iter_ptr, &iter_length, ERROR_PARAM);
					CHECK_ERROR(!ret);
					g_free(iter_ptr);
				}
				ret = j_db_iterator_next(iterator, NULL);
				CHECK_ERROR(ret);
				j_db_iterator_unref(iterator);
				j_db_selector_unref(selector[j]);
			}
			elapsed_iterator_single += j_benchmark_timer_elapsed();
		}
		//selector all
		while (m4 == 0 || elapsed_iterator_all < target_time)
		{
			m3++;
			m4++;
			j_benchmark_timer_start();
			iterator = j_db_iterator_new(schema, NULL, ERROR_PARAM);
			CHECK_ERROR(!iterator);
			for (j = 0; j < n; j++)
			{
				ret = j_db_iterator_next(iterator, ERROR_PARAM);
				CHECK_ERROR(!ret);
				for (i = 0; i < global_n2; i++)
				{
					sprintf(varname, "varname_%d", i);
					ret = j_db_iterator_get_field(iterator, varname, &iter_type, &iter_ptr, &iter_length, ERROR_PARAM);
					CHECK_ERROR(!ret);
					g_free(iter_ptr);
				}
			}
			ret = j_db_iterator_next(iterator, NULL);
			CHECK_ERROR(ret);
			j_db_iterator_unref(iterator);
			elapsed_iterator_all += j_benchmark_timer_elapsed();
		}
		while (m2 == 0 || elapsed_entry_update < target_time)
		{
			m2++;
			//update
			j_benchmark_timer_start();
			for (j = 0; j < n; j++)
			{
				entry[j] = j_db_entry_new(schema, ERROR_PARAM);
				CHECK_ERROR(!entry[j]);
				for (i = 0; i < global_n2; i++)
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
			elapsed_entry_update += j_benchmark_timer_elapsed();
		}
		//delete
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
		elapsed_entry_delete += j_benchmark_timer_elapsed();
		ret = j_db_schema_delete(schema, batch, ERROR_PARAM);
		CHECK_ERROR(!ret);
		ret = j_batch_execute(batch);
		CHECK_ERROR(!ret);
		j_db_schema_unref(schema);
	}
	benchmark_db_entry_insert_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_insert_executed->elapsed_time = elapsed_entry_insert;
	benchmark_db_entry_insert_executed->operations = n * m;
	benchmark_db_entry_update_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_update_executed->elapsed_time = elapsed_entry_update;
	benchmark_db_entry_update_executed->operations = n * m2;
	benchmark_db_entry_delete_executed = g_new(BenchmarkResult, 1);
	benchmark_db_entry_delete_executed->elapsed_time = elapsed_entry_delete;
	benchmark_db_entry_delete_executed->operations = n * m;
	benchmark_db_iterator_single_executed = g_new(BenchmarkResult, 1);
	benchmark_db_iterator_single_executed->elapsed_time = elapsed_iterator_single;
	benchmark_db_iterator_single_executed->operations = n * m3;
	benchmark_db_iterator_all_executed = g_new(BenchmarkResult, 1);
	benchmark_db_iterator_all_executed->elapsed_time = elapsed_iterator_all;
	benchmark_db_iterator_all_executed->operations = n * m4;
	result->elapsed_time = benchmark_db_entry_insert_executed->elapsed_time;
	result->operations = benchmark_db_entry_insert_executed->operations;
	g_free(names);
	g_free(entry);
	g_free(selector);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_insert(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_insert(result, FALSE, FALSE, global_n, J_SEMANTICS_ATOMICITY_NONE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_insert_batch(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_insert(result, TRUE, FALSE, global_n, J_SEMANTICS_ATOMICITY_NONE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_insert_batch_index(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_insert(result, TRUE, TRUE, global_n, J_SEMANTICS_ATOMICITY_NONE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_insert_batch_index_atomicity(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_insert(result, TRUE, TRUE, global_n, J_SEMANTICS_ATOMICITY_BATCH);
	j_trace_leave(G_STRFUNC);
}
static void
_benchmark_db_entry_update(BenchmarkResult* result, gboolean use_batch, gboolean use_index, JSemanticsAtomicity atomicity)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	if (!benchmark_db_entry_update_executed)
	{
		_benchmark_db_entry_insert(&b, use_batch, use_index, global_n, atomicity);
	}
	result->elapsed_time = benchmark_db_entry_update_executed->elapsed_time;
	result->operations = benchmark_db_entry_update_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_update(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_update(result, FALSE, FALSE, J_SEMANTICS_ATOMICITY_NONE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_update_batch(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_update(result, TRUE, FALSE, J_SEMANTICS_ATOMICITY_NONE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_update_batch_index(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_update(result, TRUE, TRUE, J_SEMANTICS_ATOMICITY_NONE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_update_batch_index_atomicity(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_update(result, TRUE, TRUE, J_SEMANTICS_ATOMICITY_BATCH);
	j_trace_leave(G_STRFUNC);
}
static void
_benchmark_db_entry_delete(BenchmarkResult* result, gboolean use_batch, gboolean use_index, JSemanticsAtomicity atomicity)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	if (!benchmark_db_entry_delete_executed)
	{
		_benchmark_db_entry_insert(&b, use_batch, use_index, global_n, atomicity);
	}
	result->elapsed_time = benchmark_db_entry_delete_executed->elapsed_time;
	result->operations = benchmark_db_entry_delete_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_delete(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_delete(result, FALSE, FALSE, J_SEMANTICS_ATOMICITY_NONE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_delete_batch(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_delete(result, TRUE, FALSE, J_SEMANTICS_ATOMICITY_NONE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_delete_batch_index(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_delete(result, TRUE, TRUE, J_SEMANTICS_ATOMICITY_NONE);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_entry_delete_batch_index_atomicity(BenchmarkResult* result)
{
	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	_benchmark_db_entry_delete(result, TRUE, TRUE, J_SEMANTICS_ATOMICITY_BATCH);
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_iterator_single(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	if (!benchmark_db_iterator_single_executed)
	{
		_benchmark_db_entry_insert(&b, TRUE, FALSE, global_n, J_SEMANTICS_ATOMICITY_NONE);
	}
	result->elapsed_time = benchmark_db_iterator_single_executed->elapsed_time;
	result->operations = benchmark_db_iterator_single_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_iterator_single_index(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	if (!benchmark_db_iterator_single_executed)
	{
		_benchmark_db_entry_insert(&b, TRUE, TRUE, global_n, J_SEMANTICS_ATOMICITY_NONE);
	}
	result->elapsed_time = benchmark_db_iterator_single_executed->elapsed_time;
	result->operations = benchmark_db_iterator_single_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_iterator_single_index_atomicity(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	if (!benchmark_db_iterator_single_executed)
	{
		_benchmark_db_entry_insert(&b, TRUE, TRUE, global_n, J_SEMANTICS_ATOMICITY_BATCH);
	}
	result->elapsed_time = benchmark_db_iterator_single_executed->elapsed_time;
	result->operations = benchmark_db_iterator_single_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_iterator_all(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	if (!benchmark_db_iterator_all_executed)
	{
		_benchmark_db_entry_insert(&b, TRUE, FALSE, global_n, J_SEMANTICS_ATOMICITY_NONE);
	}
	result->elapsed_time = benchmark_db_iterator_all_executed->elapsed_time;
	result->operations = benchmark_db_iterator_all_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_iterator_all_index(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	if (!benchmark_db_iterator_all_executed)
	{
		_benchmark_db_entry_insert(&b, TRUE, TRUE, global_n, J_SEMANTICS_ATOMICITY_NONE);
	}
	result->elapsed_time = benchmark_db_iterator_all_executed->elapsed_time;
	result->operations = benchmark_db_iterator_all_executed->operations;
	j_trace_leave(G_STRFUNC);
}
static void
benchmark_db_iterator_all_index_atomicity(BenchmarkResult* result)
{
	BenchmarkResult b;

	j_trace_enter(G_STRFUNC, "(n=%d-n2=%d)", global_n, global_n2);
	if (!benchmark_db_iterator_all_executed)
	{
		_benchmark_db_entry_insert(&b, TRUE, TRUE, global_n, J_SEMANTICS_ATOMICITY_BATCH);
	}
	result->elapsed_time = benchmark_db_iterator_all_executed->elapsed_time;
	result->operations = benchmark_db_iterator_all_executed->operations;
	j_trace_leave(G_STRFUNC);
}
void
benchmark_db_entry(gdouble _target_time, guint _n)
{
	guint i;
	char testname[500];
	const guint n = global_n = _n;

	j_trace_enter(G_STRFUNC, "(n=%d)", n);
	target_time = _target_time;
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
	if (n * scale_factor < 500)
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
		case 0:
			global_n2 = 5;
			break;
		case 1:
			global_n2 = 50;
			break;
		case 2:
			global_n2 = 500;
			break;
		default:
			global_n2 = 1;
		}
		if (n * scale_factor <= 1000)
		{
			//not using batches with more than 1000 same functions does not make sense
			sprintf(testname, "/db/%d/%d/entry/insert", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_insert);
			sprintf(testname, "/db/%d/%d/entry/update", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_update);
			sprintf(testname, "/db/%d/%d/entry/delete", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_delete);
			g_free(benchmark_db_entry_insert_executed);
			benchmark_db_entry_insert_executed = NULL;
			g_free(benchmark_db_entry_update_executed);
			benchmark_db_entry_update_executed = NULL;
			g_free(benchmark_db_entry_delete_executed);
			benchmark_db_entry_delete_executed = NULL;
			g_free(benchmark_db_iterator_single_executed);
			benchmark_db_iterator_single_executed = NULL;
			g_free(benchmark_db_iterator_all_executed);
			benchmark_db_iterator_all_executed = NULL;
		}
		if ((global_n2 == 500 && n * scale_factor <= 50000) || (global_n2 == 50 && n * scale_factor <= 150000) || (global_n2 == 5 && n * scale_factor <= 200000))
		{
			// j_db_entry_insert 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/insert-batch", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_insert_batch);
			// j_db_entry_update 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/update-batch", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_update_batch);
			// j_db_entry_delete 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/delete-batch", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_delete_batch);
			sprintf(testname, "/db/%d/%d/iterator/single", n, global_n2);
			j_benchmark_run(testname, benchmark_db_iterator_single);
			sprintf(testname, "/db/%d/%d/iterator/all", n, global_n2);
			j_benchmark_run(testname, benchmark_db_iterator_all);
			g_free(benchmark_db_entry_insert_executed);
			benchmark_db_entry_insert_executed = NULL;
			g_free(benchmark_db_entry_update_executed);
			benchmark_db_entry_update_executed = NULL;
			g_free(benchmark_db_entry_delete_executed);
			benchmark_db_entry_delete_executed = NULL;
			g_free(benchmark_db_iterator_single_executed);
			benchmark_db_iterator_single_executed = NULL;
			g_free(benchmark_db_iterator_all_executed);
			benchmark_db_iterator_all_executed = NULL;
		}
		if ((global_n2 == 500 && n * scale_factor <= 50000) || (global_n2 == 50 && n * scale_factor <= 150000) || (global_n2 == 5 && n * scale_factor <= 200000))
		{
			// j_db_entry_insert 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/insert-batch-index", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_insert_batch_index);
			// j_db_entry_update 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/update-batch-index", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_update_batch_index);
			// j_db_entry_delete 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/delete-batch-index", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_delete_batch_index);
			sprintf(testname, "/db/%d/%d/iterator/single-index", n, global_n2);
			j_benchmark_run(testname, benchmark_db_iterator_single_index);
			sprintf(testname, "/db/%d/%d/iterator/all-index", n, global_n2);
			j_benchmark_run(testname, benchmark_db_iterator_all_index);
			g_free(benchmark_db_entry_insert_executed);
			benchmark_db_entry_insert_executed = NULL;
			g_free(benchmark_db_entry_update_executed);
			benchmark_db_entry_update_executed = NULL;
			g_free(benchmark_db_entry_delete_executed);
			benchmark_db_entry_delete_executed = NULL;
			g_free(benchmark_db_iterator_single_executed);
			benchmark_db_iterator_single_executed = NULL;
			g_free(benchmark_db_iterator_all_executed);
			benchmark_db_iterator_all_executed = NULL;
		}
		if ((global_n2 == 500 && n * scale_factor <= 50000) || (global_n2 == 50 && n * scale_factor <= 150000) || (global_n2 == 5 && n * scale_factor <= 200000))
		{
			// j_db_entry_insert 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/insert-batch-index-atomicity", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_insert_batch_index_atomicity);
			// j_db_entry_update 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/update-batch-index-atomicity", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_update_batch_index_atomicity);
			// j_db_entry_delete 5,50,500 variables, n entrys
			sprintf(testname, "/db/%d/%d/entry/delete-batch-index-atomicity", n, global_n2);
			j_benchmark_run(testname, benchmark_db_entry_delete_batch_index_atomicity);
			sprintf(testname, "/db/%d/%d/iterator/single-index-atomicity", n, global_n2);
			j_benchmark_run(testname, benchmark_db_iterator_single_index_atomicity);
			sprintf(testname, "/db/%d/%d/iterator/all-index-atomicity", n, global_n2);
			j_benchmark_run(testname, benchmark_db_iterator_all_index_atomicity);
			g_free(benchmark_db_entry_insert_executed);
			benchmark_db_entry_insert_executed = NULL;
			g_free(benchmark_db_entry_update_executed);
			benchmark_db_entry_update_executed = NULL;
			g_free(benchmark_db_entry_delete_executed);
			benchmark_db_entry_delete_executed = NULL;
			g_free(benchmark_db_iterator_single_executed);
			benchmark_db_iterator_single_executed = NULL;
			g_free(benchmark_db_iterator_all_executed);
			benchmark_db_iterator_all_executed = NULL;
		}
	}
	j_trace_leave(G_STRFUNC);
}
