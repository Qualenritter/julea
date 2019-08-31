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

#include "benchmark-mpi.h"

struct BenchmarkResult
{
	guint operations;
	gdouble elapsed_time;
	gdouble prognosted_time;
};
typedef struct BenchmarkResult BenchmarkResult;

static GTimer* j_benchmark_timer = NULL;

void
j_benchmark_timer_start(void)
{
	g_timer_start(j_benchmark_timer);
}

gdouble
j_benchmark_timer_elapsed(void)
{
	return g_timer_elapsed(j_benchmark_timer, NULL);
}

gdouble
max(gdouble a, gdouble b)
{
	return a > b ? a : b;
}

static gdouble target_time = 30.0;
static const guint tmp_result_count = 10;

struct result_step
{
	guint n;
	BenchmarkResult schema_create[2];
	BenchmarkResult schema_get[2];
	BenchmarkResult schema_delete[2];
	//
	BenchmarkResult schema_new;
	BenchmarkResult schema_free;
	//
	BenchmarkResult schema_ref;
	BenchmarkResult schema_unref;
	//
	BenchmarkResult schema_equals;
	BenchmarkResult schema_add_field;
	BenchmarkResult schema_get_field;
	BenchmarkResult schema_get_fields;
	//
	BenchmarkResult entry_new;
	BenchmarkResult entry_free;
	BenchmarkResult entry_set_field;
	//
	BenchmarkResult entry_ref;
	BenchmarkResult entry_unref;
	//
	BenchmarkResult entry_insert[12];
	BenchmarkResult entry_update[12];
	BenchmarkResult entry_delete[12];
	BenchmarkResult iterator_single[12];
	BenchmarkResult iterator_all[12];
};
typedef struct result_step result_step;
static result_step* current_result_step = NULL;
static result_step* next_result_step = NULL;
static result_step* all_result_step = NULL;

#include "benchmark-mpi-entry.c"
#include "benchmark-mpi-schema.c"

static void
myprintf(const char* name, guint n, BenchmarkResult* result)
{
	if (result->elapsed_time > 0)
		printf("/db/%d/%s %.3f seconds (%.0f)",
			n,
			name,
			result->elapsed_time,
			(gdouble)result->operations / result->elapsed_time);
}
static void
myprintf2(const char* name, guint n, guint n2, BenchmarkResult* result)
{
	if (result->elapsed_time > 0)
		printf("/db/%d/%d/%s %.3f seconds (%.0f)",
			n,
			n2,
			name,
			result->elapsed_time,
			(gdouble)result->operations / result->elapsed_time);
}

static void
exec_tests(guint n)
{
	guint my_index;
	guint n2;
	if (n < 500)
	{
		{
			_benchmark_db_schema_create(TRUE, n);
			_benchmark_db_schema_create(FALSE, n);
			myprintf("schema/create", n, &current_result_step->schema_create[FALSE]);
			myprintf("schema/get", n, &current_result_step->schema_get[FALSE]);
			myprintf("schema/delete", n, &current_result_step->schema_delete[FALSE]);
			myprintf("schema/create-batch", n, &current_result_step->schema_create[TRUE]);
			myprintf("schema/get-batch", n, &current_result_step->schema_get[TRUE]);
			myprintf("schema/delete-batch", n, &current_result_step->schema_delete[TRUE]);
		}
		{
			_benchmark_db_schema_ref();
			myprintf("schema/ref", n, &current_result_step->schema_ref);
			myprintf("schema/unref", n, &current_result_step->schema_unref);
		}
		{
			_benchmark_db_schema_new();
			myprintf("schema/new", n, &current_result_step->schema_new);
			myprintf("schema/free", n, &current_result_step->schema_free);
		}
		{
			_benchmark_db_schema_add_field(n);
			myprintf("schema/add_field", n, &current_result_step->schema_add_field);
			myprintf("schema/get_field", n, &current_result_step->schema_get_field);
			myprintf("schema/get_fields", n, &current_result_step->schema_get_fields);
			myprintf("schema/equals", n, &current_result_step->schema_equals);
		}
		{
			_benchmark_db_entry_ref();
			myprintf("entry/ref", n, &current_result_step->entry_ref);
			myprintf("entry/unref", n, &current_result_step->entry_unref);
		}
		{
			_benchmark_db_entry_new();
			myprintf("entry/new", n, &current_result_step->entry_new);
			myprintf("entry/free", n, &current_result_step->entry_free);
		}
		{
			_benchmark_db_entry_set_field(n);
			myprintf("entry/set_field", n, &current_result_step->entry_set_field);
		}
	}
	my_index = 0;
	for (n2 = 5; n2 <= 500; n2 *= 10, my_index += 4)
	{
		{
			_benchmark_db_entry_insert(FALSE, FALSE, n, n2, J_SEMANTICS_ATOMICITY_NONE);
			myprintf2("entry/insert", n, n2, &current_result_step->entry_insert[my_index + 0]);
			myprintf2("entry/update", n, n2, &current_result_step->entry_update[my_index + 0]);
			myprintf2("entry/delete", n, n2, &current_result_step->entry_delete[my_index + 0]);
		}
		{
			_benchmark_db_entry_insert(TRUE, FALSE, n, n2, J_SEMANTICS_ATOMICITY_NONE);
			myprintf2("entry/insert-batch", n, n2, &current_result_step->entry_insert[my_index + 1]);
			myprintf2("entry/update-batch", n, n2, &current_result_step->entry_update[my_index + 1]);
			myprintf2("entry/delete-batch", n, n2, &current_result_step->entry_delete[my_index + 1]);
			myprintf2("iterator/single", n, n2, &current_result_step->iterator_single[my_index + 1]);
			myprintf2("iterator/all", n, n2, &current_result_step->iterator_all[my_index + 1]);
		}
		{
			_benchmark_db_entry_insert(TRUE, TRUE, n, n2, J_SEMANTICS_ATOMICITY_NONE);
			myprintf2("entry/update-batch-index", n, n2, &current_result_step->entry_update[my_index + 2]);
			myprintf2("entry/insert-batch-index", n, n2, &current_result_step->entry_insert[my_index + 2]);
			myprintf2("entry/delete-batch-index", n, n2, &current_result_step->entry_delete[my_index + 2]);
			myprintf2("iterator/single-index", n, n2, &current_result_step->iterator_single[my_index + 2]);
			myprintf2("iterator/all-index", n, n2, &current_result_step->iterator_all[my_index + 2]);
		}
		{
			_benchmark_db_entry_insert(TRUE, TRUE, n, n2, J_SEMANTICS_ATOMICITY_BATCH);
			myprintf2("entry/update-batch-index-atomicity", n, n2, &current_result_step->entry_update[my_index + 3]);
			myprintf2("entry/insert-batch-index-atomicity", n, n2, &current_result_step->entry_insert[my_index + 3]);
			myprintf2("entry/delete-batch-index-atomicity", n, n2, &current_result_step->entry_delete[my_index + 3]);
			myprintf2("iterator/single-index-atomicity", n, n2, &current_result_step->iterator_single[my_index + 3]);
			myprintf2("iterator/all-index-atomicity", n, n2, &current_result_step->iterator_all[my_index + 3]);
		}
	}
}

static gboolean
calculate_prognose(guint n, gint n_next)
{
	gboolean result = FALSE;
	gdouble i = 0;
	guint j;
	result_step* tmp;

	next_result_step->n = n_next;
	next_result_step->schema_new.prognosted_time = target_time + 1;
	next_result_step->schema_free.prognosted_time = target_time + 1;
	next_result_step->schema_ref.prognosted_time = target_time + 1;
	next_result_step->schema_unref.prognosted_time = target_time + 1;
	next_result_step->entry_new.prognosted_time = target_time + 1;
	next_result_step->entry_free.prognosted_time = target_time + 1;
	next_result_step->entry_ref.prognosted_time = target_time + 1;
	next_result_step->entry_unref.prognosted_time = target_time + 1;
	{
		tmp = all_result_step;
		while (tmp <= current_result_step)
		{
			i++;
			next_result_step->schema_equals.prognosted_time += tmp->schema_equals.elapsed_time / (tmp->n * tmp->n);
			next_result_step->schema_add_field.prognosted_time += tmp->schema_add_field.elapsed_time / (tmp->n * tmp->n);
			next_result_step->schema_get_field.prognosted_time += tmp->schema_get_field.elapsed_time / (tmp->n * tmp->n);
			next_result_step->schema_get_fields.prognosted_time += tmp->schema_get_fields.elapsed_time / (tmp->n * tmp->n);
			next_result_step->entry_set_field.prognosted_time += tmp->entry_set_field.elapsed_time / (tmp->n * tmp->n);
			for (j = 0; j < 2; j++)
			{
				next_result_step->schema_create[j].prognosted_time += tmp->schema_create[j].elapsed_time / (tmp->n * tmp->n);
				next_result_step->schema_get[j].prognosted_time += tmp->schema_get[j].elapsed_time / (tmp->n * tmp->n);
				next_result_step->schema_delete[j].prognosted_time += tmp->schema_delete[j].elapsed_time / (tmp->n * tmp->n);
			}
			for (j = 0; j < 12; j++)
			{
				next_result_step->entry_insert[j].prognosted_time += tmp->entry_insert[j].elapsed_time / (tmp->n * tmp->n);
				next_result_step->entry_update[j].prognosted_time += tmp->entry_update[j].elapsed_time / (tmp->n * tmp->n);
				next_result_step->entry_delete[j].prognosted_time += tmp->entry_delete[j].elapsed_time / (tmp->n * tmp->n);
				next_result_step->iterator_single[j].prognosted_time += tmp->iterator_single[j].elapsed_time / (tmp->n * tmp->n);
				next_result_step->iterator_all[j].prognosted_time += tmp->iterator_all[j].elapsed_time / (tmp->n * tmp->n);
			}
			tmp++;
		}
	}
	{
		next_result_step->schema_equals.prognosted_time = (next_result_step->schema_equals.prognosted_time / i) * n_next * n_next;
		next_result_step->schema_add_field.prognosted_time = (next_result_step->schema_add_field.prognosted_time / i) * n_next * n_next;
		next_result_step->schema_get_field.prognosted_time = (next_result_step->schema_get_field.prognosted_time / i) * n_next * n_next;
		next_result_step->schema_get_fields.prognosted_time = (next_result_step->schema_get_fields.prognosted_time / i) * n_next * n_next;
		next_result_step->entry_set_field.prognosted_time = (next_result_step->entry_set_field.prognosted_time / i) * n_next * n_next;
		for (j = 0; j < 2; j++)
		{
			next_result_step->schema_create[j].prognosted_time = (next_result_step->schema_create[j].prognosted_time / i) * n_next * n_next;
			next_result_step->schema_get[j].prognosted_time = (next_result_step->schema_get[j].prognosted_time / i) * n_next * n_next;
			next_result_step->schema_delete[j].prognosted_time = (next_result_step->schema_delete[j].prognosted_time / i) * n_next * n_next;
		}
		for (j = 0; j < 12; j++)
		{
			next_result_step->entry_insert[j].prognosted_time = (next_result_step->entry_insert[j].prognosted_time / i) * n_next * n_next;
			next_result_step->entry_update[j].prognosted_time = (next_result_step->entry_update[j].prognosted_time / i) * n_next * n_next;
			next_result_step->entry_delete[j].prognosted_time = (next_result_step->entry_delete[j].prognosted_time / i) * n_next * n_next;
			next_result_step->iterator_single[j].prognosted_time = (next_result_step->iterator_single[j].prognosted_time / i) * n_next * n_next;
			next_result_step->iterator_all[j].prognosted_time = (next_result_step->iterator_all[j].prognosted_time / i) * n_next * n_next;
		}
	}
	{
		next_result_step->schema_equals.prognosted_time = max(next_result_step->schema_equals.prognosted_time, current_result_step->schema_equals.prognosted_time);
		next_result_step->schema_add_field.prognosted_time = max(next_result_step->schema_add_field.prognosted_time, current_result_step->schema_add_field.prognosted_time);
		next_result_step->schema_get_field.prognosted_time = max(next_result_step->schema_get_field.prognosted_time, current_result_step->schema_get_field.prognosted_time);
		next_result_step->schema_get_fields.prognosted_time = max(next_result_step->schema_get_fields.prognosted_time, current_result_step->schema_get_fields.prognosted_time);
		next_result_step->entry_set_field.prognosted_time = max(next_result_step->entry_set_field.prognosted_time, current_result_step->entry_set_field.prognosted_time);
		for (j = 0; j < 2; j++)
		{
			next_result_step->schema_create[j].prognosted_time = max(next_result_step->schema_create[j].prognosted_time, current_result_step->schema_create[j].prognosted_time);
			next_result_step->schema_get[j].prognosted_time = max(next_result_step->schema_get[j].prognosted_time, current_result_step->schema_get[j].prognosted_time);
			next_result_step->schema_delete[j].prognosted_time = max(next_result_step->schema_delete[j].prognosted_time, current_result_step->schema_delete[j].prognosted_time);
		}
		for (j = 0; j < 12; j++)
		{
			next_result_step->entry_insert[j].prognosted_time = max(next_result_step->entry_insert[j].prognosted_time, current_result_step->entry_insert[j].prognosted_time);
			next_result_step->entry_update[j].prognosted_time = max(next_result_step->entry_update[j].prognosted_time, current_result_step->entry_update[j].prognosted_time);
			next_result_step->entry_delete[j].prognosted_time = max(next_result_step->entry_delete[j].prognosted_time, current_result_step->entry_delete[j].prognosted_time);
			next_result_step->iterator_single[j].prognosted_time = max(next_result_step->iterator_single[j].prognosted_time, current_result_step->iterator_single[j].prognosted_time);
			next_result_step->iterator_all[j].prognosted_time = max(next_result_step->iterator_all[j].prognosted_time, current_result_step->iterator_all[j].prognosted_time);
		}
	}
	{
		result = result || next_result_step->schema_equals.prognosted_time < target_time;
		result = result || next_result_step->schema_add_field.prognosted_time < target_time;
		result = result || next_result_step->schema_get_field.prognosted_time < target_time;
		result = result || next_result_step->schema_get_fields.prognosted_time < target_time;
		result = result || next_result_step->entry_set_field.prognosted_time < target_time;
		for (j = 0; j < 2; j++)
		{
			result = result || next_result_step->schema_create[j].prognosted_time < target_time;
			result = result || next_result_step->schema_get[j].prognosted_time < target_time;
			result = result || next_result_step->schema_delete[j].prognosted_time < target_time;
		}
		for (j = 0; j < 12; j++)
		{
			result = result || next_result_step->entry_insert[j].prognosted_time < target_time;
			result = result || next_result_step->entry_update[j].prognosted_time < target_time;
			result = result || next_result_step->entry_delete[j].prognosted_time < target_time;
			result = result || next_result_step->iterator_single[j].prognosted_time < target_time;
			result = result || next_result_step->iterator_all[j].prognosted_time < target_time;
		}
	}
	{
		printf("prognose schema_equals %f", next_result_step->schema_equals.prognosted_time);
		printf("prognose schema_add_field %f", next_result_step->schema_add_field.prognosted_time);
		printf("prognose schema_get_field %f", next_result_step->schema_get_field.prognosted_time);
		printf("prognose schema_get_fields %f", next_result_step->schema_get_fields.prognosted_time);
		printf("prognose entry_set_field %f", next_result_step->entry_set_field.prognosted_time);
		for (j = 0; j < 2; j++)
		{
			printf("prognose schema_create %d %f", j, next_result_step->schema_create[j].prognosted_time);
			printf("prognose schema_get %d %f", j, next_result_step->schema_get[j].prognosted_time);
			printf("prognose schema_delete %d %f", j, next_result_step->schema_delete[j].prognosted_time);
		}
		for (j = 0; j < 12; j++)
		{
			printf("prognose entry_insert %d %f", j, next_result_step->entry_insert[j].prognosted_time);
			printf("prognose entry_update %d %f", j, next_result_step->entry_update[j].prognosted_time);
			printf("prognose entry_delete %d %f", j, next_result_step->entry_delete[j].prognosted_time);
			printf("prognose iterator_single %d %f", j, next_result_step->iterator_single[j].prognosted_time);
			printf("prognose iterator_all %d %f", j, next_result_step->iterator_all[j].prognosted_time);
		}
	}
	return result;
}

void
benchmark_db(void)
{
	const char* target_str;
	int ret;
	double target = 0.0;
	guint n;
	guint n_next;
	guint i;
	target_str = g_getenv("J_BENCHMARK_TARGET");
	if (target_str)
	{
		g_debug("J_BENCHMARK_TARGET %s", target_str);
		ret = sscanf(target_str, "%lf", &target);
		if (ret == 1)
		{
			g_debug("J_BENCHMARK_TARGET %s %f", target_str, target);
			target_time = target;
		}
	}
	all_result_step = g_new0(result_step, tmp_result_count);
	current_result_step = all_result_step;
	j_benchmark_timer = g_timer_new();
	n = 1;
	current_result_step->n = n;
	while (1)
	{
		n_next = n * 4;
		exec_tests(n);
		n = n_next;
		if (current_result_step < all_result_step + tmp_result_count - 1)
		{
			next_result_step = current_result_step + 1;
		}
		else
		{
			for (i = 0; i < tmp_result_count - 1; i++)
				memcpy(all_result_step + i, all_result_step + i + 1, sizeof(result_step));
			memset(all_result_step + tmp_result_count - 1, 0, sizeof(result_step));
		}
		if (!calculate_prognose(n, n_next))
			break;
		current_result_step = next_result_step;
	}
	g_timer_destroy(j_benchmark_timer);
}
