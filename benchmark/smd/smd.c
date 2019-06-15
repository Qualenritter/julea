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
#include <string.h>
#include <julea-smd.h>
#include <julea.h>
#include "benchmark.h"

static void
_benchmark_smd_scheme_create(BenchmarkResult* result, gboolean use_batch)
{
	const char* filename = "filename";
	char schemename[50];
	guint i;
	void* file;
	void* type;
	void* space;
	void* scheme;
	guint const n = 500;
	guint one = 1;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	file = j_smd_file_create(filename, batch);
	j_batch_execute(batch);
	j_benchmark_timer_start();
	for (i = 0; i < n; i++)
	{
		space = j_smd_space_create(one, &one);
		type = j_smd_type_create();
		j_smd_type_add_atomic_type(type, "name", 0, 10, SMD_TYPE_BLOB, one, &one); /*TODO allow string pointer*/
		j_smd_type_add_atomic_type(type, "loc", 0, 10, SMD_TYPE_INT, one, &one);
		j_smd_type_add_atomic_type(type, "coverage", 0, 10, SMD_TYPE_FLOAT, one, &one);
		j_smd_type_add_atomic_type(type, "lastrun", 0, 10, SMD_TYPE_INT, one, &one); /*TODO allow time value*/
		sprintf(schemename, "schemename_%d", i);
		scheme = j_smd_scheme_create(schemename, file, type, space, J_DISTRIBUTION_DATABASE, batch);
		j_smd_scheme_unref(scheme);
		j_smd_space_unref(space);
		j_smd_type_unref(type);
		if (!use_batch)
			j_batch_execute(batch);
	}
	if (use_batch)
		j_batch_execute(batch);
	elapsed = j_benchmark_timer_elapsed();
	for (i = 0; i < n; i++)
	{
		sprintf(schemename, "schemename_%d", i);
		j_smd_scheme_delete(schemename, file, batch);
	}
	j_batch_execute(batch);
	j_smd_file_unref(file);
	j_smd_file_delete(filename, batch);
	j_batch_execute(batch);
	result->elapsed_time = elapsed;
	result->operations = n;
}
static void
_benchmark_smd_scheme_open(BenchmarkResult* result, gboolean use_batch)
{
	const char* filename = "filename";
	char schemename[50];
	guint i, j;
	void* file;
	void* type;
	void* space;
	void* scheme;
	guint const n = 500;
	guint const m = 30;
	guint one = 1;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	file = j_smd_file_create(filename, batch);
	j_batch_execute(batch);
	for (i = 0; i < n; i++)
	{
		space = j_smd_space_create(one, &one);
		type = j_smd_type_create();
		j_smd_type_add_atomic_type(type, "name", 0, 10, SMD_TYPE_BLOB, one, &one); /*TODO allow string pointer*/
		j_smd_type_add_atomic_type(type, "loc", 0, 10, SMD_TYPE_INT, one, &one);
		j_smd_type_add_atomic_type(type, "coverage", 0, 10, SMD_TYPE_FLOAT, one, &one);
		j_smd_type_add_atomic_type(type, "lastrun", 0, 10, SMD_TYPE_INT, one, &one); /*TODO allow time value*/
		sprintf(schemename, "schemename_%d", i);
		scheme = j_smd_scheme_create(schemename, file, type, space, J_DISTRIBUTION_DATABASE, batch);
		j_smd_scheme_unref(scheme);
		j_smd_space_unref(space);
		j_smd_type_unref(type);
	}
	j_batch_execute(batch);
	j_benchmark_timer_start();
	for (j = 0; j < m; j++)
	{
		for (i = 0; i < n; i++)
		{
			sprintf(schemename, "schemename_%d", i);
			scheme = j_smd_scheme_open(schemename, file, batch);
			j_smd_scheme_unref(scheme);
			if (!use_batch)
				j_batch_execute(batch);
		}
	}
	if (use_batch)
		j_batch_execute(batch);
	elapsed = j_benchmark_timer_elapsed();
	for (i = 0; i < n; i++)
	{
		sprintf(schemename, "schemename_%d", i);
		j_smd_scheme_delete(schemename, file, batch);
	}
	j_batch_execute(batch);
	j_smd_file_unref(file);
	j_smd_file_delete(filename, batch);
	j_batch_execute(batch);
	result->elapsed_time = elapsed;
	result->operations = n * m;
}
static void
_benchmark_smd_scheme_delete(BenchmarkResult* result, gboolean use_batch)
{
	const char* filename = "filename";
	char schemename[50];
	guint i;
	void* file;
	void* type;
	void* space;
	void* scheme;
	guint const n = 500;
	guint one = 1;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	file = j_smd_file_create(filename, batch);
	j_batch_execute(batch);
	for (i = 0; i < n; i++)
	{
		space = j_smd_space_create(one, &one);
		type = j_smd_type_create();
		j_smd_type_add_atomic_type(type, "name", 0, 10, SMD_TYPE_BLOB, one, &one); /*TODO allow string pointer*/
		j_smd_type_add_atomic_type(type, "loc", 0, 10, SMD_TYPE_INT, one, &one);
		j_smd_type_add_atomic_type(type, "coverage", 0, 10, SMD_TYPE_FLOAT, one, &one);
		j_smd_type_add_atomic_type(type, "lastrun", 0, 10, SMD_TYPE_INT, one, &one); /*TODO allow time value*/
		sprintf(schemename, "schemename_%d", i);
		scheme = j_smd_scheme_create(schemename, file, type, space, J_DISTRIBUTION_DATABASE, batch);
		j_smd_scheme_unref(scheme);
		j_smd_space_unref(space);
		j_smd_type_unref(type);
	}
	j_batch_execute(batch);
	j_benchmark_timer_start();
	for (i = 0; i < n; i++)
	{
		sprintf(schemename, "schemename_%d", i);
		j_smd_scheme_delete(schemename, file, batch);
		if (!use_batch)
			j_batch_execute(batch);
	}
	if (use_batch)
		j_batch_execute(batch);
	elapsed = j_benchmark_timer_elapsed();
	j_smd_file_unref(file);
	j_smd_file_delete(filename, batch);
	j_batch_execute(batch);
	result->elapsed_time = elapsed;
	result->operations = n;
}

static void
benchmark_smd_create_scheme(BenchmarkResult* result)
{
	_benchmark_smd_scheme_create(result, FALSE);
}

static void
benchmark_smd_create_scheme_batch(BenchmarkResult* result)
{
	_benchmark_smd_scheme_create(result, TRUE);
}

static void
benchmark_smd_scheme_open(BenchmarkResult* result)
{
	_benchmark_smd_scheme_open(result, FALSE);
}

static void
benchmark_smd_scheme_open_batch(BenchmarkResult* result)
{
	_benchmark_smd_scheme_open(result, TRUE);
}

static void
benchmark_smd_scheme_delete(BenchmarkResult* result)
{
	_benchmark_smd_scheme_delete(result, FALSE);
}

static void
benchmark_smd_scheme_delete_batch(BenchmarkResult* result)
{
	_benchmark_smd_scheme_delete(result, TRUE);
}

void
benchmark_smd(void)
{
	j_benchmark_run("/smd/scheme/create", benchmark_smd_create_scheme);
	j_benchmark_run("/smd/scheme/create-batch", benchmark_smd_create_scheme_batch);
	j_benchmark_run("/smd/scheme/delete", benchmark_smd_scheme_delete);
	j_benchmark_run("/smd/scheme/delete-batch", benchmark_smd_scheme_delete_batch);
	j_benchmark_run("/smd/scheme/open", benchmark_smd_scheme_open);
	j_benchmark_run("/smd/scheme/open-batch", benchmark_smd_scheme_open_batch);
}
