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
#include <julea-internal.h>
#include <stdlib.h>

#ifdef JULEA_DEBUG
guint n = 500;
#else
guint n = 5000;
#endif

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
	j_smd_file_unref(file);
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
	void* scheme;
	guint const m = 200;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	file = j_smd_file_open(filename, batch);
	j_batch_execute(batch);
	j_benchmark_timer_start();
	for (i = 0; i < n; i++)
	{
		sprintf(schemename, "schemename_%d", i);
		for (j = 0; j < m; j++)
		{
			scheme = j_smd_scheme_open(schemename, file, batch);
			j_smd_scheme_unref(scheme);
			if (!use_batch)
				j_batch_execute(batch);
		}
		if (use_batch)
			j_batch_execute(batch);
	}
	elapsed = j_benchmark_timer_elapsed();
	j_smd_file_unref(file);
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
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	file = j_smd_file_open(filename, batch);
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
	guint n_values[] = {
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, //
		20, 30, 40, 50, 60, 70, 80, 90, 100, //
		200, 300, 400, 500, 600, 700, 800, 900, 1000, //
		2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, //
		10000, 50000, 100000, //
	};
	guint i;
	char testname[500];
	for (i = 0; i < sizeof(n_values) / sizeof(*n_values); i++)
	{
		n = n_values[i];
		sprintf(testname, "du -s /mnt2/julea/* >> /src/julea/benchmark_values_warnke_size_%d_01", n);
		system(testname);
		sprintf(testname, "/smd/scheme_%d/create", n);
		j_benchmark_run(testname, benchmark_smd_create_scheme);
		sprintf(testname, "du -s /mnt2/julea/* >> /src/julea/benchmark_values_warnke_size_%d_02", n);
		system(testname);
		sprintf(testname, "/smd/scheme_%d/open", n);
		j_benchmark_run(testname, benchmark_smd_scheme_open);
		sprintf(testname, "/smd/scheme_%d/delete", n);
		j_benchmark_run(testname, benchmark_smd_scheme_delete);
		sprintf(testname, "du -s /mnt2/julea/* >> /src/julea/benchmark_values_warnke_size_%d_03", n);
		system(testname);
		sprintf(testname, "/smd/scheme_%d/create-batch", n);
		j_benchmark_run(testname, benchmark_smd_create_scheme_batch);
		sprintf(testname, "du -s /mnt2/julea/* >> /src/julea/benchmark_values_warnke_size_%d_04", n);
		system(testname);
		sprintf(testname, "/smd/scheme_%d/open-batch", n);
		j_benchmark_run(testname, benchmark_smd_scheme_open_batch);
		sprintf(testname, "/smd/scheme_%d/delete-batch", n);
		j_benchmark_run(testname, benchmark_smd_scheme_delete_batch);
		sprintf(testname, "du -s /mnt2/julea/* >> /src/julea/benchmark_values_warnke_size_%d_05", n);
		system(testname);
	}
}
