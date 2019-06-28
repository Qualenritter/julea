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
#include <unistd.h>

float target_time = 60;
guint n = 1; //overwrite in benchmark_smd
static void
_benchmark_smd_scheme_write(BenchmarkResult* result, const gboolean use_batch, JDistributionType distribution)
{
	guint space_length = n;
	guint array_length = 100;
	const char* filename = "filename";
	const char* schemename = "schemename";
	guint i = 0;
	guint m = 0;
	void* file;
	void* type;
	void* space;
	void* scheme;
	int* databuffer;
	guint one = 1;
	databuffer = g_new(int, array_length* space_length);
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed = 0;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	file = j_smd_file_create(filename, batch);
	j_batch_execute(batch);
	i = space_length * n;
	space = j_smd_space_create(one, &i);
	type = j_smd_type_create();
	j_smd_type_add_atomic_type(type, "data", 0, sizeof(int), SMD_TYPE_INT, one, &array_length);
	scheme = j_smd_scheme_create(schemename, file, type, space, distribution, batch);
	j_batch_execute(batch);
start:
	m++;
	j_benchmark_timer_start();
	j_smd_scheme_write(scheme, databuffer, 0, space_length, batch); //write entire file at once
	j_batch_execute(batch);
	elapsed += j_benchmark_timer_elapsed();
	if (elapsed < target_time)
	{
		goto start;
	}
	j_smd_scheme_unref(scheme);
	j_smd_space_unref(space);
	j_smd_type_unref(type);
	j_smd_file_unref(file);
	result->elapsed_time = elapsed;
	result->operations = n * m * array_length;
	g_free(databuffer);
	(void)use_batch;
}
static void
_benchmark_smd_scheme_read(BenchmarkResult* result, const gboolean use_batch, JDistributionType distribution)
{
	guint space_length = n;
	guint array_length = 100;
	const char* filename = "filename";
	const char* schemename = "schemename";
	guint m = 0;
	void* file;
	void* scheme;
	int* databuffer;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	databuffer = g_new(int, array_length* space_length);
	gdouble elapsed = 0;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	file = j_smd_file_open(filename, batch);
	j_batch_execute(batch);
	scheme = j_smd_scheme_open(schemename, file, batch); //read entire file at once
	j_batch_execute(batch);
start:
	m++;
	j_benchmark_timer_start();
	j_smd_scheme_read(scheme, databuffer, 0, space_length, batch);
	j_batch_execute(batch);
	elapsed += j_benchmark_timer_elapsed();
	if (elapsed < target_time)
	{
		goto start;
	}
	j_smd_scheme_unref(scheme);
	j_smd_file_delete(filename, batch);
	j_batch_execute(batch);
	j_smd_file_unref(file);
	result->elapsed_time = elapsed;
	result->operations = n * m * array_length;
	g_free(databuffer);
	(void)use_batch;
	(void)distribution;
}
static void
_benchmark_smd_scheme_create(BenchmarkResult* result, const gboolean use_batch)
{
	const char* filename = "filename";
	char schemename[50];
	guint i;
	guint m = 0;
	void* file;
	void* type;
	void* space;
	void* scheme;
	guint one = 1;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed = 0;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	file = j_smd_file_create(filename, batch);
	j_batch_execute(batch);
start:
	m++;
	j_benchmark_timer_start();
	for (i = 0; i < n; i++)
	{
		space = j_smd_space_create(one, &one);
		type = j_smd_type_create();
		j_smd_type_add_atomic_type(type, "name", 0, 10, SMD_TYPE_BLOB, one, &one); /*TODO allow string pointer*/
		j_smd_type_add_atomic_type(type, "loc", 10, 4, SMD_TYPE_INT, one, &one);
		j_smd_type_add_atomic_type(type, "coverage", 14, 4, SMD_TYPE_FLOAT, one, &one);
		j_smd_type_add_atomic_type(type, "lastrun", 18, 4, SMD_TYPE_INT, one, &one); /*TODO allow time value*/
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
	elapsed += j_benchmark_timer_elapsed();
	if (elapsed < target_time)
	{
		for (i = 0; i < n; i++)
		{
			sprintf(schemename, "schemename_%d", i);
			j_smd_scheme_delete(schemename, file, batch);
		}
		j_batch_execute(batch);
		goto start;
	}
	j_smd_file_unref(file);
	result->elapsed_time = elapsed;
	result->operations = n * m;
}
static void
_benchmark_smd_scheme_open(BenchmarkResult* result, const gboolean use_batch)
{
	const char* filename = "filename";
	char schemename[50];
	guint i;
	void* file;
	guint m = 0;
	void* scheme;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed = 0;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	file = j_smd_file_open(filename, batch);
	j_batch_execute(batch);
start:
	m++;
	j_benchmark_timer_start();
	for (i = 0; i < n; i++)
	{
		sprintf(schemename, "schemename_%d", i);
		scheme = j_smd_scheme_open(schemename, file, batch);
		j_smd_scheme_unref(scheme);
		if (!use_batch)
			j_batch_execute(batch);
	}
	if (use_batch)
		j_batch_execute(batch);
	elapsed += j_benchmark_timer_elapsed();
	if (elapsed < target_time)
		goto start;
	j_smd_file_unref(file);
	j_batch_execute(batch);
	result->elapsed_time = elapsed;
	result->operations = n * m;
}
static void
_benchmark_smd_scheme_delete(BenchmarkResult* result, const gboolean use_batch)
{
	const char* filename = "filename";
	char schemename[50];
	guint i;
	guint m = 0;
	void* file;
	void* type;
	void* space;
	void* scheme;
	guint one = 1;
	g_autoptr(JBatch) batch = NULL;
	g_autoptr(JSemantics) semantics = NULL;
	gdouble elapsed = 0;
	semantics = j_benchmark_get_semantics();
	batch = j_batch_new(semantics);
	file = j_smd_file_open(filename, batch);
	j_batch_execute(batch);
start:
	m++;
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
	elapsed += j_benchmark_timer_elapsed();
	if (elapsed < target_time)
	{
		for (i = 0; i < n; i++)
		{
			space = j_smd_space_create(one, &one);
			type = j_smd_type_create();
			j_smd_type_add_atomic_type(type, "name", 0, 10, SMD_TYPE_BLOB, one, &one); /*TODO allow string pointer*/
			j_smd_type_add_atomic_type(type, "loc", 10, 4, SMD_TYPE_INT, one, &one);
			j_smd_type_add_atomic_type(type, "coverage", 14, 4, SMD_TYPE_FLOAT, one, &one);
			j_smd_type_add_atomic_type(type, "lastrun", 18, 4, SMD_TYPE_INT, one, &one); /*TODO allow time value*/
			sprintf(schemename, "schemename_%d", i);
			scheme = j_smd_scheme_create(schemename, file, type, space, J_DISTRIBUTION_DATABASE, batch);
			j_smd_scheme_unref(scheme);
			j_smd_space_unref(space);
			j_smd_type_unref(type);
		}
		j_batch_execute(batch);
		goto start;
	}
	j_smd_file_unref(file);
	j_smd_file_delete(filename, batch);
	j_batch_execute(batch);
	result->elapsed_time = elapsed;
	result->operations = n * m;
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
static void
benchmark_smd_write_scheme_db(BenchmarkResult* result)
{
	_benchmark_smd_scheme_write(result, FALSE, J_DISTRIBUTION_DATABASE);
}
static void
benchmark_smd_write_scheme_object(BenchmarkResult* result)
{
	_benchmark_smd_scheme_write(result, FALSE, J_DISTRIBUTION_SINGLE_SERVER);
}
static void
benchmark_smd_read_scheme_db(BenchmarkResult* result)
{
	_benchmark_smd_scheme_read(result, FALSE, J_DISTRIBUTION_DATABASE);
}
static void
benchmark_smd_read_scheme_object(BenchmarkResult* result)
{
	_benchmark_smd_scheme_read(result, FALSE, J_DISTRIBUTION_SINGLE_SERVER);
}

void
benchmark_smd(void)
{
	char cwd[PATH_MAX];
	guint n_values[] = {
		1, 5, //
		10, 50, //
		100, 500, //
		1000, 5000, //
		10000,
		50000, //
		100000, //
		1000000, //
	};
	guint i;
	guint res;
	char* res2;
	char testname[500 + PATH_MAX];
	res2 = getcwd(cwd, sizeof(cwd));
	for (i = 0; i < sizeof(n_values) / sizeof(*n_values); i++)
	{ //read write benchmark
		n = n_values[i];
		sprintf(testname, "/smd/scheme_%d/write/db", n);
		j_benchmark_run(testname, benchmark_smd_write_scheme_db);
		sprintf(testname, "du -s /mnt2/julea/* >> %s/benchmark_values_size_%d_03", cwd, n);
		res = system(testname);
		sprintf(testname, "/smd/scheme_%d/read/db", n);
		j_benchmark_run(testname, benchmark_smd_read_scheme_db);
		sprintf(testname, "/smd/scheme_%d/write/object", n);
		j_benchmark_run(testname, benchmark_smd_write_scheme_object);
		sprintf(testname, "/smd/scheme_%d/read/object", n);
		j_benchmark_run(testname, benchmark_smd_read_scheme_object);
	}
	for (i = 0; i < sizeof(n_values) / sizeof(*n_values); i++)
	{ //create open delete benchmark
		n = n_values[i];
		if (n < 1000)
		{
			//this is enough to demonstrate that batch messages are faster
			sprintf(testname, "/smd/scheme_%d/create", n);
			j_benchmark_run(testname, benchmark_smd_create_scheme);
			sprintf(testname, "/smd/scheme_%d/open", n);
			j_benchmark_run(testname, benchmark_smd_scheme_open);
			sprintf(testname, "/smd/scheme_%d/delete", n);
			j_benchmark_run(testname, benchmark_smd_scheme_delete);
		}
		sprintf(testname, "du -s /mnt2/julea/* >> %s/benchmark_values_size_%d_01", cwd, n);
		res = system(testname);
		sprintf(testname, "/smd/scheme_%d/create-batch", n);
		j_benchmark_run(testname, benchmark_smd_create_scheme_batch);
		sprintf(testname, "du -s /mnt2/julea/* >> %s/benchmark_values_size_%d_02", cwd, n);
		res = system(testname);
		sprintf(testname, "/smd/scheme_%d/open-batch", n);
		j_benchmark_run(testname, benchmark_smd_scheme_open_batch);
		sprintf(testname, "/smd/scheme_%d/delete-batch", n);
		j_benchmark_run(testname, benchmark_smd_scheme_delete_batch);
	}
	(void)res;
	(void)res2;
}
