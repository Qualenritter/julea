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

static gdouble target_time=0;
static guint n=0;
static JDBSchema** schema_array=NULL;

static void
_benchmark_db_schema_create(BenchmarkResult* result, gboolean use_batch)
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
        elapsed += j_benchmark_timer_elapsed();
        if (elapsed < target_time)
        {
                for (i = 0; i < n; i++)
                {
                        ret = j_db_schema_delete(schema_array[i], batch, ERROR_PARAM);
                        CHECK_ERROR(!ret);
                }
                ret = j_batch_execute(batch);
                CHECK_ERROR(!ret);
                for (i = 0; i < n; i++)
                        j_db_schema_unref(schema_array[i]);
                goto start;
        }
        result->elapsed_time = elapsed;
        result->operations = n * m;
}
static void
_benchmark_db_schema_delete(BenchmarkResult* result, gboolean use_batch)
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
        elapsed += j_benchmark_timer_elapsed();
        if (elapsed < target_time)
        {
                for (i = 0; i < n; i++)
                {
                        j_db_schema_unref(schema_array[i]);
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
                        ret = j_db_schema_create(schema_array[i], batch, ERROR_PARAM);
                        CHECK_ERROR(!ret);
                }
                ret = j_batch_execute(batch);
                CHECK_ERROR(!ret);
                goto start;
        }
        for (i = 0; i < n; i++)
                j_db_schema_unref(schema_array[i]);
        result->elapsed_time = elapsed;
        result->operations = n * m;
}
static void
_benchmark_db_schema_get(BenchmarkResult* result, gboolean use_batch)
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
                j_db_schema_unref(schema_array[i]);
        for (i = 0; i < n; i++)
        {
                sprintf(name, "name%d", i);
                schema_array[i] = j_db_schema_new(namespace, name, ERROR_PARAM);
                CHECK_ERROR(!schema_array[i]);
        }
        m++;
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
        elapsed += j_benchmark_timer_elapsed();
        if (elapsed < target_time)
        {
                goto start;
        }
        result->elapsed_time = elapsed;
        result->operations = n * m;
}

static void
benchmark_db_schema_create(BenchmarkResult* result)
{
        _benchmark_db_schema_create(result, FALSE);
}
static void
benchmark_db_schema_create_batch(BenchmarkResult* result)
{
        _benchmark_db_schema_create(result, TRUE);
}
static void
benchmark_db_schema_delete(BenchmarkResult* result)
{
        _benchmark_db_schema_delete(result, FALSE);
}
static void
benchmark_db_schema_delete_batch(BenchmarkResult* result)
{
        _benchmark_db_schema_delete(result, TRUE);
}
static void
benchmark_db_schema_get(BenchmarkResult* result)
{
        _benchmark_db_schema_get(result, FALSE);
}
static void
benchmark_db_schema_get_batch(BenchmarkResult* result)
{
        _benchmark_db_schema_get(result, TRUE);
}

void benchmark_db_schema(gdouble _target_time,guint _n){
char testname[500];
target_time=_target_time;
n=_n;
if (n <= 100000)
{
//tests with more than 100000 schema does not make sense
                schema_array = g_new(JDBSchema*, n);
                if (n <= 1000)
                {
                        //not using batches with more than 1000 same functions does not make sense
                        sprintf(testname, "/db/%d/schema/create", n);
                        j_benchmark_run(testname, benchmark_db_schema_create);
                        sprintf(testname, "/db/%d/schema/get", n);
                        j_benchmark_run(testname, benchmark_db_schema_get);
                        sprintf(testname, "/db/%d/schema/delete", n);
                        j_benchmark_run(testname, benchmark_db_schema_delete);
                }
                sprintf(testname, "/db/%d/schema/create-batch", n);
                j_benchmark_run(testname, benchmark_db_schema_create_batch);
                sprintf(testname, "/db/%d/schema/get-batch", n);
                j_benchmark_run(testname, benchmark_db_schema_get_batch);
                sprintf(testname, "/db/%d/schema/delete-batch", n);
                j_benchmark_run(testname, benchmark_db_schema_delete_batch);
                g_free(schema_array);
}
}
