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

#include <julea-config.h>
#include <math.h>
#include <glib.h>
#include <string.h>
#include <julea-db.h>
#include <julea.h>
#include "benchmark.h"
#include <stdlib.h>
#include <unistd.h>
#ifdef HAVE_HDF5

#include <hdf5.h>
#include <H5PLextern.h>

static gdouble target_time = 30.0;

static guint n;
static gboolean useVOL = 1;
struct result_sets
{
	BenchmarkResult dataset_create;
	BenchmarkResult dataset_open;
	BenchmarkResult dataset_close;
	BenchmarkResult dataset_read;
	BenchmarkResult dataset_write;
	BenchmarkResult attr_create;
	BenchmarkResult attr_open;
	BenchmarkResult attr_close;
	BenchmarkResult attr_read;
	BenchmarkResult attr_write;
};
static struct result_sets shared_result;

static void
benchmark_hdf_main()
{
	const guint dim_size = 1024;
	hsize_t dims_ds[2];
	hsize_t dims_attr[1];
	hid_t dataspace_ds;
	hid_t dataspace_attr;
	hid_t attribute;
	int* data_attr;
	int* data_ds;
	hid_t dataset;
	hid_t acc_tpl;
	hid_t julea_vol_id;
	hid_t file;
	const H5VL_class_t* h5vl_julea;
	guint j;
	guint i;
	data_attr = g_new(int, dim_size);
	data_ds = g_new(int, dim_size* dim_size);
	for (i = 0; i < dim_size; i++)
	{
		for (j = 0; j < dim_size; j++)
		{
			data_ds[i * dim_size + j] = i + j;
		}
		data_attr[i] = i * 10;
	}
	acc_tpl = H5Pcreate(H5P_FILE_ACCESS);
	if (useVOL)
	{
		h5vl_julea = H5PLget_plugin_info();
		julea_vol_id = H5VLregister_connector(h5vl_julea, H5P_DEFAULT);
		H5VLinitialize(julea_vol_id, H5P_DEFAULT);
		H5Pset_vol(acc_tpl, julea_vol_id, NULL);
	}
	dims_ds[0] = dim_size;
	dims_ds[1] = dim_size;
	dims_attr[0] = dim_size;
	dataspace_ds = H5Screate_simple(2, dims_ds, NULL);
	dataspace_attr = H5Screate_simple(1, dims_attr, NULL);
	while (shared_result.dataset_create.operations == 0 || shared_result.dataset_create.elapsed_time < target_time)
	{
		file = H5Fcreate("JULEA.h5", H5F_ACC_TRUNC, H5P_DEFAULT, acc_tpl);
		j_benchmark_timer_start();
		dataset = H5Dcreate2(file, "BenchmarkDataset", H5T_NATIVE_INT, dataspace_ds, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
		shared_result.dataset_create.elapsed_time += j_benchmark_timer_elapsed();
		shared_result.dataset_create.operations++;
		while (shared_result.dataset_write.operations == 0 || shared_result.dataset_write.elapsed_time < target_time)
		{
			j_benchmark_timer_start();
			H5Dwrite(dataset, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data_ds);
			shared_result.dataset_write.elapsed_time += j_benchmark_timer_elapsed();
			shared_result.dataset_write.operations++;
			shared_result.dataset_write.bytes += dim_size * dim_size * sizeof(guint);
		}
		j_benchmark_timer_start();
		H5Dclose(dataset);
		shared_result.dataset_close.elapsed_time += j_benchmark_timer_elapsed();
		shared_result.dataset_close.operations++;
		while (shared_result.dataset_open.operations == 0 || shared_result.dataset_open.elapsed_time < target_time)
		{
			j_benchmark_timer_start();
			dataset = H5Dopen2(file, "BenchmarkDataset", H5P_DEFAULT);
			shared_result.dataset_open.elapsed_time += j_benchmark_timer_elapsed();
			shared_result.dataset_open.operations++;
			while (shared_result.dataset_read.operations == 0 || shared_result.dataset_read.elapsed_time < target_time)
			{
				j_benchmark_timer_start();
				H5Dread(dataset, H5T_NATIVE_INT, dataspace_ds, H5S_ALL, H5P_DEFAULT, data_ds);
				shared_result.dataset_read.elapsed_time += j_benchmark_timer_elapsed();
				shared_result.dataset_read.operations++;
				shared_result.dataset_read.bytes += dim_size * dim_size * sizeof(guint);
			}
			j_benchmark_timer_start();
			H5Dclose(dataset);
			shared_result.dataset_close.elapsed_time += j_benchmark_timer_elapsed();
			shared_result.dataset_close.operations++;
		}
		H5Fclose(file);
	}
	while (shared_result.attr_create.operations == 0 || shared_result.attr_create.elapsed_time < target_time)
	{
		file = H5Fcreate("JULEA.h5", H5F_ACC_TRUNC, H5P_DEFAULT, acc_tpl);
		j_benchmark_timer_start();
		attribute = H5Acreate2(file, "BenchmarkAttribute", H5T_NATIVE_INT, dataspace_attr, H5P_DEFAULT, H5P_DEFAULT);
		shared_result.attr_create.elapsed_time += j_benchmark_timer_elapsed();
		shared_result.attr_create.operations++;
		while (shared_result.attr_write.operations == 0 || shared_result.attr_write.elapsed_time < target_time)
		{
			j_benchmark_timer_start();
			H5Awrite(attribute, H5T_NATIVE_INT, data_attr);
			shared_result.attr_write.elapsed_time += j_benchmark_timer_elapsed();
			shared_result.attr_write.operations++;
			shared_result.attr_write.bytes += dim_size * sizeof(guint);
		}
		j_benchmark_timer_start();
		H5Aclose(attribute);
		shared_result.attr_close.elapsed_time += j_benchmark_timer_elapsed();
		shared_result.attr_close.operations++;
		while (shared_result.attr_open.operations == 0 || shared_result.attr_open.elapsed_time < target_time)
		{
			j_benchmark_timer_start();
			attribute = H5Aopen(file, "BenchmarkAttribute", H5P_DEFAULT);
			shared_result.attr_open.elapsed_time += j_benchmark_timer_elapsed();
			shared_result.attr_open.operations++;
			while (shared_result.attr_read.operations == 0 || shared_result.attr_read.elapsed_time < target_time)
			{
				j_benchmark_timer_start();
				H5Aread(attribute, H5T_NATIVE_INT, data_attr);
				shared_result.attr_read.elapsed_time += j_benchmark_timer_elapsed();
				shared_result.attr_read.operations++;
				shared_result.attr_read.bytes += dim_size * sizeof(guint);
			}
			j_benchmark_timer_start();
			H5Aclose(attribute);
			shared_result.attr_close.elapsed_time += j_benchmark_timer_elapsed();
			shared_result.attr_close.operations++;
		}
		H5Fclose(file);
	}
	g_free(data_ds);
	g_free(data_attr);
	H5Sclose(dataspace_ds);
	H5Pclose(acc_tpl);
	if (useVOL)
	{
		H5VLterminate(julea_vol_id);
		H5VLunregister_connector(julea_vol_id);
	}
}
static void
benchmark_hdf_dataset_create(BenchmarkResult* result)
{
	memcpy(result, &shared_result.dataset_create, sizeof(*result));
}
static void
benchmark_hdf_dataset_open(BenchmarkResult* result)
{
	memcpy(result, &shared_result.dataset_open, sizeof(*result));
}
static void
benchmark_hdf_dataset_close(BenchmarkResult* result)
{
	memcpy(result, &shared_result.dataset_close, sizeof(*result));
}
static void
benchmark_hdf_dataset_write(BenchmarkResult* result)
{
	memcpy(result, &shared_result.dataset_write, sizeof(*result));
}
static void
benchmark_hdf_dataset_read(BenchmarkResult* result)
{
	memcpy(result, &shared_result.dataset_read, sizeof(*result));
}
static void
benchmark_hdf_attr_create(BenchmarkResult* result)
{
	memcpy(result, &shared_result.attr_create, sizeof(*result));
}
static void
benchmark_hdf_attr_open(BenchmarkResult* result)
{
	memcpy(result, &shared_result.attr_open, sizeof(*result));
}
static void
benchmark_hdf_attr_close(BenchmarkResult* result)
{
	memcpy(result, &shared_result.attr_close, sizeof(*result));
}
static void
benchmark_hdf_attr_write(BenchmarkResult* result)
{
	memcpy(result, &shared_result.attr_write, sizeof(*result));
}
static void
benchmark_hdf_attr_read(BenchmarkResult* result)
{
	memcpy(result, &shared_result.attr_read, sizeof(*result));
}
static void
exec_tests(guint _n)
{
	char testname[500];
	n = _n;
	benchmark_hdf_main();
	sprintf(testname, "/hdf5/dataset/create/%d", n);
	j_benchmark_run(testname, benchmark_hdf_dataset_create);
	sprintf(testname, "/hdf5/dataset/open/%d", n);
	j_benchmark_run(testname, benchmark_hdf_dataset_open);
	sprintf(testname, "/hdf5/dataset/close/%d", n);
	j_benchmark_run(testname, benchmark_hdf_dataset_close);
	sprintf(testname, "/hdf5/dataset/write/%d", n);
	j_benchmark_run(testname, benchmark_hdf_dataset_write);
	sprintf(testname, "/hdf5/dataset/read/%d", n);
	j_benchmark_run(testname, benchmark_hdf_dataset_read);
	sprintf(testname, "/hdf5/attr/create/%d", n);
	j_benchmark_run(testname, benchmark_hdf_attr_create);
	sprintf(testname, "/hdf5/attr/open/%d", n);
	j_benchmark_run(testname, benchmark_hdf_attr_open);
	sprintf(testname, "/hdf5/attr/close/%d", n);
	j_benchmark_run(testname, benchmark_hdf_attr_close);
	sprintf(testname, "/hdf5/attr/write/%d", n);
	j_benchmark_run(testname, benchmark_hdf_attr_write);
	sprintf(testname, "/hdf5/attr/read/%d", n);
	j_benchmark_run(testname, benchmark_hdf_attr_read);
}
static void
exec_tree(guint depth, gfloat min, gfloat max)
{
	//exec tests such that n increases exponentially
	//exec tests in an ordering such that some huge and some small n are executed fast to gain a overview of the result before executing everything completely
	gfloat val = (max - min) * 0.5f + min;
	guint imin = pow(min, 10.0f);
	guint imax = pow(max, 10.0f);
	guint ival = pow(val, 10.0f);
	if (ival != imin && ival != imax)
	{
		if (depth == 0)
		{
			exec_tests(ival);
		}
		else
		{
			exec_tree(depth - 1, min, val);
			exec_tree(depth - 1, val, max);
		}
	}
}
static void
exec_tree1(guint depth, gfloat min, gfloat max)
{
	if (depth == 0)
	{
		exec_tests(min);
		exec_tests(max);
	}
	exec_tree(depth, pow(min, 1.0f / 10.0f), pow(max, 1.0f / 10.0f));
}
#endif
void
benchmark_hdf2(void)
{
#ifdef HAVE_HDF5
	const char* target_str;
	int ret;
	double target = 0.0;
	const char* s = getenv("J_BENCHMARK_VOL");
	useVOL = (s != NULL) && (*s == '1');
	memset(&shared_result, 0, sizeof(shared_result));
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
	exec_tests(1);
/*#ifdef JULEA_DEBUG
	exec_tree1(0, 1, 5);
#else
	guint i;
	for (i = 0; i < 7; i++)
	{
		exec_tree1(i, 1, 1000000);
	}
#endif
*/
#endif
}
