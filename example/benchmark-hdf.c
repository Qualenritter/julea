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

#include <stdlib.h>
#include <hdf5.h>
#include <glib.h>
#include <julea-db.h>
#include <julea.h>
#define JULEA_HDF5_DB_NAMESPACE "HDF5_DB"
static
gdouble factor_native = 0;
static
gdouble factor_julea = 0;
static
gdouble timer_initialize_random_data = 0;
static
gdouble timer_write_julea_vol = 0;
static
gdouble timer_write_native = 0;
static
gdouble timer_read_native_sync = 0;
static
gdouble timer_read_julea_sync = 0;
static
gdouble timer_read_native = 0;
static
gdouble timer_read_julea = 0;
static
GTimer* j_benchmark_timer = NULL;
static
hid_t fapl_julea;
static
hid_t fapl_native;

static
void
j_benchmark_timer_start(void)
{
	g_timer_start(j_benchmark_timer);
}

static
gdouble
j_benchmark_timer_elapsed(void)
{
	gdouble elapsed;
	elapsed = g_timer_elapsed(j_benchmark_timer, NULL);
	return elapsed;
}

static
void
initialize_random_data(const guint m, gint* data)
{
	guint i;
	j_benchmark_timer_start();

	for (i = 0; i < m; i++)
	{
		data[i] = rand();
	}

	timer_initialize_random_data += j_benchmark_timer_elapsed();
}

static
void
write_data(const guint n, const guint m, gint* data)
{
	hsize_t dims_ds[1];
	hid_t dataspace_ds;
	hid_t ds;
	hid_t file;
	char filenamebuffer[30];
	guint i;
	dims_ds[0] = m;
	dataspace_ds = H5Screate_simple(1, dims_ds, NULL);

	for (i = 0; i < n; i++)
	{
		initialize_random_data(m, data);
		{
			snprintf(filenamebuffer, sizeof(filenamebuffer), "benchmark_julea_vol_%d.h5", i);
			j_benchmark_timer_start();
			file = H5Fcreate(filenamebuffer, H5F_ACC_TRUNC, H5P_DEFAULT, fapl_julea);
			ds = H5Dcreate2(file, "temperatures", H5T_NATIVE_INT, dataspace_ds, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
			H5Dwrite(ds, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
			H5Dclose(ds);
			H5Fclose(file);
			timer_write_julea_vol += j_benchmark_timer_elapsed();
		}
		{
			snprintf(filenamebuffer, sizeof(filenamebuffer), "benchmark_native_%d.h5", i);
			j_benchmark_timer_start();
			file = H5Fcreate(filenamebuffer, H5F_ACC_TRUNC, H5P_DEFAULT, fapl_native);
			ds = H5Dcreate2(file, "temperatures", H5T_NATIVE_INT, dataspace_ds, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
			H5Dwrite(ds, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
			H5Dclose(ds);
			H5Fclose(file);
			timer_write_native += j_benchmark_timer_elapsed();
		}
	}

	H5Sclose(dataspace_ds);
}
static
void
read_data_native(const guint n, const guint m, gint* data)
{
	// calculate the max value in all files datasets, and print the file name
	hid_t ds;
	hid_t file;
	char filenamebuffer[30];
	guint i;
	guint j;
	gint data_max = 0;
	gint data_max_local = 0;
	j_benchmark_timer_start();

	for (i = 0; i < n; i++)
	{
		snprintf(filenamebuffer, sizeof(filenamebuffer), "benchmark_native_%d.h5", i);
		file = H5Fopen(filenamebuffer, H5P_DEFAULT, fapl_native);
		ds = H5Dopen2(file, "temperatures", H5P_DEFAULT);
		H5Dread(ds, H5T_NATIVE_INT, H5S_ALL, H5S_ALL, H5P_DEFAULT, data);
		H5Dclose(ds);
		H5Fclose(file);

		for (j = 0; j < m; j++)
		{
			if ((j == 0) || (data_max_local < data[j]))
			{
				data_max_local = data[j];
			}
		}

		if ((i == 0) || (data_max_local >= data_max))
		{
			data_max = data_max_local;
			printf("read_data_native found max value (%d) in file (%s)\n", data_max, filenamebuffer);
		}
	}

	timer_read_native += j_benchmark_timer_elapsed();
}
void
read_data_julea_db(const guint n, const guint m, gint* data)
{
	JDBSchema* julea_db_schema_dataset = NULL;
	JDBSchema* julea_db_schema_file = NULL;
	JDBIterator* julea_db_iterator_dataset = NULL;
	JDBIterator* julea_db_iterator_file = NULL;
	JDBSelector* julea_db_selector_file = NULL;
	g_autoptr(JBatch) batch = NULL;
	gint data_max = 0;
	gint64* data_max_local;
	guint i;
	char* filenamebuffer;
	void* backend_id;
	guint64 len;
	guint64 backend_id_len;
	JDBType type;

	j_benchmark_timer_start();
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	julea_db_schema_dataset = j_db_schema_new(JULEA_HDF5_DB_NAMESPACE, "dataset", NULL);
	j_db_schema_get(julea_db_schema_dataset, batch, NULL);
	julea_db_schema_file = j_db_schema_new(JULEA_HDF5_DB_NAMESPACE, "file", NULL);
	j_db_schema_get(julea_db_schema_file, batch, NULL);
	j_batch_execute(batch);
	julea_db_iterator_dataset = j_db_iterator_new(julea_db_schema_dataset, NULL, NULL);
	i = 0;

	while (j_db_iterator_next(julea_db_iterator_dataset, NULL))
	{
		j_db_iterator_get_field(julea_db_iterator_dataset, "max_value_i", &type, (gpointer*)&data_max_local, &len, NULL);

		if ((i == 0) || (*data_max_local >= data_max))
		{
			data_max = *data_max_local;
			julea_db_selector_file = j_db_selector_new(julea_db_schema_file, J_DB_SELECTOR_MODE_AND, NULL);
			j_db_iterator_get_field(julea_db_iterator_dataset, "file", &type, &backend_id, &backend_id_len, NULL);
			j_db_selector_add_field(julea_db_selector_file, "_id", J_DB_SELECTOR_OPERATOR_EQ, backend_id, backend_id_len, NULL);
			julea_db_iterator_file = j_db_iterator_new(julea_db_schema_file, julea_db_selector_file, NULL);
			j_db_iterator_next(julea_db_iterator_file, NULL);
			j_db_iterator_get_field(julea_db_iterator_file, "name", &type, (gpointer*)&filenamebuffer, &len, NULL);
			printf("read_data_julea_db found max value (%d) in file (%s)\n", data_max, filenamebuffer);
			free(filenamebuffer);
		}

		i++;
	}

	j_db_iterator_unref(julea_db_iterator_dataset);
	j_db_schema_unref(julea_db_schema_dataset);
	j_db_schema_unref(julea_db_schema_file);
	timer_read_julea += j_benchmark_timer_elapsed();
}
static
void
print_times(const guint n)
{
	printf("timer_initialize_random_data %f\n", timer_initialize_random_data);
	printf("timer_write_julea_vol %f (%f)\n", timer_write_julea_vol, n / timer_write_julea_vol);
	printf("timer_write_native %f (%f)\n", timer_write_native, n / timer_write_native);
	printf("timer_read_julea %f (%f) %f\n", timer_read_julea, n / timer_read_julea * factor_julea, factor_julea);
	printf("timer_read_native %f (%f) %f\n", timer_read_native, n / timer_read_native * factor_native, factor_native);
	printf("timer_read_julea_sync %f (%f) %f\n", timer_read_julea_sync, n / timer_read_julea_sync * factor_julea, factor_julea);
	printf("timer_read_native_sync %f (%f) %f\n", timer_read_native_sync, n / timer_read_native_sync * factor_native, factor_native);
}
int
main()
{
	const gdouble target = 20;
	const gdouble n = 1000; //file	count
	const gdouble m = 1000000; //dataset dimensions
	hid_t julea_vol_id;
	gint* data;

	srand(12345); //enough randomness for this benchmark if using constant random seed
	j_benchmark_timer = g_timer_new();

	julea_vol_id = H5VLregister_connector_by_name("julea", H5P_DEFAULT);
	H5VLinitialize(julea_vol_id, H5P_DEFAULT);

	fapl_native = H5Pcreate(H5P_FILE_ACCESS);
	fapl_julea = H5Pcreate(H5P_FILE_ACCESS);
	H5Pset_vol(fapl_julea, julea_vol_id, NULL);

	data = malloc(sizeof(*data) * (guint)m);

	write_data(n, m, data);

	while (timer_read_native < target && timer_read_native_sync < target * 30)
	{
		factor_native++;
		j_benchmark_timer_start();
		system("sync");
		system("echo 3 > /proc/sys/vm/drop_caches");
		timer_read_native_sync += j_benchmark_timer_elapsed();
		read_data_native(n, m, data);

		if ((((guint)factor_native) % 100) == 0)
		{
			print_times(n);
		}
	}

	while (timer_read_julea < target && timer_read_julea_sync < target * 30)
	{
		factor_julea++;
		j_benchmark_timer_start();
		system("sync");
		system("echo 3 > /proc/sys/vm/drop_caches");
		timer_read_julea_sync += j_benchmark_timer_elapsed();
		read_data_julea_db(n, m, data);

		if ((((guint)factor_julea) % 100) == 0)
		{
			print_times(n);
		}
	}

	free(data);
	H5Pclose(fapl_julea);
	H5Pclose(fapl_native);

	H5VLterminate(julea_vol_id);
	H5VLunregister_connector(julea_vol_id);

	print_times(n);

	g_timer_destroy(j_benchmark_timer);
	return 0;
}
