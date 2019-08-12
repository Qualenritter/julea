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

#ifndef H5VL_JULEA_DB_H
#define H5VL_JULEA_DB_H

#include <hdf5.h>
#include <H5PLextern.h>

struct JHDF5File_t
{
	gint ref_count;
	char* name;
};
typedef struct JHDF5File_t JHDF5File_t;

struct JHDF5Dataset_t
{
	gint ref_count;
	JHDF5File_t* file;
	char* name;
};
typedef struct JHDF5Dataset_t JHDF5Dataset_t;

static void
H5VL_julea_db_error_handler(GError* error);

//file
static JHDF5File_t*
H5VL_julea_db_file_ref(JHDF5File_t* file);
static void
H5VL_julea_db_file_unref(JHDF5File_t* file);
static herr_t H5VL_julea_db_file_init(hid_t vipl_id);
static herr_t
H5VL_julea_db_file_term(void);

//dataset
static JHDF5Dataset_t*
H5VL_julea_db_dataset_ref(JHDF5Dataset_t* dataset);
static void
H5VL_julea_db_dataset_unref(JHDF5Dataset_t* dataset);
static herr_t
H5VL_julea_db_dataset_init(hid_t vipl_id);
static herr_t
H5VL_julea_db_dataset_term(void);

#endif
