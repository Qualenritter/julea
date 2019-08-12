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

enum JHDF5ObjectType
{
	J_HDF5_OBJECT_TYPE_FILE = 0,
	J_HDF5_OBJECT_TYPE_DATASET,
	J_HDF5_OBJECT_TYPE_DATATYPE,
	J_HDF5_OBJECT_TYPE_SPACE,
	_J_HDF5_OBJECT_TYPE_COUNT
};

typedef enum JHDF5ObjectType JHDF5ObjectType;

typedef struct JHDF5Object_t JHDF5Object_t;
struct JHDF5Object_t
{
	gint ref_count;
	JHDF5ObjectType type;
	union
	{
		struct
		{
			char* name;
		} file;
		struct
		{
			char* name;
			JHDF5Object_t* file;
		} dataset;
		struct
		{
			void* data;
			size_t data_size;
			void* backend_id;
			guint64 backend_id_len;
			hid_t hdf5_id;
		} datatype;
		struct
		{
			void* data;
			size_t data_size;
			void* backend_id;
			guint64 backend_id_len;
			hid_t hdf5_id;
		} space;
	};
};

/*internal helper functions*/

static void
H5VL_julea_db_error_handler(GError* error);

static JHDF5Object_t*
H5VL_julea_db_object_new(JHDF5ObjectType type);
static JHDF5Object_t*
H5VL_julea_db_object_ref(JHDF5Object_t* object);
static void
H5VL_julea_db_object_unref(JHDF5Object_t* object);

static JHDF5Object_t*
H5VL_julea_db_datatype_encode(hid_t* type_id);
static JHDF5Object_t*
H5VL_julea_db_datatype_decode(void* backend_id, guint64 backend_id_len);

static JHDF5Object_t*
H5VL_julea_db_space_encode(hid_t* type_id);
static JHDF5Object_t*
H5VL_julea_db_space_decode(void* backend_id, guint64 backend_id_len);

static herr_t
H5VL_julea_db_attr_init(hid_t vipl_id);
herr_t
H5VL_julea_db_attr_term(void);
static herr_t
H5VL_julea_db_dataset_init(hid_t vipl_id);
static herr_t
H5VL_julea_db_dataset_term(void);
static herr_t
H5VL_julea_db_datatype_init(hid_t vipl_id);
herr_t
H5VL_julea_db_datatype_term(void);
static herr_t
H5VL_julea_db_file_init(hid_t vipl_id);
static herr_t
H5VL_julea_db_file_term(void);
static herr_t
H5VL_julea_db_group_init(hid_t vipl_id);
herr_t
H5VL_julea_db_group_term(void);
static herr_t
H5VL_julea_db_space_init(hid_t vipl_id);
herr_t
H5VL_julea_db_space_term(void);
#endif
