/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2017 Olga Perevalova
 * Copyright (C) 2017 Eugen Betke
 * Copyright (C) 2018-2019 Johannes Coym
 * Copyright (C) 2019 Michael Kuhn
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

// FIXME check whether version is up to date: https://github.com/Olgasnezh/hdf5-vol-sqlite-plugin
// FIXME clean up
// FIXME fix memory leaks

#define JULEA_HDF_COMPILES

// FIXME
#define H5Sencode_vers 1

#include <julea-config.h>
#include <julea.h>
#include <julea-kv.h>
#include <julea-object.h>
#include <glib.h>
#include <bson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <hdf5.h>
#include <H5PLextern.h>

#define _GNU_SOURCE

#define JULEA 520

#include "jhdf5-kv.c"

/**
 * Initializes the plugin
 *
 * \return err Error
 **/
static
herr_t
H5VL_julea_init (hid_t vipl_id)
{
	H5VL_julea_kv_init(vipl_id);
	return 0;
}

/**
 * Terminates the plugin
 *
 * \return err Error
 **/
static
herr_t
H5VL_julea_term (void)
{
	return H5VL_julea_kv_term();
}

/**
 * Creates a new attribute
 *
 * \return attribute The new attribute
 **/
static
void*
H5VL_julea_attr_create (void* obj, const H5VL_loc_params_t* loc_params, const char* attr_name, hid_t type_id, hid_t space_id, hid_t acpl_id, hid_t aapl_id, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_attr_create(obj,loc_params,attr_name,type_id,space_id,acpl_id,aapl_id,dxpl_id,req);
}

/**
 * Opens an attribute
 *
 * \return attribute The attribute
 **/
static
void*
H5VL_julea_attr_open(void* obj, const H5VL_loc_params_t* loc_params, const char* attr_name, hid_t aapl_id, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_attr_open(obj,loc_params,attr_name,aapl_id,dxpl_id,req);
}

/**
 * Reads the data from the attribute
 **/
static
herr_t
H5VL_julea_attr_read(void* attr, hid_t dtype_id, void* buf, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_attr_read(attr,dtype_id,buf,dxpl_id,req);
}

/**
 * Writes the data of the attribute
 **/
static
herr_t
H5VL_julea_attr_write (void* attr, hid_t dtype_id, const void* buf, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_attr_write(attr,dtype_id,buf,dxpl_id,req);
}

/**
 * Provides get Functions of the attribute
 *
 * \return ret_value The error code
 **/
static
herr_t
H5VL_julea_attr_get (void* attr, H5VL_attr_get_t get_type, hid_t dxpl_id, void** req, va_list arguments)
{
	return H5VL_julea_kv_attr_get(attr,get_type,dxpl_id,req,arguments);
}

/**
 * Closes the attribute
 **/
static
herr_t
H5VL_julea_attr_close (void* attr, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_attr_close(attr,dxpl_id,req);
}

/**
 * Creates a new file
 *
 * \return file The new file
 **/
static
void*
H5VL_julea_file_create (const char* fname, unsigned flags, hid_t fcpl_id, hid_t fapl_id, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_file_create(fname,flags,fcpl_id,fapl_id,dxpl_id,req);
}

/**
 * Opens a file
 *
 * \return file The file
 **/
static
void*
H5VL_julea_file_open (const char* fname, unsigned flags, hid_t fapl_id, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_file_open(fname,flags,fapl_id,dxpl_id,req);
}

/**
 * Closes the file
 **/
static
herr_t
H5VL_julea_file_close (void* file, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_file_close(file,dxpl_id,req);
}

/**
 * Creates a new group
 *
 * \return group The new group
 **/
static
void*
H5VL_julea_group_create (void* obj, const H5VL_loc_params_t* loc_params, const char* name, hid_t lcpl_id, hid_t gcpl_id, hid_t gapl_id, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_group_create(obj,loc_params,name,lcpl_id,gcpl_id,gapl_id,dxpl_id,req);
}

/**
 * Opens a group
 *
 * \return group The group
 **/
static
void*
H5VL_julea_group_open (void* obj, const H5VL_loc_params_t* loc_params, const char* name, hid_t gapl_id, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_group_open(obj,loc_params,name,gapl_id,dxpl_id,req);
}

/**
 * Closes the group
 **/
static
herr_t
H5VL_julea_group_close (void* grp, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_group_close(grp,dxpl_id,req);
}

/**
 * Creates a new dataset
 *
 * \return dset The new dataset
 **/
static
void*
H5VL_julea_dataset_create (void* obj, const H5VL_loc_params_t* loc_params, const char* name, hid_t lcpl_id, hid_t type_id, hid_t space_id, hid_t dcpl_id, hid_t dapl_id, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_dataset_create(obj,loc_params,name,lcpl_id,type_id.space_id,dcpl_id,dapl_id,dxpl_id,req);
}

/**
 * Opens a dataset
 *
 * \return dset The dataset
 **/
static
void*
H5VL_julea_dataset_open (void* obj, const H5VL_loc_params_t* loc_params, const char* name, hid_t dapl_id, hid_t dxpl_id, void** req)
{
	return H5VL_julea_kv_dataset_open(obj,loc_params,name,dapl_id,dxpl_id,req);
}

/**
 * Reads the data from the dataset
 **/
static
herr_t
H5VL_julea_dataset_read (void* dset, hid_t mem_type_id  __attribute__((unused)), hid_t mem_space_id  __attribute__((unused)), hid_t file_space_id  __attribute__((unused)), hid_t plist_id  __attribute__((unused)), void* buf, void** req  __attribute__((unused)))
{
	return H5VL_julea_kv_dataset_read(dset,mem_type_id,mem_space_id,file_space_id,plist_id,buf,req);
}

/**
 * Provides get Functions of the dataset
 *
 * \return ret_value The error code
 **/
static
herr_t
H5VL_julea_dataset_get (void* dset, H5VL_dataset_get_t get_type, hid_t dxpl_id  __attribute__((unused)), void** req  __attribute__((unused)), va_list arguments)
{
	return H5VL_julea_kv_dataset_get(dset,get_type,dxpl_id,req,arguments);
}

/**
 * Writes the data to the dataset
 **/
static
herr_t
H5VL_julea_dataset_write (void* dset, hid_t mem_type_id  __attribute__((unused)), hid_t mem_space_id  __attribute__((unused)), hid_t file_space_id  __attribute__((unused)), hid_t plist_id  __attribute__((unused)), const void* buf, void** req  __attribute__((unused)))
{
	return H5VL_julea_kv_dataset_write(dset,mem_type_id,mem_space_id,file_space_id,plist_id,buf,req);
}

/**
 * Closes the dataset
 **/
static
herr_t
H5VL_julea_dataset_close (void* dset, hid_t dxpl_id  __attribute__((unused)), void** req  __attribute__((unused)))
{
	return H5VL_julea_kv_dataset_close(dset,dxpl_id,req);
}

/**
 * The class providing the functions to HDF5
 **/
static
const
H5VL_class_t H5VL_julea_g =
{
	0,
	JULEA,
	"julea",	  /* name */
	0,
	H5VL_julea_init, /* initialize */
	H5VL_julea_term, /* terminate */
	{
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	},
	{
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	},
	{
		/* attribute_cls */
		H5VL_julea_attr_create, /* create */
		H5VL_julea_attr_open,   /* open */
		H5VL_julea_attr_read,   /* read */
		H5VL_julea_attr_write,  /* write */
		H5VL_julea_attr_get,	/* get */
		NULL,					 //H5VL_julea_attr_specific,              /* specific */
		NULL,					 //H5VL_julea_attr_optional,              /* optional */
		H5VL_julea_attr_close   /* close */
	},
	{
		/* dataset_cls */
		H5VL_julea_dataset_create, /* create */
		H5VL_julea_dataset_open,   /* open */
		H5VL_julea_dataset_read,   /* read */
		H5VL_julea_dataset_write,  /* write */
		H5VL_julea_dataset_get,	/* get */
		NULL,						//H5VL_julea_dataset_specific,          /* specific */
		NULL,						//H5VL_julea_dataset_optional,          /* optional */
		H5VL_julea_dataset_close   /* close */
	},
	{
		/* datatype_cls */
		NULL, //H5VL_julea_datatype_commit, /* commit */
		NULL, //H5VL_julea_datatype_open,   /* open */
		NULL, //H5VL_julea_datatype_get,	/* get_size */
		NULL,						 //H5VL_julea_datatype_specific,         /* specific */
		NULL,						 //H5VL_julea_datatype_optional,         /* optional */
		NULL, //H5VL_julea_datatype_close   /* close */
	},
	{
		/* file_cls */
		H5VL_julea_file_create, /* create */
		H5VL_julea_file_open,   /* open */
		NULL, //H5VL_julea_file_get,	/* get */
		NULL,					 //H5VL_julea_file_specific,            /* specific */
		NULL,					 //H5VL_julea_file_optional,            /* optional */
		H5VL_julea_file_close   /* close */
	},
	{
		/* group_cls */
		H5VL_julea_group_create, /* create */
		H5VL_julea_group_open,   /* open */
		NULL, //H5VL_julea_group_get,	/* get */
		NULL,					  //H5VL_julea_group_specific,           /* specific */
		NULL,					  //H5VL_julea_group_optional,           /* optional */
		H5VL_julea_group_close   /* close */
	},
	{
		/* link_cls */
		NULL, //H5VL_julea_link_create,                /* create */
		NULL, //H5VL_julea_link_copy,                  /* copy */
		NULL, //H5VL_julea_link_move,                  /* move */
		NULL, //H5VL_julea_link_get,                   /* get */
		NULL, //H5VL_julea_link_specific,              /* specific */
		NULL, //H5VL_julea_link_optional,              /* optional */
	},
	{
		/* object_cls */
		NULL, //H5VL_julea_object_open,                        /* open */
		NULL, //H5VL_julea_object_copy,                /* copy */
		NULL, //H5VL_julea_object_get,                 /* get */
		NULL, //H5VL_julea_object_specific,                    /* specific */
		NULL, //H5VL_julea_object_optional,            /* optional */
	},
	{
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	},
	NULL
};

/**
 * Provides the plugin type
 **/
H5PL_type_t
H5PLget_plugin_type (void)
{
	return H5PL_TYPE_VOL;
}

/**
 * Provides a pointer to the plugin structure
 **/
const void*
H5PLget_plugin_info (void)
{
	return &H5VL_julea_g;
}
