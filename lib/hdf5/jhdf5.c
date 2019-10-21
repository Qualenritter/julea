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

#define H5Sencode_vers 1

#include <julea-config.h>

#include <hdf5.h>
#include <H5PLextern.h>

#include "jhdf5-db.c"
#include "jhdf5-kv.c"

#define _GNU_SOURCE

enum JHDF5Implementation
{
	J_HDF5_IMPLEMENTATION_KV = 0,
	J_HDF5_IMPLEMENTATION_DB,
	_J_HDF5_IMPLEMENTATION_COUNT
};

typedef enum JHDF5Implementation JHDF5Implementation;

static
JHDF5Implementation hdf5_implementation_to_use = J_HDF5_IMPLEMENTATION_DB;

/**
 * Provides the plugin type
 **/
H5PL_type_t
H5PLget_plugin_type(void)
{
	J_TRACE_FUNCTION(NULL);

	g_debug("H5PLget_plugin_type");
	return H5PL_TYPE_VOL;
}

/**
 * Provides a pointer to the plugin structure
 **/
const void*
H5PLget_plugin_info(void)
{
	J_TRACE_FUNCTION(NULL);

	g_debug("H5PLget_plugin_info");

	//FIXME override hdf5_implementation_to_use with environment variable?
	//FIXME override hdf5_implementation_to_use within julea-test AT RUNTIME to test all (different) implementations?
	switch (hdf5_implementation_to_use)
	{
	case J_HDF5_IMPLEMENTATION_KV:
		return &H5VL_julea_kv_g;
	case J_HDF5_IMPLEMENTATION_DB:
		return &H5VL_julea_db_g;
	case _J_HDF5_IMPLEMENTATION_COUNT:
	default:
		return NULL;
	}
}
