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
#include <julea.h>
#include <julea-db.h>
#include <julea-object.h>
#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#ifdef JULEA_HDF_COMPILES
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "jhdf5-db.h"

#define _GNU_SOURCE

static herr_t
H5VL_julea_db_group_init(hid_t vipl_id)
{
	return 0;
}
herr_t
H5VL_julea_db_group_term(void)
{
	return 0;
}

static void*
H5VL_julea_db_group_create(void* obj, const H5VL_loc_params_t* loc_params, const char* name,
	hid_t lcpl_id, hid_t gcpl_id, hid_t gapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);

	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static void*
H5VL_julea_db_group_open(void* obj, const H5VL_loc_params_t* loc_params, const char* name,
	hid_t gapl_id, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);

	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_group_get(void* obj, H5VL_group_get_t get_type, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);

	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_group_specific(void* obj, H5VL_group_specific_t specific_type,
	hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);

	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_group_optional(void* obj, hid_t dxpl_id, void** req, va_list arguments)
{
	J_TRACE_FUNCTION(NULL);

	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}
static herr_t
H5VL_julea_db_group_close(void* grp, hid_t dxpl_id, void** req)
{
	J_TRACE_FUNCTION(NULL);

	g_critical("%s NOT implemented !!", G_STRLOC);
	abort();
}

#pragma GCC diagnostic pop
#endif
