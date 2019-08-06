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

#ifndef BENCHMAR_DB_H
#define BENCHMAR_DB_H

#include <julea-config.h>
#include <math.h>
#include <glib.h>
#include <string.h>
#include <julea-db.h>
#include <julea.h>
#include "benchmark.h"
#include <stdlib.h>
#include <unistd.h>
#include <jtrace-internal.h>

#ifdef JULEA_DEBUG
#define ERROR_PARAM &error
#define CHECK_ERROR(_ret_)                                                       \
	do                                                                       \
	{                                                                        \
		if (error)                                                       \
		{                                                                \
			g_debug("ERROR (%d) (%s)", error->code, error->message); \
			abort();                                                 \
		}                                                                \
		if (_ret_)                                                       \
		{                                                                \
			g_debug("ret was %d", _ret_);                            \
			abort();                                                 \
		}                                                                \
	} while (0)
#else
#define ERROR_PARAM NULL
#define CHECK_ERROR(_ret_)   \
	do                   \
	{                    \
		(void)error; \
		(void)_ret_; \
	} while (0)
#endif

void benchmark_db_schema(gdouble _target_time, guint _n);
void benchmark_db_entry(gdouble _target_time, guint _n);


#define SCALE_FACTOR_SSD_M2 1
#define SCALE_FACTOR_SSD_SATA 10
#define SCALE_FACTOR_HDD 100

#define scale_factor SCALE_FACTOR_HDD


#endif
