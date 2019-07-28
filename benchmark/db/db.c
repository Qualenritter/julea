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
#ifdef JULEA_DEBUG
static gdouble target_time = 1;
#else
static gdouble target_time = 60;
#endif

static void
exec_tests(guint n)
{
	benchmark_db_schema(target_time, n);
	benchmark_db_entry(target_time, n);
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
void
benchmark_db(void)
{
#ifdef JULEA_DEBUG
	exec_tree1(0, 1, 5);
#else
	guint i;
	for (i = 0; i < 7; i++)
		exec_tree1(i, 1, 1000000);
#endif
}
