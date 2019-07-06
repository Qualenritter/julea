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

#include <glib.h>

#include <string.h>

#include <bson.h>

#include <julea-smd.h>

#include <julea.h>
#include <julea-internal.h>

gboolean
smd_schema_create(gchar const* namespace, gchar const* name, bson_t const* schema)
{
	return TRUE;
}
gboolean
smd_schema_get(gchar const* namespace, gchar const* name, bson_t* schema)
{
	return TRUE;
}
gboolean
smd_schema_delete(gchar const* namespace, gchar const* name)
{
	return TRUE;
}
gboolean
smd_insert(gchar const* namespace, gchar const* name, bson_t const* metadata)
{
	return TRUE;
}
gboolean
smd_update(gchar const* namespace, gchar const* name, bson_t const* selector, bson_t const* metadata)
{
	return TRUE;
}
gboolean
smd_delete(gchar const* namespace, gchar const* name, bson_t const* selector)
{
	return TRUE;
}
gboolean
smd_query(gchar const* namespace, gchar const* name, bson_t const* selector, gpointer* iterator)
{
	return TRUE;
}
gboolean
smd_iterate(gpointer iterator, bson_t* metadata)
{
	return TRUE;
}
