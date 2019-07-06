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
j_smd_schema_create(gchar const* namespace, gchar const* name, bson_t const* schema)
{
	JBackend* smd_backend;
	smd_backend = j_smd_backend();
	if (smd_backend != NULL)
	{
		return j_backend_smd_schema_create(smd_backend, namespace, name, schema);
	}
	else
		abort();
	return TRUE;
}
gboolean
j_smd_schema_get(gchar const* namespace, gchar const* name, bson_t* schema)
{
	JBackend* smd_backend;
	smd_backend = j_smd_backend();
	if (smd_backend != NULL)
	{
		return j_backend_smd_schema_get(smd_backend, namespace, name, schema);
	}
	else
		abort();
	return TRUE;
}
gboolean
j_smd_schema_delete(gchar const* namespace, gchar const* name)
{
	JBackend* smd_backend;
	smd_backend = j_smd_backend();
	if (smd_backend != NULL)
	{
		return j_backend_smd_schema_delete(smd_backend, namespace, name);
	}
	else
		abort();
	return TRUE;
}
gboolean
j_smd_insert(gchar const* namespace, gchar const* name, bson_t const* metadata)
{
	JBackend* smd_backend;
	smd_backend = j_smd_backend();
	if (smd_backend != NULL)
	{
		return j_backend_smd_insert(smd_backend, namespace, name, metadata);
	}
	else
		abort();
	return TRUE;
}
gboolean
j_smd_update(gchar const* namespace, gchar const* name, bson_t const* selector, bson_t const* metadata)
{
	JBackend* smd_backend;
	smd_backend = j_smd_backend();
	if (smd_backend != NULL)
	{
		return j_backend_smd_update(smd_backend, namespace, name, selector, metadata);
	}
	else
		abort();
	return TRUE;
}
gboolean
j_smd_delete(gchar const* namespace, gchar const* name, bson_t const* selector)
{
	JBackend* smd_backend;
	smd_backend = j_smd_backend();
	if (smd_backend != NULL)
	{
		return j_backend_smd_delete(smd_backend, namespace, name, selector);
	}
	else
		abort();
	return TRUE;
}
gboolean
j_smd_query(gchar const* namespace, gchar const* name, bson_t const* selector, gpointer* iterator)
{
	JBackend* smd_backend;
	smd_backend = j_smd_backend();
	if (smd_backend != NULL)
	{
		return j_backend_smd_query(smd_backend, namespace, name, selector, iterator);
	}
	else
		abort();
	return TRUE;
}
gboolean
j_smd_iterate(gpointer iterator, bson_t* metadata)
{
	JBackend* smd_backend;
	smd_backend = j_smd_backend();
	if (smd_backend != NULL)
	{
		return j_backend_smd_iterate(smd_backend, iterator, metadata);
	}
	else
		abort();
	return TRUE;
}
