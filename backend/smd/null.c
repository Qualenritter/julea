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

#include <julea-config.h>

#include <glib.h>
#include <gmodule.h>

#include <julea.h>
#include <julea-internal.h>

static gboolean
backend_init(gchar const* path)
{
	(void)path;
	return TRUE;
}
static void
backend_fini(void)
{}
static gboolean
backend_schema_create(gchar const* namespace, gchar const* name, bson_t const* schema)
{
	(void)namespace;
	(void)name;
	(void)schema;
	return TRUE;
}
static gboolean
backend_schema_get(gchar const* namespace, gchar const* name, bson_t* schema)
{
	(void)namespace;
	(void)name;
	(void)schema;
	return TRUE;
}
static gboolean
backend_schema_delete(gchar const* namespace, gchar const* name)
{
	(void)namespace;
	(void)name;
	return TRUE;
}
static gboolean
backend_insert(gchar const* namespace, gchar const* name, bson_t const* metadata)
{
	(void)namespace;
	(void)name;
	(void)metadata;
	return TRUE;
}
static gboolean
backend_update(gchar const* namespace, gchar const* name, bson_t const* selector, bson_t const* metadata)
{
	(void)namespace;
	(void)name;
	(void)selector;
	(void)metadata;
	return TRUE;
}
static gboolean
backend_delete(gchar const* namespace, gchar const* name, bson_t const* selector)
{
	(void)namespace;
	(void)name;
	(void)selector;
	return TRUE;
}
static gboolean
backend_query(gchar const* namespace, gchar const* name, bson_t const* selector, gpointer* iterator)
{
	(void)namespace;
	(void)name;
	(void)selector;
	(void)iterator;
	return TRUE;
}
static gboolean
backend_iterate(gpointer iterator, bson_t* metadata)
{
	(void)iterator;
	(void)metadata;
	return TRUE;
}
static JBackend null_backend = {
	.type = J_BACKEND_TYPE_SMD,
	.component = J_BACKEND_COMPONENT_CLIENT | J_BACKEND_COMPONENT_SERVER,
	.smd = {
		.backend_init = backend_init,
		.backend_fini = backend_fini,
		.backend_schema_create = backend_schema_create,
		.backend_schema_get = backend_schema_get,
		.backend_schema_delete = backend_schema_delete,
		.backend_insert = backend_insert,
		.backend_update = backend_update,
		.backend_delete = backend_delete,
		.backend_query = backend_query,
		.backend_iterate = backend_iterate,
	},
};

G_MODULE_EXPORT
JBackend*
backend_info(void)
{
	return &null_backend;
}
