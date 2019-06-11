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
#include <gmodule.h>

#include <julea.h>

static gboolean
backend_init(gchar const* path)
{
	(void)path;
	return TRUE;
}
static void
backend_fini(void)
{
}
static gboolean
backend_attr_delete(const char* name, char* parent)
{
	(void)name;
	(void)parent;
	return TRUE;
}
static gboolean
backend_attr_create(const char* name, char* parent, bson_t* bson, char* key)
{
	*key = 0;
	(void)name;
	(void)parent;
	(void)bson;
	return TRUE;
}
static gboolean
backend_attr_open(const char* name, char* parent, bson_t* bson, char* key)
{
	*key = 0;
	(void)bson;
	(void)name;
	(void)parent;
	return TRUE;
}
static gboolean
backend_attr_read(char* key, bson_t* bson)
{
	(void)bson;
	(void)key;
	return TRUE;
}
static gboolean
backend_attr_write(char* key, bson_t* bson)
{
	(void)key;
	(void)bson;
	return TRUE;
}
static gboolean
backend_file_create(const char* name, bson_t* bson, char* key)
{
	(void)name;
	(void)bson;
	*key = 0;
	return TRUE;
}
static gboolean
backend_file_delete(const char* name)
{
	(void)name;
	return TRUE;
}
static gboolean
backend_file_open(const char* name, bson_t* bson, char* key)
{
	(void)name;
	(void)bson;
	*key = 0;
	return TRUE;
}
static gboolean
backend_dataset_create(const char* name, char* parent, bson_t* bson, char* key)
{
	(void)name;
	(void)parent;
	(void)bson;
	*key = 0;
	return TRUE;
}
static gboolean
backend_dataset_delete(const char* name, char* parent)
{
	(void)name;
	(void)parent;
	return TRUE;
}
static gboolean
backend_dataset_open(const char* name, char* parent, bson_t* bson, char* key)
{
	(void)name;
	(void)parent;
	(void)bson;
	*key = 0;
	return TRUE;
}

static JBackend null_backend = { .type = J_BACKEND_TYPE_SMD,
	.component = J_BACKEND_COMPONENT_CLIENT | J_BACKEND_COMPONENT_SERVER,
	.smd = { .backend_init = backend_init, .backend_fini = backend_fini, .backend_attr_create = backend_attr_create, .backend_attr_delete = backend_attr_delete, .backend_attr_open = backend_attr_open, .backend_attr_read = backend_attr_read, .backend_attr_write = backend_attr_write, .backend_file_create = backend_file_create, .backend_file_delete = backend_file_delete, .backend_file_open = backend_file_open, .backend_dataset_create = backend_dataset_create, .backend_dataset_delete = backend_dataset_delete, .backend_dataset_open = backend_dataset_open } };
G_MODULE_EXPORT
JBackend*
backend_info(void)
{
	return &null_backend;
}
