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

#include <julea.h>
#include <julea-internal.h>
#include <julea-smd-internal.h>
#include <julea-smd-schema.h>

JSMDSchema*
j_smd_schema_new(gchar const* namespace, gchar const* name, GError** error)
{
	JSMDSchema* schema;
	j_goto_error_frontend(!namespace, JULEA_FRONTEND_ERROR_NAMESPACE_NULL, "");
	j_goto_error_frontend(!name, JULEA_FRONTEND_ERROR_NAME_NULL, "");
	schema = g_slice_new(JSMDSchema);
	schema->namespace = g_strdup(namespace);
	schema->name = g_strdup(name);
	schema->bson_initialized = FALSE;
	schema->ref_count = 1;
	bson_init(&schema->bson);
	return schema;
_error:
	return NULL;
}
JSMDSchema*
j_smd_schema_ref(JSMDSchema* schema, GError** error)
{
	j_goto_error_frontend(!schema, JULEA_FRONTEND_ERROR_SCHEMA_NULL, "");
	g_atomic_int_inc(&schema->ref_count);
	return schema;
_error:
	return NULL;
}
void
j_smd_schema_unref(JSMDSchema* schema, GError** error)
{
	j_goto_error_frontend(!schema, JULEA_FRONTEND_ERROR_SCHEMA_NULL, "");
	if (g_atomic_int_dec_and_test(&schema->ref_count))
	{
		g_free(schema->namespace);
		g_free(schema->name);
		if (schema->bson_initialized)
			bson_destroy(&schema->bson);
		g_slice_free(JSMDSchema, schema);
	}
_error:;
}
gboolean
j_smd_schema_add_field(JSMDSchema* schema, gchar const* name, JSMDType type, GError** error)
{
	gint ret;
	bson_iter_t iter;
	j_goto_error_frontend(!schema, JULEA_FRONTEND_ERROR_SCHEMA_NULL, "");
	j_goto_error_frontend(!name, JULEA_FRONTEND_ERROR_NAME_NULL, "");
	j_goto_error_frontend(type >= _J_SMD_TYPE_COUNT, JULEA_FRONTEND_ERROR_SMD_TYPE_INVALID, "");
	if (!schema->bson_initialized)
	{
		bson_init(&schema->bson);
		schema->bson_initialized = TRUE;
	}
	ret = bson_iter_init(&iter, &schema->bson);
	j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_ITER_INIT, "");
	ret = bson_iter_find(&iter, name);
	j_goto_error_frontend(ret, JULEA_FRONTEND_ERROR_BSON_KEY_FOUND, "");
	ret = bson_append_int32(&schema->bson, name, -1, type);
	j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "");
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_smd_schema_get_field(JSMDSchema* schema, gchar const* name, JSMDType* type, GError** error)
{
	j_goto_error_frontend(!schema, JULEA_FRONTEND_ERROR_SCHEMA_NULL, "");
	return TRUE;
_error:
	return FALSE;
}
guint32
j_smd_schema_get_all_fields(JSMDSchema* schema, gchar const*** names, JSMDType** types, GError** error)
{
	j_goto_error_frontend(!schema, JULEA_FRONTEND_ERROR_SCHEMA_NULL, "");
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_smd_schema_add_index(JSMDSchema* schema, gchar const* name, GError** error)
{
	j_goto_error_frontend(!schema, JULEA_FRONTEND_ERROR_SCHEMA_NULL, "");
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_smd_schema_create(JSMDSchema* schema, JBatch* batch, GError** error)
{
	j_goto_error_frontend(!schema, JULEA_FRONTEND_ERROR_SCHEMA_NULL, "");
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_smd_schema_get(JSMDSchema* schema, JBatch* batch, GError** error)
{
	j_goto_error_frontend(!schema, JULEA_FRONTEND_ERROR_SCHEMA_NULL, "");
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_smd_schema_delete(JSMDSchema* schema, JBatch* batch, GError** error)
{
	j_goto_error_frontend(!schema, JULEA_FRONTEND_ERROR_SCHEMA_NULL, "");
	return TRUE;
_error:
	return FALSE;
}
