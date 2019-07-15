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
#include <smd/jsmd-internal.h>
#include <julea-smd.h>

JSMDEntry*
j_smd_entry_new(JSMDSchema* schema, GError** error)
{
	JSMDEntry* entry = NULL;
	j_goto_error_frontend(!schema, JULEA_FRONTEND_ERROR_SCHEMA_NULL, "");
	entry = g_slice_new(JSMDEntry);
	bson_init(&entry->bson);
	entry->ref_count = 1;
	entry->selector = NULL;
	entry->schema = j_smd_schema_ref(schema, error);
	j_goto_error_subcommand(!entry->schema);
	return entry;
_error:
	j_smd_entry_unref(entry);
	return NULL;
}
JSMDEntry*
j_smd_entry_ref(JSMDEntry* entry, GError** error)
{
	j_goto_error_frontend(!entry, JULEA_FRONTEND_ERROR_ENTRY_NULL, "");
	g_atomic_int_inc(&entry->ref_count);
	return entry;
_error:
	return NULL;
}
void
j_smd_entry_unref(JSMDEntry* entry)
{
	if (entry && g_atomic_int_dec_and_test(&entry->ref_count))
	{
		j_smd_selector_unref(entry->selector);
		j_smd_schema_unref(entry->schema);
		bson_destroy(&entry->bson);
		g_slice_free(JSMDEntry, entry);
	}
}
gboolean
j_smd_entry_set_field(JSMDEntry* entry, gchar const* name, gconstpointer value, guint64 length, GError** error)
{
	JSMDType type;
	gboolean ret;
	j_goto_error_frontend(!entry, JULEA_FRONTEND_ERROR_ENTRY_NULL, "");
	j_goto_error_frontend(!name, JULEA_FRONTEND_ERROR_VARIABLE_NAME_NULL, "");
	ret = j_smd_schema_get_field(entry->schema, name, &type, error);
	j_goto_error_subcommand(!ret);
	ret = bson_has_field(&entry->bson, name);
	j_goto_error_frontend(ret, JULEA_FRONTEND_ERROR_VARIABLE_ALREADY_SET, "");
	switch (type)
	{
	case J_SMD_TYPE_SINT32:
		ret = bson_append_int32(&entry->bson, name, -1, *(gint32 const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "SINT32");
		break;
	case J_SMD_TYPE_UINT32:
		ret = bson_append_int32(&entry->bson, name, -1, *(guint32 const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "UINT32");
		break;
	case J_SMD_TYPE_FLOAT32:
		ret = bson_append_double(&entry->bson, name, -1, *(gfloat const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "FLOAT32");
		break;
	case J_SMD_TYPE_SINT64:
		ret = bson_append_int64(&entry->bson, name, -1, *(gint64 const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "SINT64");
		break;
	case J_SMD_TYPE_UINT64:
		ret = bson_append_int64(&entry->bson, name, -1, *(guint64 const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "UINT64");
		break;
	case J_SMD_TYPE_FLOAT64:
		ret = bson_append_double(&entry->bson, name, -1, *(gdouble const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "FLOAT64");
		break;
	case J_SMD_TYPE_STRING:
		ret = bson_append_utf8(&entry->bson, name, -1, value, -1);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "STRING");
		break;
	case J_SMD_TYPE_BLOB:
		if (value)
			ret = bson_append_binary(&entry->bson, name, -1, BSON_SUBTYPE_BINARY, value, length);
		else
			ret = bson_append_null(&entry->bson, name, -1);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "BLOB");
		break;
	case _J_SMD_TYPE_COUNT:
	default:
		j_goto_error_frontend(TRUE, JULEA_FRONTEND_ERROR_SMD_TYPE_INVALID, "");
	}
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_smd_entry_set_selector(JSMDEntry* entry, JSMDSelector* selector, GError** error)
{
	j_goto_error_frontend(!entry, JULEA_FRONTEND_ERROR_ENTRY_NULL, "");
	j_smd_selector_unref(entry->selector);
	entry->selector = j_smd_selector_ref(selector, error);
	j_goto_error_subcommand(!entry->selector);
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_smd_entry_insert(JSMDEntry* entry, JBatch* batch, GError** error)
{
	gint ret;
	j_goto_error_frontend(!entry, JULEA_FRONTEND_ERROR_ENTRY_NULL, "");
	j_goto_error_frontend(!batch, JULEA_FRONTEND_ERROR_BATCH_NULL, "");
	ret = j_smd_internal_insert(entry->schema->namespace, entry->schema->name, &entry->bson, batch, error);
	j_goto_error_subcommand(!ret);
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_smd_entry_update(JSMDEntry* entry, JBatch* batch, GError** error)
{
	gint ret;
	j_goto_error_frontend(!entry, JULEA_FRONTEND_ERROR_ENTRY_NULL, "");
	j_goto_error_frontend(!batch, JULEA_FRONTEND_ERROR_BATCH_NULL, "");
	ret = j_smd_internal_update(entry->schema->namespace, entry->schema->name, &entry->selector->bson, &entry->bson, batch, error);
	j_goto_error_subcommand(!ret);
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_smd_entry_delete(JSMDEntry* entry, JBatch* batch, GError** error)
{
	gint ret;
	j_goto_error_frontend(!entry, JULEA_FRONTEND_ERROR_ENTRY_NULL, "");
	j_goto_error_frontend(!batch, JULEA_FRONTEND_ERROR_BATCH_NULL, "");
	ret = j_smd_internal_delete(entry->schema->namespace, entry->schema->name, &entry->selector->bson, batch, error);
	j_goto_error_subcommand(!ret);
	return TRUE;
_error:
	return FALSE;
}
