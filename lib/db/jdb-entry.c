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
#include <jtrace-internal.h>
#include <db/jdb-internal.h>
#include <julea-db.h>
#include <core/jbson-wrapper.h>

JDBEntry*
j_db_entry_new(JDBSchema* schema, GError** error)
{
	JDBEntry* entry = NULL;

	j_trace_enter(G_STRFUNC, NULL);
	if (G_UNLIKELY(!schema))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
		goto _error;
	}
	entry = g_slice_new(JDBEntry);
	if (G_UNLIKELY(!j_bson_init(&entry->bson, error)))
	{
		goto _error;
	}
	entry->ref_count = 1;
	entry->schema = j_db_schema_ref(schema, error);
	if (G_UNLIKELY(!entry->schema))
	{
		goto _error;
	}
	j_trace_leave(G_STRFUNC);
	return entry;
_error:
	j_db_entry_unref(entry);
	j_trace_leave(G_STRFUNC);
	return NULL;
}
JDBEntry*
j_db_entry_ref(JDBEntry* entry, GError** error)
{
	j_trace_enter(G_STRFUNC, NULL);
	if (G_UNLIKELY(!entry))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_ENTRY_NULL, "entry must not be NULL");
		goto _error;
	}
	g_atomic_int_inc(&entry->ref_count);
	j_trace_leave(G_STRFUNC);
	return entry;
_error:
	j_trace_leave(G_STRFUNC);
	return NULL;
}
void
j_db_entry_unref(JDBEntry* entry)
{
	j_trace_enter(G_STRFUNC, NULL);
	if (entry && g_atomic_int_dec_and_test(&entry->ref_count))
	{
		j_db_schema_unref(entry->schema);
		j_bson_destroy(&entry->bson);
		g_slice_free(JDBEntry, entry);
	}
	j_trace_leave(G_STRFUNC);
}
gboolean
j_db_entry_set_field(JDBEntry* entry, gchar const* name, gconstpointer value, guint64 length, GError** error)
{
	JDBType type;
	gboolean ret;
	JDBTypeValue val;

	j_trace_enter(G_STRFUNC, NULL);
	if (G_UNLIKELY(!entry))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_ENTRY_NULL, "entry must not be NULL");
		goto _error;
	}
	if (G_UNLIKELY(!name))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_VARIABLE_NAME_NULL, "variable name must not be NULL");
		goto _error;
	}
	if (G_UNLIKELY(!j_db_schema_get_field(entry->schema, name, &type, error)))
	{
		goto _error;
	}
	if (G_UNLIKELY(!j_bson_has_field(&entry->bson, name, &ret, error)))
	{
		goto _error;
	}
	if (G_UNLIKELY(ret))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_VARIABLE_ALREADY_SET, "variable value must not be set more than once");
		goto _error;
	}
	switch (type)
	{
	case J_DB_TYPE_SINT32:
		val.val_sint32 = *(const gint32*)value;
		break;
	case J_DB_TYPE_UINT32:
		val.val_uint32 = *(const guint32*)value;
		break;
	case J_DB_TYPE_SINT64:
		val.val_sint64 = *(const gint64*)value;
		break;
	case J_DB_TYPE_UINT64:
		val.val_uint64 = *(const guint64*)value;
		break;
	case J_DB_TYPE_FLOAT32:
		val.val_float32 = *(const gfloat*)value;
		break;
	case J_DB_TYPE_FLOAT64:
		val.val_float64 = *(const gdouble*)value;
		break;
	case J_DB_TYPE_STRING:
		val.val_string = (const char*)value;
		break;
	case J_DB_TYPE_BLOB:
		val.val_blob = (const char*)value;
		val.val_blob_length = length;
		break;
	case _J_DB_TYPE_COUNT:
	default:;
	}
	if (G_UNLIKELY(!j_bson_append_value(&entry->bson, name, type, &val, error)))
	{
		goto _error;
	}
	j_trace_leave(G_STRFUNC);
	return TRUE;
_error:
	j_trace_leave(G_STRFUNC);
	return FALSE;
}
gboolean
j_db_entry_insert(JDBEntry* entry, JBatch* batch, GError** error)
{
	j_trace_enter(G_STRFUNC, NULL);
	if (G_UNLIKELY(!entry))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_ENTRY_NULL, "entry must not be NULL");
		goto _error;
	}
	if (G_UNLIKELY(!batch))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_BATCH_NULL, "batch must not be NULL");
		goto _error;
	}
	if (G_UNLIKELY(!j_db_internal_insert(entry->schema->namespace, entry->schema->name, &entry->bson, batch, error)))
	{
		goto _error;
	}
	j_trace_leave(G_STRFUNC);
	return TRUE;
_error:
	j_trace_leave(G_STRFUNC);
	return FALSE;
}
gboolean
j_db_entry_update(JDBEntry* entry, JDBSelector* selector, JBatch* batch, GError** error)
{
	bson_t* bson;

	j_trace_enter(G_STRFUNC, NULL);
	if (G_UNLIKELY(!entry))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_ENTRY_NULL, "entry must not be NULL");
		goto _error;
	}
	if (G_UNLIKELY(!batch))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_BATCH_NULL, "batch must not be NULL");
		goto _error;
	}
	if (G_UNLIKELY(!selector))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SELECTOR_NULL, "selector must not be NULL");
		goto _error;
	}
	bson = j_db_selector_get_bson(selector);
	if (G_UNLIKELY(!bson))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SELECTOR_NULL, "selector must not be NULL");
		goto _error;
	}
	if (G_UNLIKELY(!j_db_internal_update(entry->schema->namespace, entry->schema->name, bson, &entry->bson, batch, error)))
	{
		goto _error;
	}
	j_trace_leave(G_STRFUNC);
	return TRUE;
_error:
	j_trace_leave(G_STRFUNC);
	return FALSE;
}
gboolean
j_db_entry_delete(JDBEntry* entry, JDBSelector* selector, JBatch* batch, GError** error)
{
	j_trace_enter(G_STRFUNC, NULL);
	if (G_UNLIKELY(!entry))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_ENTRY_NULL, "entry must not be NULL");
		goto _error;
	}
	if (G_UNLIKELY(!batch))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_BATCH_NULL, "batch must not be NULL");
		goto _error;
	}
	if (G_UNLIKELY(!j_db_internal_delete(entry->schema->namespace, entry->schema->name, j_db_selector_get_bson(selector), batch, error)))
	{
		goto _error;
	}
	j_trace_leave(G_STRFUNC);
	return TRUE;
_error:
	j_trace_leave(G_STRFUNC);
	return FALSE;
}