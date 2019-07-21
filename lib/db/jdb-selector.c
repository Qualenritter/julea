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
#include <db/jdb-internal.h>
#include <julea-db.h>

JDBSelector*
j_db_selector_new(JDBSchema* schema, JDBSelectorMode mode, GError** error)
{
	gboolean ret;
	JDBSelector* selector = NULL;
	j_goto_error_frontend(mode >= _J_DB_SELECTOR_MODE_COUNT, JULEA_FRONTEND_ERROR_SELECTOR_MODE_INVALID, mode);
	selector = g_slice_new(JDBSelector);
	selector->ref_count = 1;
	selector->mode = mode;
	selector->bson_count = 0;
	bson_init(&selector->bson);
	selector->schema = j_db_schema_ref(schema, error);
	j_goto_error_subcommand(!selector->schema);
	ret = bson_append_int32(&selector->bson, "_mode", -1, mode);
	j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "");
	return selector;
_error:
	j_db_selector_unref(selector);
	return NULL;
}
JDBSelector*
j_db_selector_ref(JDBSelector* selector, GError** error)
{
	j_goto_error_frontend(!selector, JULEA_FRONTEND_ERROR_SELECTOR_NULL, "");
	g_atomic_int_inc(&selector->ref_count);
	return selector;
_error:
	return FALSE;
}
void
j_db_selector_unref(JDBSelector* selector)
{
	if (selector && g_atomic_int_dec_and_test(&selector->ref_count))
	{
		j_db_schema_unref(selector->schema);
		bson_destroy(&selector->bson);
		g_slice_free(JDBSelector, selector);
	}
}
gboolean
j_db_selector_add_field(JDBSelector* selector, gchar const* name, JDBOperator operator, gconstpointer value, guint64 length, GError** error)
{
	char buf[20];
	bson_t bson;
	JDBType type;
	gboolean ret;
	j_goto_error_frontend(!selector, JULEA_FRONTEND_ERROR_SELECTOR_NULL, "");
	ret = j_db_schema_get_field(selector->schema, name, &type, error);
	j_goto_error_subcommand(!ret);
	sprintf(buf, "%d", selector->bson_count);
	bson_append_document_begin(&selector->bson, buf, -1, &bson);
	ret = bson_append_utf8(&bson, "_name", -1, name, -1);
	j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "");
	ret = bson_append_int32(&bson, "_operator", -1, operator);
	j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "");
	switch (type)
	{
	case J_DB_TYPE_SINT32:
		ret = bson_append_int32(&bson, "_value", -1, *(gint32 const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "SINT32");
		break;
	case J_DB_TYPE_UINT32:
		ret = bson_append_int32(&bson, "_value", -1, *(guint32 const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "UINT32");
		break;
	case J_DB_TYPE_FLOAT32:
		ret = bson_append_double(&bson, "_value", -1, *(gfloat const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "FLOAT32");
		break;
	case J_DB_TYPE_SINT64:
		ret = bson_append_int64(&bson, "_value", -1, *(gint64 const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "SINT64");
		break;
	case J_DB_TYPE_UINT64:
		ret = bson_append_int64(&bson, "_value", -1, *(guint64 const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "UINT64");
		break;
	case J_DB_TYPE_FLOAT64:
		ret = bson_append_double(&bson, "_value", -1, *(gdouble const*)value);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "FLOAT64");
		break;
	case J_DB_TYPE_STRING:
		ret = bson_append_utf8(&bson, "_value", -1, value, -1);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "STRING");
		break;
	case J_DB_TYPE_BLOB:
		if (value)
			ret = bson_append_binary(&bson, "_value", -1, BSON_SUBTYPE_BINARY, value, length);
		else
			ret = bson_append_null(&bson, "_value", -1);
		j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "BLOB");
		break;
	case _J_DB_TYPE_COUNT:
	default:
		j_goto_error_frontend(TRUE, JULEA_FRONTEND_ERROR_DB_TYPE_INVALID, "");
	}
	bson_append_document_end(&selector->bson, &bson);
	selector->bson_count++;
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_db_selector_add_selector(JDBSelector* selector, JDBSelector* sub_selector, GError** error)
{
	char buf[20];
	gboolean ret;
	j_goto_error_frontend(!selector, JULEA_FRONTEND_ERROR_SELECTOR_NULL, "");
	j_goto_error_frontend(!sub_selector, JULEA_FRONTEND_ERROR_SELECTOR_NULL, "");
	j_goto_error_frontend(selector == sub_selector, JULEA_FRONTEND_ERROR_SELECTOR_EQUAL, "");
	sprintf(buf, "%d", selector->bson_count);
	ret = bson_append_document(&selector->bson, buf, -1, &sub_selector->bson);
	j_goto_error_frontend(!ret, JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED, "DOCUMENT");
	selector->bson_count += sub_selector->bson_count;
	return TRUE;
_error:
	return FALSE;
}

gboolean
j_db_selector_get_bson(JDBSelector* selector)
{
	if (selector && selector->bson_count > 0)
		return &selector->bson;
	return NULL;
}
