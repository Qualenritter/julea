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
#include <core/jbson-wrapper.h>

JDBIterator*
j_db_iterator_new(JDBSchema* schema, JDBSelector* selector, GError** error)
{
	guint ret;
	guint ret2 = FALSE;
	JBatch* batch;
	JDBIterator* iterator = NULL;
	if (!schema)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
		goto _error;
	}
	iterator = g_slice_new(JDBIterator);
	iterator->schema = j_db_schema_ref(schema, error);
	if (!iterator->schema)
		goto _error;
	if (selector)
	{
		iterator->selector = j_db_selector_ref(selector, error);
		if (!iterator->selector)
			goto _error;
	}
	else
		iterator->selector = NULL;
	iterator->iterator = NULL;
	iterator->ref_count = 1;
	iterator->valid = FALSE;
	iterator->bson_valid = FALSE;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	ret2 = j_db_internal_query(schema->namespace, schema->name, j_db_selector_get_bson(selector), &iterator->iterator, batch, error);
	ret = ret2 && j_batch_execute(batch);
	j_batch_unref(batch);
	if (!ret)
		goto _error;
	iterator->valid = TRUE;
	return iterator;
_error:
	if (ret2)
	{
		while (j_db_internal_iterate(iterator->iterator, NULL, NULL))
		{
			/*do nothing*/
		}
	}
	j_db_iterator_unref(iterator);
	return NULL;
}
JDBIterator*
j_db_iterator_ref(JDBIterator* iterator, GError** error)
{
	if (!iterator)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_ITERATOR_NULL, "iterator must not be NULL");
		goto _error;
	}
	g_atomic_int_inc(&iterator->ref_count);
	return iterator;
_error:
	return NULL;
}
void
j_db_iterator_unref(JDBIterator* iterator)
{
	if (iterator && g_atomic_int_dec_and_test(&iterator->ref_count))
	{
		while (iterator->valid)
			j_db_iterator_next(iterator, NULL);
		j_db_schema_unref(iterator->schema);
		j_db_selector_unref(iterator->selector);
		if (iterator->bson_valid)
			j_bson_destroy(&iterator->bson);
		g_slice_free(JDBIterator, iterator);
	}
}
gboolean
j_db_iterator_next(JDBIterator* iterator, GError** error)
{
	if (!iterator)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_ITERATOR_NULL, "iterator must not be NULL");
		goto _error;
	}
	if (!iterator->valid)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_ITERATOR_NO_MORE_ELEMENTS, "iterator no more elements");
		goto _error;
	}
	if (iterator->bson_valid)
		j_bson_destroy(&iterator->bson);
	if (!j_db_internal_iterate(iterator->iterator, &iterator->bson, error))
		goto _error2;
	iterator->bson_valid = TRUE;
	return TRUE;
_error2:
	iterator->valid = FALSE;
	iterator->bson_valid = FALSE;
_error:
	return FALSE;
}
gboolean
j_db_iterator_get_field(JDBIterator* iterator, gchar const* name, JDBType* type, gpointer* value, guint64* length, GError** error)
{
	JDBType_value val;
	bson_iter_t iter;
	if (!iterator)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_ITERATOR_NULL, "iterator must not be NULL");
		goto _error;
	}
	if (!iterator->bson_valid)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_ITERATOR_NOT_INITIALIZED, "iterator must be initialized");
		goto _error;
	}
	if (!name)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_VARIABLE_NAME_NULL, "variable name must not be NULL");
		goto _error;
	}
	if (!type)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_TYPE_NULL, "type must not be NULL");
		goto _error;
	}
	if (!value)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_VALUE_NULL, "value must not be NULL");
		goto _error;
	}
	if (!length)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_LENGTH_NULL, "length must not be NULL");
		goto _error;
	}
	if (!j_db_schema_get_field(iterator->schema, name, type, error))
		goto _error;
	if (!j_bson_iter_init(&iter, &iterator->bson, error))
		goto _error;
	if (!j_bson_iter_find(&iter, name, error))
		goto _error;
	if (!j_bson_iter_value(&iter, *type, &val, error))
		goto _error;
	switch (*type)
	{
	case J_DB_TYPE_SINT32:
		*value = g_new(gint32, 1);
		*((gint32*)*value) = val.val_sint32;
		*length = sizeof(gint32);
		break;
	case J_DB_TYPE_UINT32:
		*value = g_new(guint32, 1);
		*((guint32*)*value) = val.val_uint32;
		*length = sizeof(guint32);
		break;
	case J_DB_TYPE_FLOAT32:
		*value = g_new(gfloat, 1);
		*((gfloat*)*value) = val.val_float32;
		*length = sizeof(gfloat);
		break;
	case J_DB_TYPE_SINT64:
		*value = g_new(gint64, 1);
		*((gint64*)*value) = val.val_sint64;
		*length = sizeof(gint64);
		break;
	case J_DB_TYPE_UINT64:
		*value = g_new(guint64, 1);
		*((guint64*)*value) = val.val_uint64;
		*length = sizeof(guint64);
		break;
	case J_DB_TYPE_FLOAT64:
		*value = g_new(gdouble, 1);
		*((gdouble*)*value) = val.val_float64;
		*length = sizeof(gdouble);
		break;
	case J_DB_TYPE_STRING:
		*value = g_strdup(val.val_string);
		*length = strlen(val.val_string);
		break;
	case J_DB_TYPE_BLOB:
		*value = g_new(gchar, val.val_blob_length);
		memcpy(*value, val.val_blob, val.val_blob_length);
		*length = val.val_blob_length;
		break;
	case _J_DB_TYPE_COUNT:
	default:;
	}
	return TRUE;
_error:
	return FALSE;
}
