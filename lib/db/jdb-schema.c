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

JDBSchema*
j_db_schema_new(gchar const* namespace, gchar const* name, GError** error)
{
	JDBSchema* schema = NULL;
	if (!namespace)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_NAMESPACE_NULL, "namespace must not be NULL");
		goto _error;
	}
	if (!name)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_NAME_NULL, "name must not be NULL");
		goto _error;
	}
	schema = g_slice_new(JDBSchema);
	schema->namespace = g_strdup(namespace);
	schema->name = g_strdup(name);
	schema->bson_initialized = FALSE;
	schema->bson_index_initialized = FALSE;
	schema->ref_count = 1;
	schema->server_side = FALSE;
	bson_init(&schema->bson);
	return schema;
_error:
	return NULL;
}
JDBSchema*
j_db_schema_ref(JDBSchema* schema, GError** error)
{

	if (!schema)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
		goto _error;
	}
	g_atomic_int_inc(&schema->ref_count);
	return schema;
_error:
	return NULL;
}
void
j_db_schema_unref(JDBSchema* schema)
{
	if (schema && g_atomic_int_dec_and_test(&schema->ref_count))
	{
		g_free(schema->namespace);
		g_free(schema->name);
		if (schema->bson_initialized)
			bson_destroy(&schema->bson);
		g_slice_free(JDBSchema, schema);
	}
}
gboolean
j_db_schema_add_field(JDBSchema* schema, gchar const* name, JDBType type, GError** error)
{
	JDBType_value val;
	bson_iter_t iter;
	if (!schema)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
		goto _error;
	}
	if (!name)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_VARIABLE_NAME_NULL, "variable name must not be NULL");
		goto _error;
	}
	if (type >= _J_DB_TYPE_COUNT)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_TYPE_INVALID, "db type invalid");
		goto _error;
	}
	if (schema->server_side)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_SERVER, "schema must not be modified after it is applied");
		goto _error;
	}
	if (!schema->bson_initialized)
	{
		if (!j_bson_init(&schema->bson, error))
			goto _error;
		schema->bson_initialized = TRUE;
	}
	if (!j_bson_iter_init(&iter, &schema->bson, error))
		goto _error;
	if (!j_bson_iter_not_find(&iter, name, error))
		goto _error;
	val.val_uint32 = type;
	if (!j_bson_append_value(&schema->bson, name, type, &val, error))
		goto _error;
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_db_schema_get_field(JDBSchema* schema, gchar const* name, JDBType* type, GError** error)
{
	JDBType_value val;
	bson_iter_t iter;
	if (!schema)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
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
	if (!schema->bson_initialized || !g_strcmp0(name, "_index"))
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_VARIABLE_NOT_FOUND, "variable not found");
		goto _error;
	}
	if (!j_bson_iter_init(&iter, &schema->bson, error))
		goto _error;
	if (!j_bson_iter_find(&iter, name, error))
		goto _error;
	if (!j_bson_iter_value(&iter, J_DB_TYPE_UINT32, &val, error))
		goto _error;
	*type = val.val_uint32;
	return TRUE;
_error:
	return FALSE;
}
guint32
j_db_schema_get_all_fields(JDBSchema* schema, gchar*** names, JDBType** types, GError** error)
{
	bson_iter_t iter;
	guint count;
	guint i;
	JDBType_value val;
	const char* key;
	*names = NULL;
	*types = NULL;
	if (!schema)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
		goto _error;
	}
	if (!names)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_VARIABLE_NAME_NULL, "variable name must not be NULL");
		goto _error;
	}
	if (!types)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_TYPE_NULL, "type must not be NULL");
		goto _error;
	}
	if (!schema->bson_initialized)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_VARIABLE_NOT_FOUND, "variable not found");
		goto _error;
	}
	if (!j_bson_iter_init(&iter, &schema->bson, error))
		goto _error;
	if (!j_bson_count_keys(&schema->bson, &count, error))
		goto _error;
	count++;
	*names = g_new(gchar*, count);
	*types = g_new(JDBType, count);
	i = 0;
	while (bson_iter_next(&iter))
	{
		key = j_bson_iter_key(&iter, error);
		if (!key)
			goto _error;
		if (g_strcmp0(key, "_index"))
		{
			if (!j_bson_iter_value(&iter, J_DB_TYPE_UINT32, &val, error))
				goto _error;
			(*names)[i] = g_strdup(key);
			(*types)[i] = val.val_uint32;
			i++;
		}
	}
	(*names)[i] = NULL;
	(*types)[i] = _J_DB_TYPE_COUNT;
	return TRUE;
_error:
	/*TODO free names*/
	/*TODO free types*/
	return FALSE;
}
gboolean
j_db_schema_add_index(JDBSchema* schema, gchar const** names, GError** error)
{
	/*TODO prevent double insert same index*/
	/*TODO check indexed column already exist*/
	guint i;
	bson_t bson;
	JDBType_value val;
	const char* key;
	char buf[20];
	gchar const** name;
	if (!schema)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
		goto _error;
	}
	if (!names || !*names)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_VARIABLE_NAME_NULL, "variable name must not be NULL");
		goto _error;
	}
	if (schema->server_side)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_SERVER, "schema must not be modified after it is applied");
		goto _error;
	}
	if (!schema->bson_index_initialized)
	{
		if (!j_bson_init(&schema->bson_index, error))
			goto _error;
		schema->bson_index_count = 0;
		schema->bson_index_initialized = TRUE;
	}
	if (!j_bson_array_generate_key(schema->bson_index_count, &key, buf, sizeof(buf), error))
		goto _error;
	if (!j_bson_append_array_begin(&schema->bson_index, key, &bson, error))
		goto _error;
	i = 0;
	name = names;
	while (name)
	{
		if (*name)
		{
			if (!j_bson_array_generate_key(i, &key, buf, sizeof(buf), error))
				goto _error;
			val.val_string = *name;
			if (!j_bson_append_value(&bson, key, J_DB_TYPE_STRING, &val, error))
				goto _error;
			name++;
		}
		i++;
	}
	if (!j_bson_append_array_end(&schema->bson_index, &bson, error))
		goto _error;
	schema->bson_index_count++;
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_db_schema_create(JDBSchema* schema, JBatch* batch, GError** error)
{
	if (!schema)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
		goto _error;
	}
	if (!batch)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_BATCH_NULL, "batch must not be NULL");
		goto _error;
	}
	if (schema->server_side)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_SERVER, "schema must not be created multiple times");
		goto _error;
	}
	if (!schema->bson_initialized)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NOT_INITIALIZED, "schema must not be empty");
		goto _error;
	}
	if (schema->bson_index_initialized)
	{
		if (!j_bson_append_array(&schema->bson, "_index", &schema->bson_index, error))
			goto _error;
	}
	schema->server_side = TRUE;
	if (!j_db_internal_schema_create(schema->namespace, schema->name, &schema->bson, batch, error))
		goto _error;
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_db_schema_get(JDBSchema* schema, JBatch* batch, GError** error)
{
	if (!schema)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
		goto _error;
	}
	if (!batch)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_BATCH_NULL, "batch must not be NULL");
		goto _error;
	}
	if (schema->server_side)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_SERVER, "schema already synchronized with server");
		goto _error;
	}
	if (schema->bson_initialized)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_INITIALIZED, "schema must be empty");
		goto _error;
	}
	schema->server_side = TRUE;
	schema->bson_initialized = TRUE;
	if (!j_db_internal_schema_get(schema->namespace, schema->name, &schema->bson, batch, error))
		goto _error;
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_db_schema_delete(JDBSchema* schema, JBatch* batch, GError** error)
{
	if (!schema)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
		goto _error;
	}
	if (!batch)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_BATCH_NULL, "batch must not be NULL");
		goto _error;
	}
	if (!j_db_internal_schema_delete(schema->namespace, schema->name, batch, error))
		goto _error;
	return TRUE;
_error:
	return FALSE;
}

gboolean
j_db_schema_equals(JDBSchema* schema1, JDBSchema* schema2, gboolean* equal, GError** error)
{
	guint schema1_count;
	guint schema2_count;
	bson_iter_t iter1;
	bson_iter_t iter2;
	JDBType_value val1;
	JDBType_value val2;
	gint ret;
	gboolean has_next;
	const char* key;
	if (!schema1 || !schema2)
	{
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_SCHEMA_NULL, "schema must not be NULL");
		goto _error;
	}
	if (schema1 == schema2)
	{
		*equal = TRUE;
	}
	else
	{
		*equal = TRUE;
		*equal = *equal && !g_strcmp0(schema1->namespace, schema2->namespace);
		*equal = *equal && !g_strcmp0(schema1->name, schema2->name);
		*equal = *equal && (schema1->bson_initialized == schema2->bson_initialized);
		if (*equal && schema1->bson_initialized)
		{
			schema1_count = 0;
			schema2_count = 0;
			if (!j_bson_iter_init(&iter1, &schema1->bson, error))
				goto _error;
			while (TRUE)
			{
				if (!j_bson_iter_next(&iter1, &has_next, error))
					goto _error;
				if (!has_next)
					break;
				key = j_bson_iter_key(&iter1, error);
				if (!key)
					goto _error;
				if (g_strcmp0(key, "_index"))
				{
					schema1_count++;
					if (!j_bson_iter_init(&iter2, &schema2->bson, error))
						goto _error;
					ret = j_bson_iter_find(&iter2, key, NULL);
					*equal = *equal && ret;
					if (!*equal)
						break;
					if (!j_bson_iter_value(&iter1, J_DB_TYPE_UINT32, &val1, error))
						goto _error;
					if (!j_bson_iter_value(&iter2, J_DB_TYPE_UINT32, &val2, error))
						goto _error;
					*equal = *equal && val1.val_uint32 == val2.val_uint32;
				}
			}
			if (!j_bson_iter_init(&iter2, &schema2->bson, error))
				goto _error;
			ret = j_bson_iter_find(&iter2, "_index", NULL);
			if (ret)
				schema2_count++;
			*equal = *equal && schema1_count == schema2_count;
		}
	}
	return TRUE;
_error:
	return FALSE;
}
