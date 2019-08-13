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
#include <db/jdb-internal.h>
#include <julea-db.h>
#include <core/jbson-wrapper.h>

JDBSchema*
j_db_schema_new(gchar const* namespace, gchar const* name, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	JDBSchema* schema = NULL;

	g_return_val_if_fail(namespace != NULL, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);
	(void)error;

	schema = g_slice_new(JDBSchema);
	schema->namespace = g_strdup(namespace);
	schema->name = g_strdup(name);
	schema->variables = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	schema->index = g_array_new(FALSE, FALSE, sizeof(JDBSchemaIndex));
	schema->bson_initialized = FALSE;
	schema->bson_index_initialized = FALSE;
	schema->ref_count = 1;
	schema->server_side = FALSE;
	bson_init(&schema->bson);
	return schema;
}
JDBSchema*
j_db_schema_ref(JDBSchema* schema, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	g_return_val_if_fail(schema != NULL, FALSE);
	(void)error;

	g_atomic_int_inc(&schema->ref_count);
	return schema;
}
void
j_db_schema_unref(JDBSchema* schema)
{
	J_TRACE_FUNCTION(NULL);

	guint i;
	JDBSchemaIndex* index;

	if (schema && g_atomic_int_dec_and_test(&schema->ref_count))
	{
		g_free(schema->namespace);
		g_free(schema->name);
		g_hash_table_unref(schema->variables);
		for (i = 0; i < schema->index->len; i++)
		{
			index = &g_array_index(schema->index, JDBSchemaIndex, i);
			g_hash_table_unref(index->variables);
		}
		g_array_unref(schema->index);
		if (schema->bson_initialized)
		{
			bson_destroy(&schema->bson);
		}
		if (schema->bson_index_initialized)
		{
			bson_destroy(&schema->bson_index);
		}
		g_slice_free(JDBSchema, schema);
	}
}
gboolean
j_db_schema_add_field(JDBSchema* schema, gchar const* name, JDBType type, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	JDBTypeValue val;
	bson_iter_t iter;

	g_return_val_if_fail(schema != NULL, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(type < _J_DB_TYPE_COUNT, FALSE);
	g_return_val_if_fail(!schema->server_side, FALSE);

	g_debug("add_field '%s'", name);

	if (!schema->bson_initialized)
	{
		if (G_UNLIKELY(!j_bson_init(&schema->bson, error)))
		{
			goto _error;
		}
		schema->bson_initialized = TRUE;
	}
	if (G_UNLIKELY(!j_bson_iter_init(&iter, &schema->bson, error)))
	{
		goto _error;
	}
	if (G_UNLIKELY(!j_bson_iter_not_find(&iter, name, error)))
	{
		goto _error;
	}
	val.val_uint32 = type;
	if (G_UNLIKELY(!j_bson_append_value(&schema->bson, name, J_DB_TYPE_UINT32, &val, error)))
	{
		goto _error;
	}
	g_hash_table_insert(schema->variables, g_strdup(name), GINT_TO_POINTER(type));
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_db_schema_get_field(JDBSchema* schema, gchar const* name, JDBType* type, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	JDBTypeValue val;
	bson_iter_t iter;

	g_return_val_if_fail(schema != NULL, FALSE);
	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(type != NULL, FALSE);
	g_return_val_if_fail(g_strcmp0(name, "_index"), FALSE);
	g_return_val_if_fail(schema->bson_initialized, FALSE);

	if (!g_strcmp0(name, "_id"))
	{
		*type = J_DB_TYPE_UINT32;
		goto _done;
	}
	if (G_UNLIKELY(!j_bson_iter_init(&iter, &schema->bson, error)))
	{
		goto _error;
	}
	if (G_UNLIKELY(!j_bson_iter_find(&iter, name, error)))
	{
		goto _error;
	}
	if (G_UNLIKELY(!j_bson_iter_value(&iter, J_DB_TYPE_UINT32, &val, error)))
	{
		goto _error;
	}
	*type = val.val_uint32;
_done:
	return TRUE;
_error:
	return FALSE;
}
guint32
j_db_schema_get_all_fields(JDBSchema* schema, gchar*** names, JDBType** types, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	bson_iter_t iter;
	guint count;
	guint i;
	JDBTypeValue val;
	const char* key;

	g_return_val_if_fail(schema != NULL, FALSE);
	g_return_val_if_fail(names != NULL, FALSE);
	g_return_val_if_fail(types != NULL, FALSE);
	g_return_val_if_fail(schema->bson_initialized, FALSE);

	*names = NULL;
	*types = NULL;
	if (G_UNLIKELY(!j_bson_iter_init(&iter, &schema->bson, error)))
	{
		goto _error;
	}
	if (G_UNLIKELY(!j_bson_count_keys(&schema->bson, &count, error)))
	{
		goto _error;
	}
	count++;
	*names = g_new(gchar*, count);
	*types = g_new(JDBType, count);
	i = 0;
	while (bson_iter_next(&iter))
	{
		key = j_bson_iter_key(&iter, error);
		if (G_UNLIKELY(!key))
		{
			goto _error;
		}
		if (g_strcmp0(key, "_index"))
		{
			if (G_UNLIKELY(!j_bson_iter_value(&iter, J_DB_TYPE_UINT32, &val, error)))
			{
				goto _error;
			}
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
	J_TRACE_FUNCTION(NULL);

	JDBSchemaIndex index;
	JDBSchemaIndex* index_tmp;
	guint i;
	bson_t bson;
	JDBTypeValue val;
	const char* key;
	char buf[20];
	gchar const** name;

	g_return_val_if_fail(schema != NULL, FALSE);
	g_return_val_if_fail(names != NULL, FALSE);
	g_return_val_if_fail(*names != NULL, FALSE);
	g_return_val_if_fail(!schema->server_side, FALSE);

	index.variables = NULL;
	if (!schema->bson_index_initialized)
	{
		if (G_UNLIKELY(!j_bson_init(&schema->bson_index, error)))
		{
			goto _error;
		}
		schema->bson_index_initialized = TRUE;
	}
	i = 0;
	index.variable_count = 0;
	name = names;
	index.variables = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	while (*name)
	{
		if (G_UNLIKELY(!g_hash_table_lookup_extended(schema->variables, *name, NULL, NULL)))
		{
			g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_VARIABLE_NOT_FOUND, "variable not found");
			goto _error;
		}
		index.variable_count++;
		g_hash_table_add(index.variables, g_strdup(*name));
		name++;
		i++;
	}
	i = 0;
_not_equal:
	i++;
	if (i <= schema->index->len)
	{
		index_tmp = &g_array_index(schema->index, JDBSchemaIndex, i - 1);
		if (index.variable_count != index_tmp->variable_count)
		{
			goto _not_equal;
		}
		name = names;
		while (*name)
		{
			if (!g_hash_table_contains(index_tmp->variables, *name))
			{
				goto _not_equal;
			}
			name++;
		}
		g_set_error_literal(error, J_FRONTEND_DB_ERROR, J_FRONTEND_DB_ERROR_DUPLICATE_INDEX, "duplicate index");
		goto _error;
	}
	if (G_UNLIKELY(!j_bson_array_generate_key(schema->index->len, &key, buf, sizeof(buf), error)))
	{
		goto _error;
	}
	if (G_UNLIKELY(!j_bson_append_array_begin(&schema->bson_index, key, &bson, error)))
	{
		goto _error;
	}
	name = names;
	while (*name)
	{
		if (G_UNLIKELY(!j_bson_array_generate_key(i, &key, buf, sizeof(buf), error)))
		{
			goto _error;
		}
		val.val_string = *name;
		if (G_UNLIKELY(!j_bson_append_value(&bson, key, J_DB_TYPE_STRING, &val, error)))
		{
			goto _error;
		}
		name++;
		i++;
	}
	if (G_UNLIKELY(!j_bson_append_array_end(&schema->bson_index, &bson, error)))
	{
		goto _error;
	}
	g_array_append_val(schema->index, index);
	return TRUE;
_error:
	if (index.variables)
	{
		g_hash_table_unref(index.variables);
	}
	return FALSE;
}
gboolean
j_db_schema_create(JDBSchema* schema, JBatch* batch, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	g_return_val_if_fail(schema != NULL, FALSE);
	g_return_val_if_fail(batch != NULL, FALSE);
	g_return_val_if_fail(!schema->server_side, FALSE);
	g_return_val_if_fail(schema->bson_initialized, FALSE);

	if (schema->bson_index_initialized)
	{
		if (G_UNLIKELY(!j_bson_append_array(&schema->bson, "_index", &schema->bson_index, error)))
		{
			goto _error;
		}
	}
	schema->server_side = TRUE;
	if (G_UNLIKELY(!j_db_internal_schema_create(schema->namespace, schema->name, &schema->bson, batch, error)))
	{
		goto _error;
	}
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_db_schema_get(JDBSchema* schema, JBatch* batch, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	g_return_val_if_fail(schema != NULL, FALSE);
	g_return_val_if_fail(batch != NULL, FALSE);
	g_return_val_if_fail(!schema->server_side, FALSE);
	g_return_val_if_fail(!schema->bson_initialized, FALSE);

	schema->server_side = TRUE;
	schema->bson_initialized = TRUE;
	if (G_UNLIKELY(!j_db_internal_schema_get(schema->namespace, schema->name, &schema->bson, batch, error)))
	{
		goto _error;
	}
	return TRUE;
_error:
	return FALSE;
}
gboolean
j_db_schema_delete(JDBSchema* schema, JBatch* batch, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	g_return_val_if_fail(schema != NULL, FALSE);
	g_return_val_if_fail(batch != NULL, FALSE);

	if (G_UNLIKELY(!j_db_internal_schema_delete(schema->namespace, schema->name, batch, error)))
	{
		goto _error;
	}
	return TRUE;
_error:
	return FALSE;
}

gboolean
j_db_schema_equals(JDBSchema* schema1, JDBSchema* schema2, gboolean* equal, GError** error)
{
	J_TRACE_FUNCTION(NULL);

	guint schema1_count;
	guint schema2_count;
	bson_iter_t iter1;
	bson_iter_t iter2;
	JDBTypeValue val1;
	JDBTypeValue val2;
	gint ret;
	gboolean has_next;
	const char* key;

	g_return_val_if_fail(schema1 != NULL, FALSE);
	g_return_val_if_fail(schema2 != NULL, FALSE);

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
			if (G_UNLIKELY(!j_bson_iter_init(&iter1, &schema1->bson, error)))
			{
				goto _error;
			}
			while (TRUE)
			{
				if (G_UNLIKELY(!j_bson_iter_next(&iter1, &has_next, error)))
				{
					goto _error;
				}
				if (!has_next)
				{
					break;
				}
				key = j_bson_iter_key(&iter1, error);
				if (G_UNLIKELY(!key))
				{
					goto _error;
				}
				if (g_strcmp0(key, "_index"))
				{
					schema1_count++;
					if (G_UNLIKELY(!j_bson_iter_init(&iter2, &schema2->bson, error)))
					{
						goto _error;
					}
					ret = j_bson_iter_find(&iter2, key, NULL);
					*equal = *equal && ret;
					if (!*equal)
					{
						break;
					}
					if (G_UNLIKELY(!j_bson_iter_value(&iter1, J_DB_TYPE_UINT32, &val1, error)))
					{
						goto _error;
					}
					if (G_UNLIKELY(!j_bson_iter_value(&iter2, J_DB_TYPE_UINT32, &val2, error)))
					{
						goto _error;
					}
					*equal = *equal && val1.val_uint32 == val2.val_uint32;
				}
			}
			if (G_UNLIKELY(!j_bson_iter_init(&iter2, &schema2->bson, error)))
			{
				goto _error;
			}
			if (G_UNLIKELY(!j_bson_count_keys(&schema2->bson, &schema2_count, error)))
			{
				goto _error;
			}
			ret = j_bson_iter_find(&iter2, "_index", NULL);
			if (ret)
			{
				schema2_count--;
			}
			*equal = *equal && schema1_count == schema2_count;
		}
	}
	return TRUE;
_error:
	return FALSE;
}
