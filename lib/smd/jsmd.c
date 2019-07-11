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
enum JSMDParameterType
{
	J_SMD_PARAM_TYPE_STR = 0,
	J_SMD_PARAM_TYPE_BLOB,
	J_SMD_PARAM_TYPE_BSON,
	_J_SMD_PARAM_TYPE_COUNT,
};
typedef enum JSMDParameterType JSMDParameterType;
struct JSMDOperationData
{
	GArray* in;
	GArray* out;
};
typedef struct JSMDOperationData JSMDOperationData;
struct JSMDOperation
{
	gpointer ptr;
	gint len;
	JSMDParameterType type;
};
typedef struct JSMDOperation JSMDOperation;
static gboolean
j_smd_schema_create_exec(JList* operations, JSemantics* semantics)
{
	/*	//TODO this will not work
	JSMDOperationData* data;
	JSMDOperation* element;
	guint len;
	guint i;
	JBackend* backend = j_smd_backend();
	g_autoptr(JListIterator) iter_send = NULL;
	g_autoptr(JListIterator) iter_recieve = NULL;
	g_autoptr(JMessage) message = NULL;
	message = j_message_new(J_MESSAGE_SMD_SCHEMA_CREATE, 0);
	iter_send = j_list_iterator_new(operations);
	while (j_list_iterator_next(iter_send))
	{
		data = j_list_iterator_get(iter_send);
		len = 0;
		for (i = 0; i < data->in->len; i++)
		{
			len += 4;
			element = &g_array_index(data->in, JSMDOperation, i);
			switch (element->type)
			{
			case J_SMD_PARAM_TYPE_STR:
				if (element->ptr)
				{
					element->len = strlen(element->ptr);
					len += strlen(element->ptr);
				}
				break;
			case J_SMD_PARAM_TYPE_BLOB:
				len += element->len;
				break;
			case J_SMD_PARAM_TYPE_BSON:
				//BSON to send could have been converted to blob in the previous function
			default:
				abort();
			}
		}
		j_message_add_operation(message, len) for (i = 0; i < data->in->len; i++)
		{
			element = &g_array_index(data->in, JSMDOperation, i);
			j_message_append_4(message, &element->len);
			if (element->ptr && element->len)
				j_message_append_n(message, element->ptr, element->len);
		}
	}
	j_message_send(message, connection);
	iter_recieve = j_list_iterator_new(operations);
	while (j_list_iterator_next(iter_recieve))
	{
		data = j_list_iterator_get(iter_recieve);
		for (i = 0; i < data->out->len; i++)
		{
			element = &g_array_index(data->out, JSMDOperation, i);
			switch (element->type)
			{
			case J_SMD_PARAM_TYPE_STR:
				*element->ptr = //TODO
					case J_SMD_PARAM_TYPE_BLOB : case J_SMD_PARAM_TYPE_BSON : default : abort();
			}
			//TODO j_message_get_ #retrieve all data
		}
	}
	return TRUE;*/
}
static void
j_smd_schema_create_free(gpointer _data)
{
/*	JSMDOperationData* data = _data;
	JSMDOperation* element;
	guint i;
	if (data)
	{
		for (i = 0; i < data->in->len; i++)
		{
			element = &g_array_index(data->in, JSMDOperation, i);
			switch (element->type)
			{
			case J_SMD_PARAM_TYPE_STR:
				g_free(element->ptr);
				break;
			case J_SMD_PARAM_TYPE_BLOB:
			case J_SMD_PARAM_TYPE_BSON:
			default:;
			}
		}
		g_array_free(data->in, TRUE);
		g_array_free(data->out, TRUE);
		g_slice_free(JSMDOperationData, data);
	}
*/}
gboolean
_j_smd_schema_create(gchar const* namespace, gchar const* name, bson_t const* schema, gboolean* ret, JBatch* batch)
{
	JOperation* op;
	JSMDOperation opsmd;
	JSMDOperationData* data;
	JBackend* smd_backend = j_smd_backend();
	if (smd_backend != NULL)
	{
		*ret = j_backend_smd_schema_create(smd_backend, namespace, name, schema);
	}
	else
	{
		data = g_slice_new(JSMDOperationData);
		data->in = g_array_new(FALSE, FALSE, sizeof(opsmd));
		data->out = g_array_new(FALSE, FALSE, sizeof(opsmd));
		opsmd.ptr = g_strdup(namespace);
		opsmd.type = J_SMD_PARAM_TYPE_STR;
		g_array_append_val(data->in, opsmd);
		opsmd.ptr = g_strdup(name);
		opsmd.type = J_SMD_PARAM_TYPE_STR;
		g_array_append_val(data->in, opsmd);
		opsmd.ptr = ret;
		opsmd.len = sizeof(*ret);
		g_array_append_val(data->out, opsmd);
		op = j_operation_new();
		op->key = NULL;
		op->data = data;
		op->exec_func = j_smd_schema_create_exec;
		op->free_func = j_smd_schema_create_free;
		j_batch_add(batch, op);
	}
	return TRUE;
}
gboolean
j_smd_schema_create(gchar const* namespace, gchar const* name, bson_t const* schema)
{
	gboolean ret;
	gboolean ret2;
	ret2 = _j_smd_schema_create(namespace, name, schema, &ret, NULL);
	return ret && ret2;
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
