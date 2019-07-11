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
	gboolean* ret;
};
typedef struct JSMDOperationData JSMDOperationData;
struct JSMDOperationIn
{
	gconstpointer ptr;
	gint len;
	JSMDParameterType type;
};
struct JSMDOperationOut
{
	gpointer ptr;
	gint len;
	JSMDParameterType type;
};
typedef struct JSMDOperationIn JSMDOperationIn;
typedef struct JSMDOperationOut JSMDOperationOut;
static gboolean
j_smd_func_exec(JList* operations, JSemantics* semantics, JMessageType type)
{
	JSMDOperationData* data;
	JSMDOperationIn* element_in;
	JSMDOperationOut* element_out;
	guint len;
	guint i;
	bson_t tmp;
	guint index = 0; //TODO distribute to different backends
	GSocketConnection* smd_connection;
	g_autoptr(JListIterator) iter_send = NULL;
	g_autoptr(JListIterator) iter_recieve = NULL;
	g_autoptr(JMessage) message = NULL;
	g_autoptr(JMessage) reply = NULL;
	message = j_message_new(type, 0);
	iter_send = j_list_iterator_new(operations);
	while (j_list_iterator_next(iter_send))
	{
		data = j_list_iterator_get(iter_send);
		len = 0;
		for (i = 0; i < data->in->len; i++)
		{
			len += 4;
			element_in = &g_array_index(data->in, JSMDOperationIn, i);
			switch (element_in->type)
			{
			case J_SMD_PARAM_TYPE_STR:
				if (element_in->ptr)
				{
					element_in->len = strlen(element_in->ptr) + 1;
					len += element_in->len;
				}
				break;
			case J_SMD_PARAM_TYPE_BLOB:
				len += element_in->len;
				break;
			case J_SMD_PARAM_TYPE_BSON:
				//BSON to send could have been converted to blob in the previous function
			case _J_SMD_PARAM_TYPE_COUNT:
			default:
				abort();
			}
		}
		j_message_add_operation(message, len);
		for (i = 0; i < data->in->len; i++)
		{
			element_in = &g_array_index(data->in, JSMDOperationIn, i);
			j_message_append_4(message, &element_in->len);
			if (element_in->ptr && element_in->len)
				j_message_append_n(message, element_in->ptr, element_in->len);
		}
	}
	smd_connection = j_connection_pool_pop_smd(index);
	j_message_send(message, smd_connection);
	iter_recieve = j_list_iterator_new(operations);
	while (j_list_iterator_next(iter_recieve))
	{
		data = j_list_iterator_get(iter_recieve);
		for (i = 0; i < data->out->len; i++)
		{
			len = j_message_get_4(reply);
			element_out = &g_array_index(data->out, JSMDOperationOut, i);
			*data->ret = TRUE;
			switch (element_out->type)
			{
			case J_SMD_PARAM_TYPE_STR:
				if (len)
					memcpy(element_out->ptr, j_message_get_n(reply, len), len);
				else
					*((char*)element_out->ptr) = 0;
				break;
			case J_SMD_PARAM_TYPE_BLOB:
				memcpy(element_out->ptr, j_message_get_n(reply, len), len);
				break;
			case J_SMD_PARAM_TYPE_BSON:
				*data->ret = bson_init_static(&tmp, j_message_get_n(reply, len), len) && *data->ret;
				bson_copy_to(&tmp, element_out->ptr); //TODO free tmp bson neccessary?
				break;
			case _J_SMD_PARAM_TYPE_COUNT:
			default:
				abort();
			}
			//TODO j_message_get_ #retrieve all data
		}
	}
	j_connection_pool_push_smd(index, smd_connection);
	return TRUE;
}
static gboolean
j_smd_schema_create_exec(JList* operations, JSemantics* semantics)
{
	j_smd_func_exec(operations, semantics, J_MESSAGE_SMD_SCHEMA_CREATE);
}
static void
j_smd_func_free(gpointer _data)
{
	JSMDOperationData* data = _data;
	if (data)
	{
		g_array_free(data->in, TRUE);
		g_array_free(data->out, TRUE);
		g_slice_free(JSMDOperationData, data);
	}
}
static gboolean
_j_smd_schema_create(gchar const* namespace, gchar const* name, bson_t const* schema, gboolean* ret, JBatch* batch)
{
	JOperation* op;
	JSMDOperationIn opsmd_in;
	JSMDOperationOut opsmd_out;
	JSMDOperationData* data;
	JBackend* smd_backend = j_smd_backend();
	if (smd_backend != NULL)
	{
		*ret = j_backend_smd_schema_create(smd_backend, namespace, name, schema);
	}
	else
	{
		data = g_slice_new(JSMDOperationData);
		data->in = g_array_new(FALSE, FALSE, sizeof(opsmd_in));
		data->out = g_array_new(FALSE, FALSE, sizeof(opsmd_out));
		data->ret = ret;
		opsmd_in.ptr = namespace;
		opsmd_in.type = J_SMD_PARAM_TYPE_STR;
		g_array_append_val(data->in, opsmd_in);
		opsmd_in.ptr = name;
		opsmd_in.type = J_SMD_PARAM_TYPE_STR;
		g_array_append_val(data->in, opsmd_in);
		op = j_operation_new();
		op->key = NULL;
		op->data = data;
		op->exec_func = j_smd_schema_create_exec;
		op->free_func = j_smd_func_free;
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
