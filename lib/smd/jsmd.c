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
struct J_smd_iterator_helper
{
	bson_t bson;
	bson_iter_t iter;
	gboolean initialized;
};
typedef struct J_smd_iterator_helper J_smd_iterator_helper;
static gboolean
j_backend_smd_func_call(JBackend* backend, gpointer batch, JBackend_smd_operation_data* data, JMessageType type)
{
	switch (type)
	{
	case J_MESSAGE_SMD_SCHEMA_CREATE:
		return j_backend_smd_schema_create(backend, batch, data);
	case J_MESSAGE_SMD_SCHEMA_GET:
		return j_backend_smd_schema_get(backend, batch, data);
	case J_MESSAGE_SMD_SCHEMA_DELETE:
		return j_backend_smd_schema_delete(backend, batch, data);
	case J_MESSAGE_SMD_INSERT:
		return j_backend_smd_insert(backend, batch, data);
	case J_MESSAGE_SMD_UPDATE:
		return j_backend_smd_update(backend, batch, data);
	case J_MESSAGE_SMD_DELETE:
		return j_backend_smd_delete(backend, batch, data);
	case J_MESSAGE_SMD_GET_ALL:
		return j_backend_smd_get_all(backend, batch, data);
	default:
		return FALSE;
	}
}
static gboolean
j_backend_smd_func_exec(JList* operations, JSemantics* semantics, JMessageType type)
{
	gpointer batch = NULL;
	JBackend_smd_operation_data* data = NULL;
	gboolean ret = TRUE;
	GSocketConnection* smd_connection;
	JBackend* smd_backend = j_smd_backend();
	g_autoptr(JListIterator) iter_send = NULL;
	g_autoptr(JListIterator) iter_recieve = NULL;
	g_autoptr(JMessage) message = NULL;
	g_autoptr(JMessage) reply = NULL;
	if (smd_backend == NULL)
		message = j_message_new(type, 0);
	iter_send = j_list_iterator_new(operations);
	while (j_list_iterator_next(iter_send))
	{
		data = j_list_iterator_get(iter_send);
		if (smd_backend != NULL)
		{
			if (!batch)
				ret = smd_backend->smd.backend_batch_start( //
					      data->in_param[0].ptr, //
					      j_semantics_get(semantics, J_SEMANTICS_SAFETY), //
					      &batch, data->out_param[data->out_param_count - 1].ptr) &&
					ret;
			ret = j_backend_smd_func_call(smd_backend, batch, data, type) && ret;
		}
		else
			ret = j_backend_smd_message_from_data(message, data->in_param, data->in_param_count) && ret;
	}
	if (smd_backend != NULL && data != NULL)
		ret = smd_backend->smd.backend_batch_execute(batch, data->out_param[data->out_param_count - 1].ptr) && ret;
	else
	{
		smd_connection = j_connection_pool_pop_smd(0);
		j_message_send(message, smd_connection);
		iter_recieve = j_list_iterator_new(operations);
		while (j_list_iterator_next(iter_recieve))
		{
			data = j_list_iterator_get(iter_recieve);
			ret = j_backend_smd_message_to_data(reply, data->out_param, data->out_param_count) && ret;
		}
		j_connection_pool_push_smd(0, smd_connection);
	}
	return ret;
}
static void
j_backend_smd_func_free(gpointer _data)
{
	JBackend_smd_operation_data* data = _data;
	if (data)
	{
		g_slice_free(JBackend_smd_operation_data, data);
	}
}

static gboolean
j_smd_schema_create_exec(JList* operations, JSemantics* semantics)
{
	return j_backend_smd_func_exec(operations, semantics, J_MESSAGE_SMD_SCHEMA_CREATE);
}
gboolean
j_smd_schema_create(gchar const* namespace, gchar const* name, bson_t const* schema, JBatch* batch, GError** error)
{
	JOperation* op;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	memcpy(data, &j_smd_schema_create_params, sizeof(JBackend_smd_operation_data));
	data->in_param[0].ptr_const = namespace;
	data->in_param[1].ptr_const = name;
	data->in_param[2].ptr_const = schema;
	data->out_param[0].ptr_const = error;
	op = j_operation_new();
	op->key = namespace;
	op->data = data;
	op->exec_func = j_smd_schema_create_exec;
	op->free_func = j_backend_smd_func_free;
	j_batch_add(batch, op);
	return TRUE;
}
static gboolean
j_smd_schema_get_exec(JList* operations, JSemantics* semantics)
{
	return j_backend_smd_func_exec(operations, semantics, J_MESSAGE_SMD_SCHEMA_GET);
}
gboolean
j_smd_schema_get(gchar const* namespace, gchar const* name, bson_t* schema, JBatch* batch, GError** error)
{
	JOperation* op;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	memcpy(data, &j_smd_schema_get_params, sizeof(JBackend_smd_operation_data));
	data->in_param[0].ptr_const = namespace;
	data->in_param[1].ptr_const = name;
	data->out_param[0].ptr_const = schema;
	data->out_param[1].ptr_const = error;
	op = j_operation_new();
	op->key = namespace;
	op->data = data;
	op->exec_func = j_smd_schema_get_exec;
	op->free_func = j_backend_smd_func_free;
	j_batch_add(batch, op);
	return TRUE;
}
static gboolean
j_smd_schema_delete_exec(JList* operations, JSemantics* semantics)
{
	return j_backend_smd_func_exec(operations, semantics, J_MESSAGE_SMD_SCHEMA_DELETE);
}
gboolean
j_smd_schema_delete(gchar const* namespace, gchar const* name, JBatch* batch, GError** error)
{
	JOperation* op;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	memcpy(data, &j_smd_schema_delete_params, sizeof(JBackend_smd_operation_data));
	data->in_param[0].ptr_const = namespace;
	data->in_param[1].ptr_const = name;
	data->out_param[0].ptr_const = error;
	op = j_operation_new();
	op->key = namespace;
	op->data = data;
	op->exec_func = j_smd_schema_delete_exec;
	op->free_func = j_backend_smd_func_free;
	j_batch_add(batch, op);
	return TRUE;
}
static gboolean
j_smd_insert_exec(JList* operations, JSemantics* semantics)
{
	return j_backend_smd_func_exec(operations, semantics, J_MESSAGE_SMD_INSERT);
}
gboolean
j_smd_insert(gchar const* namespace, gchar const* name, bson_t const* metadata, JBatch* batch, GError** error)
{
	JOperation* op;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	memcpy(data, &j_smd_insert_params, sizeof(JBackend_smd_operation_data));
	data->in_param[0].ptr_const = namespace;
	data->in_param[1].ptr_const = name;
	data->in_param[2].ptr_const = metadata;
	data->out_param[0].ptr_const = error;
	op = j_operation_new();
	op->key = namespace;
	op->data = data;
	op->exec_func = j_smd_insert_exec;
	op->free_func = j_backend_smd_func_free;
	j_batch_add(batch, op);
	return TRUE;
}
static gboolean
j_smd_update_exec(JList* operations, JSemantics* semantics)
{
	return j_backend_smd_func_exec(operations, semantics, J_MESSAGE_SMD_UPDATE);
}
gboolean
j_smd_update(gchar const* namespace, gchar const* name, bson_t const* selector, bson_t const* metadata, JBatch* batch, GError** error)
{
	JOperation* op;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	memcpy(data, &j_smd_update_params, sizeof(JBackend_smd_operation_data));
	data->in_param[0].ptr_const = namespace;
	data->in_param[1].ptr_const = name;
	data->in_param[2].ptr_const = selector;
	data->in_param[3].ptr_const = metadata;
	data->out_param[0].ptr_const = error;
	op = j_operation_new();
	op->key = namespace;
	op->data = data;
	op->exec_func = j_smd_update_exec;
	op->free_func = j_backend_smd_func_free;
	j_batch_add(batch, op);
	return TRUE;
}
static gboolean
j_smd_delete_exec(JList* operations, JSemantics* semantics)
{
	return j_backend_smd_func_exec(operations, semantics, J_MESSAGE_SMD_DELETE);
}
gboolean
j_smd_delete(gchar const* namespace, gchar const* name, bson_t const* selector, JBatch* batch, GError** error)
{
	JOperation* op;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	memcpy(data, &j_smd_delete_params, sizeof(JBackend_smd_operation_data));
	data->in_param[0].ptr_const = namespace;
	data->in_param[1].ptr_const = name;
	data->in_param[2].ptr_const = selector;
	data->out_param[0].ptr_const = error;
	op = j_operation_new();
	op->key = namespace;
	op->data = data;
	op->exec_func = j_smd_delete_exec;
	op->free_func = j_backend_smd_func_free;
	j_batch_add(batch, op);
	return TRUE;
}
static gboolean
j_smd_get_all_exec(JList* operations, JSemantics* semantics)
{
	return j_backend_smd_func_exec(operations, semantics, J_MESSAGE_SMD_GET_ALL);
}
gboolean
j_smd_query(gchar const* namespace, gchar const* name, bson_t const* selector, gpointer* iterator, JBatch* batch, GError** error)
{
	J_smd_iterator_helper* helper;
	JOperation* op;
	JBackend_smd_operation_data* data;
	if (!iterator)
		return FALSE;
	helper = g_slice_new(J_smd_iterator_helper);
	helper->initialized = FALSE;
	*iterator = helper;
	data = g_slice_new(JBackend_smd_operation_data);
	memcpy(data, &j_smd_get_all_params, sizeof(JBackend_smd_operation_data));
	data->in_param[0].ptr_const = namespace;
	data->in_param[1].ptr_const = name;
	data->in_param[2].ptr_const = selector;
	data->out_param[0].ptr_const = &helper->bson;
	data->out_param[1].ptr_const = error;
	op = j_operation_new();
	op->key = namespace;
	op->data = data;
	op->exec_func = j_smd_get_all_exec;
	op->free_func = j_backend_smd_func_free;
	j_batch_add(batch, op);
	return TRUE;
}
gboolean
j_smd_iterate(gpointer iterator, bson_t* metadata, GError** error)
{
	const uint8_t* data;
	uint32_t length;
	J_smd_iterator_helper* helper = iterator;
	(void)error;
	if (!helper->initialized)
	{
		bson_iter_init(&helper->iter, &helper->bson);
		helper->initialized = TRUE;
	}
	if (!bson_iter_next(&helper->iter))
	{
		g_set_error(error, JULEA_BACKEND_ERROR, JULEA_BACKEND_ERROR_ITERATOR_NO_MORE_ELEMENTS, "no %d more elements to iterate", 0);
		goto error;
	}
	if (!BSON_ITER_HOLDS_DOCUMENT(&helper->iter))
	{
		g_set_error(error, JULEA_BACKEND_ERROR, JULEA_BACKEND_ERROR_BSON_INVALID_TYPE, "bson invalid type %d", bson_iter_type(&helper->iter));
		goto error;
	}
	bson_iter_document(&helper->iter, &length, &data);
	bson_init_static(metadata, data, length);
	return TRUE;
error:
	bson_destroy(&helper->bson);
	g_slice_free(J_smd_iterator_helper, helper);
	return FALSE;
}
