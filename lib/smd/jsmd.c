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
	bson_t* bson;
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
	JBackend_smd_operation_data* data;
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
					      g_array_index(data->in, JBackend_smd_operation_in, 0).ptr, //
					      j_semantics_get(semantics, J_SEMANTICS_SAFETY), //
					      &batch) &&
					ret;
			ret = j_backend_smd_func_call(smd_backend, batch, data, type) && ret;
		}
		else
			ret = j_backend_smd_message_from_data(message, data) && ret;
	}
	if (smd_backend != NULL)
		ret = smd_backend->smd.backend_batch_execute(batch) && ret;
	else
	{
		smd_connection = j_connection_pool_pop_smd(0);
		j_message_send(message, smd_connection);
		iter_recieve = j_list_iterator_new(operations);
		while (j_list_iterator_next(iter_recieve))
		{
			data = j_list_iterator_get(iter_recieve);
			ret = j_backend_smd_message_to_data(reply, data) && ret;
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
		g_array_free(data->in, TRUE);
		g_array_free(data->out, TRUE);
		g_slice_free(JBackend_smd_operation_data, data);
	}
}

static gboolean
j_smd_schema_create_exec(JList* operations, JSemantics* semantics)
{
	return j_backend_smd_func_exec(operations, semantics, J_MESSAGE_SMD_SCHEMA_CREATE);
}
gboolean
j_smd_schema_create(gchar const* namespace, gchar const* name, bson_t const* schema, JBatch* batch)
{
	JOperation* op;
	JBackend_smd_operation_in opsmd_in;
	JBackend_smd_operation_out opsmd_out;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	data->in = g_array_new(FALSE, FALSE, sizeof(opsmd_in));
	data->out = g_array_new(FALSE, FALSE, sizeof(opsmd_out));
	opsmd_in.ptr = namespace;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = name;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = schema;
	opsmd_in.type = J_SMD_PARAM_TYPE_BSON;
	g_array_append_val(data->in, opsmd_in);
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
j_smd_schema_get(gchar const* namespace, gchar const* name, bson_t* schema, JBatch* batch)
{
	JOperation* op;
	JBackend_smd_operation_in opsmd_in;
	JBackend_smd_operation_out opsmd_out;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	data->in = g_array_new(FALSE, FALSE, sizeof(opsmd_in));
	data->out = g_array_new(FALSE, FALSE, sizeof(opsmd_out));
	opsmd_in.ptr = namespace;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = name;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_out.ptr = schema;
	opsmd_out.type = J_SMD_PARAM_TYPE_BSON;
	g_array_append_val(data->out, opsmd_out);
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
j_smd_schema_delete(gchar const* namespace, gchar const* name, JBatch* batch)
{
	JOperation* op;
	JBackend_smd_operation_in opsmd_in;
	JBackend_smd_operation_out opsmd_out;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	data->in = g_array_new(FALSE, FALSE, sizeof(opsmd_in));
	data->out = g_array_new(FALSE, FALSE, sizeof(opsmd_out));
	opsmd_in.ptr = namespace;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = name;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
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
j_smd_insert(gchar const* namespace, gchar const* name, bson_t const* metadata, JBatch* batch)
{
	JOperation* op;
	JBackend_smd_operation_in opsmd_in;
	JBackend_smd_operation_out opsmd_out;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	data->in = g_array_new(FALSE, FALSE, sizeof(opsmd_in));
	data->out = g_array_new(FALSE, FALSE, sizeof(opsmd_out));
	opsmd_in.ptr = namespace;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = name;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = metadata;
	opsmd_in.type = J_SMD_PARAM_TYPE_BSON;
	g_array_append_val(data->in, opsmd_in);
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
j_smd_update(gchar const* namespace, gchar const* name, bson_t const* selector, bson_t const* metadata, JBatch* batch)
{
	JOperation* op;
	JBackend_smd_operation_in opsmd_in;
	JBackend_smd_operation_out opsmd_out;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	data->in = g_array_new(FALSE, FALSE, sizeof(opsmd_in));
	data->out = g_array_new(FALSE, FALSE, sizeof(opsmd_out));
	opsmd_in.ptr = namespace;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = name;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = selector;
	opsmd_in.type = J_SMD_PARAM_TYPE_BSON;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = metadata;
	opsmd_in.type = J_SMD_PARAM_TYPE_BSON;
	g_array_append_val(data->in, opsmd_in);
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
j_smd_delete(gchar const* namespace, gchar const* name, bson_t const* selector, JBatch* batch)
{
	JOperation* op;
	JBackend_smd_operation_in opsmd_in;
	JBackend_smd_operation_out opsmd_out;
	JBackend_smd_operation_data* data;
	data = g_slice_new(JBackend_smd_operation_data);
	data->in = g_array_new(FALSE, FALSE, sizeof(opsmd_in));
	data->out = g_array_new(FALSE, FALSE, sizeof(opsmd_out));
	opsmd_in.ptr = namespace;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = name;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = selector;
	opsmd_in.type = J_SMD_PARAM_TYPE_BSON;
	g_array_append_val(data->in, opsmd_in);
	op = j_operation_new();
	op->key = namespace;
	op->data = data;
	op->exec_func = j_smd_delete_exec;
	op->free_func = j_backend_smd_func_free;
	j_batch_add(batch, op);
	return TRUE;
}
static gboolean
j_smd_getall_exec(JList* operations, JSemantics* semantics)
{
	return j_backend_smd_func_exec(operations, semantics, J_MESSAGE_SMD_GET_ALL);
}
gboolean
j_smd_query(gchar const* namespace, gchar const* name, bson_t const* selector, gpointer* iterator, JBatch* batch)
{
	J_smd_iterator_helper* helper;
	JOperation* op;
	JBackend_smd_operation_in opsmd_in;
	JBackend_smd_operation_out opsmd_out;
	JBackend_smd_operation_data* data;
	if (!iterator)
		return FALSE;
	helper = g_slice_new(J_smd_iterator_helper);
	helper->initialized = FALSE;
	helper->bson = bson_new();
	*iterator = helper;
	data = g_slice_new(JBackend_smd_operation_data);
	data->in = g_array_new(FALSE, FALSE, sizeof(opsmd_in));
	data->out = g_array_new(FALSE, FALSE, sizeof(opsmd_out));
	opsmd_in.ptr = namespace;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = name;
	opsmd_in.type = J_SMD_PARAM_TYPE_STR;
	g_array_append_val(data->in, opsmd_in);
	opsmd_in.ptr = selector;
	opsmd_in.type = J_SMD_PARAM_TYPE_BSON;
	g_array_append_val(data->in, opsmd_in);
	opsmd_out.ptr = helper->bson;
	opsmd_out.type = J_SMD_PARAM_TYPE_BSON;
	g_array_append_val(data->out, opsmd_out);
	op = j_operation_new();
	op->key = namespace;
	op->data = data;
	op->exec_func = j_smd_getall_exec;
	op->free_func = j_backend_smd_func_free;
	j_batch_add(batch, op);
	return TRUE;
}
gboolean
j_smd_iterate(gpointer iterator, bson_t* metadata)
{
	const uint8_t* data;
	uint32_t length;
	J_smd_iterator_helper* helper = iterator;
	if (!helper->initialized)
	{
		bson_iter_init(&helper->iter, helper->bson);
		helper->initialized = TRUE;
	}
	if (!bson_iter_next(&helper->iter))
		goto error;
	if (!BSON_ITER_HOLDS_DOCUMENT(&helper->iter))
		goto error;
	bson_iter_document(&helper->iter, &length, &data);
	bson_init_static(metadata, data, length);
	return TRUE;
error:
	bson_destroy(helper->bson);
	g_slice_free(J_smd_iterator_helper, helper);
	return FALSE;
}
