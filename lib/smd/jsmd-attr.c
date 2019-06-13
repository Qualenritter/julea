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
/*http://mongoc.org/libbson/current/bson_t.html*/
/**
 * \file
 **/

#include <julea-config.h>

#include <glib.h>

#include <string.h>

#include <bson.h>

#include <julea.h>

#include <julea-internal.h>
#include <julea-smd.h>
struct JSMDAttributeOperation
{
	J_Metadata_t* metadata;
	char* name;
	J_Metadata_t* parent;
	union
	{
		char* buf_read;
		const char* buf_write;
	};
	guint64 buf_offset;
	guint64 buf_size;
};
typedef struct JSMDAttributeOperation JSMDAttributeOperation;

static gboolean
j_smd_create_exec(JList* operations, JSemantics* semantics)
{
	JBackend* smd_backend;
	int message_size;
	JSMDAttributeOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	GSocketConnection* smd_connection;
	JBatch* batch;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_ATTR_CREATE, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
		{
			j_backend_smd_attr_create(smd_backend, operation->name, operation->parent->key, operation->metadata->bson, operation->metadata->key);
		}
		else
		{
			message_size = strlen(operation->name) + 1 + SMD_KEY_LENGTH + 4 + operation->metadata->bson->len;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->name, strlen(operation->name) + 1);
			j_message_append_n(message, operation->parent->key, SMD_KEY_LENGTH);
			j_message_append_4(message, &operation->metadata->bson->len);
			j_message_append_n(message, bson_get_data(operation->metadata->bson), operation->metadata->bson->len);
		}
	}
	if (smd_backend == NULL)
	{
		smd_connection = j_connection_pool_pop_smd(index);
		j_message_send(message, smd_connection);
		reply = j_message_new_reply(message);
		j_message_receive(reply, smd_connection);
		iter = j_list_iterator_new(operations);
		batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
		while (j_list_iterator_next(iter))
		{
			operation = j_list_iterator_get(iter);
			memcpy(operation->metadata->key, j_message_get_n(reply, SMD_KEY_LENGTH), SMD_KEY_LENGTH);
		}
		j_connection_pool_push_smd(index, smd_connection);
		j_batch_execute(batch);
	}
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
static void
j_smd_create_free(gpointer data)
{
	JSMDAttributeOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
void*
j_smd_attr_create(const char* name, void* parent, void* _data_type, void* _space_type, JBatch* batch)
{
	JOperation* op;
	JSMDAttributeOperation* smd_op;
	bson_t* data_type;
	bson_t* space_type;
	j_trace_enter(G_STRFUNC, NULL);
	data_type = j_smd_type_to_bson(_data_type);
	space_type = j_smd_space_to_bson(_space_type);
	smd_op = g_new(JSMDAttributeOperation, 1);
	smd_op->metadata = g_new(J_Metadata_t, 1);
	smd_op->metadata->bson = g_new(bson_t, 1);
	smd_op->metadata->bson_requires_free = TRUE;
	bson_init(smd_op->metadata->bson);
	bson_append_document(smd_op->metadata->bson, "space_type", -1, space_type);
	bson_append_document(smd_op->metadata->bson, "data_type", -1, data_type);
	bson_destroy(data_type);
	bson_destroy(space_type);
	g_free(data_type);
	g_free(space_type);
	memset(smd_op->metadata->key, 0, SMD_KEY_LENGTH);
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_create_exec;
	op->free_func = j_smd_create_free;
	smd_op->name = g_strdup(name);
	smd_op->parent = parent;
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return smd_op->metadata;
}
static gboolean
j_smd_delete_exec(JList* operations, JSemantics* semantics)
{
	JBackend* smd_backend;
	JSMDAttributeOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	int message_size;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	GSocketConnection* smd_connection;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_ATTR_DELETE, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
		{
			j_backend_smd_attr_delete(smd_backend, operation->name, operation->parent->key);
		}
		else
		{
			message_size = strlen(operation->name) + 1 + SMD_KEY_LENGTH;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->name, strlen(operation->name) + 1);
			j_message_append_n(message, operation->parent->key, SMD_KEY_LENGTH);
		}
	}
	if (smd_backend == NULL)
	{
		smd_connection = j_connection_pool_pop_smd(index);
		j_message_send(message, smd_connection);
		reply = j_message_new_reply(message);
		j_message_receive(reply, smd_connection);
		j_connection_pool_push_smd(index, smd_connection);
	}
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
static void
j_smd_delete_free(gpointer data)
{
	JSMDAttributeOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
gboolean
j_smd_attr_delete(const char* name, void* parent, JBatch* batch)
{
	JOperation* op;
	JSMDAttributeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDAttributeOperation, 1);
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_delete_exec;
	op->free_func = j_smd_delete_free;
	smd_op->name = g_strdup(name);
	smd_op->parent = parent;
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
static gboolean
j_smd_open_exec(JList* operations, JSemantics* semantics)
{
	JBackend* smd_backend;
	JSMDAttributeOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	int bson_len;
	uint8_t* bson_data;
	int message_size;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	GSocketConnection* smd_connection;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_ATTR_OPEN, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
		{
			operation->metadata->bson = g_new(bson_t, 1);
			operation->metadata->bson_requires_free = TRUE;
			bson_init(operation->metadata->bson);
			j_backend_smd_attr_open(smd_backend, operation->name, operation->parent->key, operation->metadata->bson, operation->metadata->key);
		}
		else
		{
			message_size = strlen(operation->name) + 1 + SMD_KEY_LENGTH;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->name, strlen(operation->name) + 1);
			j_message_append_n(message, operation->parent->key, SMD_KEY_LENGTH);
		}
	}
	if (smd_backend == NULL)
	{
		smd_connection = j_connection_pool_pop_smd(index);
		j_message_send(message, smd_connection);
		reply = j_message_new_reply(message);
		j_message_receive(reply, smd_connection);
		iter = j_list_iterator_new(operations);
		while (j_list_iterator_next(iter))
		{
			operation = j_list_iterator_get(iter);
			memcpy(operation->metadata->key, j_message_get_n(reply, SMD_KEY_LENGTH), SMD_KEY_LENGTH);
			if (j_is_key_initialized(operation->metadata->key))
			{
				bson_len = j_message_get_4(reply);
				bson_data = j_message_get_n(reply, bson_len);
				operation->metadata->bson = bson_new_from_data(bson_data, bson_len);
				operation->metadata->bson_requires_free = FALSE;
			}
		}
		j_connection_pool_push_smd(index, smd_connection);
	}
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
static void
j_smd_open_free(gpointer data)
{
	JSMDAttributeOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
void*
j_smd_attr_open(const char* name, void* parent, JBatch* batch)
{
	JOperation* op;
	JSMDAttributeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDAttributeOperation, 1);
	smd_op->metadata = g_new(J_Metadata_t, 1);
	memset(smd_op->metadata->key, 0, SMD_KEY_LENGTH);
	smd_op->metadata->bson = NULL;
	smd_op->metadata->bson_requires_free = FALSE;
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_open_exec;
	op->free_func = j_smd_open_free;
	smd_op->name = g_strdup(name);
	smd_op->parent = parent;
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return smd_op->metadata;
}
gboolean
j_smd_attr_close(void* _metadata)
{
	J_Metadata_t* metadata = _metadata;
	j_trace_enter(G_STRFUNC, NULL);
	if (metadata->bson)
		bson_destroy(metadata->bson);
	if (metadata->bson_requires_free)
		g_free(metadata->bson);
	g_free(metadata);
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
static gboolean
j_smd_read_exec(JList* operations, JSemantics* semantics)
{
	guint64 ret;
	JBackend* smd_backend;
	JSMDAttributeOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	int message_size;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	GSocketConnection* smd_connection;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_ATTR_READ, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
		{
			j_backend_smd_attr_read(smd_backend, operation->metadata->key, operation->buf_read, operation->buf_offset, operation->buf_size);
		}
		else
		{
			message_size = 8 + 8 + SMD_KEY_LENGTH;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->metadata->key, SMD_KEY_LENGTH);
			j_message_append_8(message, &operation->buf_offset);
			j_message_append_8(message, &operation->buf_size);
		}
	}
	if (smd_backend == NULL)
	{
		smd_connection = j_connection_pool_pop_smd(index);
		j_message_send(message, smd_connection);
		reply = j_message_new_reply(message);
		j_message_receive(reply, smd_connection);
		iter = j_list_iterator_new(operations);
		while (j_list_iterator_next(iter))
		{
			operation = j_list_iterator_get(iter);
			ret = j_message_get_8(reply);
			memcpy(operation->buf_read, j_message_get_n(reply, ret), ret);
			J_DEBUG("test-var-content %ld", *((guint64*)operation->buf_read));
			//TODO ASSERT ret==operation->buf_size
		}
		j_connection_pool_push_smd(index, smd_connection);
	}
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
static void
j_smd_read_free(gpointer data)
{
	g_free(data);
}
gboolean
j_smd_attr_read(void* _metadata, void* buf, guint64 buf_offset, guint64 buf_size, JBatch* batch)
{
	JOperation* op;
	JSMDAttributeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDAttributeOperation, 1);
	smd_op->metadata = _metadata;
	smd_op->buf_offset = buf_offset;
	smd_op->buf_size = buf_size;
	smd_op->buf_read = buf;
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_read_exec;
	op->free_func = j_smd_read_free;
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
static gboolean
j_smd_write_exec(JList* operations, JSemantics* semantics)
{
	guint64 ret;
	JBackend* smd_backend;
	JSMDAttributeOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	int message_size;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	GSocketConnection* smd_connection;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_ATTR_WRITE, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
		{
			j_backend_smd_attr_write(smd_backend, operation->metadata->key, operation->buf_write, operation->buf_offset, operation->buf_size);
		}
		else
		{
			message_size = 8 + 8 + SMD_KEY_LENGTH + operation->buf_size;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->metadata->key, SMD_KEY_LENGTH);
			j_message_append_8(message, &operation->buf_offset);
			j_message_append_8(message, &operation->buf_size);
			j_message_append_n(message, operation->buf_write, operation->buf_size);
		}
	}
	if (smd_backend == NULL)
	{
		smd_connection = j_connection_pool_pop_smd(index);
		j_message_send(message, smd_connection);
		reply = j_message_new_reply(message);
		j_message_receive(reply, smd_connection);
		iter = j_list_iterator_new(operations);
		while (j_list_iterator_next(iter))
		{
			operation = j_list_iterator_get(iter);
			ret = j_message_get_8(reply);
			//TODO ASSERT ret==operation->buf_size
		}
		j_connection_pool_push_smd(index, smd_connection);
	}
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
static void
j_smd_write_free(gpointer data)
{
	g_free(data);
}
gboolean
j_smd_attr_write(void* _metadata, const void* buf, guint64 buf_offset, guint64 buf_size, JBatch* batch)
{
	JOperation* op;
	JSMDAttributeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDAttributeOperation, 1);
	smd_op->metadata = _metadata;
	smd_op->buf_offset = buf_offset;
	smd_op->buf_size = buf_size;
	smd_op->buf_write = buf;
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_write_exec;
	op->free_func = j_smd_write_free;
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
void*
j_smd_attr_get_type(void* metadata)
{
	return j_smd_get_type(metadata);
}
void*
j_smd_attr_get_space(void* metadata)
{
	return j_smd_get_space(metadata);
}
