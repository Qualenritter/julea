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
struct JSMDSchemeOperation
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
typedef struct JSMDSchemeOperation JSMDSchemeOperation;
static gboolean
j_smd_read_exec(JList* operations, JSemantics* semantics)
{
	guint64 ret;
	JBackend* smd_backend;
	JSMDSchemeOperation* operation;
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
		message = j_message_new(J_MESSAGE_SMD_SCHEME_READ, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
			j_backend_smd_scheme_read(smd_backend, operation->metadata->key, operation->buf_read, operation->buf_offset, operation->buf_size);
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
j_smd_scheme_read(void* _metadata, void* buf, guint64 buf_offset, guint64 buf_size, JBatch* batch)
{
	JOperation* op;
	JSMDSchemeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDSchemeOperation, 1);
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
	JSMDSchemeOperation* operation;
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
		message = j_message_new(J_MESSAGE_SMD_SCHEME_WRITE, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
			j_backend_smd_scheme_write(smd_backend, operation->metadata->key, operation->buf_write, operation->buf_offset, operation->buf_size);
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
j_smd_scheme_write(void* _metadata, const void* buf, guint64 buf_offset, guint64 buf_size, JBatch* batch)
{
	JOperation* op;
	JSMDSchemeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDSchemeOperation, 1);
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
