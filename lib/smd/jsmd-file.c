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
struct JSMDFileOperation
{
	J_Metadata_t* metadata;
	char* name;
};
typedef struct JSMDFileOperation JSMDFileOperation;
static gboolean
j_smd_file_create_exec(JList* operations, JSemantics* semantics)
{
	int message_size;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	GSocketConnection* smd_connection;
	JBackend* smd_backend;
	JSMDFileOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_FILE_CREATE, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
			j_backend_smd_file_create(smd_backend, operation->name, operation->metadata->bson, operation->metadata->key);
		else
		{
			message_size = strlen(operation->name) + 1 + 4 + operation->metadata->bson->len;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->name, strlen(operation->name) + 1);
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
		while (j_list_iterator_next(iter))
		{
			operation = j_list_iterator_get(iter);
			memcpy(operation->metadata->key, j_message_get_n(reply, SMD_KEY_LENGTH), SMD_KEY_LENGTH);
		}
		j_connection_pool_push_smd(index, smd_connection);
	}
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
static void
j_smd_file_create_free(gpointer data)
{
	JSMDFileOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
void*
j_smd_file_create(const char* name, JBatch* batch)
{
	JOperation* op;
	JSMDFileOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDFileOperation, 1);
	smd_op->metadata = g_new(J_Metadata_t, 1);
	smd_op->metadata->bson = g_new(bson_t, 1);
	smd_op->metadata->bson_requires_free = TRUE;
	bson_init(smd_op->metadata->bson);
	memset(smd_op->metadata->key, 0, SMD_KEY_LENGTH);
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_file_create_exec;
	op->free_func = j_smd_file_create_free;
	smd_op->name = g_strdup(name);
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return smd_op->metadata;
}
static gboolean
j_smd_file_delete_exec(JList* operations, JSemantics* semantics)
{
	int message_size;
	JBackend* smd_backend;
	JSMDFileOperation* operation;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	GSocketConnection* smd_connection;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_FILE_DELETE, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
			j_backend_smd_file_delete(smd_backend, operation->name);
		else
		{
			message_size = strlen(operation->name) + 1;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->name, strlen(operation->name) + 1);
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
j_smd_file_delete_free(gpointer data)
{
	JSMDFileOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
gboolean
j_smd_file_delete(const char* name, JBatch* batch)
{
	JOperation* op;
	JSMDFileOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDFileOperation, 1);
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_file_delete_exec;
	op->free_func = j_smd_file_delete_free;
	smd_op->name = g_strdup(name);
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
static gboolean
j_smd_file_open_exec(JList* operations, JSemantics* semantics)
{
	JBackend* smd_backend;
	JSMDFileOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	int bson_len;
	int message_size;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	GSocketConnection* smd_connection;
	uint8_t* bson_data;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_FILE_OPEN, 0);
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
			j_backend_smd_file_open(smd_backend, operation->name, operation->metadata->bson, operation->metadata->key);
		}
		else
		{
			message_size = strlen(operation->name) + 1;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->name, strlen(operation->name) + 1);
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
j_smd_file_open_free(gpointer data)
{
	JSMDFileOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
void*
j_smd_file_open(const char* name, JBatch* batch)
{
	JOperation* op;
	JSMDFileOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDFileOperation, 1);
	smd_op->metadata = g_new(J_Metadata_t, 1);
	smd_op->metadata->bson = NULL;
	smd_op->metadata->bson_requires_free = FALSE;
	memset(smd_op->metadata->key, 0, SMD_KEY_LENGTH);
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_file_open_exec;
	op->free_func = j_smd_file_open_free;
	smd_op->name = g_strdup(name);
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return smd_op->metadata;
}
gboolean
j_smd_file_close(void* _file)
{
	J_Metadata_t* file = _file;
	j_trace_enter(G_STRFUNC, NULL);
	if (file->bson)
		bson_destroy(file->bson);
	if (file->bson_requires_free)
		g_free(file->bson);
	g_free(file);
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
