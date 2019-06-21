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
#include <julea-smd.h>
struct JSMDFileOperation
{
	J_Scheme_t* scheme;
	char* name;
};
typedef struct JSMDFileOperation JSMDFileOperation;
static gboolean
j_smd_file_create_exec(JList* operations, JSemantics* semantics)
{
	int message_size;
	int zero = 0;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	bson_t bson[1];
	GSocketConnection* smd_connection;
	JBackend* smd_backend;
	JSMDFileOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
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
		{
			bson_init(bson);
			j_backend_smd_file_create(smd_backend, operation->name, bson, operation->scheme->key);
			bson_destroy(bson);
		}
		else
		{
			message_size = strlen(operation->name) + 1 + 4 + 4;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->name, strlen(operation->name) + 1);
			j_message_append_4(message, &zero);
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
			memcpy(operation->scheme->key, j_message_get_n(reply, SMD_KEY_LENGTH), SMD_KEY_LENGTH);
		}
		j_connection_pool_push_smd(index, smd_connection);
	}
	return TRUE;
}
static void
j_smd_file_create_free(gpointer data)
{
	JSMDFileOperation* smd_op = data;
	g_free(smd_op->name);
	j_smd_file_unref(smd_op->scheme);
	g_free(smd_op);
}
void*
j_smd_file_create(const char* name, JBatch* batch)
{
	JOperation* op;
	JSMDFileOperation* smd_op;
	smd_op = g_new(JSMDFileOperation, 1);
	smd_op->scheme = g_new(J_Scheme_t, 1);
	smd_op->scheme->user_data = NULL;
	smd_op->scheme->ref_count = 2;
	smd_op->scheme->type = NULL;
	smd_op->scheme->space = NULL;
	memset(smd_op->scheme->key, 0, SMD_KEY_LENGTH);
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_file_create_exec;
	op->free_func = j_smd_file_create_free;
	smd_op->name = g_strdup(name);
	j_batch_add(batch, op);
	return smd_op->scheme;
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
	smd_op = g_new(JSMDFileOperation, 1);
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_file_delete_exec;
	op->free_func = j_smd_file_delete_free;
	smd_op->name = g_strdup(name);
	j_batch_add(batch, op);
	return TRUE;
}
static gboolean
j_smd_file_open_exec(JList* operations, JSemantics* semantics)
{
	JBackend* smd_backend;
	JSMDFileOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	int message_size;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	bson_t bson[1];
	GSocketConnection* smd_connection;
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
			bson_init(bson);
			j_backend_smd_file_open(smd_backend, operation->name, bson, operation->scheme->key);
			bson_destroy(bson);
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
			memcpy(operation->scheme->key, j_message_get_n(reply, SMD_KEY_LENGTH), SMD_KEY_LENGTH);
		}
		j_connection_pool_push_smd(index, smd_connection);
	}
	return TRUE;
}
static void
j_smd_file_open_free(gpointer data)
{
	JSMDFileOperation* operation = data;
	g_free(operation->name);
	j_smd_file_unref(operation->scheme);
	g_free(operation);
}
void*
j_smd_file_open(const char* name, JBatch* batch)
{
	JOperation* op;
	JSMDFileOperation* smd_op;
	smd_op = g_new(JSMDFileOperation, 1);
	smd_op->scheme = g_new(J_Scheme_t, 1);
	smd_op->scheme->ref_count = 2;
	smd_op->scheme->user_data = NULL;
	smd_op->scheme->type = NULL;
	smd_op->scheme->space = NULL;
	memset(smd_op->scheme->key, 0, SMD_KEY_LENGTH);
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_file_open_exec;
	op->free_func = j_smd_file_open_free;
	smd_op->name = g_strdup(name);
	j_batch_add(batch, op);
	return smd_op->scheme;
}
void*
j_smd_file_ref(void* _file)
{
	J_Scheme_t* file = _file;
	if (file)
		g_atomic_int_inc(&(file->ref_count));
	return file;
}
gboolean
j_smd_file_unref(void* _file)
{
	J_Scheme_t* file = _file;
	if (file && g_atomic_int_dec_and_test(&(file->ref_count)))
	{
		j_smd_type_unref(file->type);
		j_smd_space_unref(file->space);
		g_free(file);
		return FALSE;
	}
	return file != NULL;
}
