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
struct JSMDDatasetOperation
{
	J_Metadata_t* metadata;
	char* name;
	J_Metadata_t* parent;
};
typedef struct JSMDDatasetOperation JSMDDatasetOperation;
static gboolean
j_smd_create_exec(JList* operations, JSemantics* semantics)
{
	int message_size;
	JBackend* smd_backend;
	JSMDDatasetOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	GSocketConnection* smd_connection;
	JBatch* batch;
	g_autoptr(JMessage) message = NULL;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_DATASET_CREATE, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
			j_backend_smd_dataset_create(smd_backend, operation->name, operation->parent->key, operation->metadata->bson, operation->metadata->key);
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
			operation->metadata->object = j_distributed_object_new("smd", operation->metadata->key, operation->metadata->distribution);
			j_distributed_object_create(operation->metadata->object, batch);
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
	JSMDDatasetOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
void*
j_smd_dataset_create(const char* name, void* parent, void* _data_type, void* _space_type, JDistributionType distribution, JBatch* batch)
{
	JOperation* op;
	JSMDDatasetOperation* smd_op;
	bson_t* data_type;
	bson_t* space_type;
	j_trace_enter(G_STRFUNC, NULL);
	data_type = j_smd_type_to_bson(_data_type);
	space_type = j_smd_space_to_bson(_space_type);
	smd_op = g_new(JSMDDatasetOperation, 1);
	smd_op->metadata = g_new(J_Metadata_t, 1);
	smd_op->metadata->bson = g_new(bson_t, 1);
	smd_op->metadata->bson_requires_free = TRUE;
	bson_init(smd_op->metadata->bson);
	bson_append_int32(smd_op->metadata->bson, "distribution", -1, distribution);
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
	smd_op->metadata->distribution = j_distribution_new(distribution);
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return smd_op->metadata;
}
static gboolean
j_smd_delete_exec(JList* operations, JSemantics* semantics)
{
	JBackend* smd_backend;
	int message_size;
	g_autoptr(JListIterator) iter = NULL;
	g_autoptr(JMessage) reply = NULL;
	int index = 0;
	GSocketConnection* smd_connection;
	JSMDDatasetOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_DATASET_DELETE, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
			j_backend_smd_dataset_delete(smd_backend, operation->name, operation->parent->key);
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
	JSMDDatasetOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
gboolean
j_smd_dataset_delete(const char* name, void* parent, JBatch* batch)
{
	JOperation* op;
	JSMDDatasetOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDDatasetOperation, 1);
	smd_op->metadata = j_smd_dataset_open(name, parent, batch);
	j_batch_execute(batch);
	j_distributed_object_delete(smd_op->metadata->object, batch);
	j_smd_dataset_close(smd_op->metadata);
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
	JSMDDatasetOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	int bson_len;
	uint8_t* bson_data;
	bson_iter_t b_iter;
	gint distribution;
	int message_size;
	bson_iter_t b_distribution;
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
		message = j_message_new(J_MESSAGE_SMD_DATASET_OPEN, 0);
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
			j_backend_smd_dataset_open(smd_backend, operation->name, operation->parent->key, operation->metadata->bson, operation->metadata->key);
			if (j_is_key_initialized(operation->metadata->key))
			{
				if (bson_iter_init(&b_iter, operation->metadata->bson) && bson_iter_find_descendant(&b_iter, "distribution", &b_distribution) && BSON_ITER_HOLDS_INT32(&b_distribution))
				{
					distribution = bson_iter_int32(&b_distribution);
					operation->metadata->distribution = j_distribution_new(distribution);
					operation->metadata->object = j_distributed_object_new("smd", operation->metadata->key, operation->metadata->distribution);
				}
				else
				{
					if (operation->metadata->bson)
						bson_destroy(operation->metadata->bson);
					if (operation->metadata->bson_requires_free)
						g_free(operation->metadata->bson);
					memset(operation->metadata->key, 0, SMD_KEY_LENGTH);
				}
			}
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
				if (bson_iter_init(&b_iter, operation->metadata->bson) && bson_iter_find_descendant(&b_iter, "distribution", &b_distribution) && BSON_ITER_HOLDS_INT32(&b_distribution))
				{
					distribution = bson_iter_int32(&b_distribution);
					operation->metadata->distribution = j_distribution_new(distribution);
					operation->metadata->object = j_distributed_object_new("smd", operation->metadata->key, operation->metadata->distribution);
				}
				else
				{
					if (operation->metadata->bson)
						bson_destroy(operation->metadata->bson);
					if (operation->metadata->bson_requires_free)
						g_free(operation->metadata->bson);
					memset(operation->metadata->key, 0, SMD_KEY_LENGTH);
				}
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
	JSMDDatasetOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
void*
j_smd_dataset_open(const char* name, void* parent, JBatch* batch)
{
	JOperation* op;
	JSMDDatasetOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDDatasetOperation, 1);
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
j_smd_dataset_close(void* _metadata)
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
gboolean
j_smd_dataset_read(void* _metadata, void* buf, guint64 len, guint64 off, guint64* bytes_read, JBatch* batch)
{
	J_Metadata_t* metadata = _metadata;
	j_trace_enter(G_STRFUNC, NULL);
	j_distributed_object_read(metadata->object, buf, len, off, bytes_read, batch);
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
gboolean
j_smd_dataset_write(void* _metadata, const void* buf, guint64 len, guint64 off, guint64* bytes_written, JBatch* batch)
{
	J_Metadata_t* metadata = _metadata;
	j_trace_enter(G_STRFUNC, NULL);
	j_distributed_object_write(metadata->object, buf, len, off, bytes_written, batch);
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
void*
j_smd_dataset_get_type(void* metadata)
{
	return j_smd_get_type(metadata);
}
void*
j_smd_dataset_get_space(void* metadata)
{
	return j_smd_get_space(metadata);
}
