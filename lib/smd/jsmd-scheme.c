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
	J_Scheme_t* scheme;
	char* name;
	J_Scheme_t* parent;
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
j_smd_create_exec(JList* operations, JSemantics* semantics)
{
	bson_t* b_type;
	bson_t* b_space;
	bson_t bson[1];
	int message_size;
	JBackend* smd_backend;
	JSMDSchemeOperation* operation;
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
		message = j_message_new(J_MESSAGE_SMD_SCHEME_CREATE, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		bson_init(bson);
		b_type = j_smd_type_to_bson(operation->scheme->type);
		b_space = j_smd_space_to_bson(operation->scheme->space);
		bson_append_document(bson, "space_type", -1, b_space);
		bson_append_document(bson, "data_type", -1, b_type);
		if (smd_backend != NULL)
			j_backend_smd_scheme_create(smd_backend, operation->name, operation->parent->key, bson, operation->scheme->distribution_type, operation->scheme->key);
		else
		{
			message_size = strlen(operation->name) + 1 + SMD_KEY_LENGTH + 4 + 4 + bson->len;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->name, strlen(operation->name) + 1);
			j_message_append_n(message, operation->parent->key, SMD_KEY_LENGTH);
			j_message_append_4(message, &operation->scheme->distribution_type);
			j_message_append_4(message, &bson->len);
			j_message_append_n(message, bson_get_data(bson), bson->len);
		}
		bson_destroy(b_type);
		bson_destroy(b_space);
		bson_destroy(bson);
		g_free(b_type);
		g_free(b_space);
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
			memcpy(operation->scheme->key, j_message_get_n(reply, SMD_KEY_LENGTH), SMD_KEY_LENGTH);
			if (operation->scheme->distribution_type != J_DISTRIBUTION_DATABASE)
			{
				operation->scheme->object = j_distributed_object_new("smd", operation->scheme->key, operation->scheme->distribution);
				j_distributed_object_create(operation->scheme->object, batch);
			}
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
	JSMDSchemeOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
void*
j_smd_scheme_create(const char* name, void* parent, void* type, void* space, JDistributionType distribution, JBatch* batch)
{
	JOperation* op;
	JSMDSchemeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDSchemeOperation, 1);
	smd_op->scheme = g_new(J_Scheme_t, 1);
	smd_op->scheme->ref_count = 1;
	smd_op->scheme->type = j_smd_type_ref(type);
	smd_op->scheme->space = j_smd_space_ref(space);
	memset(smd_op->scheme->key, 0, SMD_KEY_LENGTH);
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_create_exec;
	op->free_func = j_smd_create_free;
	smd_op->name = g_strdup(name);
	smd_op->parent = parent;
	smd_op->scheme->distribution_type = distribution;
	if (smd_op->scheme->distribution_type != J_DISTRIBUTION_DATABASE)
		smd_op->scheme->distribution = j_distribution_new(distribution);
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return smd_op->scheme;
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
	JSMDSchemeOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	j_trace_enter(G_STRFUNC, NULL);
	g_return_val_if_fail(operations != NULL, FALSE);
	g_return_val_if_fail(semantics != NULL, FALSE);
	it = j_list_iterator_new(operations);
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_SCHEME_DELETE, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
			j_backend_smd_scheme_delete(smd_backend, operation->name, operation->parent->key);
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
	JSMDSchemeOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
gboolean
j_smd_scheme_delete(const char* name, void* parent, JBatch* batch)
{
	JOperation* op;
	JSMDSchemeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDSchemeOperation, 1);
	smd_op->scheme = j_smd_scheme_open(name, parent, batch);
	j_batch_execute(batch);
	if (smd_op->scheme->distribution_type != J_DISTRIBUTION_DATABASE) /*TODO speedup - dont require db read for this?*/
		j_distributed_object_delete(smd_op->scheme->object, batch);
	j_smd_scheme_unref(smd_op->scheme);
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
	JSMDSchemeOperation* operation;
	g_autoptr(JListIterator) it = NULL;
	g_autoptr(JMessage) message = NULL;
	int bson_len;
	bson_t bson[1];
	bson_iter_t b_iter;
	bson_iter_t b_scheme;
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
		message = j_message_new(J_MESSAGE_SMD_SCHEME_OPEN, 0);
		j_message_set_safety(message, semantics);
	}
	while (j_list_iterator_next(it))
	{
		operation = j_list_iterator_get(it);
		if (smd_backend != NULL)
		{
			bson_init(bson);
			j_backend_smd_scheme_open(smd_backend, operation->name, operation->parent->key, bson, &operation->scheme->distribution_type, operation->scheme->key);
			if (j_is_key_initialized(operation->scheme->key))
			{
				if (operation->scheme->distribution_type != J_DISTRIBUTION_DATABASE)
				{
					operation->scheme->distribution = j_distribution_new(operation->scheme->distribution_type);
					operation->scheme->object = j_distributed_object_new("smd", operation->scheme->key, operation->scheme->distribution);
				}
				if (bson_iter_init(&b_iter, bson) && bson_iter_find_descendant(&b_iter, "data_type", &b_scheme) && BSON_ITER_HOLDS_DOCUMENT(&b_scheme))
					operation->scheme->type = j_smd_type_from_bson(&b_scheme);
				if (bson_iter_init(&b_iter, bson) && bson_iter_find_descendant(&b_iter, "space_type", &b_scheme) && BSON_ITER_HOLDS_DOCUMENT(&b_scheme))
					operation->scheme->space = j_smd_space_from_bson(&b_scheme);
				bson_destroy(bson);
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
			memcpy(operation->scheme->key, j_message_get_n(reply, SMD_KEY_LENGTH), SMD_KEY_LENGTH);
			if (j_is_key_initialized(operation->scheme->key))
			{
				operation->scheme->distribution_type = j_message_get_4(reply);
				bson_len = j_message_get_4(reply);
				bson_data = j_message_get_n(reply, bson_len);
				bson_init_static(bson, bson_data, bson_len);
				if (operation->scheme->distribution_type != J_DISTRIBUTION_DATABASE)
				{
					operation->scheme->distribution = j_distribution_new(operation->scheme->distribution_type);
					operation->scheme->object = j_distributed_object_new("smd", operation->scheme->key, operation->scheme->distribution);
				}
				if (bson_iter_init(&b_iter, bson) && bson_iter_find_descendant(&b_iter, "data_type", &b_scheme) && BSON_ITER_HOLDS_DOCUMENT(&b_scheme))
					operation->scheme->type = j_smd_type_from_bson(&b_scheme);
				if (bson_iter_init(&b_iter, bson) && bson_iter_find_descendant(&b_iter, "space_type", &b_scheme) && BSON_ITER_HOLDS_DOCUMENT(&b_scheme))
					operation->scheme->space = j_smd_space_from_bson(&b_scheme);
				bson_destroy(bson);
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
	JSMDSchemeOperation* operation = data;
	g_free(operation->name);
	g_free(data);
}
void*
j_smd_scheme_open(const char* name, void* parent, JBatch* batch)
{
	JOperation* op;
	JSMDSchemeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDSchemeOperation, 1);
	smd_op->scheme = g_new(J_Scheme_t, 1);
	smd_op->scheme->ref_count = 1;
	memset(smd_op->scheme->key, 0, SMD_KEY_LENGTH);
	smd_op->scheme->type = NULL;
	smd_op->scheme->space = NULL;
	op = j_operation_new();
	op->key = NULL;
	op->data = smd_op;
	op->exec_func = j_smd_open_exec;
	op->free_func = j_smd_open_free;
	smd_op->name = g_strdup(name);
	smd_op->parent = parent;
	j_batch_add(batch, op);
	j_trace_leave(G_STRFUNC);
	return smd_op->scheme;
}

void*
j_smd_scheme_ref(void* _scheme)
{
	J_Scheme_t* scheme = _scheme;
	g_atomic_int_inc(&(scheme->ref_count));
	return scheme;
}
gboolean
j_smd_scheme_unref(void* _scheme)
{
	J_Scheme_t* scheme = _scheme;
	if (scheme && g_atomic_int_dec_and_test(&(scheme->ref_count)))
	{
		j_smd_type_unref(scheme->type);
		j_smd_space_unref(scheme->space);
		g_free(scheme);
	}
	return TRUE;
}

gboolean
j_smd_dataset_read(void* _scheme, void* buf, guint64 len, guint64 off, guint64* bytes_read, JBatch* batch)
{
	J_Scheme_t* scheme = _scheme;
	j_trace_enter(G_STRFUNC, NULL);
	j_distributed_object_read(scheme->object, buf, len, off, bytes_read, batch);
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
gboolean
j_smd_dataset_write(void* _scheme, const void* buf, guint64 len, guint64 off, guint64* bytes_written, JBatch* batch)
{
	J_Scheme_t* scheme = _scheme;
	j_trace_enter(G_STRFUNC, NULL);
	j_distributed_object_write(scheme->object, buf, len, off, bytes_written, batch);
	j_trace_leave(G_STRFUNC);
	return TRUE;
}
void*
j_smd_scheme_get_type(void* _scheme)
{
	J_Scheme_t* scheme = _scheme;
	return j_smd_type_ref(scheme->type);
}
void*
j_smd_scheme_get_space(void* _scheme)
{
	J_Scheme_t* scheme = _scheme;
	return j_smd_space_ref(scheme->space);
}

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
			j_backend_smd_scheme_read(smd_backend, operation->scheme->key, operation->buf_read, operation->buf_offset, operation->buf_size);
		else
		{
			message_size = 8 + 8 + SMD_KEY_LENGTH;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->scheme->key, SMD_KEY_LENGTH);
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
j_smd_scheme_read(void* _scheme, void* buf, guint64 buf_offset, guint64 buf_size, JBatch* batch)
{
	JOperation* op;
	JSMDSchemeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDSchemeOperation, 1);
	smd_op->scheme = _scheme;
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
			j_backend_smd_scheme_write(smd_backend, operation->scheme->key, operation->buf_write, operation->buf_offset, operation->buf_size);
		else
		{
			message_size = 8 + 8 + SMD_KEY_LENGTH + operation->buf_size;
			j_message_add_operation(message, message_size);
			j_message_append_n(message, operation->scheme->key, SMD_KEY_LENGTH);
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
j_smd_scheme_write(void* _scheme, const void* buf, guint64 buf_offset, guint64 buf_size, JBatch* batch)
{
	JOperation* op;
	JSMDSchemeOperation* smd_op;
	j_trace_enter(G_STRFUNC, NULL);
	smd_op = g_new(JSMDSchemeOperation, 1);
	smd_op->scheme = _scheme;
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
