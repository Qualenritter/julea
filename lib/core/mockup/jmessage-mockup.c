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

/* this mockup should avoid the network communication and execute the requested backend operations on the client side instead */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#define JULEA_DB_COMPILATION
#include <julea-config.h>
#include <stdio.h>
#include <math.h>
#include <float.h>
#include <glib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <julea.h>
#include <db/jdb-internal.h>
#include <core/jmessage.h>
#include "../../../test-afl/afl.h"
#include "../../../server/loop.c"
#define myabort(val)                                         \
	do                                                   \
	{                                                    \
		if (val)                                     \
		{                                            \
			g_critical("assertion failed%d", 0); \
			abort();                             \
		}                                            \
	} while (0)
#if (JULEA_TEST_MOCKUP == 1)

enum JMessageSemantics
{
	J_MESSAGE_SEMANTICS_ATOMICITY_BATCH = 1 << 0,
	J_MESSAGE_SEMANTICS_ATOMICITY_OPERATION = 1 << 1,
	J_MESSAGE_SEMANTICS_ATOMICITY_NONE = 1 << 2,
	J_MESSAGE_SEMANTICS_CONCURRENCY_OVERLAPPING = 1 << 3,
	J_MESSAGE_SEMANTICS_CONCURRENCY_NON_OVERLAPPING = 1 << 4,
	J_MESSAGE_SEMANTICS_CONCURRENCY_NONE = 1 << 5,
	J_MESSAGE_SEMANTICS_CONSISTENCY_IMMEDIATE = 1 << 6,
	J_MESSAGE_SEMANTICS_CONSISTENCY_EVENTUAL = 1 << 7,
	J_MESSAGE_SEMANTICS_CONSISTENCY_NONE = 1 << 8,
	J_MESSAGE_SEMANTICS_ORDERING_STRICT = 1 << 9,
	J_MESSAGE_SEMANTICS_ORDERING_SEMI_RELAXED = 1 << 10,
	J_MESSAGE_SEMANTICS_ORDERING_RELAXED = 1 << 11,
	J_MESSAGE_SEMANTICS_PERSISTENCY_IMMEDIATE = 1 << 12,
	J_MESSAGE_SEMANTICS_PERSISTENCY_EVENTUAL = 1 << 13,
	J_MESSAGE_SEMANTICS_PERSISTENCY_NONE = 1 << 14,
	J_MESSAGE_SEMANTICS_SAFETY_STORAGE = 1 << 15,
	J_MESSAGE_SEMANTICS_SAFETY_NETWORK = 1 << 16,
	J_MESSAGE_SEMANTICS_SAFETY_NONE = 1 << 17,
	J_MESSAGE_SEMANTICS_SECURITY_STRICT = 1 << 18,
	J_MESSAGE_SEMANTICS_SECURITY_NONE = 1 << 19
};

typedef enum JMessageSemantics JMessageSemantics;

struct JMessage
{
	guint operation_count;
	GByteArray* data;
	gchar* current;
	guint size_requested;
	guint size_used;
	JMessageType type;
	gint ref_count;
	gboolean client_side;
	guint32 semantics;
};
static JMessage* server_reply;
JMessage*
j_message_new(JMessageType type, gsize size)
{
	JMessage* message;
	message = g_slice_new(JMessage);
	message->operation_count = 0;
	message->client_side = TRUE;
	message->type = type;
	message->data = g_byte_array_new();
	message->current = NULL;
	message->size_requested = size;
	message->size_used = 0;
	message->ref_count = 1;
	message->semantics = 0;
	return message;
}
JMessage*
_j_message_new_reply(JMessage* message)
{
	JMessage* reply;
	myabort(!message);
	myabort(message->size_used != message->size_requested);
	reply = j_message_new(message->type, message->size_used);
	j_message_append_n(reply, message->data->data, message->data->len);
	reply->current = (gchar*)reply->data->data;
	reply->semantics = message->semantics;
	return reply;
}
JMessage*
j_message_new_reply(JMessage* message_input)
{
	JMessage* message;
	gint ret;
	myabort(!message_input);
	if (message_input->client_side)
	{
		message = _j_message_new_reply(message_input);
		message->client_side = FALSE;
		ret = jd_handle_message(message, NULL, NULL, 0, NULL);
		if (!ret)
		{
			abort();
		}
		j_message_unref(message);
		message = _j_message_new_reply(server_reply);
		message->operation_count = server_reply->operation_count;
		j_message_unref(server_reply);
		return message;
	}
	else /*avoid infinite loop*/
	{
		return server_reply = j_message_ref(j_message_new(message_input->type, 0));
	}
}

JMessage*
j_message_ref(JMessage* message)
{
	myabort(!message);
	g_atomic_int_inc(&message->ref_count);
	return message;
}
void
j_message_unref(JMessage* message)
{
	if (message && g_atomic_int_dec_and_test(&message->ref_count))
	{
		g_byte_array_unref(message->data);
		g_slice_free(JMessage, message);
	}
}
gboolean
j_message_append_1(JMessage* message, gconstpointer data)
{

	return j_message_append_n(message, data, 1);
}
gboolean
j_message_append_4(JMessage* message, gconstpointer data)
{
	return j_message_append_n(message, data, 4);
}
gboolean
j_message_append_8(JMessage* message, gconstpointer data)
{
	return j_message_append_n(message, data, 8);
}
gboolean
j_message_append_n(JMessage* message, gconstpointer data, gsize size)
{
	myabort(!message);
	g_byte_array_append(message->data, data, size);
	message->size_used += size;
	myabort(message->size_used > message->size_requested);
	return TRUE;
}
gboolean
j_message_append_string(JMessage* message, gchar const* str)
{
	j_message_append_n(message, str, strlen(str) + 1);
}
gchar
j_message_get_1(JMessage* message)
{
	gchar result;
	myabort(!message);
	myabort(message->current - (gchar*)message->data->data + 1 > message->data->len);
	result = *(gchar*)(message->current);
	message->current++;
	return result;
}
gint32
j_message_get_4(JMessage* message)
{
	gint32 result;
	myabort(!message);
	myabort(message->current - (gchar*)message->data->data + 4 > message->data->len);
	result = *(gint32*)(message->current);
	message->current += 4;
	return result;
}
gint64
j_message_get_8(JMessage* message)
{
	gint64 result;
	myabort(!message);
	myabort(message->current - (gchar*)message->data->data + 8 > message->data->len);
	result = *(gint64*)(message->current);
	message->current += 8;
	return result;
}
gpointer
j_message_get_n(JMessage* message, gsize size)
{
	gpointer result;
	myabort(!message);
	myabort(message->current - (gchar*)message->data->data + size > message->data->len);
	result = message->current;
	message->current += size;
	return result;
}
gchar const*
j_message_get_string(JMessage* message)
{
	gchar* ptr_end;
	gchar* ptr = message->current;
	myabort(!message);
	ptr_end = (gchar*)message->data->data + message->data->len;
	while (ptr < ptr_end && *ptr)
	{
		ptr++;
	}
	myabort(ptr == ptr_end);
	return j_message_get_n(message, ptr - message->current + 1);
}
gboolean
j_message_send(JMessage* message, GSocketConnection* connection)
{
	myabort(!message);
	myabort(!connection);
	return TRUE;
}
gboolean
j_message_receive(JMessage* message, GSocketConnection* connection)
{
	myabort(!message);
	myabort(!connection);
	return TRUE;
}
void
j_message_add_operation(JMessage* message, gsize size)
{
	myabort(!message);
	message->size_requested += size;
	message->operation_count++;
}
JMessageType
j_message_get_type(JMessage const* message)
{
	myabort(!message);
	return message->type;
}
guint32
j_message_get_count(JMessage const* message)
{
	myabort(!message);
	return message->operation_count;
}

void
j_message_set_semantics(JMessage* message, JSemantics* semantics)
{
	J_TRACE_FUNCTION(NULL);

	guint32 serialized_semantics = 0;

	g_return_if_fail(message != NULL);
	g_return_if_fail(semantics != NULL);

#define SERIALIZE_SEMANTICS(type, key)                                              \
	{                                                                           \
		gint tmp;                                                           \
		tmp = j_semantics_get(semantics, J_SEMANTICS_##type);               \
		if (tmp == J_SEMANTICS_##type##_##key)                              \
		{                                                                   \
			serialized_semantics |= J_MESSAGE_SEMANTICS_##type##_##key; \
		}                                                                   \
	}

	SERIALIZE_SEMANTICS(ATOMICITY, BATCH)
	SERIALIZE_SEMANTICS(ATOMICITY, OPERATION)
	SERIALIZE_SEMANTICS(ATOMICITY, NONE)
	SERIALIZE_SEMANTICS(CONCURRENCY, OVERLAPPING)
	SERIALIZE_SEMANTICS(CONCURRENCY, NON_OVERLAPPING)
	SERIALIZE_SEMANTICS(CONCURRENCY, NONE)
	SERIALIZE_SEMANTICS(CONSISTENCY, IMMEDIATE)
	SERIALIZE_SEMANTICS(CONSISTENCY, EVENTUAL)
	SERIALIZE_SEMANTICS(CONSISTENCY, NONE)
	SERIALIZE_SEMANTICS(ORDERING, STRICT)
	SERIALIZE_SEMANTICS(ORDERING, SEMI_RELAXED)
	SERIALIZE_SEMANTICS(ORDERING, RELAXED)
	SERIALIZE_SEMANTICS(PERSISTENCY, IMMEDIATE)
	SERIALIZE_SEMANTICS(PERSISTENCY, EVENTUAL)
	SERIALIZE_SEMANTICS(PERSISTENCY, NONE)
	SERIALIZE_SEMANTICS(SAFETY, STORAGE)
	SERIALIZE_SEMANTICS(SAFETY, NETWORK)
	SERIALIZE_SEMANTICS(SAFETY, NONE)
	SERIALIZE_SEMANTICS(SECURITY, STRICT)
	SERIALIZE_SEMANTICS(SECURITY, NONE)

#undef SERIALIZE_SEMANTICS

	message->semantics = GUINT32_TO_LE(serialized_semantics);
}
JSemantics*
j_message_get_semantics(JMessage* message)
{
	J_TRACE_FUNCTION(NULL);

	JSemantics* semantics;

	guint32 serialized_semantics;

	g_return_val_if_fail(message != NULL, NULL);

	serialized_semantics = message->semantics;
	serialized_semantics = GUINT32_FROM_LE(serialized_semantics);

	// If serialized_semantics is 0, we will end up with the default semantics.
	semantics = j_semantics_new(J_SEMANTICS_TEMPLATE_DEFAULT);

#define DESERIALIZE_SEMANTICS(type, key)                                                    \
	if (serialized_semantics & J_MESSAGE_SEMANTICS_##type##_##key)                      \
	{                                                                                   \
		j_semantics_set(semantics, J_SEMANTICS_##type, J_SEMANTICS_##type##_##key); \
	}

	DESERIALIZE_SEMANTICS(ATOMICITY, BATCH)
	DESERIALIZE_SEMANTICS(ATOMICITY, OPERATION)
	DESERIALIZE_SEMANTICS(ATOMICITY, NONE)
	DESERIALIZE_SEMANTICS(CONCURRENCY, OVERLAPPING)
	DESERIALIZE_SEMANTICS(CONCURRENCY, NON_OVERLAPPING)
	DESERIALIZE_SEMANTICS(CONCURRENCY, NONE)
	DESERIALIZE_SEMANTICS(CONSISTENCY, IMMEDIATE)
	DESERIALIZE_SEMANTICS(CONSISTENCY, EVENTUAL)
	DESERIALIZE_SEMANTICS(CONSISTENCY, NONE)
	DESERIALIZE_SEMANTICS(ORDERING, STRICT)
	DESERIALIZE_SEMANTICS(ORDERING, SEMI_RELAXED)
	DESERIALIZE_SEMANTICS(ORDERING, RELAXED)
	DESERIALIZE_SEMANTICS(PERSISTENCY, IMMEDIATE)
	DESERIALIZE_SEMANTICS(PERSISTENCY, EVENTUAL)
	DESERIALIZE_SEMANTICS(PERSISTENCY, NONE)
	DESERIALIZE_SEMANTICS(SAFETY, STORAGE)
	DESERIALIZE_SEMANTICS(SAFETY, NETWORK)
	DESERIALIZE_SEMANTICS(SAFETY, NONE)
	DESERIALIZE_SEMANTICS(SECURITY, STRICT)
	DESERIALIZE_SEMANTICS(SECURITY, NONE)

#undef DESERIALIZE_SEMANTICS

	return semantics;
}

gboolean
j_message_read(JMessage* message, GInputStream* stream)
{
	g_critical("mockup not implemented%d", 0);
	abort();
}
gboolean
j_message_write(JMessage* message, GOutputStream* stream)
{
	g_critical("mockup not implemented%d", 1);
	abort();
}

void
j_message_add_send(JMessage* message, gconstpointer data, guint64 size)
{
	g_critical("mockup not implemented%d", 2);
	abort();
}

#pragma GCC diagnostic pop

#endif
