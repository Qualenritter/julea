/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2010-2019 Michael Kuhn
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

#ifndef JULEA_MESSAGE_H
#define JULEA_MESSAGE_H

#if (JULEA_TEST_MOCKUP == 1)
#ifndef JMESSAGE_COMPILATION
#define j_message_new j_message_mockup_new
#define j_message_new_reply j_message_mockup_new_reply
#define j_message_ref j_message_mockup_ref
#define j_message_unref j_message_mockup_unref
#define j_message_get_type j_message_mockup_get_type
#define j_message_get_flags j_message_mockup_get_flags
#define j_message_get_count j_message_mockup_get_count
#define j_message_append_1 j_message_mockup_append_1
#define j_message_append_4 j_message_mockup_append_4
#define j_message_append_8 j_message_mockup_append_8
#define j_message_append_n j_message_mockup_append_n
#define j_message_get_1 j_message_mockup_get_1
#define j_message_get_4 j_message_mockup_get_4
#define j_message_get_8 j_message_mockup_get_8
#define j_message_get_n j_message_mockup_get_n
#define j_message_get_string j_message_mockup_get_string
#define j_message_send j_message_mockup_send
#define j_message_receive j_message_mockup_receive
#define j_message_read j_message_mockup_read
#define j_message_write j_message_mockup_write
#define j_message_add_send j_message_mockup_add_send
#define j_message_add_operation j_message_mockup_add_operation
#define j_message_set_safety j_message_mockup_set_safety
#define j_message_force_safety j_message_mockup_force_safety
#endif
#endif

#if !defined(JULEA_H) && !defined(JULEA_COMPILATION)
#error "Only <julea.h> can be included directly."
#endif

#include <glib.h>
#include <gio/gio.h>

G_BEGIN_DECLS

enum JMessageType
{
	J_MESSAGE_NONE,
	J_MESSAGE_PING,
	J_MESSAGE_STATISTICS,
	J_MESSAGE_OBJECT_CREATE,
	J_MESSAGE_OBJECT_DELETE,
	J_MESSAGE_OBJECT_READ,
	J_MESSAGE_OBJECT_STATUS,
	J_MESSAGE_OBJECT_WRITE,
	J_MESSAGE_KV_PUT,
	J_MESSAGE_KV_DELETE,
	J_MESSAGE_KV_GET,
	J_MESSAGE_KV_GET_ALL,
	J_MESSAGE_KV_GET_BY_PREFIX,
	J_MESSAGE_SMD_SCHEMA_CREATE,
	J_MESSAGE_SMD_SCHEMA_GET,
	J_MESSAGE_SMD_SCHEMA_DELETE,
	J_MESSAGE_SMD_INSERT,
	J_MESSAGE_SMD_UPDATE,
	J_MESSAGE_SMD_DELETE,
	J_MESSAGE_SMD_GET_ALL,
};

typedef enum JMessageType JMessageType;

enum JMessageFlags
{
	J_MESSAGE_FLAGS_NONE = 0,
	J_MESSAGE_FLAGS_REPLY = 1 << 0,
	J_MESSAGE_FLAGS_SAFETY_NETWORK = 1 << 1,
	J_MESSAGE_FLAGS_SAFETY_STORAGE = 1 << 2,
};

typedef enum JMessageFlags JMessageFlags;

struct JMessage;

typedef struct JMessage JMessage;

G_END_DECLS

#include <core/jsemantics.h>

G_BEGIN_DECLS

JMessage* j_message_new(JMessageType, gsize);
JMessage* j_message_new_reply(JMessage*);
JMessage* j_message_ref(JMessage*);
void j_message_unref(JMessage*);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(JMessage, j_message_unref)

JMessageType j_message_get_type(JMessage const*);
JMessageFlags j_message_get_flags(JMessage const*);
guint32 j_message_get_count(JMessage const*);

gboolean j_message_append_1(JMessage*, gconstpointer);
gboolean j_message_append_4(JMessage*, gconstpointer);
gboolean j_message_append_8(JMessage*, gconstpointer);
gboolean j_message_append_n(JMessage*, gconstpointer, gsize);

gchar j_message_get_1(JMessage*);
gint32 j_message_get_4(JMessage*);
gint64 j_message_get_8(JMessage*);
gpointer j_message_get_n(JMessage*, gsize);
gchar const* j_message_get_string(JMessage*);

gboolean j_message_send(JMessage*, GSocketConnection*);
gboolean j_message_receive(JMessage*, GSocketConnection*);

gboolean j_message_read(JMessage*, GInputStream*);
gboolean j_message_write(JMessage*, GOutputStream*);

void j_message_add_send(JMessage*, gconstpointer, guint64);
void j_message_add_operation(JMessage*, gsize);

void j_message_set_safety(JMessage*, JSemantics*);
void j_message_force_safety(JMessage*, gint);

G_END_DECLS

#endif
