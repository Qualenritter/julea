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
gboolean
j_is_key_initialized(const char* const key)
{
	int i;
	if (!key)
		return FALSE;
	for (i = 0; i < SMD_KEY_LENGTH; i++)
	{
		if (key[i] != 0)
			return TRUE;
	}
	return FALSE;
}
gboolean
j_smd_is_initialized(void* _data)
{
	J_Scheme_t* data = _data;
	if (!data)
		return FALSE;
	return j_is_key_initialized(data->key);
}

void
j_smd_reset(void)
{
	JBackend* smd_backend;
	GSocketConnection* smd_connection;
	g_autoptr(JMessage) reply = NULL;
	g_autoptr(JMessage) message = NULL;
	smd_backend = j_smd_backend();
	if (smd_backend == NULL)
	{
		message = j_message_new(J_MESSAGE_SMD_RESET, 0);
		smd_connection = j_connection_pool_pop_smd(0);
		j_message_send(message, smd_connection);
		j_message_receive(reply, smd_connection);
		j_connection_pool_push_smd(0, smd_connection);
		//TODO reset ALL backends
	}
}
