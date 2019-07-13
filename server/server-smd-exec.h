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
#define smd_server_message_exec(func)                                                                                                                        \
	do                                                                                                                                                   \
	{                                                                                                                                                    \
		g_autoptr(JMessage) reply = NULL;                                                                                                            \
		gpointer batch = NULL;                                                                                                                       \
		JBackend_smd_operation_data data;                                                                                                            \
		GError* error = NULL;                                                                                                                        \
		reply = j_message_new_reply(message);                                                                                                        \
		memcpy(&data, &j_smd_##func##_params, sizeof(JBackend_smd_operation_data));                                                                  \
		if (operation_count)                                                                                                                         \
		{                                                                                                                                            \
			j_backend_smd_message_to_data_static(message, data.in_param, data.in_param_count);                                                   \
			if (data.out_param[data.out_param_count - 1].ptr && error)                                                                           \
				*((void**)data.out_param[data.out_param_count - 1].ptr) = g_error_copy(error);                                               \
			else                                                                                                                                 \
				jd_smd_backend->smd.backend_batch_start(data.in_param[0].ptr, safety, &batch, data.out_param[data.out_param_count - 1].ptr); \
			j_backend_smd_##func(jd_smd_backend, batch, &data);                                                                                  \
		}                                                                                                                                            \
		for (i = 1; i < operation_count; i++)                                                                                                        \
		{                                                                                                                                            \
			j_backend_smd_message_to_data_static(message, data.in_param, data.in_param_count);                                                   \
			if (data.out_param[data.out_param_count - 1].ptr && error)                                                                           \
				*((void**)data.out_param[data.out_param_count - 1].ptr) = g_error_copy(error);                                               \
			else                                                                                                                                 \
				j_backend_smd_##func(jd_smd_backend, batch, &data);                                                                          \
			if (i < operation_count - 1)                                                                                                         \
				j_backend_smd_message_from_data(reply, data.out_param, data.out_param_count);                                                \
		}                                                                                                                                            \
		if (!error)                                                                                                                                  \
			jd_smd_backend->smd.backend_batch_execute(batch, NULL);                                                                              \
		j_backend_smd_message_from_data(reply, data.out_param, data.out_param_count);                                                                \
		j_message_send(reply, connection);                                                                                                           \
		if (error)                                                                                                                                   \
			g_error_free(error);                                                                                                                 \
	} while (0)
