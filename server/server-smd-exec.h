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
#define smd_server_message_exec(func)                                                                              \
	do                                                                                                         \
	{                                                                                                          \
		gint ret;                                                                                          \
		JMessage* reply = NULL;                                                                            \
		gpointer batch = NULL;                                                                             \
		JBackend_smd_operation_data data;                                                                  \
		GError* error = NULL;                                                                              \
		reply = j_message_new_reply(message);                                                              \
		memcpy(&data, &j_smd_##func##_params, sizeof(JBackend_smd_operation_data));                        \
		for (i = 0; i < data.out_param_count; i++)                                                         \
		{                                                                                                  \
			if (data.out_param[i].type == J_SMD_PARAM_TYPE_ERROR)                                      \
			{                                                                                          \
				data.out_param[i].ptr = &data.out_param[i].error_ptr;                              \
				data.out_param[i].error_ptr = NULL;                                                \
			}                                                                                          \
			else if (data.out_param[i].type == J_SMD_PARAM_TYPE_BSON)                                  \
			{                                                                                          \
				data.out_param[i].bson_initialized = FALSE;                                        \
				data.out_param[i].ptr = &data.out_param[i].bson;                                   \
			}                                                                                          \
		}                                                                                                  \
		if (operation_count)                                                                               \
			j_backend_smd_message_to_data_static(message, data.in_param, data.in_param_count);         \
		jd_smd_backend->smd.backend_batch_start(data.in_param[0].ptr, safety, &batch, &error);             \
		for (i = 0; i < operation_count; i++)                                                              \
		{                                                                                                  \
			ret = FALSE;                                                                               \
			if (i)                                                                                     \
				j_backend_smd_message_to_data_static(message, data.in_param, data.in_param_count); \
			if (error)                                                                                 \
				data.out_param[data.out_param_count - 1].error_ptr = g_error_copy(error);          \
			else                                                                                       \
			{                                                                                          \
				ret = j_backend_smd_##func(jd_smd_backend, batch, &data);                          \
				if (ret)                                                                           \
				{                                                                                  \
					for (i = 0; i < data.out_param_count; i++)                                 \
					{                                                                          \
						if (data.out_param[i].type == J_SMD_PARAM_TYPE_BSON)               \
							data.out_param[i].bson_initialized = TRUE;                 \
					}                                                                          \
				}                                                                                  \
			}                                                                                          \
			J_DEBUG("call j_backend_smd_message_from_data%d", 0);                                      \
			j_backend_smd_message_from_data(reply, data.out_param, data.out_param_count);              \
			if (ret)                                                                                   \
			{                                                                                          \
				for (i = 0; i < data.out_param_count; i++)                                         \
				{                                                                                  \
					if (data.out_param[i].type == J_SMD_PARAM_TYPE_BSON)                       \
						bson_destroy(data.out_param[i].ptr);                               \
				}                                                                                  \
			}                                                                                          \
		}                                                                                                  \
		if (!error)                                                                                        \
			jd_smd_backend->smd.backend_batch_execute(batch, &error);                                  \
		j_message_send(reply, connection);                                                                 \
		if (error)                                                                                         \
			g_error_free(error);                                                                       \
		j_message_unref(reply);                                                                            \
	} while (0)
