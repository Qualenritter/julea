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
#ifdef JULEA_DEBUG
j_smd_timer_variables_extern(j_smd_create_exec);
j_smd_timer_variables_extern(j_smd_create_free);
j_smd_timer_variables_extern(j_smd_dataset_read);
j_smd_timer_variables_extern(j_smd_dataset_write);
j_smd_timer_variables_extern(j_smd_delete_exec);
j_smd_timer_variables_extern(j_smd_delete_free);
j_smd_timer_variables_extern(j_smd_open_exec);
j_smd_timer_variables_extern(j_smd_open_free);
j_smd_timer_variables_extern(j_smd_read_exec);
j_smd_timer_variables_extern(j_smd_read_free);
j_smd_timer_variables_extern(j_smd_scheme_create);
j_smd_timer_variables_extern(j_smd_scheme_delete);
j_smd_timer_variables_extern(j_smd_scheme_get_space);
j_smd_timer_variables_extern(j_smd_scheme_get_type);
j_smd_timer_variables_extern(j_smd_scheme_open);
j_smd_timer_variables_extern(j_smd_scheme_read);
j_smd_timer_variables_extern(j_smd_scheme_ref);
j_smd_timer_variables_extern(j_smd_scheme_unref);
j_smd_timer_variables_extern(j_smd_scheme_write);
j_smd_timer_variables_extern(j_smd_write_exec);
j_smd_timer_variables_extern(j_smd_write_free);
j_smd_timer_variables_extern(j_smd_create_exec_server);
j_smd_timer_variables_extern(j_smd_delete_exec_server);
j_smd_timer_variables_extern(j_smd_open_exec_server);
j_smd_timer_variables_extern(j_smd_read_exec_server);
j_smd_timer_variables_extern(j_smd_write_exec_server);
void
j_smd_debug_init(void)
{
	J_DEBUG("init timers %d", 0);
	j_smd_timer_alloc(j_smd_create_exec);
	j_smd_timer_alloc(j_smd_create_exec_server);
	j_smd_timer_alloc(j_smd_create_free);
	j_smd_timer_alloc(j_smd_dataset_read);
	j_smd_timer_alloc(j_smd_dataset_write);
	j_smd_timer_alloc(j_smd_delete_exec);
	j_smd_timer_alloc(j_smd_delete_exec_server);
	j_smd_timer_alloc(j_smd_delete_free);
	j_smd_timer_alloc(j_smd_open_exec);
	j_smd_timer_alloc(j_smd_open_exec_server);
	j_smd_timer_alloc(j_smd_open_free);
	j_smd_timer_alloc(j_smd_read_exec);
	j_smd_timer_alloc(j_smd_read_exec_server);
	j_smd_timer_alloc(j_smd_read_free);
	j_smd_timer_alloc(j_smd_scheme_create);
	j_smd_timer_alloc(j_smd_scheme_delete);
	j_smd_timer_alloc(j_smd_scheme_get_space);
	j_smd_timer_alloc(j_smd_scheme_get_type);
	j_smd_timer_alloc(j_smd_scheme_open);
	j_smd_timer_alloc(j_smd_scheme_read);
	j_smd_timer_alloc(j_smd_scheme_ref);
	j_smd_timer_alloc(j_smd_scheme_unref);
	j_smd_timer_alloc(j_smd_scheme_write);
	j_smd_timer_alloc(j_smd_write_exec);
	j_smd_timer_alloc(j_smd_write_exec_server);
	j_smd_timer_alloc(j_smd_write_free);
}
void
j_smd_debug_exit(void)
{
	J_DEBUG("free timers %d", 0);
	j_smd_timer_print(j_smd_create_exec);
	j_smd_timer_print(j_smd_create_exec_server);
	j_smd_timer_print(j_smd_create_free);
	j_smd_timer_print(j_smd_dataset_read);
	j_smd_timer_print(j_smd_dataset_write);
	j_smd_timer_print(j_smd_delete_exec);
	j_smd_timer_print(j_smd_delete_exec_server);
	j_smd_timer_print(j_smd_delete_free);
	j_smd_timer_print(j_smd_open_exec);
	j_smd_timer_print(j_smd_open_exec_server);
	j_smd_timer_print(j_smd_open_free);
	j_smd_timer_print(j_smd_read_exec);
	j_smd_timer_print(j_smd_read_exec_server);
	j_smd_timer_print(j_smd_read_free);
	j_smd_timer_print(j_smd_scheme_create);
	j_smd_timer_print(j_smd_scheme_delete);
	j_smd_timer_print(j_smd_scheme_get_space);
	j_smd_timer_print(j_smd_scheme_get_type);
	j_smd_timer_print(j_smd_scheme_open);
	j_smd_timer_print(j_smd_scheme_read);
	j_smd_timer_print(j_smd_scheme_ref);
	j_smd_timer_print(j_smd_scheme_unref);
	j_smd_timer_print(j_smd_scheme_write);
	j_smd_timer_print(j_smd_write_exec);
	j_smd_timer_print(j_smd_write_exec_server);
	j_smd_timer_print(j_smd_write_free);

	j_smd_timer_free(j_smd_create_exec);
	j_smd_timer_free(j_smd_create_exec_server);
	j_smd_timer_free(j_smd_create_free);
	j_smd_timer_free(j_smd_dataset_read);
	j_smd_timer_free(j_smd_dataset_write);
	j_smd_timer_free(j_smd_delete_exec);
	j_smd_timer_free(j_smd_delete_exec_server);
	j_smd_timer_free(j_smd_delete_free);
	j_smd_timer_free(j_smd_open_exec);
	j_smd_timer_free(j_smd_open_exec_server);
	j_smd_timer_free(j_smd_open_free);
	j_smd_timer_free(j_smd_read_exec);
	j_smd_timer_free(j_smd_read_exec_server);
	j_smd_timer_free(j_smd_read_free);
	j_smd_timer_free(j_smd_scheme_create);
	j_smd_timer_free(j_smd_scheme_delete);
	j_smd_timer_free(j_smd_scheme_get_space);
	j_smd_timer_free(j_smd_scheme_get_type);
	j_smd_timer_free(j_smd_scheme_open);
	j_smd_timer_free(j_smd_scheme_read);
	j_smd_timer_free(j_smd_scheme_ref);
	j_smd_timer_free(j_smd_scheme_unref);
	j_smd_timer_free(j_smd_scheme_write);
	j_smd_timer_free(j_smd_write_exec);
	j_smd_timer_free(j_smd_write_exec_server);
	j_smd_timer_free(j_smd_write_free);
}
#else
void
j_smd_debug_init(void)
{
	J_DEBUG("no init %d", 0);
}
void
j_smd_debug_exit(void)
{
	J_DEBUG("no exit %d", 0);
}
#endif
