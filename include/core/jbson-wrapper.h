/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2017-2019 Michael Kuhn
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

#ifndef JULEA_BSON_WRAPPER_H
#define JULEA_BSON_WRAPPER_H

#if !defined(JULEA_H) && !defined(JULEA_COMPILATION)
#error "Only <julea.h> can be included directly."
#endif

#include <julea-config.h>
#include <bson.h>
#include <julea-db.h>
#include <glib.h>

enum JBsonError
{
	J_BSON_ERROR_BSON_NULL,
	J_BSON_ERROR_BSON_INIT_FROM_JSON_FAILED,
	J_BSON_ERROR_BSON_NOT_ENOUGH_KEYS,
	J_BSON_ERROR_BSON_APPEND_FAILED,
	J_BSON_ERROR_ITER_NULL,
	J_BSON_ERROR_ITER_INIT,
	J_BSON_ERROR_ITER_INVALID_TYPE,
	J_BSON_ERROR_ITER_KEY_NOT_FOUND,
	J_BSON_ERROR_ITER_RECOURSE,
	_J_BSON_ERROR_COUNT
};
typedef enum JBsonError JBsonError;

GQuark j_bson_error_quark(void);

#define J_BSON_ERROR j_bson_error_quark()

gboolean j_bson_iter_init(bson_iter_t* iter, const bson_t* bson, GError** error);
gboolean j_bson_iter_next(bson_iter_t* iter, gboolean* has_next, GError** error);
gboolean j_bson_iter_key_equals(bson_iter_t* iter, const char* key, gboolean* equals, GError** error);
const char* j_bson_iter_key(bson_iter_t* iter, GError** error);
gboolean j_bson_iter_value(bson_iter_t* iter, JDBType type, JDBType_value* value, GError** error);
char* j_bson_as_json(const bson_t* bson, GError** error);
void j_bson_free_json(char* json);
gboolean j_bson_iter_find(bson_iter_t* iter, const char* key, GError** error);
gboolean j_bson_iter_recurse_array(bson_iter_t* iter, bson_iter_t* iter_child, GError** error);
gboolean j_bson_iter_recurse_document(bson_iter_t* iter, bson_iter_t* iter_child, GError** error);
gboolean j_bson_init_from_json(bson_t* bson, const char* json, GError** error);
gboolean j_bson_iter_type_db(bson_iter_t* iter, JDBType* type, GError** error);
gboolean j_bson_has_enough_keys(const bson_t* bson, guint32 min_keys, GError** error);
void j_bson_destroy(bson_t* bson);
gboolean j_bson_append_value(bson_t* bson, const char* name, JDBType type, JDBType_value* value, GError** error);
#endif