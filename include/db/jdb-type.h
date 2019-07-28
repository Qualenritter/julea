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

#ifndef JULEA_DB_TYPE_H
#define JULEA_DB_TYPE_H

#if !defined(JULEA_DB_H) && !defined(JULEA_DB_COMPILATION)
#error "Only <julea-db.h> can be included directly."
#endif

enum JDBType
{
	J_DB_TYPE_SINT32 = 0,
	J_DB_TYPE_UINT32,
	J_DB_TYPE_FLOAT32,
	J_DB_TYPE_SINT64,
	J_DB_TYPE_UINT64,
	J_DB_TYPE_FLOAT64,
	J_DB_TYPE_STRING,
	J_DB_TYPE_BLOB,
	_J_DB_TYPE_COUNT
};

typedef enum JDBType JDBType;

enum JFrontendDBError
{
	J_FRONTEND_DB_ERROR_BATCH_NULL,
	J_FRONTEND_DB_ERROR_ENTRY_NULL,
	J_FRONTEND_DB_ERROR_ITERATOR_NO_MORE_ELEMENTS,
	J_FRONTEND_DB_ERROR_ITERATOR_NOT_INITIALIZED,
	J_FRONTEND_DB_ERROR_ITERATOR_NULL,
	J_FRONTEND_DB_ERROR_LENGTH_NULL,
	J_FRONTEND_DB_ERROR_MODE_INVALID,
	J_FRONTEND_DB_ERROR_NAME_NULL,
	J_FRONTEND_DB_ERROR_NAMESPACE_NULL,
	J_FRONTEND_DB_ERROR_OPERATOR_INVALID,
	J_FRONTEND_DB_ERROR_SCHEMA_INITIALIZED,
	J_FRONTEND_DB_ERROR_SCHEMA_NOT_INITIALIZED,
	J_FRONTEND_DB_ERROR_SCHEMA_NULL,
	J_FRONTEND_DB_ERROR_SCHEMA_SERVER,
	J_FRONTEND_DB_ERROR_SELECTOR_EMPTY,
	J_FRONTEND_DB_ERROR_SELECTOR_MUST_NOT_EQUAL,
	J_FRONTEND_DB_ERROR_SELECTOR_NULL,
	J_FRONTEND_DB_ERROR_SELECTOR_TOO_COMPLEX,
	J_FRONTEND_DB_ERROR_TYPE_INVALID,
	J_FRONTEND_DB_ERROR_TYPE_NULL,
	J_FRONTEND_DB_ERROR_VALUE_NULL,
	J_FRONTEND_DB_ERROR_VARIABLE_ALREADY_SET,
	J_FRONTEND_DB_ERROR_VARIABLE_NAME_NULL,
	J_FRONTEND_DB_ERROR_VARIABLE_NOT_FOUND,
	_J_FRONTEND_DB_ERROR_COUNT
};

typedef enum JFrontendDBError JFrontendDBError;

union JDBType_value
{
	guint32 val_uint32;
	gint32 val_sint32;
	guint64 val_uint64;
	gint64 val_sint64;
	gdouble val_float64;
	gfloat val_float32;
	const char* val_string;
	struct
	{
		const char* val_blob;
		guint val_blob_length;
	};
};

typedef union JDBType_value JDBType_value;

#define J_FRONTEND_DB_ERROR j_frontend_db_error_quark()

GQuark j_frontend_db_error_quark(void);

#endif
