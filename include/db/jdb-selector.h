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

#ifndef JULEA_DB_SELECTOR_H
#define JULEA_DB_SELECTOR_H

#if !defined(JULEA_DB_H) && !defined(JULEA_DB_COMPILATION)
#error "Only <julea-db.h> can be included directly."
#endif

#include <glib.h>
#include <bson.h>
#include <julea.h>
#include <db/jdb-type.h>
#include <db/jdb-schema.h>
enum JDBSelectorMode
{
	J_DB_SELECTOR_MODE_AND,
	J_DB_SELECTOR_MODE_OR,
	_J_DB_SELECTOR_MODE_COUNT
};

typedef enum JDBSelectorMode JDBSelectorMode;

enum JDBSelectorOperator
{
	// <
	J_DB_SELECTOR_OPERATOR_LT = 0,
	// <=
	J_DB_SELECTOR_OPERATOR_LE,
	// >
	J_DB_SELECTOR_OPERATOR_GT,
	// >=
	J_DB_SELECTOR_OPERATOR_GE,
	// =
	J_DB_SELECTOR_OPERATOR_EQ,
	// !=
	J_DB_SELECTOR_OPERATOR_NE,
	_J_DB_SELECTOR_OPERATOR_COUNT
};

typedef enum JDBSelectorOperator JDBSelectorOperator;

struct JDBSelector
{
	JDBSelectorMode mode;
	JDBSchema* schema;
	gint ref_count;
	bson_t bson;
	guint bson_count;
};

typedef struct JDBSelector JDBSelector;

JDBSelector* j_db_selector_new(JDBSchema* schema, JDBSelectorMode mode, GError** error);

JDBSelector* j_db_selector_ref(JDBSelector* selector, GError** error);
void j_db_selector_unref(JDBSelector* selector);

gboolean j_db_selector_add_field(JDBSelector* selector, gchar const* name, JDBOperator operator, gconstpointer value, guint64 length, GError** error);
gboolean j_db_selector_add_selector(JDBSelector* selector, JDBSelector* sub_selector, GError** error);

#endif
