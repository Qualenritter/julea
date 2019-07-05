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

#ifndef JULEA_SMD_ITERATOR_H
#define JULEA_SMD_ITERATOR_H

#include <glib.h>
#include <bson.h>
#include <julea.h>
#include <smd/jsmd-schema.h>
#include <smd/jsmd-selector.h>

struct JSMDIterator
{
	JSMDSchema* schema;
	JSMDSelector* selector;
	gpointer iterator;
	gint ref_count;
	gboolean valid;
	gboolean bson_valid;
	bson_t bson;
};
typedef struct JSMDIterator JSMDIterator;

JSMDIterator* j_smd_iterator_new(JSMDSchema* schema, JSMDSelector* selector, JBatch* batch, GError** error);
JSMDIterator* j_smd_iterator_ref(JSMDIterator* iterator, GError** error);
void j_smd_iterator_unref(JSMDIterator* iterator);

gboolean j_smd_iterator_next(JSMDIterator* iterator, GError** error);
gboolean j_smd_iterator_get_field(JSMDIterator* iterator, gchar const* name, JSMDType* type, gpointer* value, guint64* length, GError** error);

#endif
