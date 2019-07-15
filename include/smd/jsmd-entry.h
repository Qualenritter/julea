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

#ifndef JULEA_SMD_ENTRY_H
#define JULEA_SMD_ENTRY_H

#include <glib.h>
#include <bson.h>
#include <julea.h>
#include <smd/jsmd-type.h>
#include <smd/jsmd-selector.h>
#include <smd/jsmd-schema.h>

struct JSMDEntry
{
	gint ref_count;
	JSMDSchema* schema;
	JSMDSelector* selector;
	bson_t bson;
};
typedef struct JSMDEntry JSMDEntry;

JSMDEntry* j_smd_entry_new(JSMDSchema* schema, GError** error);

JSMDEntry* j_smd_entry_ref(JSMDEntry* entry, GError** error);
void j_smd_entry_unref(JSMDEntry* entry);

gboolean j_smd_entry_set_field(JSMDEntry* entry, gchar const* name, gconstpointer value, guint64 length, GError** error);

gboolean j_smd_entry_set_selector(JSMDEntry* entry, JSMDSelector* selector, GError** error);

gboolean j_smd_entry_insert(JSMDEntry* entry, JBatch* batch, GError** error);
gboolean j_smd_entry_update(JSMDEntry* entry, JBatch* batch, GError** error);
gboolean j_smd_entry_delete(JSMDEntry* entry, JBatch* batch, GError** error);

#endif
