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

#ifndef JULEA_SMD_SCHEMA_H
#define JULEA_SMD_SCHEMA_H

#include <glib.h>
#include <bson.h>
#include <julea.h>

struct JSMDSchema
{
	gchar const* namespace;
	gchar const* name;
	gboolean bson_initialized;
	bson_t bson;
	gint ref_count;
};
typedef struct JSMDSchema JSMDSchema;

JSMDSchema* j_smd_schema_new(gchar const* namespace, gchar const* name, GError** error);

JSMDSchema* j_smd_schema_ref(JSMDSchema* schema, GError** error);
void j_smd_schema_unref(JSMDSchema* schema, GError** error);

gboolean j_smd_schema_add_field(JSMDSchema* schema, gchar const* name, JSMDType type, GError** error);
gboolean j_smd_schema_get_field(JSMDSchema* schema, gchar const* name, JSMDType* type, GError** error);
guint32 j_smd_schema_get_all_fields(JSMDSchema* schema, gchar const*** names, JSMDType** types, GError** error);

gboolean j_smd_schema_add_index(JSMDSchema* schema, gchar const* name, GError** error);

gboolean j_smd_schema_create(JSMDSchema* schema, JBatch* batch, GError** error);
gboolean j_smd_schema_get(JSMDSchema* schema, JBatch* batch, GError** error);
gboolean j_smd_schema_delete(JSMDSchema* schema, JBatch* batch, GError** error);

#endif
