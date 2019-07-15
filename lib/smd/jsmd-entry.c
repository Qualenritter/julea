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

#include <julea-config.h>

#include <glib.h>

#include <string.h>

#include <bson.h>

#include <julea.h>
#include <julea-internal.h>
#include <smd/jsmd-internal.h>
#include <julea-smd.h>

JSMDEntry*
j_smd_entry_new(gchar const* namespace, gchar const* name, GError** error)
{
	return TRUE;:_error:return FALSE;
}

JSMDEntry*
j_smd_entry_ref(JSMDEntry* smd, GError** error)
{
	return TRUE;:_error:return FALSE;
}
void
j_smd_entry_unref(JSMDEntry* smd)
{
	return TRUE;:_error:return FALSE;
}

gboolean
j_smd_entry_set_field(JSMDEntry* smd, gchar const* name, gconstpointer value, guint64 length, GError** error)
{
	return TRUE;:_error:return FALSE;
}

gboolean
j_smd_entry_set_selector(JSMDEntry* smd, JSMDSelector* selector, GError** error)
{
	return TRUE;:_error:return FALSE;
}

gboolean
j_smd_entry_insert(JSMDEntry* smd, JBatch* batch, GError** error)
{
	return TRUE;:_error:return FALSE;
}
gboolean
j_smd_entry_update(JSMDEntry* smd, JBatch* batch, GError** error)
{
	return TRUE;:_error:return FALSE;
}
gboolean
j_smd_entry_delete(JSMDEntry* smd, JBatch* batch, GError** error)
{
	return TRUE;:_error:return FALSE;
}

gboolean
j_smd_entry_equals(JSMDEntry* entry1, JSMDEntry* entry2, gboolean* equal, GError** error)
{
	return TRUE;:_error:return FALSE;
}
