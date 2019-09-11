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

/*
 * this file is part of 'test-db-client.c'
 */
static void
event_entry_new(void)
{
	GError* error = NULL;
	guint ret_expected;
	g_debug("AFL_EVENT_DB_ENTRY_NEW %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	G_DEBUG_HERE();
	j_db_entry_unref(the_stored_entry);
	the_stored_entry_field_set = 0;
	if (!the_stored_schema)
	{
		return;
	}
	if (!the_stored_schema->bson_initialized)
		return;
	ret_expected = TRUE;
	G_DEBUG_HERE();
	the_stored_entry = j_db_entry_new(the_stored_schema, &error);
	J_AFL_DEBUG_ERROR(the_stored_entry != NULL, ret_expected, error);
}
static void
event_entry_ref(void)
{
	GError* error = NULL;
	JDBEntry* ptr = NULL;
	gint ref_count;
	g_debug("AFL_EVENT_DB_ENTRY_REF %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	if (!the_stored_entry)
	{
		return;
	}
	ref_count = the_stored_entry->ref_count;
	G_DEBUG_HERE();
	ptr = j_db_entry_ref(the_stored_entry);
	J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
	MYABORT_IF(ptr != the_stored_entry);
	MYABORT_IF(the_stored_entry->ref_count != ref_count + 1);
	G_DEBUG_HERE();
	j_db_entry_unref(the_stored_entry);
	MYABORT_IF(the_stored_entry->ref_count != ref_count);
}
static void
event_entry_set_field(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	JDBType type;
	g_debug("AFL_EVENT_DB_ENTRY_SET_FIELD %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	if (!the_stored_entry)
	{
		return;
	}
	ret_expected = TRUE;
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, random_values.var_name);
	random_values.var_type = random_values.var_type % (_J_DB_TYPE_COUNT + 1);
	type = random_values.var_type;
	ret_expected = ret_expected && (the_schema_field_type != _J_DB_TYPE_COUNT);
	G_DEBUG_HERE();
	ret = j_db_schema_get_field(the_stored_entry->schema, varname_strbuf, &type, &error);
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
	ret_expected = ret_expected && !(the_stored_entry_field_set & (1 << random_values.var_name));
	switch (type)
	{
	case J_DB_TYPE_SINT32:
		G_DEBUG_HERE();
		ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_sint32, 4, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
		{
			the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
		}
		break;
	case J_DB_TYPE_UINT32:
		G_DEBUG_HERE();
		ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_uint32, 4, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
		{
			the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
		}
		break;
	case J_DB_TYPE_FLOAT32:
		G_DEBUG_HERE();
		ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_float32, 4, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
		{
			the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
		}
		break;
	case J_DB_TYPE_SINT64:
		G_DEBUG_HERE();
		ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_sint64, 8, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
		{
			the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
		}
		break;
	case J_DB_TYPE_UINT64:
		G_DEBUG_HERE();
		ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_uint64, 8, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
		{
			the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
		}
		break;
	case J_DB_TYPE_FLOAT64:
		G_DEBUG_HERE();
		ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_float64, 8, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
		{
			the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
		}
		break;
	case J_DB_TYPE_STRING:
	case J_DB_TYPE_BLOB:
		sprintf(varvalue_strbuf, AFL_VARVALUE_FORMAT, random_values.var_value_str % AFL_LIMIT_SCHEMA_STRING_VALUES);
		G_DEBUG_HERE();
		ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, varvalue_strbuf, strlen(varvalue_strbuf) + 1, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
		{
			the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
		}
		break;
	case J_DB_TYPE_ID:
		break;
	case _J_DB_TYPE_COUNT:
		MYABORT_IF(ret_expected);
		break;
	default: //LCOV_EXCL_LINE
		MYABORT(); //LCOV_EXCL_LINE
	}
}
static void
event_entry_insert(void)
{
	JBatch* batch;
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	g_debug("AFL_EVENT_DB_ENTRY_INSERT %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	if (!the_stored_entry)
	{
		return;
	}
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	ret_expected = TRUE;
	ret_expected = ret_expected && the_stored_schema->server_side;
	ret_expected = ret_expected && the_stored_entry_field_set;
	G_DEBUG_HERE();
	ret = j_db_entry_insert(the_stored_entry, batch, &error);
	ret = j_batch_execute(batch) && ret;
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
	j_batch_unref(batch);
}
static void
event_entry_update(void)
{
	JBatch* batch;
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	g_debug("AFL_EVENT_DB_ENTRY_UPDATE %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	if (!the_stored_entry)
	{
		return;
	}
	if (!the_stored_selector)
	{
		return;
	}
	if (!j_db_selector_get_bson(the_stored_selector))
	{
		return;
	}
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	ret_expected = TRUE;
	ret_expected = ret_expected && the_stored_entry_field_set;
	ret_expected = ret_expected && the_stored_schema->server_side;
	G_DEBUG_HERE();
	ret = j_db_entry_update(the_stored_entry, the_stored_selector, batch, &error);
	ret = j_batch_execute(batch) && ret;
	if (error && error->domain == J_BACKEND_DB_ERROR && error->code == J_BACKEND_DB_ERROR_ITERATOR_NO_MORE_ELEMENTS)
	{
		ret_expected = FALSE;
	}
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
	j_batch_unref(batch);
}
static void
event_entry_delete(void)
{
	JBatch* batch;
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	g_debug("AFL_EVENT_DB_ENTRY_DELETE %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	if (!the_stored_entry)
	{
		return;
	}
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	ret_expected = TRUE;
	ret_expected = ret_expected && the_stored_schema->server_side;
	G_DEBUG_HERE();
	ret = j_db_entry_delete(the_stored_entry, the_stored_selector, batch, &error);
	ret = j_batch_execute(batch) && ret;
	if (error && error->domain == J_BACKEND_DB_ERROR && error->code == J_BACKEND_DB_ERROR_ITERATOR_NO_MORE_ELEMENTS)
	{
		ret_expected = FALSE;
	}
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
	j_batch_unref(batch);
}
