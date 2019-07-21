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
	guint ret;
	guint ret_expected;
	J_DEBUG("AFL_EVENT_DB_ENTRY_NEW %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	j_db_entry_unref(the_stored_entry);
	the_stored_entry_field_set = 0;
	switch (random_values.invalid_switch % 2)
	{
	case 1: //schema NULL
		the_stored_entry = j_db_entry_new(NULL, &error);
		ret = the_stored_entry != NULL;
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0: //success
		ret_expected = the_stored_schema != NULL;
		the_stored_entry = j_db_entry_new(the_stored_schema, &error);
		ret = the_stored_entry != NULL;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
		MYABORT_DEFAULT();
	}
}
static void
event_entry_ref(void)
{
	GError* error = NULL;
	JDBEntry* ptr = NULL;
	gint ref_count;
	J_DEBUG("AFL_EVENT_DB_ENTRY_REF %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	if (the_stored_entry)
	{
		ref_count = the_stored_entry->ref_count;
		ptr = j_db_entry_ref(the_stored_entry, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
		MYABORT_IF(ptr != the_stored_entry);
		MYABORT_IF(the_stored_entry->ref_count != ref_count + 1);
		j_db_entry_unref(the_stored_entry);
		MYABORT_IF(the_stored_entry->ref_count != ref_count);
	}
	else
	{
		ptr = j_db_entry_ref(the_stored_entry, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, FALSE, error);
	}
}
static void
event_entry_set_field(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	JDBType type;
	J_DEBUG("AFL_EVENT_DB_ENTRY_SET_FIELD %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	ret_expected = the_stored_entry != NULL;
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, random_values.var_name);
	random_values.var_type = random_values.var_type % (_J_DB_TYPE_COUNT + 1);
	switch (random_values.invalid_switch % 5)
	{
	case 4: //not existing varname
		if (the_stored_entry != NULL)
			ret = j_db_schema_get_field(the_stored_entry->schema, "_not_existing_name_", &type, &error);
		else
			ret = j_db_schema_get_field(NULL, "_not_existing_name_", &type, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 3: //NULL varname
		if (the_stored_entry != NULL)
			ret = j_db_schema_get_field(the_stored_entry->schema, NULL, &type, &error);
		else
			ret = j_db_schema_get_field(NULL, NULL, &type, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 2: //NULL entry
		ret = j_db_schema_get_field(NULL, varname_strbuf, &type, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //NULL type
		if (the_stored_entry != NULL)
			ret = j_db_schema_get_field(the_stored_entry->schema, varname_strbuf, NULL, &error);
		else
			ret = j_db_schema_get_field(NULL, varname_strbuf, NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		type = random_values.var_type;
		ret_expected = ret_expected && (the_schema_field_type != _J_DB_TYPE_COUNT);
		if (the_stored_entry)
			ret = j_db_schema_get_field(the_stored_entry->schema, varname_strbuf, &type, &error);
		else
			ret = j_db_schema_get_field(NULL, varname_strbuf, &type, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		ret_expected = ret_expected && !(the_stored_entry_field_set & (1 << random_values.var_name));
		switch (type)
		{
		case J_DB_TYPE_SINT32:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_sint32, 4, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
			break;
		case J_DB_TYPE_UINT32:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_uint32, 4, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
			break;
		case J_DB_TYPE_FLOAT32:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_float32, 4, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
			break;
		case J_DB_TYPE_SINT64:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_sint64, 8, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
			break;
		case J_DB_TYPE_UINT64:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_uint64, 8, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
			break;
		case J_DB_TYPE_FLOAT64:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_float64, 8, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
			break;
		case J_DB_TYPE_STRING:
		case J_DB_TYPE_BLOB:
			sprintf(varvalue_strbuf, AFL_VARVALUE_FORMAT, random_values.var_value_str % AFL_LIMIT_SCHEMA_STRING_VALUES);
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, varvalue_strbuf, strlen(varvalue_strbuf) + 1, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_entry_field_set = the_stored_entry_field_set | (1 << random_values.var_name);
			break;
		case _J_DB_TYPE_COUNT:
			ret = FALSE;
			MYABORT_IF(ret_expected);
			break;
			MYABORT_DEFAULT();
		}
		break;
		MYABORT_DEFAULT();
	}
}
static void
event_entry_insert(void)
{
	JBatch* batch;
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	J_DEBUG("AFL_EVENT_DB_ENTRY_INSERT %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	ret_expected = the_stored_entry != NULL;
	ret_expected = ret_expected && the_stored_entry_field_set;
	switch (random_values.invalid_switch % 3)
	{
	case 2: //NULL entry
		ret = j_db_entry_insert(NULL, batch, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //NULL batch
		ret = j_db_entry_insert(the_stored_entry, NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		ret = j_db_entry_insert(the_stored_entry, batch, &error);
		ret = j_batch_execute(batch) && ret;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
		MYABORT_DEFAULT();
	}
	j_batch_unref(batch);
}
static void
event_entry_update(void)
{
	JBatch* batch;
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	J_DEBUG("AFL_EVENT_DB_ENTRY_UPDATE %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	ret_expected = the_stored_entry != NULL;
	ret_expected = ret_expected && the_stored_entry_field_set;
	ret_expected = ret_expected && the_stored_selector;
	ret_expected = ret_expected && j_db_selector_get_bson(the_stored_selector);
	switch (random_values.invalid_switch % 4)
	{
	case 3: //null selector
		ret = j_db_entry_update(the_stored_entry, NULL, batch, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 2: //null entry
		ret = j_db_entry_update(NULL, the_stored_selector, batch, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //null batch
		ret = j_db_entry_update(the_stored_entry, the_stored_selector, NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		ret = j_db_entry_update(the_stored_entry, the_stored_selector, batch, &error);
		ret = j_batch_execute(batch) && ret;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
		MYABORT_DEFAULT();
	}
	j_batch_unref(batch);
}
static void
event_entry_delete(void)
{
	JBatch* batch;
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	J_DEBUG("AFL_EVENT_DB_ENTRY_DELETE %d %d %d", random_values.namespace, random_values.name, random_values.entry);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	ret_expected = the_stored_entry != NULL;
	ret_expected = ret_expected && the_stored_schema->server_side;
	switch (random_values.invalid_switch % 3)
	{
	case 2: //null entry
		ret = j_db_entry_delete(NULL, the_stored_selector, batch, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //null batch
		ret = j_db_entry_delete(the_stored_entry, the_stored_selector, NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		ret = j_db_entry_delete(the_stored_entry, the_stored_selector, batch, &error);
		ret = j_batch_execute(batch) && ret;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
		MYABORT_DEFAULT();
	}
	j_batch_unref(batch);
}
