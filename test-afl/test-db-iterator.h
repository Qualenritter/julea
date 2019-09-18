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
static
void
event_iterator_new(void)
{
	GError* error = NULL;
	guint ret_expected;
	g_debug("AFL_EVENT_DB_ITERATOR_NEW %d %d", random_values.namespace, random_values.name);
	G_DEBUG_HERE();
	if (the_stored_iterator)
		j_db_iterator_unref(the_stored_iterator);
	the_stored_iterator_next_count = 0;
	if (!the_stored_schema)
	{
		return;
	}
	ret_expected = TRUE;
	switch (random_values.invalid_switch % 2)
	{
	case 1: //selector NULL - is allowed - should get everything
		if (the_stored_schema)
		{
			ret_expected = ret_expected && the_stored_schema->server_side;
		}
		G_DEBUG_HERE();
		the_stored_iterator = j_db_iterator_new(the_stored_schema, NULL, &error);
		J_AFL_DEBUG_ERROR(the_stored_iterator != NULL, ret_expected, error);
		break;
	case 0: //success
		if (the_stored_schema)
		{
			ret_expected = ret_expected && the_stored_schema->server_side;
		}
		G_DEBUG_HERE();
		the_stored_iterator = j_db_iterator_new(the_stored_schema, the_stored_selector, &error);
		J_AFL_DEBUG_ERROR(the_stored_iterator != NULL, ret_expected, error);
		break;
	default: //LCOV_EXCL_LINE
		MYABORT(); //LCOV_EXCL_LINE
	}
}
static
void
event_iterator_ref(void)
{
	GError* error = NULL;
	JDBIterator* ptr = NULL;
	gint ref_count;
	g_debug("AFL_EVENT_DB_ITERATOR_REF %d %d", random_values.namespace, random_values.name);
	if (!the_stored_iterator)
	{
		return;
	}
	ref_count = the_stored_iterator->ref_count;
	G_DEBUG_HERE();
	ptr = j_db_iterator_ref(the_stored_iterator);
	J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
	MYABORT_IF(ptr != the_stored_iterator);
	MYABORT_IF(the_stored_iterator->ref_count != ref_count + 1);
	G_DEBUG_HERE();
	if (the_stored_iterator)
		j_db_iterator_unref(the_stored_iterator);
	MYABORT_IF(the_stored_iterator->ref_count != ref_count);
}
static
void
event_iterator_next(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	g_debug("AFL_EVENT_DB_ITERATOR_NEXT %d %d", random_values.namespace, random_values.name);
	if (!the_stored_iterator)
	{
		return;
	}
	if (!the_stored_iterator->valid)
	{
		return;
	}
	G_DEBUG_HERE();
	ret = j_db_iterator_next(the_stored_iterator, &error);
	ret_expected = TRUE;
	if (error)
	{ //this selects which errors count as error and which not
		ret_expected = TRUE;
		if (error->domain == J_BACKEND_DB_ERROR)
		{
			switch (error->code)
			{
			case J_BACKEND_DB_ERROR_ITERATOR_NO_MORE_ELEMENTS:
				ret_expected = FALSE;
				break;
			case J_BACKEND_DB_ERROR_COMPARATOR_INVALID:
			case J_BACKEND_DB_ERROR_NO_VARIABLE_SET:
			case J_BACKEND_DB_ERROR_SCHEMA_EMPTY:
			case J_BACKEND_DB_ERROR_SCHEMA_NOT_FOUND:
			case J_BACKEND_DB_ERROR_SELECTOR_EMPTY:
			case J_BACKEND_DB_ERROR_DB_TYPE_INVALID:
			case J_BACKEND_DB_ERROR_THREADING_ERROR:
			case J_BACKEND_DB_ERROR_VARIABLE_NOT_FOUND:
				break;
			default: //LCOV_EXCL_LINE
				MYABORT(); //LCOV_EXCL_LINE
			}
		}
		else if (error->domain == J_DB_ERROR)
		{
			switch (error->code)
			{
			case J_DB_ERROR_ITERATOR_NO_MORE_ELEMENTS:
				ret_expected = FALSE;
				break;
			case J_DB_ERROR_VARIABLE_ALREADY_SET:
			case J_DB_ERROR_SCHEMA_NOT_INITIALIZED:
			case J_DB_ERROR_MODE_INVALID:
			case J_DB_ERROR_SCHEMA_INITIALIZED:
			case J_DB_ERROR_SELECTOR_MUST_NOT_EQUAL:
			case J_DB_ERROR_SELECTOR_EMPTY:
			case J_DB_ERROR_OPERATOR_INVALID:
			case J_DB_ERROR_SELECTOR_TOO_COMPLEX:
			case J_DB_ERROR_SCHEMA_SERVER:
			case J_DB_ERROR_TYPE_INVALID:
			case J_DB_ERROR_VARIABLE_NOT_FOUND:
				break;
			default: //LCOV_EXCL_LINE
				 MYABORT(); //LCOV_EXCL_LINE
			}
		}
	}
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
	if (ret)
	{
		the_stored_iterator_next_count++;
	}
}
static
void
event_iterator_get_field(void)
{
	JDBType type;
	gpointer value = NULL;
	guint64 length;
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	g_debug("AFL_EVENT_DB_ITERATOR_GET_FIELD %d %d", random_values.namespace, random_values.name);
	random_values.var_name = random_values.var_name % AFL_LIMIT_SCHEMA_FIELDS;
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, random_values.var_name);
	if (!the_stored_iterator)
	{
		return;
	}
	if (!the_stored_iterator->bson_valid)
	{
		return;
	}
	ret_expected = TRUE;
	ret_expected = ret_expected && the_schema_field_type != _J_DB_TYPE_COUNT;
	ret_expected = ret_expected && the_stored_iterator_next_count;
	ret_expected = ret_expected && the_stored_iterator->bson_valid;
	G_DEBUG_HERE();
	ret = j_db_iterator_get_field(the_stored_iterator, varname_strbuf, &type, &value, &length, &error);
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
	if (ret)
	{
		MYABORT_IF(type == _J_DB_TYPE_COUNT);
		MYABORT_IF(length && !value);
		MYABORT_IF(!length && value);
	}
	if (value)
	{
		g_free(value);
	}
}
