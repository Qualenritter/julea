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
event_iterator_new(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	J_DEBUG("AFL_EVENT_DB_ITERATOR_NEW %d %d", random_values.namespace, random_values.name);
	j_db_iterator_unref(the_stored_iterator);
	the_stored_iterator_next_count = 0;
	switch (random_values.invalid_switch % 3)
	{
	case 2: //schema NULL
		the_stored_iterator = j_db_iterator_new(NULL, the_stored_selector, &error);
		ret = the_stored_iterator != NULL;
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //selector NULL - is allowed - should get everything
		ret_expected = the_stored_schema != NULL;
		if (the_stored_schema)
			ret_expected = ret_expected && the_stored_schema->server_side;
		the_stored_iterator = j_db_iterator_new(the_stored_schema, NULL, &error);
		ret = the_stored_iterator != NULL;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
	case 0: //success
		ret_expected = the_stored_schema != NULL;
		if (the_stored_schema)
			ret_expected = ret_expected && the_stored_schema->server_side;
		the_stored_iterator = j_db_iterator_new(the_stored_schema, the_stored_selector, &error);
		ret = the_stored_iterator != NULL;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
	default: //LCOV_EXCL_LINE
		MYABORT(); //LCOV_EXCL_LINE
	}
}
static void
event_iterator_ref(void)
{
	GError* error = NULL;
	JDBIterator* ptr = NULL;
	gint ref_count;
	J_DEBUG("AFL_EVENT_DB_ITERATOR_REF %d %d", random_values.namespace, random_values.name);
	if (the_stored_iterator)
	{
		ref_count = the_stored_iterator->ref_count;
		ptr = j_db_iterator_ref(the_stored_iterator, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
		MYABORT_IF(ptr != the_stored_iterator);
		MYABORT_IF(the_stored_iterator->ref_count != ref_count + 1);
		j_db_iterator_unref(the_stored_iterator);
		MYABORT_IF(the_stored_iterator->ref_count != ref_count);
	}
	else
	{
		ptr = j_db_iterator_ref(the_stored_iterator, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, FALSE, error);
	}
}
static void
event_iterator_next(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	J_DEBUG("AFL_EVENT_DB_ITERATOR_NEXT %d %d", random_values.namespace, random_values.name);
	switch (random_values.invalid_switch % 2)
	{
	case 1: //null iterator
		ret = j_db_iterator_next(NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		ret = j_db_iterator_next(the_stored_iterator, &error);
		ret_expected = TRUE;
		if (error)
		{ //this selects which errors count as error and which not
			if (error->domain == J_BACKEND_DB_ERROR)
			{
				switch (error->code)
				{
				case J_BACKEND_DB_ERROR_BATCH_NULL:
				case J_BACKEND_DB_ERROR_NAME_NULL:
				case J_BACKEND_DB_ERROR_SCHEMA_NULL:
				case J_BACKEND_DB_ERROR_NAMESPACE_NULL:
				case J_BACKEND_DB_ERROR_SELECTOR_NULL:
				case J_BACKEND_DB_ERROR_METADATA_NULL:
				case J_BACKEND_DB_ERROR_ITERATOR_NULL:
				case J_BACKEND_DB_ERROR_ITERATOR_NO_MORE_ELEMENTS:
					ret_expected = FALSE;
					break;
				case J_BACKEND_DB_ERROR_BSON_APPEND_FAILED:
				case J_BACKEND_DB_ERROR_BSON_FAILED:
				case J_BACKEND_DB_ERROR_BSON_INVALID:
				case J_BACKEND_DB_ERROR_BSON_INVALID_TYPE:
				case J_BACKEND_DB_ERROR_BSON_ITER_INIT:
				case J_BACKEND_DB_ERROR_BSON_ITER_RECOURSE:
				case J_BACKEND_DB_ERROR_BSON_KEY_NOT_FOUND:
				case J_BACKEND_DB_ERROR_COMPARATOR_INVALID:
				case J_BACKEND_DB_ERROR_METADATA_EMPTY:
				case J_BACKEND_DB_ERROR_NO_VARIABLE_SET:
				case J_BACKEND_DB_ERROR_SCHEMA_EMPTY:
				case J_BACKEND_DB_ERROR_SCHEMA_NOT_FOUND:
				case J_BACKEND_DB_ERROR_SELECTOR_EMPTY:
				case J_BACKEND_DB_ERROR_DB_TYPE_INVALID:
				case J_BACKEND_DB_ERROR_SQL_CONSTRAINT:
				case J_BACKEND_DB_ERROR_SQL_FAILED:
				case J_BACKEND_DB_ERROR_THREADING_ERROR:
				case J_BACKEND_DB_ERROR_VARIABLE_NOT_FOUND:
				default: //LCOV_EXCL_LINE
					ret_expected = TRUE;
				}
			}
			else if (error->domain == JULEA_FRONTEND_ERROR)
			{
				switch (error->code)
				{
				case JULEA_FRONTEND_ERROR_NAME_NULL:
				case JULEA_FRONTEND_ERROR_NAMESPACE_NULL:
				case JULEA_FRONTEND_ERROR_VARIABLE_NAME_NULL:
				case JULEA_FRONTEND_ERROR_VARIABLE_TYPE_NULL:
				case JULEA_FRONTEND_ERROR_SELECTOR_NULL:
				case JULEA_FRONTEND_ERROR_ENTRY_NULL:
				case JULEA_FRONTEND_ERROR_TYPE_NULL:
				case JULEA_FRONTEND_ERROR_VALUE_NULL:
				case JULEA_FRONTEND_ERROR_LENGTH_NULL:
				case JULEA_FRONTEND_ERROR_ITERATOR_NULL:
				case JULEA_FRONTEND_ERROR_SCHEMA_NULL:
				case JULEA_FRONTEND_ERROR_BATCH_NULL:
				case JULEA_FRONTEND_ERROR_ITERATOR_NO_MORE_ELEMENTS:
					ret_expected = FALSE;
					break;
				case JULEA_FRONTEND_ERROR_BSON_APPEND_FAILED:
				case JULEA_FRONTEND_ERROR_BSON_INITIALIZED:
				case JULEA_FRONTEND_ERROR_BSON_ITER_INIT:
				case JULEA_FRONTEND_ERROR_BSON_KEY_FOUND:
				case JULEA_FRONTEND_ERROR_BSON_NOT_INITIALIZED:
				case JULEA_FRONTEND_ERROR_DB_BSON_SERVER:
				case JULEA_FRONTEND_ERROR_DB_TYPE_INVALID:
				case JULEA_FRONTEND_ERROR_VARIABLE_NOT_FOUND:
				case JULEA_FRONTEND_ERROR_SELECTOR_MODE_INVALID:
				case JULEA_FRONTEND_ERROR_BSON_INVALID_TYPE:
				case JULEA_FRONTEND_ERROR_VARIABLE_ALREADY_SET:
				default: //LCOV_EXCL_LINE
					ret_expected = TRUE;
				}
			}
		}
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
			the_stored_iterator_next_count++;
		if (!ret)
		{
			ret = j_db_iterator_next(the_stored_iterator, &error);
			J_AFL_DEBUG_ERROR(ret, FALSE, error);
		}
		break;
	default: //LCOV_EXCL_LINE
		MYABORT(); //LCOV_EXCL_LINE
	}
}
static void
event_iterator_get_field(void)
{
	JDBType type;
	gpointer value = NULL;
	guint64 length;
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	J_DEBUG("AFL_EVENT_DB_ITERATOR_GET_FIELD %d %d", random_values.namespace, random_values.name);
	random_values.var_name = random_values.var_name % AFL_LIMIT_SCHEMA_FIELDS;
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, random_values.var_name);
	ret_expected = the_stored_iterator != NULL;
	ret_expected = ret_expected && the_schema_field_type != _J_DB_TYPE_COUNT;
	ret_expected = ret_expected && the_stored_iterator_next_count;
	switch (random_values.invalid_switch % 6)
	{
	case 5: //iterator null
		ret = j_db_iterator_get_field(NULL, varname_strbuf, &type, &value, &length, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 4: //varname null
		ret = j_db_iterator_get_field(the_stored_iterator, NULL, &type, &value, &length, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 3: //type null
		ret = j_db_iterator_get_field(the_stored_iterator, varname_strbuf, NULL, &value, &length, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 2: //value NULL
		ret = j_db_iterator_get_field(the_stored_iterator, varname_strbuf, &type, NULL, &length, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //length NULL
		ret = j_db_iterator_get_field(the_stored_iterator, varname_strbuf, &type, &value, NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		ret = j_db_iterator_get_field(the_stored_iterator, varname_strbuf, &type, &value, &length, &error);
		if (error && error->domain == JULEA_FRONTEND_ERROR && error->code == JULEA_FRONTEND_ERROR_BSON_NOT_INITIALIZED)
			ret_expected = FALSE;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
		{
			MYABORT_IF(type == _J_DB_TYPE_COUNT);
			MYABORT_IF(length && !value);
			MYABORT_IF(!length && value);
		}
		break;
	default: //LCOV_EXCL_LINE
		MYABORT(); //LCOV_EXCL_LINE
	}
	if (value)
		g_free(value);
}
