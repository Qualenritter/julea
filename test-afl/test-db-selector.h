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
event_selector_new(void)
{
	GError* error = NULL;
	guint ret_expected;
	G_DEBUG_HERE();
	j_db_selector_unref(the_stored_selector);
	the_stored_selector = NULL;
	the_stored_selector_field_count = 0;
	g_debug("AFL_EVENT_DB_SELECTOR_NEW %d %d", random_values.namespace, random_values.name);
	random_values.selector_mode = random_values.selector_mode % _J_DB_SELECTOR_MODE_COUNT;
	if (!the_stored_schema)
		return;
	ret_expected = TRUE;
	ret_expected = ret_expected && (random_values.selector_mode != _J_DB_SELECTOR_MODE_COUNT);
	G_DEBUG_HERE();
	the_stored_selector = j_db_selector_new(the_stored_schema, random_values.selector_mode, &error);
	J_AFL_DEBUG_ERROR(the_stored_selector != NULL, ret_expected, error);
}
static void
event_selector_ref(void)
{
	GError* error = NULL;
	JDBSelector* ptr = NULL;
	gint ref_count;
	g_debug("AFL_EVENT_DB_SELECTOR_REF %d %d", random_values.namespace, random_values.name);
	if (!the_stored_selector)
		return;
	ref_count = the_stored_selector->ref_count;
	G_DEBUG_HERE();
	ptr = j_db_selector_ref(the_stored_selector, &error);
	J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
	MYABORT_IF(ptr != the_stored_selector);
	MYABORT_IF(the_stored_selector->ref_count != ref_count + 1);
	G_DEBUG_HERE();
	j_db_selector_unref(the_stored_selector);
	MYABORT_IF(the_stored_selector->ref_count != ref_count);
}
static void
event_selector_add_field(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	JDBType type;
	JDBSelectorOperator operator= random_values.selector_operator % _J_DB_SELECTOR_OPERATOR_COUNT;
	g_debug("AFL_EVENT_DB_SELECTOR_ADD_FIELD %d %d", random_values.namespace, random_values.name);
	if (!the_stored_selector)
		return;
	ret_expected = TRUE;
	ret_expected = ret_expected && operator<_J_DB_SELECTOR_OPERATOR_COUNT;
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, random_values.var_name);
	random_values.var_type = random_values.var_type % _J_DB_TYPE_COUNT;
	switch (random_values.invalid_switch % 2)
	{
	case 1: //not existing varname
		G_DEBUG_HERE();
		ret = j_db_schema_get_field(the_stored_selector->schema, "_not_existing_name_", &type, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		type = random_values.var_type;
		ret_expected = ret_expected && (the_schema_field_type != _J_DB_TYPE_COUNT);
		G_DEBUG_HERE();
		ret = j_db_schema_get_field(the_stored_selector->schema, varname_strbuf, &type, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected || ret, error);
		switch (type)
		{
		case J_DB_TYPE_SINT32:
			G_DEBUG_HERE();
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, operator, & random_values.var_value_sint32, 4, & error);
			if (error && error->domain == J_FRONTEND_DB_ERROR && error->code == J_FRONTEND_DB_ERROR_SELECTOR_TOO_COMPLEX)
			{
				ret_expected = FALSE;
			}
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
			{
				the_stored_selector_field_count++;
			}
			break;
		case J_DB_TYPE_UINT32:
			G_DEBUG_HERE();
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, operator, & random_values.var_value_uint32, 4, & error);
			if (error && error->domain == J_FRONTEND_DB_ERROR && error->code == J_FRONTEND_DB_ERROR_SELECTOR_TOO_COMPLEX)
			{
				ret_expected = FALSE;
			}
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
			{
				the_stored_selector_field_count++;
			}
			break;
		case J_DB_TYPE_FLOAT32:
			G_DEBUG_HERE();
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, operator, & random_values.var_value_float32, 4, & error);
			if (error && error->domain == J_FRONTEND_DB_ERROR && error->code == J_FRONTEND_DB_ERROR_SELECTOR_TOO_COMPLEX)
			{
				ret_expected = FALSE;
			}
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
			{
				the_stored_selector_field_count++;
			}
			break;
		case J_DB_TYPE_SINT64:
			G_DEBUG_HERE();
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, operator, & random_values.var_value_sint64, 8, & error);
			if (error && error->domain == J_FRONTEND_DB_ERROR && error->code == J_FRONTEND_DB_ERROR_SELECTOR_TOO_COMPLEX)
			{
				ret_expected = FALSE;
			}
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
			{
				the_stored_selector_field_count++;
			}
			break;
		case J_DB_TYPE_UINT64:
			G_DEBUG_HERE();
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, operator, & random_values.var_value_uint64, 8, & error);
			if (error && error->domain == J_FRONTEND_DB_ERROR && error->code == J_FRONTEND_DB_ERROR_SELECTOR_TOO_COMPLEX)
			{
				ret_expected = FALSE;
			}
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
			{
				the_stored_selector_field_count++;
			}
			break;
		case J_DB_TYPE_FLOAT64:
			G_DEBUG_HERE();
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, operator, & random_values.var_value_float64, 8, & error);
			if (error && error->domain == J_FRONTEND_DB_ERROR && error->code == J_FRONTEND_DB_ERROR_SELECTOR_TOO_COMPLEX)
			{
				ret_expected = FALSE;
			}
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
			{
				the_stored_selector_field_count++;
			}
			break;
		case J_DB_TYPE_STRING:
		case J_DB_TYPE_BLOB:
			sprintf(varvalue_strbuf, AFL_VARVALUE_FORMAT, random_values.var_value_str % AFL_LIMIT_SCHEMA_STRING_VALUES);
			G_DEBUG_HERE();
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, operator, varvalue_strbuf, strlen(varvalue_strbuf) + 1, &error);
			if (error && error->domain == J_FRONTEND_DB_ERROR && error->code == J_FRONTEND_DB_ERROR_SELECTOR_TOO_COMPLEX)
			{
				ret_expected = FALSE;
			}
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
			{
				the_stored_selector_field_count++;
			}
			break;
		case _J_DB_TYPE_COUNT:
			MYABORT_IF(ret_expected);
			break;
		default: //LCOV_EXCL_LINE
			MYABORT(); //LCOV_EXCL_LINE
		}
		break;
	default: //LCOV_EXCL_LINE
		MYABORT(); //LCOV_EXCL_LINE
	}
}
static void
event_selector_add_selector(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	g_debug("AFL_EVENT_DB_SELECTOR_ADD_SELECTOR %d %d", random_values.namespace, random_values.name);
	random_values.selector_selector = random_values.selector_selector % AFL_LIMIT_SELECTOR;
	if (!the_stored_selector)
		return;
	if (!stored_selectors[random_values.namespace][random_values.name][random_values.selector_selector])
		return;
	ret_expected = TRUE;
	ret_expected = ret_expected && (stored_selectors[random_values.namespace][random_values.name][random_values.selector_selector]->bson_count);
	ret_expected = ret_expected && random_values.selector_selector != random_values.selector;
	G_DEBUG_HERE();
	ret = j_db_selector_add_selector(the_stored_selector, stored_selectors[random_values.namespace][random_values.name][random_values.selector_selector], &error);
	if (error && error->domain == J_FRONTEND_DB_ERROR && error->code == J_FRONTEND_DB_ERROR_SELECTOR_TOO_COMPLEX)
	{
		ret_expected = FALSE;
	}
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
	if (ret)
	{
		the_stored_selector_field_count += stored_selectors_field_count[random_values.namespace][random_values.name][random_values.selector_selector];
	}
}
