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
event_schema_new(void)
{
	GError* error = NULL;
	guint i;
	guint ret;
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	if (the_stored_schema)
	{
		if (the_stored_schema->server_side)
		{
			ret = j_db_schema_delete(the_stored_schema, batch, &error);
			ret = j_batch_execute(batch) && ret;
			J_AFL_DEBUG_ERROR(ret, TRUE, error);
		}
		j_db_schema_unref(the_stored_schema);
		the_stored_schema = NULL;
	}
	the_stored_schema = NULL;
	sprintf(namespace_strbuf, AFL_NAMESPACE_FORMAT, random_values.namespace);
	sprintf(name_strbuf, AFL_NAME_FORMAT, random_values.name);
	switch (random_values.invalid_switch % 3)
	{
	case 2:
		the_stored_schema = j_db_schema_new(namespace_strbuf, NULL, &error);
		J_AFL_DEBUG_ERROR(the_stored_schema != NULL, FALSE, error);
		break;
	case 1:
		the_stored_schema = j_db_schema_new(NULL, name_strbuf, &error);
		J_AFL_DEBUG_ERROR(the_stored_schema != NULL, FALSE, error);
		break;
	case 0:
		the_stored_schema = j_db_schema_new(namespace_strbuf, name_strbuf, &error);
		J_AFL_DEBUG_ERROR(the_stored_schema != NULL, TRUE, error);
		for (i = 0; i < AFL_LIMIT_SCHEMA_FIELDS; i++)
		{
			schema_field_types[random_values.namespace][random_values.name][i] = _J_DB_TYPE_COUNT;
		}
		break;
	default:
		MYABORT();
	}
}
static void
event_schema_ref(void)
{
	GError* error = NULL;
	JDBSchema* ptr = NULL;
	if (the_stored_schema)
	{
		if (the_stored_schema->ref_count != 1)
			MYABORT();
		ptr = j_db_schema_ref(the_stored_schema, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
		if (ptr != the_stored_schema)
			MYABORT();
		if (the_stored_schema->ref_count != 2)
			MYABORT();
		j_db_schema_unref(the_stored_schema);
		if (the_stored_schema->ref_count != 1)
			MYABORT();
	}
	else
	{
		ptr = j_db_schema_ref(the_stored_schema, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, FALSE, error);
	}
}
static void
event_schema_add_field(void)
{
	gboolean ret;
	GError* error = NULL;
	gboolean ret_expected;
	random_values.var_name = random_values.var_name % AFL_LIMIT_SCHEMA_FIELDS;
	random_values.var_type = random_values.var_type % (_J_DB_TYPE_COUNT + 1);
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, random_values.var_name);
	ret_expected = the_stored_schema != NULL;
	ret_expected = ret_expected && random_values.var_type < _J_DB_TYPE_COUNT;
	ret_expected = ret_expected && the_schema_field_type == _J_DB_TYPE_COUNT;
	if (the_stored_schema)
		ret_expected = ret_expected && !the_stored_schema->server_side;
	if (random_values.invalid_switch % 2)
	{
		ret_expected = FALSE;
		ret = j_db_schema_add_field(the_stored_schema, NULL, random_values.var_type, &error);
	}
	else
		ret = j_db_schema_add_field(the_stored_schema, varname_strbuf, random_values.var_type, &error);
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
	if (ret)
		the_schema_field_type = random_values.var_type;
}
static void
event_schema_get_field(void)
{
	gboolean ret;
	JDBType type;
	GError* error = NULL;
	gboolean ret_expected;
	random_values.var_name = random_values.var_name % AFL_LIMIT_SCHEMA_FIELDS;
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, random_values.var_name);
	ret_expected = the_stored_schema != NULL;
	ret_expected = ret_expected && the_schema_field_type < _J_DB_TYPE_COUNT;
	switch (random_values.invalid_switch % 3)
	{
	case 2:
		ret_expected = FALSE;
		ret = j_db_schema_get_field(the_stored_schema, NULL, &type, &error);
		break;
	case 1:
		ret_expected = FALSE;
		ret = j_db_schema_get_field(the_stored_schema, varname_strbuf, NULL, &error);
		break;
	case 0:
		ret = j_db_schema_get_field(the_stored_schema, varname_strbuf, &type, &error);
		if (ret_expected && ret)
		{
			if (ret != (the_schema_field_type != _J_DB_TYPE_COUNT))
				MYABORT();
			if (type != the_schema_field_type)
				MYABORT();
		}
		break;
	default:
		MYABORT();
	}
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
}
static void
event_schema_get_fields(void)
{
	guint i, j, k;
	gboolean found;
	gboolean ret;
	JDBType* types;
	gchar** names;
	JDBType* types_cur;
	gchar** names_cur;
	GError* error = NULL;
	gboolean ret_expected;
	ret_expected = the_stored_schema != NULL;
	switch (random_values.invalid_switch % 3)
	{
	case 2:
		ret_expected = FALSE;
		ret = j_db_schema_get_all_fields(the_stored_schema, NULL, &types, &error);
		break;
	case 1:
		ret_expected = FALSE;
		ret = j_db_schema_get_all_fields(the_stored_schema, &names, NULL, &error);
		break;
	case 0:
		k = 0;
		for (j = 0; j < AFL_LIMIT_SCHEMA_FIELDS; j++)
			if (schema_field_types[random_values.namespace][random_values.name][j] != _J_DB_TYPE_COUNT)
				k++;
		ret_expected = ret_expected && k > 0;
		ret = j_db_schema_get_all_fields(the_stored_schema, &names, &types, &error);
		if (ret_expected && ret)
		{
			i = 0;
			types_cur = types;
			names_cur = names;
			while (*names_cur)
			{
				found = FALSE;
				for (j = 0; j < AFL_LIMIT_SCHEMA_FIELDS; j++)
				{
					sprintf(varname_strbuf, AFL_VARNAME_FORMAT, j);
					if (!g_strcmp0(varname_strbuf, *names_cur))
					{
						found = TRUE;
						break;
					}
				}
				if (!found)
					MYABORT();
				if (*types_cur != schema_field_types[random_values.namespace][random_values.name][j])
					MYABORT();
				i++;
				types_cur++;
				names_cur++;
			}
			if (*types_cur != _J_DB_TYPE_COUNT)
				MYABORT();
			if (i != k)
				MYABORT();
			g_free(types);
			g_strfreev(names);
		}
		break;
	default:
		MYABORT();
	}
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
}
static void
event_schema_add_index(void)
{
	//TODO event_schema_add_index
}
static void
event_schema_create(void)
{
	guint k, j;
	JDBSchema* schema = NULL;
	GError* error = NULL;
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	gboolean ret;
	gboolean ret_expected;
	switch (random_values.invalid_switch % 3)
	{
	case 2: //batch null
		ret_expected = the_stored_schema != NULL;
		ret = j_db_schema_create(the_stored_schema, NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //schema null
		ret = j_db_schema_create(NULL, batch, &error);
		ret = j_batch_execute(batch) && ret;
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0: //success
		ret_expected = the_stored_schema != NULL;
		k = 0;
		for (j = 0; j < AFL_LIMIT_SCHEMA_FIELDS; j++)
			if (schema_field_types[random_values.namespace][random_values.name][j] != _J_DB_TYPE_COUNT)
				k++;
		ret_expected = ret_expected && k > 0;
		if (the_stored_schema)
			ret_expected = ret_expected && !the_stored_schema->server_side;
		ret = j_db_schema_create(the_stored_schema, batch, &error);
		ret = j_batch_execute(batch) && ret;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
	default:
		MYABORT();
	}
	j_db_schema_unref(schema);
}
static void
event_schema_get(void)
{
	JDBSchema* schema = NULL;
	GError* error = NULL;
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	gboolean ret;
	gboolean bool_tmp;
	gboolean ret_expected;
	if (the_stored_schema != NULL)
	{
		switch (random_values.invalid_switch % 3)
		{
		case 2: //schema null
			ret = j_db_schema_get(NULL, batch, &error);
			ret = j_batch_execute(batch) && ret;
			J_AFL_DEBUG_ERROR(ret, FALSE, error);
			break;
		case 1: //batch null
			schema = j_db_schema_new(the_stored_schema->namespace, the_stored_schema->name, &error);
			J_AFL_DEBUG_ERROR(schema != NULL, TRUE, error);
			ret = j_db_schema_get(schema, NULL, &error);
			J_AFL_DEBUG_ERROR(ret, FALSE, error);
			break;
		case 0: //success
			ret_expected = the_stored_schema->server_side;
			schema = j_db_schema_new(the_stored_schema->namespace, the_stored_schema->name, &error);
			J_AFL_DEBUG_ERROR(schema != NULL, TRUE, error);
			ret = j_db_schema_get(schema, batch, &error);
			ret = j_batch_execute(batch) && ret;
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
			{
				ret = j_db_schema_equals(schema, the_stored_schema, &bool_tmp, &error);
				J_AFL_DEBUG_ERROR(ret, TRUE, error);
				if (!bool_tmp)
					MYABORT();
			}
			break;
		default:
			MYABORT();
		}
		j_db_schema_unref(schema);
	}
}
static void
event_schema_delete(void)
{
	//TODO schema delete invalidates all entrys iterators and selectors
	gboolean ret_expected;
	gboolean ret;
	GError* error = NULL;
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	switch (random_values.invalid_switch % 3)
	{
	case 2:
		ret = j_db_schema_delete(NULL, batch, &error);
		ret = j_batch_execute(batch) && ret;
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1:
		ret = j_db_schema_delete(the_stored_schema, NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		ret_expected = the_stored_schema != NULL;
		if (the_stored_schema)
			ret_expected = ret_expected && the_stored_schema->server_side;
		ret = j_db_schema_delete(the_stored_schema, batch, &error);
		ret = j_batch_execute(batch) && ret;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
		{
			j_db_schema_unref(the_stored_schema);
			the_stored_schema = NULL;
		}
		break;
	default:
		MYABORT();
	}
}
