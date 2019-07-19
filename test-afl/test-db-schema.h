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
        if (stored_schemas[random_values.namespace][random_values.name])
        {
                if (stored_schemas[random_values.namespace][random_values.name]->server_side)
                {
                        ret = j_db_schema_delete(stored_schemas[random_values.namespace][random_values.name], batch, &error);
                        ret = j_batch_execute(batch) && ret;
                        J_AFL_DEBUG_ERROR(ret, TRUE, error);
                }
                j_db_schema_unref(stored_schemas[random_values.namespace][random_values.name]);
                stored_schemas[random_values.namespace][random_values.name] = NULL;
        }
        stored_schemas[random_values.namespace][random_values.name] = NULL;
        sprintf(namespace_strbuf, AFL_NAMESPACE_FORMAT, random_values.namespace);
        sprintf(name_strbuf, AFL_NAME_FORMAT, random_values.name);
        switch (random_values.invalid_switch % 3)
        {
        case 2:
                stored_schemas[random_values.namespace][random_values.name] = j_db_schema_new(namespace_strbuf, NULL, &error);
                J_AFL_DEBUG_ERROR(stored_schemas[random_values.namespace][random_values.name] != NULL, FALSE, error);
                break;
        case 1:
                stored_schemas[random_values.namespace][random_values.name] = j_db_schema_new(NULL, name_strbuf, &error);
                J_AFL_DEBUG_ERROR(stored_schemas[random_values.namespace][random_values.name] != NULL, FALSE, error);
                break;
        case 0:
                stored_schemas[random_values.namespace][random_values.name] = j_db_schema_new(namespace_strbuf, name_strbuf, &error);
                J_AFL_DEBUG_ERROR(stored_schemas[random_values.namespace][random_values.name] != NULL, TRUE, error);
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
        if (stored_schemas[random_values.namespace][random_values.name])
        {
                if (stored_schemas[random_values.namespace][random_values.name]->ref_count != 1)
                        MYABORT();
                ptr = j_db_schema_ref(stored_schemas[random_values.namespace][random_values.name], &error);
                J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
                if (ptr != stored_schemas[random_values.namespace][random_values.name])
                        MYABORT();
                if (stored_schemas[random_values.namespace][random_values.name]->ref_count != 2)
                        MYABORT();
                j_db_schema_unref(stored_schemas[random_values.namespace][random_values.name]);
                if (stored_schemas[random_values.namespace][random_values.name]->ref_count != 1)
                        MYABORT();
        }
        else
        {
                ptr = j_db_schema_ref(stored_schemas[random_values.namespace][random_values.name], &error);
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
        ret_expected = stored_schemas[random_values.namespace][random_values.name] != NULL;
        ret_expected = ret_expected && random_values.var_type < _J_DB_TYPE_COUNT;
        ret_expected = ret_expected && schema_field_types[random_values.namespace][random_values.name][random_values.var_name] == _J_DB_TYPE_COUNT;
        if (stored_schemas[random_values.namespace][random_values.name])
                ret_expected = ret_expected && !stored_schemas[random_values.namespace][random_values.name]->server_side;
        if (random_values.invalid_switch % 2)
        {
                ret_expected = FALSE;
                ret = j_db_schema_add_field(stored_schemas[random_values.namespace][random_values.name], NULL, random_values.var_type, &error);
        }
        else
                ret = j_db_schema_add_field(stored_schemas[random_values.namespace][random_values.name], varname_strbuf, random_values.var_type, &error);
        J_AFL_DEBUG_ERROR(ret, ret_expected, error);
        if (ret)
                schema_field_types[random_values.namespace][random_values.name][random_values.var_name] = random_values.var_type;
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
        ret_expected = stored_schemas[random_values.namespace][random_values.name] != NULL;
        ret_expected = ret_expected && schema_field_types[random_values.namespace][random_values.name][random_values.var_name] < _J_DB_TYPE_COUNT;
        switch (random_values.invalid_switch % 3)
        {
        case 2:
                ret_expected = FALSE;
                ret = j_db_schema_get_field(stored_schemas[random_values.namespace][random_values.name], NULL, &type, &error);
                break;
        case 1:
                ret_expected = FALSE;
                ret = j_db_schema_get_field(stored_schemas[random_values.namespace][random_values.name], varname_strbuf, NULL, &error);
                break;
        case 0:
                ret = j_db_schema_get_field(stored_schemas[random_values.namespace][random_values.name], varname_strbuf, &type, &error);
                if (ret_expected && ret)
                {
                        if (ret != (schema_field_types[random_values.namespace][random_values.name][random_values.var_name] != _J_DB_TYPE_COUNT))
                                MYABORT();
                        if (type != schema_field_types[random_values.namespace][random_values.name][random_values.var_name])
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
        ret_expected = stored_schemas[random_values.namespace][random_values.name] != NULL;
        switch (random_values.invalid_switch % 3)
        {
        case 2:
                ret_expected = FALSE;
                ret = j_db_schema_get_all_fields(stored_schemas[random_values.namespace][random_values.name], NULL, &types, &error);
                break;
        case 1:
                ret_expected = FALSE;
                ret = j_db_schema_get_all_fields(stored_schemas[random_values.namespace][random_values.name], &names, NULL, &error);
                break;
        case 0:
                k = 0;
                for (j = 0; j < AFL_LIMIT_SCHEMA_FIELDS; j++)
                        if (schema_field_types[random_values.namespace][random_values.name][j] != _J_DB_TYPE_COUNT)
                                k++;
                ret_expected = ret_expected && k > 0;
                ret = j_db_schema_get_all_fields(stored_schemas[random_values.namespace][random_values.name], &names, &types, &error);
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
        //TODO test index function
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
                ret_expected = stored_schemas[random_values.namespace][random_values.name] != NULL;
                ret = j_db_schema_create(stored_schemas[random_values.namespace][random_values.name], NULL, &error);
                J_AFL_DEBUG_ERROR(ret, FALSE, error);
                break;
        case 1: //schema null
                ret = j_db_schema_create(NULL, batch, &error);
                ret = j_batch_execute(batch) && ret;
                J_AFL_DEBUG_ERROR(ret, FALSE, error);
                break;
        case 0: //success
                ret_expected = stored_schemas[random_values.namespace][random_values.name] != NULL;
                k = 0;
                for (j = 0; j < AFL_LIMIT_SCHEMA_FIELDS; j++)
                        if (schema_field_types[random_values.namespace][random_values.name][j] != _J_DB_TYPE_COUNT)
                                k++;
                ret_expected = ret_expected && k > 0;
                if (stored_schemas[random_values.namespace][random_values.name])
                        ret_expected = ret_expected && !stored_schemas[random_values.namespace][random_values.name]->server_side;
                ret = j_db_schema_create(stored_schemas[random_values.namespace][random_values.name], batch, &error);
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
        if (stored_schemas[random_values.namespace][random_values.name] != NULL)
        {
                switch (random_values.invalid_switch % 3)
                {
                case 2: //schema null
                        ret = j_db_schema_get(NULL, batch, &error);
                        ret = j_batch_execute(batch) && ret;
                        J_AFL_DEBUG_ERROR(ret, FALSE, error);
                        break;
                case 1: //batch null
                        schema = j_db_schema_new(stored_schemas[random_values.namespace][random_values.name]->namespace, stored_schemas[random_values.namespace][random_values.name]->name, &error);
                        J_AFL_DEBUG_ERROR(schema != NULL, TRUE, error);
                        ret = j_db_schema_get(schema, NULL, &error);
                        J_AFL_DEBUG_ERROR(ret, FALSE, error);
                        break;
                case 0: //success
                        ret_expected = stored_schemas[random_values.namespace][random_values.name]->server_side;
                        schema = j_db_schema_new(stored_schemas[random_values.namespace][random_values.name]->namespace, stored_schemas[random_values.namespace][random_values.name]->name, &error);
                        J_AFL_DEBUG_ERROR(schema != NULL, TRUE, error);
                        ret = j_db_schema_get(schema, batch, &error);
                        ret = j_batch_execute(batch) && ret;
                        J_AFL_DEBUG_ERROR(ret, ret_expected, error);
                        if (ret)
                        {
                                ret = j_db_schema_equals(schema, stored_schemas[random_values.namespace][random_values.name], &bool_tmp, &error);
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
                ret = j_db_schema_delete(stored_schemas[random_values.namespace][random_values.name], NULL, &error);
                J_AFL_DEBUG_ERROR(ret, FALSE, error);
                break;
        case 0:
                ret_expected = stored_schemas[random_values.namespace][random_values.name] != NULL;
                if (stored_schemas[random_values.namespace][random_values.name])
                        ret_expected = ret_expected && stored_schemas[random_values.namespace][random_values.name]->server_side;
                ret = j_db_schema_delete(stored_schemas[random_values.namespace][random_values.name], batch, &error);
                ret = j_batch_execute(batch) && ret;
                J_AFL_DEBUG_ERROR(ret, ret_expected, error);
                if (ret)
                {
                        j_db_schema_unref(stored_schemas[random_values.namespace][random_values.name]);
                        stored_schemas[random_values.namespace][random_values.name] = NULL;
                }
                break;
        default:
                MYABORT();
        }
}
