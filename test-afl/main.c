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
#include <julea-config.h>

#include <glib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <julea.h>
#include <julea-smd.h>
#include <julea-internal.h>

//configure here->
#define AFL_NAMESPACE_FORMAT "namespace_%d"
#define AFL_NAME_FORMAT "name_%d"
#define AFL_VARNAME_FORMAT "varname_%d"
#define AFL_STRING_CONST_FORMAT "value_%d"
#define AFL_LIMIT_STRING_LEN 15
#define AFL_LIMIT_SCHEMA_NAMESPACE 4
#define AFL_LIMIT_SCHEMA_NAME 4
#define AFL_LIMIT_SCHEMA_VARIABLES 4
#define AFL_LIMIT_SCHEMA_VALUES 4
#define AFL_LIMIT_SCHEMA_STRING_VALUES (AFL_LIMIT_SCHEMA_VALUES + 0)
//<-

enum JSMDAflEvent
{
	AFL_EVENT_SMD_SCHEMA_CREATE = 0,//TODO check & verify 0 column-scheme -> should deny
	AFL_EVENT_SMD_SCHEMA_GET,
	AFL_EVENT_SMD_SCHEMA_DELETE,
	AFL_EVENT_SMD_INSERT,
	AFL_EVENT_SMD_UPDATE,//TODO
	AFL_EVENT_SMD_DELETE,
	AFL_EVENT_SMD_QUERY,//TODO
	AFL_EVENT_SMD_ITERATE,//TODO
	_AFL_EVENT_EVENT_COUNT,
};
typedef enum JSMDAflEvent JSMDAflEvent;

#define MY_READ(var)                                                              \
	do                                                                        \
	{                                                                         \
		if (read(STDIN_FILENO, &var, sizeof(var)) < (ssize_t)sizeof(var)) \
			goto cleanup;                                             \
	} while (0)
#define MY_READ_LEN(var, len)                                    \
	do                                                       \
	{                                                        \
		if (read(STDIN_FILENO, var, len) < (ssize_t)len) \
			goto cleanup;                            \
	} while (0)
#define MY_READ_MAX(var, max)      \
	do                         \
	{                          \
		MY_READ(var);      \
		var = var % (max); \
	} while (0)
#define MYABORT()                       \
	do                              \
	{                               \
		J_DEBUG("error %d", 0); \
		abort();                \
	} while (0)

struct JSMDAflRandomValues
{
	guint namespace;
	guint name;
	union
	{
		struct
		{
			guint variable_count; //variables to create in schema
			JSMDType variable_types[AFL_LIMIT_SCHEMA_VARIABLES]; //the given types in this schema
		} schema_create;
		struct
		{
			union
			{
				gdouble d; //random double
				guint64 i; //random int
				guint s; //random string INDEX (point to namespace_varvalues_string_const)
			} values[AFL_LIMIT_SCHEMA_VARIABLES];
			guint value_count; //insert <real number of vaiables in schema> + ((mod 3) - 1)
			guint value_index; //"primary key" first column
			guint delete_existent; // mod 2 -> Yes/No
		} values;
	};
};
typedef struct JSMDAflRandomValues JSMDAflRandomValues;

//schema->
static gboolean namespace_exist[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME];
static bson_t* namespace_bson[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME];
static guint namespace_varcount[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME];
static JSMDType namespace_vartypes[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SCHEMA_VARIABLES];
//<-
//values->
static guint64 namespace_varvalues_int64[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SCHEMA_VARIABLES][AFL_LIMIT_SCHEMA_VALUES];
static gdouble namespace_varvalues_double[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SCHEMA_VARIABLES][AFL_LIMIT_SCHEMA_VALUES];
static char namespace_varvalues_string_const[AFL_LIMIT_SCHEMA_STRING_VALUES][AFL_LIMIT_SCHEMA_NAME];
static guint namespace_varvalues_string[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SCHEMA_VARIABLES][AFL_LIMIT_SCHEMA_VALUES];
//<-
//allgemein->
static JSMDAflRandomValues random_values;
static char namespace_strbuf[AFL_LIMIT_STRING_LEN];
static char name_strbuf[AFL_LIMIT_STRING_LEN];
static char varname_strbuf[AFL_LIMIT_STRING_LEN];
//<-
static void
event_delete(void)
{
	bson_t* bson;
	bson_t bson_child;
	gboolean ret;
	gboolean ret_expected = TRUE;
	guint index;
	bson = bson_new();
	random_values.values.delete_existent = random_values.values.delete_existent % 2;
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		random_values.values.value_index = random_values.values.value_index % AFL_LIMIT_SCHEMA_VALUES;
		sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
		bson_append_document_begin(bson, varname_strbuf, -1, &bson_child);
		ret = !bson_append_int32(bson, "operator", -1, J_SMD_OPERATOR_EQ);
		index = random_values.values.value_index;
		if (!random_values.values.delete_existent)
		{
			index = index + AFL_LIMIT_SCHEMA_VALUES; //delete invalid index
			ret_expected = FALSE;
		}
		if (ret)
			MYABORT();
		switch (namespace_vartypes[random_values.namespace][random_values.name][0])
		{
		case J_SMD_TYPE_SINT32:
			ret = !bson_append_int32(bson, "value", -1, index);
			break;
		case J_SMD_TYPE_UINT32:
			ret = !bson_append_int32(bson, "value", -1, index);
			break;
		case J_SMD_TYPE_FLOAT32:
			ret = !bson_append_double(bson, "value", -1, index);
			break;
		case J_SMD_TYPE_SINT64:
			ret = !bson_append_int64(bson, "value", -1, index);
			break;
		case J_SMD_TYPE_UINT64:
			ret = !bson_append_int64(bson, "value", -1, index);
			break;
		case J_SMD_TYPE_FLOAT64:
			ret = !bson_append_double(bson, "value", -1, index);
			break;
		case J_SMD_TYPE_STRING:
			ret = !bson_append_utf8(bson, "value", -1, namespace_varvalues_string_const[index % AFL_LIMIT_SCHEMA_STRING_VALUES], -1);
			break;
		case J_SMD_TYPE_INVALID:
		case _J_SMD_TYPE_COUNT:
		default:;
		}
		bson_append_document_end(bson, &bson_child);
	}
	else
	{
		//empty bson is a valid delete selector - but not existent namespace is invalid
		ret_expected = FALSE;
	}
	ret = j_smd_delete(namespace_strbuf, name_strbuf, bson);
	if (ret != ret_expected)
		MYABORT();
	bson_destroy(bson);
}
static void
event_insert(void)
{
	bson_t* bson;
	guint i;
	gboolean ret;
	gboolean ret_expected = TRUE;
	bson = bson_new();
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		random_values.values.value_index = random_values.values.value_index % AFL_LIMIT_SCHEMA_VALUES;
		random_values.values.value_count = namespace_varcount[random_values.namespace][random_values.name] + ((random_values.values.value_count % 3) - 1);
		namespace_varvalues_int64[random_values.namespace][random_values.name][0][random_values.values.value_index] = random_values.values.value_index;
		namespace_varvalues_double[random_values.namespace][random_values.name][0][random_values.values.value_index] = random_values.values.value_index;
		namespace_varvalues_string[random_values.namespace][random_values.name][0][random_values.values.value_index] = random_values.values.value_index % AFL_LIMIT_SCHEMA_STRING_VALUES;
		for (i = 1; i < AFL_LIMIT_SCHEMA_VARIABLES; i++)
		{
			namespace_varvalues_int64[random_values.namespace][random_values.name][i][random_values.values.value_index] = random_values.values.values[i].i;
			namespace_varvalues_double[random_values.namespace][random_values.name][i][random_values.values.value_index] = random_values.values.values[i].d;
			namespace_varvalues_string[random_values.namespace][random_values.name][i][random_values.values.value_index] = random_values.values.values[i].s % AFL_LIMIT_SCHEMA_STRING_VALUES;
		}
		for (i = 0; i < AFL_LIMIT_SCHEMA_VARIABLES; i++)
		{
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, i);
			if (i < random_values.values.value_count)
			{
				if (i < namespace_varcount[random_values.namespace][random_values.name])
				{
					switch (namespace_vartypes[random_values.namespace][random_values.name][i])
					{
					case J_SMD_TYPE_SINT32:
						ret = !bson_append_int32(bson, varname_strbuf, -1, (gint32)namespace_varvalues_int64[random_values.namespace][random_values.name][i][random_values.values.value_index]);
						break;
					case J_SMD_TYPE_UINT32:
						ret = !bson_append_int32(bson, varname_strbuf,-1, (guint32)namespace_varvalues_int64[random_values.namespace][random_values.name][i][random_values.values.value_index]);
						break;
					case J_SMD_TYPE_FLOAT32:
						ret = !bson_append_double(bson, varname_strbuf,-1, (gfloat)namespace_varvalues_double[random_values.namespace][random_values.name][i][random_values.values.value_index]);
						break;
					case J_SMD_TYPE_SINT64:
						ret = !bson_append_int64(bson, varname_strbuf,-1, (gint64)namespace_varvalues_int64[random_values.namespace][random_values.name][i][random_values.values.value_index]);
						break;
					case J_SMD_TYPE_UINT64:
						ret = !bson_append_int64(bson, varname_strbuf,-1, (guint64)namespace_varvalues_int64[random_values.namespace][random_values.name][i][random_values.values.value_index]);
						break;
					case J_SMD_TYPE_FLOAT64:
						ret = !bson_append_double(bson, varname_strbuf,-1, (gdouble)namespace_varvalues_double[random_values.namespace][random_values.name][i][random_values.values.value_index]);
						break;
					case J_SMD_TYPE_STRING:
						ret = !bson_append_utf8(bson, varname_strbuf,-1, namespace_varvalues_string_const[namespace_varvalues_string[random_values.namespace][random_values.name][i][random_values.values.value_index]], -1);
						break;
					case J_SMD_TYPE_INVALID:
					case _J_SMD_TYPE_COUNT:
					default:;
					}
				}
				else
				{
					sprintf(varname_strbuf, AFL_VARNAME_FORMAT, i + AFL_LIMIT_SCHEMA_VARIABLES);
					bson_append_int32(bson,varname_strbuf, -1, 1); //not existent varname
					ret_expected = FALSE;
				}
			}
			else
			{ //undefined column -> undefined result
				namespace_varvalues_int64[random_values.namespace][random_values.name][i][random_values.values.value_index] = 0;
				namespace_varvalues_double[random_values.namespace][random_values.name][i][random_values.values.value_index] = 0;
				namespace_varvalues_string[random_values.namespace][random_values.name][i][random_values.values.value_index] = 0;
			}
		}
	}
	else
	{
		sprintf(varname_strbuf, AFL_VARNAME_FORMAT, AFL_LIMIT_SCHEMA_VARIABLES);
		bson_append_int32(bson,varname_strbuf, -1, 1); //not existent namespace & not existent varname
		ret_expected = FALSE;
	}
	ret = j_smd_insert(namespace_strbuf, name_strbuf, bson);
	if (ret != ret_expected)
		MYABORT();
	bson_destroy(bson);
}
static void
event_schema_get(void)
{
	bson_iter_t iter;
	gboolean ret;
	bson_t* bson;
	guint i;
	bson = bson_new();
	ret = j_smd_schema_get(namespace_strbuf, name_strbuf, bson);
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		if (ret)
		{
			for (i = 0; i < AFL_LIMIT_SCHEMA_VARIABLES; i++)
			{
				sprintf(varname_strbuf, AFL_VARNAME_FORMAT, i);
				if (!bson_iter_init(&iter, namespace_bson[random_values.namespace][random_values.name]))
					MYABORT();
				if (i < namespace_varcount[random_values.namespace][random_values.name])
				{
					if (!bson_iter_find(&iter, varname_strbuf))
						MYABORT();
					if (!BSON_ITER_HOLDS_INT32(&iter))
						MYABORT();
					if (namespace_vartypes[random_values.namespace][random_values.name][i] != (JSMDType)bson_iter_int32(&iter))
						MYABORT();
				}
				else
				{
					if (bson_iter_find(&iter, varname_strbuf))
						MYABORT();
				}
			}
		}
		else
			MYABORT();
	}
	else
	{
		if (ret)
			MYABORT();
	}
	bson_destroy(bson);
}
static void
event_schema_delete(void)
{
	gboolean ret;
	bson_t* bson;
	bson = bson_new();
	ret = j_smd_schema_delete(namespace_strbuf, name_strbuf);
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		if (!ret)
			MYABORT();
		bson_destroy(namespace_bson[random_values.namespace][random_values.name]);
		namespace_bson[random_values.namespace][random_values.name] = NULL;
		namespace_exist[random_values.namespace][random_values.name] = FALSE;
	}
	else
	{
		if (ret)
			MYABORT();
	}
	bson_destroy(bson);
}
static void
event_schema_create(void)
{
	gboolean ret;
	gboolean ret_expected;
	bson_t* bson;
	guint i;
	random_values.schema_create.variable_count = (random_values.schema_create.variable_count + 1) % AFL_LIMIT_SCHEMA_VARIABLES;
	for (i = 0; i < random_values.schema_create.variable_count; i++)
		random_values.schema_create.variable_types[i] = random_values.schema_create.variable_types[i] % _J_SMD_TYPE_COUNT;
	bson = bson_new();
	ret_expected = TRUE;
	for (i = 0; i < random_values.schema_create.variable_count; i++)
	{
		sprintf(varname_strbuf, AFL_VARNAME_FORMAT, i);
		if (random_values.schema_create.variable_types[i] == J_SMD_TYPE_INVALID)
			ret_expected = FALSE;
		bson_append_int32(bson, varname_strbuf, -1, random_values.schema_create.variable_types[i]);
	}
	ret = j_smd_schema_create(namespace_strbuf, name_strbuf, bson);
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		if (ret)
			MYABORT();
	}
	else
	{
		if (ret != ret_expected)
			MYABORT();
	}
	if (namespace_exist[random_values.namespace][random_values.name])
		bson_destroy(bson);
	else
	{
		namespace_exist[random_values.namespace][random_values.name] = TRUE;
		namespace_bson[random_values.namespace][random_values.name] = bson;
		namespace_varcount[random_values.namespace][random_values.name] = random_values.schema_create.variable_count;
		for (i = 0; i < random_values.schema_create.variable_count; i++)
			namespace_vartypes[random_values.namespace][random_values.name][i] = random_values.schema_create.variable_types[i];
	}
}
int
main(int argc, char* argv[])
{
	JSMDAflEvent event;
	guint i, j, k;
	(void)argc;
	(void)argv;
	for (i = 0; i < AFL_LIMIT_SCHEMA_STRING_VALUES; i++)
	{
		sprintf(namespace_varvalues_string_const[i], AFL_STRING_CONST_FORMAT, i);
	}
	for (i = 0; i < AFL_LIMIT_SCHEMA_NAMESPACE; i++)
	{
		for (j = 0; j < AFL_LIMIT_SCHEMA_NAME; j++)
		{
			namespace_exist[i][j] = FALSE;
			namespace_varcount[i][j] = 0;
			namespace_bson[i][j] = NULL;
			for (k = 0; k < AFL_LIMIT_SCHEMA_VARIABLES; k++)
			{
				namespace_vartypes[i][j][k] = J_SMD_TYPE_INVALID;
			}
		}
	}
#ifdef __AFL_HAVE_MANUAL_CONTROL
	//https://github.com/mirrorer/afl/tree/master/llvm_mode
	//        __AFL_INIT();
	//      while (__AFL_LOOP(1000))
#endif
	{
	loop:
		MY_READ_MAX(event, _AFL_EVENT_EVENT_COUNT);
		MY_READ(random_values);
		random_values.namespace = random_values.namespace % AFL_LIMIT_SCHEMA_NAMESPACE;
		random_values.name = random_values.name % AFL_LIMIT_SCHEMA_NAME;
		sprintf(namespace_strbuf, AFL_NAMESPACE_FORMAT, random_values.namespace);
		sprintf(name_strbuf, AFL_NAME_FORMAT, random_values.name);
		switch (event)
		{
		case AFL_EVENT_SMD_SCHEMA_CREATE:
			event_schema_get();
			event_schema_create();
			event_schema_get();
			break;
		case AFL_EVENT_SMD_SCHEMA_GET:
			event_schema_get();
			break;
		case AFL_EVENT_SMD_SCHEMA_DELETE:
			event_schema_get();
			event_schema_delete();
			event_schema_get();
			break;
		case AFL_EVENT_SMD_INSERT:
			random_values.values.delete_existent = 1; //override random
			event_delete(); //unit tests should not uncontrolled insert same "primary key" multiple times
			event_insert();
			break;
		case AFL_EVENT_SMD_UPDATE:
			break;
		case AFL_EVENT_SMD_DELETE:
			event_delete();
			break;
		case AFL_EVENT_SMD_QUERY:
		case AFL_EVENT_SMD_ITERATE:
			break;
		case _AFL_EVENT_EVENT_COUNT:
		default:
			MYABORT();
		}
		goto loop;
	}
cleanup:
	for (i = 0; i < AFL_LIMIT_SCHEMA_NAMESPACE; i++)
	{
		for (j = 0; j < AFL_LIMIT_SCHEMA_NAME; j++)
		{
			bson_destroy(namespace_bson[i][j]);
			namespace_bson[i][j] = NULL;
		}
	}
	return 0;
}
