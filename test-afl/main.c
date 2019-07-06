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
#define AFL_LIMIT_STRING_LEN 15
#define AFL_LIMIT_SCHEMA_NAMESPACE 4
#define AFL_LIMIT_SCHEMA_NAME 4
#define AFL_LIMIT_SCHEMA_VARIABLES 4
//<-

enum JSMDAflEvent
{
	AFL_EVENT_SMD_SCHEMA_CREATE = 0,
	AFL_EVENT_SMD_SCHEMA_GET,
	AFL_EVENT_SMD_SCHEMA_DELETE,
	AFL_EVENT_SMD_INSERT,
	AFL_EVENT_SMD_UPDATE,
	AFL_EVENT_SMD_DELETE,
	AFL_EVENT_SMD_QUERY,
	AFL_EVENT_SMD_ITERATE,
	_AFL_EVENT_EVENT_COUNT,
};
typedef enum JSMDAflEvent JSMDAflEvent;

struct JSMDAflRandomValues
{
	guint namespace;
	guint name;
	union
	{
		struct
		{
			guint variable_count;
			JSMDType variable_types[AFL_LIMIT_SCHEMA_VARIABLES];
		} schema_create;
	};
};
typedef struct JSMDAflRandomValues JSMDAflRandomValues;

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
#define MYABORT()                      \
	do                             \
	{                              \
		J_DEBUG("error%d", 0); \
		abort();               \
	} while (0)

int
main(int argc, char* argv[])
{
	//schema->
	gboolean namespace_name_exist[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME];
	bson_t* namespace_name_bson[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME];
	guint namespace_name_variable_count[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME];
	JSMDType namespace_name_variable_type[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SCHEMA_VARIABLES];
	//<-
	//allgemein->
	char namespace_strbuf[AFL_LIMIT_STRING_LEN];
	char name_strbuf[AFL_LIMIT_STRING_LEN];
	char varname_strbuf[AFL_LIMIT_STRING_LEN];
	gboolean ret;
	bson_t* bson;
	JSMDAflEvent event;
	JSMDAflRandomValues random_values;
	guint i, j, k;
	//<-
	for (i = 0; i < AFL_LIMIT_SCHEMA_NAMESPACE; i++)
	{
		for (j = 0; j < AFL_LIMIT_SCHEMA_NAME; j++)
		{
			namespace_name_exist[i][j] = FALSE;
			namespace_name_variable_count[i][j] = 0;
			namespace_name_bson[i][j] = NULL;
			for (k = 0; k < AFL_LIMIT_SCHEMA_VARIABLES; k++)
			{
				namespace_name_variable_type = J_SMD_TYPE_INVALID;
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
			random_values.schema_create.variable_count = (random_values.schema_create.variable_count + 1) % AFL_LIMIT_SCHEMA_VARIABLES;
			if (namespace_name_exist[random_values.namespace][random_values.name])
			{

				bson = bson_new();
				ret = j_smd_schema_get(namespace_strbuf, name_strbuf, bson);
				if (!ret)
					MYABORT();
				if (bson_compare(bson, namespace_name_bson[random_values.namespace][random_values.name]))
					MYABORT();
				bson_destroy(bson);
			}
			bson = bson_new();
			for (i = 0; i < random_values.schema_create.variable_count; i++)
			{
				sprintf(varname_strbuf, AFL_VARNAME_FORMAT, i);
				bson_append_int32(bson, varname_strbuf, -1, random_values.schema_create.variable_type[i]);
			}
			ret = j_smd_schema_create(namespace_strbuf, name_strbuf, bson);
			if ((ret && namespace_name_exist[random_values.namespace][random_values.name]) || (!ret && !namespace_name_exist[random_values.namespace][random_values.name]))
				MYABORT();
			if (namespace_name_exist[random_values.namespace][random_values.name])
			{
				bson_destroy(bson);
			}
			else
			{
				namespace_name_exist[random_values.namespace][random_values.name] = TRUE;
				namespace_name_bson[random_values.namespace][random_values.name] = bson;
				namespace_name_variable_count[random_values.namespace][random_values.name] = random_values.schema_create.variable_count;
				for (i = 0; i < random_values.schema_create.variable_count; i++)
					namespace_name_variable_type[random_values.namespace][random_values.name][i] = random_values.schema_create.variable_type[i]
			}
			bson = bson_new();
			ret = j_smd_schema_get(namespace_strbuf, name_strbuf, bson);
			if (!ret)
				MYABORT();
			if (bson_compare(bson, namespace_name_bson[random_values.namespace][random_values.name]))
				MYABORT();
			bson_destroy(bson);
			break;
		case AFL_EVENT_SMD_SCHEMA_GET:
			break;
		case AFL_EVENT_SMD_SCHEMA_DELETE:
			break;
		case AFL_EVENT_SMD_INSERT:
			break;
		case AFL_EVENT_SMD_UPDATE:
			break;
		case AFL_EVENT_SMD_DELETE:
			break;
		case AFL_EVENT_SMD_QUERY:
		case AFL_EVENT_SMD_ITERATE:
			break;
		case _AFL_EVENT_EVENT_COUNT:
		default:
			MYABORT();
		}
	free:
		return 0;
	}
