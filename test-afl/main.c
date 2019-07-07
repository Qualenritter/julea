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

#if (GLIB_MAJOR_VERSION < 2) || (GLIB_MINOR_VERSION < 58)
#define G_APPROX_VALUE(a, b, epsilon) (((a) > (b) ? (a) - (b) : (b) - (a)) < (epsilon))
#endif

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
			guint duplicate_variables; //mod 2 -> Yes/No
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
			guint existent; //mod 2 -> Yes/No
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
static char namespace_varvalues_string_const[AFL_LIMIT_SCHEMA_STRING_VALUES][AFL_LIMIT_SCHEMA_NAME];
//
static guint64 namespace_varvalues_int64[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SCHEMA_VALUES][AFL_LIMIT_SCHEMA_VARIABLES];
static gdouble namespace_varvalues_double[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SCHEMA_VALUES][AFL_LIMIT_SCHEMA_VARIABLES];
static guint namespace_varvalues_string[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SCHEMA_VALUES][AFL_LIMIT_SCHEMA_VARIABLES];
static guint namespace_varvalues_valid[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SCHEMA_VALUES]; // (x == 0) -> row does not exist, (x > 0) -> row exist with given number of valid columns
//<-
//allgemein->
static JSMDAflRandomValues random_values;
static char namespace_strbuf[AFL_LIMIT_STRING_LEN];
static char name_strbuf[AFL_LIMIT_STRING_LEN];
static char varname_strbuf[AFL_LIMIT_STRING_LEN];
bson_t* selector;
bson_t* metadata;
//<-
static gboolean
build_selector_single(guint varname, guint value)
{
	gboolean ret_expected = TRUE;
	bson_t bson_child;
	selector = bson_new();
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, varname);
	bson_append_document_begin(selector, varname_strbuf, -1, &bson_child);
	if (!bson_append_int32(&bson_child, "operator", -1, J_SMD_OPERATOR_EQ))
		MYABORT();
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		switch (namespace_vartypes[random_values.namespace][random_values.name][varname])
		{
		case J_SMD_TYPE_SINT32:
			if (!bson_append_int32(&bson_child, "value", -1, value))
				MYABORT();
			break;
		case J_SMD_TYPE_UINT32:
			if (!bson_append_int32(&bson_child, "value", -1, value))
				MYABORT();
			break;
		case J_SMD_TYPE_FLOAT32:
			if (!bson_append_double(&bson_child, "value", -1, value))
				MYABORT();
			break;
		case J_SMD_TYPE_SINT64:
			if (!bson_append_int64(&bson_child, "value", -1, value))
				MYABORT();
			break;
		case J_SMD_TYPE_UINT64:
			if (!bson_append_int64(&bson_child, "value", -1, value))
				MYABORT();
			break;
		case J_SMD_TYPE_FLOAT64:
			if (!bson_append_double(&bson_child, "value", -1, value))
				MYABORT();
			break;
		case J_SMD_TYPE_STRING:
			if (!bson_append_utf8(&bson_child, "value", -1, namespace_varvalues_string_const[value % AFL_LIMIT_SCHEMA_STRING_VALUES], -1))
				MYABORT();
			break;
		case J_SMD_TYPE_INVALID:
		case _J_SMD_TYPE_COUNT:
		default:
			MYABORT();
		}
	}
	else
	{ //operation on not existent namespace
		ret_expected = FALSE;
		if (!bson_append_int32(&bson_child, "value", -1, value))
			MYABORT();
	}
	bson_append_document_end(selector, &bson_child);
	return ret_expected;
}
static gboolean
build_metadata(void)
{
	gboolean ret_expected = TRUE;
	guint i;
	metadata = bson_new();
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		random_values.values.value_index = random_values.values.value_index % AFL_LIMIT_SCHEMA_VALUES;
		random_values.values.value_count = namespace_varcount[random_values.namespace][random_values.name] + ((random_values.values.value_count % 3) - 1);
		namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][0] = random_values.values.value_index;
		namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index][0] = random_values.values.value_index;
		namespace_varvalues_string[random_values.namespace][random_values.name][random_values.values.value_index][0] = random_values.values.value_index % AFL_LIMIT_SCHEMA_STRING_VALUES;
		for (i = 1; i < AFL_LIMIT_SCHEMA_VARIABLES; i++)
		{
			namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][i] = random_values.values.values[i].i;
			namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index][i] = random_values.values.values[i].d;
			namespace_varvalues_string[random_values.namespace][random_values.name][random_values.values.value_index][i] = random_values.values.values[i].s % AFL_LIMIT_SCHEMA_STRING_VALUES;
		}
		namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index] = random_values.values.value_count;
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
						if (!bson_append_int32(metadata, varname_strbuf, -1, (gint32)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][i]))
							MYABORT();
						break;
					case J_SMD_TYPE_UINT32:
						if (!bson_append_int32(metadata, varname_strbuf, -1, (guint32)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][i]))
							MYABORT();
						break;
					case J_SMD_TYPE_FLOAT32:
						if (!bson_append_double(metadata, varname_strbuf, -1, (gfloat)namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index][i]))
							MYABORT();
						break;
					case J_SMD_TYPE_SINT64:
						if (!bson_append_int64(metadata, varname_strbuf, -1, (gint64)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][i]))
							MYABORT();
						break;
					case J_SMD_TYPE_UINT64:
						if (!bson_append_int64(metadata, varname_strbuf, -1, (guint64)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][i]))
							MYABORT();
						break;
					case J_SMD_TYPE_FLOAT64:
						if (!bson_append_double(metadata, varname_strbuf, -1, (gdouble)namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index][i]))
							MYABORT();
						break;
					case J_SMD_TYPE_STRING:
						if (!bson_append_utf8(metadata, varname_strbuf, -1, namespace_varvalues_string_const[namespace_varvalues_string[random_values.namespace][random_values.name][random_values.values.value_index][i]], -1))
							MYABORT();
						break;
					case J_SMD_TYPE_INVALID:
					case _J_SMD_TYPE_COUNT:
					default:
						MYABORT();
					}
				}
				else
				{ //TODO test other types for theinvalid extra column - should fail on the column name anyway
					sprintf(varname_strbuf, AFL_VARNAME_FORMAT, i + AFL_LIMIT_SCHEMA_VARIABLES);
					bson_append_int32(metadata, varname_strbuf, -1, 1); //not existent varname
					ret_expected = FALSE;
				}
			}
		}
	}
	else
	{
		sprintf(varname_strbuf, AFL_VARNAME_FORMAT, AFL_LIMIT_SCHEMA_VARIABLES);
		bson_append_int32(metadata, varname_strbuf, -1, 1); //not existent namespace & not existent varname
		ret_expected = FALSE;
	}
	return ret_expected;
}
static void
event_query_single(void)
{
	bson_t* bson;
	bson_iter_t iter;
	guint i;
	gboolean ret;
	gboolean ret_expected = TRUE;
	gpointer iterator;
	random_values.values.existent = random_values.values.existent % 2;
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		random_values.values.value_index = random_values.values.value_index % AFL_LIMIT_SCHEMA_VALUES;
		if (random_values.values.existent)
		{
			ret_expected = ret_expected && build_selector_single(0, random_values.values.value_index);
		}
		else
		{
			ret_expected = ret_expected && build_selector_single(0, AFL_LIMIT_SCHEMA_VALUES);
			ret_expected = FALSE;
		}
	}
	else
	{
		ret_expected = FALSE;
	}
	ret = j_smd_query(namespace_strbuf, name_strbuf, selector, &iterator);
	if (ret != ret_expected)
		MYABORT();
	if (selector)
	{
		bson_destroy(selector);
		selector = NULL;
	}
	if (ret)
	{
		bson = bson_new();
		ret = j_smd_iterate(iterator, bson);
		if (!ret)
			MYABORT();
		if (!bson_iter_init(&iter, bson))
			MYABORT();
		if (!bson_iter_find(&iter, "id"))
			MYABORT();
		for (i = 0; i < AFL_LIMIT_SCHEMA_VARIABLES; i++)
		{
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, i);
			if (!bson_iter_init(&iter, bson))
				MYABORT();
			if (i < namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index])
			{
				if (!bson_iter_find(&iter, varname_strbuf))
					MYABORT();
				switch (namespace_vartypes[random_values.namespace][random_values.name][i])
				{
				case J_SMD_TYPE_SINT32:
					if ((gint32)bson_iter_int32(&iter) != (gint32)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][i])
						MYABORT();
					break;
				case J_SMD_TYPE_UINT32:
					if ((guint32)bson_iter_int32(&iter) != (guint32)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][i])
						MYABORT();
					break;
				case J_SMD_TYPE_FLOAT32:
					if (G_APPROX_VALUE((gfloat)bson_iter_double(&iter), (gfloat)namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index][i], 0.001f))
						MYABORT();
					break;
				case J_SMD_TYPE_SINT64:
					if ((gint64)bson_iter_int64(&iter) != (gint64)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][i])
						MYABORT();
					break;
				case J_SMD_TYPE_UINT64:
					if ((guint64)bson_iter_int64(&iter) != (guint64)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][i])
						MYABORT();
					break;
				case J_SMD_TYPE_FLOAT64:
					if (G_APPROX_VALUE((gdouble)bson_iter_double(&iter), (gdouble)namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index][i], 001))
						MYABORT();
					break;
				case J_SMD_TYPE_STRING:
					if (g_strcmp0(bson_iter_utf8(&iter, NULL), namespace_varvalues_string_const[namespace_varvalues_string[random_values.namespace][random_values.name][random_values.values.value_index][i]]))
						MYABORT();
					break;
				case J_SMD_TYPE_INVALID:
				case _J_SMD_TYPE_COUNT:
				default:
					MYABORT();
				}
			}
			else if (i < namespace_varcount[random_values.namespace][random_values.name])
			{
				//undefined result - since variable was NOT written to DB, but variable was declared in the schema
			}
			else
			{
				if (bson_iter_find(&iter, varname_strbuf))
					MYABORT();
			}
		}
		if (bson)
			bson_destroy(bson);
		bson = bson_new();
		ret = j_smd_iterate(iterator, bson);
		if (bson)
			bson_destroy(bson);
		if (ret)
			MYABORT();
		selector = NULL;
	}
}
static void
event_query_all(void)
{
	guint i;
	//TODO query all at once
	for (i = 0; i < AFL_LIMIT_SCHEMA_VALUES; i++)
	{
		if (namespace_varvalues_valid[random_values.namespace][random_values.name][i])
		{
			random_values.values.value_index = i;
			event_query_single();
		}
	}
}
static void
event_delete(void)
{
	gboolean ret;
	gboolean ret_expected = TRUE;
	random_values.values.existent = random_values.values.existent % 2;
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		random_values.values.value_index = random_values.values.value_index % AFL_LIMIT_SCHEMA_VALUES;
		if (random_values.values.existent)
		{
			ret_expected = ret_expected && build_selector_single(0, random_values.values.value_index); //selector only contains valid columns
			ret_expected = ret_expected && namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index]; //row exists before ?
			namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index] = 0;
		}
		else
		{
			ret_expected = ret_expected && build_selector_single(0, AFL_LIMIT_SCHEMA_VALUES); //row does not exist before
			ret_expected = FALSE;
		}
	}
	else
	{
		ret_expected = FALSE;
	}
	ret = j_smd_delete(namespace_strbuf, name_strbuf, selector);
	if (ret != ret_expected)
		MYABORT();
	if (selector)
	{
		bson_destroy(selector);
		selector = NULL;
	}
	selector = NULL;
}
static void
event_insert(void)
{
	gboolean ret;
	gboolean ret_expected = TRUE;
	ret_expected = ret_expected && build_metadata(); //inserting valid metadata should succeed
	ret = j_smd_insert(namespace_strbuf, name_strbuf, metadata);
	if (ret != ret_expected)
		MYABORT();
	if (metadata)
	{
		bson_destroy(metadata);
		metadata = NULL;
	}
}
static void
event_update(void)
{
	//TODO update multile rows together
	gboolean ret;
	gboolean ret_expected = TRUE;
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		random_values.values.value_index = random_values.values.value_index % AFL_LIMIT_SCHEMA_VALUES;
		if (random_values.values.existent)
		{
			ret_expected = ret_expected && build_selector_single(0, random_values.values.value_index); //update a (maybe) existent row
		}
		else
		{
			ret_expected = ret_expected && build_selector_single(0, AFL_LIMIT_SCHEMA_VALUES); //update a definetly not existing row
			ret_expected = FALSE;
		}
	}
	else
	{
		ret_expected = FALSE; //operation on not existent namespace must fail
	}
	ret_expected = ret_expected && build_metadata(); //metadata contains valid data ?
	ret = j_smd_update(namespace_strbuf, name_strbuf, selector, metadata);
	if (ret != ret_expected)
		MYABORT();
	if (selector)
	{
		bson_destroy(selector);
		selector = NULL;
	}
	if (metadata)
	{
		bson_destroy(metadata);
		metadata = NULL;
	}
}
static void
event_schema_get(void)
{
	bson_iter_t iter;
	gboolean ret;
	bson_t* bson;
	guint i;
	bson = g_new0(bson_t, 1);
	ret = j_smd_schema_get(namespace_strbuf, name_strbuf, bson);
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		if (ret)
		{
			for (i = 0; i < AFL_LIMIT_SCHEMA_VARIABLES; i++)
			{
				sprintf(varname_strbuf, AFL_VARNAME_FORMAT, i);
				J_DEBUG("varname_strbuf %s %d", varname_strbuf, random_values.schema_create.variable_count);
				if (!bson_iter_init(&iter, bson))
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
	if (ret && bson)
		bson_destroy(bson);
	g_free(bson);
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
		if (namespace_bson[random_values.namespace][random_values.name])
			bson_destroy(namespace_bson[random_values.namespace][random_values.name]);
		namespace_bson[random_values.namespace][random_values.name] = NULL;
		namespace_exist[random_values.namespace][random_values.name] = FALSE;
	}
	else
	{
		if (ret)
			MYABORT();
	}
	if (bson)
		bson_destroy(bson);
}
static void
event_schema_create(void)
{
	//TODO duplicated column names should fail
	gboolean ret;
	gboolean ret_expected;
	bson_t* bson;
	guint i;
	random_values.schema_create.duplicate_variables = random_values.schema_create.duplicate_variables % 2;
	random_values.schema_create.variable_count = random_values.schema_create.variable_count % AFL_LIMIT_SCHEMA_VARIABLES;
	for (i = 0; i < random_values.schema_create.variable_count; i++)
		random_values.schema_create.variable_types[i] = random_values.schema_create.variable_types[i] % _J_SMD_TYPE_COUNT;
	bson = bson_new();
	ret_expected = random_values.schema_create.variable_count > 0;
	J_DEBUG("ret_expected %d %d", ret_expected, random_values.schema_create.variable_count);
	for (i = 0; i < random_values.schema_create.variable_count; i++)
	{
		sprintf(varname_strbuf, AFL_VARNAME_FORMAT, i);
		if (random_values.schema_create.variable_types[i] == J_SMD_TYPE_INVALID)
		{
			ret_expected = FALSE; //all specified types must be valid
			J_DEBUG("ret_expected %d", ret_expected);
		}
		J_DEBUG("varname_strbuf %s", varname_strbuf);
		bson_append_int32(bson, varname_strbuf, -1, random_values.schema_create.variable_types[i]);
		if (i == 0 && random_values.schema_create.duplicate_variables)
		{
			J_DEBUG("varname_strbuf %s", varname_strbuf);
			bson_append_int32(bson, varname_strbuf, -1, random_values.schema_create.variable_types[i]);
			ret_expected = FALSE; //duplicate variable names not allowed
			J_DEBUG("ret_expected %d", ret_expected);
		}
	}
	ret = j_smd_schema_create(namespace_strbuf, name_strbuf, bson);
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		if (ret)
			MYABORT();
		if (bson)
			bson_destroy(bson);
	}
	else
	{
		if (ret != ret_expected)
			MYABORT();
		if (ret)
		{
			namespace_exist[random_values.namespace][random_values.name] = TRUE;
			namespace_bson[random_values.namespace][random_values.name] = bson;
			namespace_varcount[random_values.namespace][random_values.name] = random_values.schema_create.variable_count;
			for (i = 0; i < random_values.schema_create.variable_count; i++)
				namespace_vartypes[random_values.namespace][random_values.name][i] = random_values.schema_create.variable_types[i];
		}
		else
		{
			if (bson)
				bson_destroy(bson);
		}
	}
}
int
main(int argc, char* argv[])
{
	FILE* file;
	JSMDAflEvent event;
	guint i, j, k;
	if (argc > 1)
	{
		char filename[50 + strlen(argv[1])];
		mkdir(argv[1], S_IRUSR | S_IRGRP | S_IROTH);
		sprintf(filename, "%s/start-files", argv[1]);
		mkdir(filename, S_IRUSR | S_IRGRP | S_IROTH);
		memset(&random_values, 0, sizeof(random_values));
		for (i = 0; i < _AFL_EVENT_EVENT_COUNT; i++)
		{
			sprintf(filename, "%s/start-files/%d.bin", argv[1], i);
			file = fopen(filename, "wb");
			event = i;
			fwrite(&event, sizeof(event), 1, file);
			fwrite(&random_values, sizeof(random_values), 1, file);
			fclose(file);
		}
		goto fini;
	}
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
			J_DEBUG("AFL_EVENT_SMD_SCHEMA_CREATE %s %s", namespace_strbuf, name_strbuf);
			event_schema_get();
			event_schema_create();
			event_schema_get();
			break;
		case AFL_EVENT_SMD_SCHEMA_GET:
			J_DEBUG("AFL_EVENT_SMD_SCHEMA_GET %s %s", namespace_strbuf, name_strbuf);
			event_schema_get();
			break;
		case AFL_EVENT_SMD_SCHEMA_DELETE:
			J_DEBUG("AFL_EVENT_SMD_SCHEMA_DELETE %s %s", namespace_strbuf, name_strbuf);
			event_schema_get();
			event_schema_delete();
			event_schema_get();
			break;
		case AFL_EVENT_SMD_INSERT:
			J_DEBUG("AFL_EVENT_SMD_INSERT %s %s", namespace_strbuf, name_strbuf);
			random_values.values.existent = 1; //override random
			event_query_all();
			event_delete();
			event_query_single();
			event_insert();
			event_query_all();
			break;
		case AFL_EVENT_SMD_UPDATE:
			J_DEBUG("AFL_EVENT_SMD_UPDATE %s %s", namespace_strbuf, name_strbuf);
			event_query_all();
			event_update();
			event_query_all();
			break;
		case AFL_EVENT_SMD_DELETE:
			J_DEBUG("AFL_EVENT_SMD_DELETE %s %s", namespace_strbuf, name_strbuf);
			event_query_all();
			event_delete();
			event_query_all();
			break;
		case AFL_EVENT_SMD_QUERY:
		case AFL_EVENT_SMD_ITERATE:
			J_DEBUG("AFL_EVENT_SMD_QUERY %s %s", namespace_strbuf, name_strbuf);
			event_query_all();
			event_query_single();
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
			if (namespace_bson[i][j])
				bson_destroy(namespace_bson[i][j]);
			namespace_bson[i][j] = NULL;
		}
	}
fini:
	j_fini();
	return 0;
}
