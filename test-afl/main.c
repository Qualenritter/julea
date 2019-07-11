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
#include <stdio.h>
#include <math.h>
#include <float.h>
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
#define G_APPROX_VALUE(a, b, epsilon) ((((a) > (b) ? (a) - (b) : (b) - (a)) < (epsilon)) || !isfinite(a) || !isfinite(b))
#endif

#define J_DEBUG_BSON(bson)                               \
	do                                               \
	{                                                \
		char* json = NULL;                       \
		if (bson)                                \
			json = bson_as_json(bson, NULL); \
		J_DEBUG("json = %s", json);              \
		bson_free((void*)json);                  \
	} while (0)
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
		J_DEBUG("abort %d", 0); \
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
			guint invalid_bson_schema;
		} schema_create;
		struct
		{
			union
			{
				gdouble d; //random double
				guint64 i; //random int
				guint s; //random string INDEX (point to namespace_varvalues_string_const)
			} values[AFL_LIMIT_SCHEMA_VARIABLES][2];
			guint multiple_values_insert; //mod 2 -> Yes/No
			guint value_count; //insert <real number of vaiables in schema> + ((mod 3) - 1)
			guint value_index; //"primary key" first column
			guint existent; //mod 2 -> Yes/No
			guint invalid_bson_selector;
			guint invalid_bson_metadata;
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
static char namespace_varvalues_string_const[AFL_LIMIT_SCHEMA_STRING_VALUES][AFL_LIMIT_STRING_LEN];
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
static bson_t* selector;
static bson_t* metadata;
//<-
static gboolean
build_selector_single(guint varname, guint value)
{
	gboolean ret_expected = TRUE;
	bson_t bson_child;
	selector = bson_new();
	J_DEBUG("afl_build_selector_single%d", 0);
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
			if (value == AFL_LIMIT_SCHEMA_VALUES)
			{
				if (!bson_append_utf8(&bson_child, "value", -1, "not_existent_var_name", -1))
					MYABORT();
			}
			else
			{
				if (!bson_append_utf8(&bson_child, "value", -1, namespace_varvalues_string_const[value % AFL_LIMIT_SCHEMA_STRING_VALUES], -1))
					MYABORT();
			}
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
	J_DEBUG_BSON(selector);
	return ret_expected;
}
static gboolean
build_metadata(guint allow_multiple)
{
	char str_buf[16];
	const char* key;
	bson_t bson_child;
	bson_t bson_child2;
	bson_t* bson;
	gboolean ret_expected = TRUE;
	guint count = 0;
	guint i;
	guint j;
	J_DEBUG("afl_build_metadata%d", 0);
	if (random_values.values.invalid_bson_metadata % 3)
	{
		switch (random_values.values.invalid_bson_metadata % 3)
		{
		case 2: //empty metadata
			metadata = bson_new();
			return FALSE;
		case 1: //NULL metadata
			metadata = NULL;
			return FALSE;
		case 0:
		default:;
		}
	}
	metadata = bson_new();
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		random_values.values.multiple_values_insert = random_values.values.multiple_values_insert % 2;
		if (random_values.values.multiple_values_insert && allow_multiple)
			random_values.values.value_index = random_values.values.value_index % (AFL_LIMIT_SCHEMA_VALUES - 1);
		else
			random_values.values.value_index = random_values.values.value_index % AFL_LIMIT_SCHEMA_VALUES;
		random_values.values.value_count = namespace_varcount[random_values.namespace][random_values.name] + ((random_values.values.value_count % 3) - 1);
		namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][0] = random_values.values.value_index;
		namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index][0] = random_values.values.value_index;
		namespace_varvalues_string[random_values.namespace][random_values.name][random_values.values.value_index][0] = random_values.values.value_index % AFL_LIMIT_SCHEMA_STRING_VALUES;
		if (random_values.values.multiple_values_insert && allow_multiple)
		{
			namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index + 1][0] = random_values.values.value_index + 1;
			namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index + 1][0] = random_values.values.value_index + 1;
			namespace_varvalues_string[random_values.namespace][random_values.name][random_values.values.value_index + 1][0] = (random_values.values.value_index + 1) % AFL_LIMIT_SCHEMA_STRING_VALUES;
		}
		for (i = 1; i < AFL_LIMIT_SCHEMA_VARIABLES; i++)
		{
			namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index][i] = random_values.values.values[i][0].i;
			namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index][i] = random_values.values.values[i][0].d;
			namespace_varvalues_string[random_values.namespace][random_values.name][random_values.values.value_index][i] = random_values.values.values[i][0].s % AFL_LIMIT_SCHEMA_STRING_VALUES;
			if (random_values.values.multiple_values_insert && allow_multiple)
			{
				namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index + 1][i] = random_values.values.values[i][1].i;
				namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index + 1][i] = random_values.values.values[i][1].d;
				namespace_varvalues_string[random_values.namespace][random_values.name][random_values.values.value_index + 1][i] = random_values.values.values[i][1].s % AFL_LIMIT_SCHEMA_STRING_VALUES;
			}
		}
		if (random_values.values.multiple_values_insert && allow_multiple)
			bson_append_array_begin(metadata, "_arr", -1, &bson_child);
		else
			bson = metadata;
		for (j = 0; j < random_values.values.multiple_values_insert + 1; j++)
		{
			if (random_values.values.multiple_values_insert && allow_multiple)
			{
				bson_uint32_to_string(j, &key, str_buf, sizeof(str_buf));
				bson_append_document_begin(&bson_child, key, -1, &bson_child2);
				bson = &bson_child2;
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
							count++;
							if (!bson_append_int32(bson, varname_strbuf, -1, (gint32)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index + j][i]))
								MYABORT();
							break;
						case J_SMD_TYPE_UINT32:
							count++;
							if (!bson_append_int32(bson, varname_strbuf, -1, (guint32)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index + j][i]))
								MYABORT();
							break;
						case J_SMD_TYPE_FLOAT32:
							count++;
							if (!bson_append_double(bson, varname_strbuf, -1, (gfloat)namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index + j][i]))
								MYABORT();
							break;
						case J_SMD_TYPE_SINT64:
							count++;
							if (!bson_append_int64(bson, varname_strbuf, -1, (gint64)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index + j][i]))
								MYABORT();
							break;
						case J_SMD_TYPE_UINT64:
							count++;
							if (!bson_append_int64(bson, varname_strbuf, -1, (guint64)namespace_varvalues_int64[random_values.namespace][random_values.name][random_values.values.value_index + j][i]))
								MYABORT();
							break;
						case J_SMD_TYPE_FLOAT64:
							count++;
							if (!bson_append_double(bson, varname_strbuf, -1, (gdouble)namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index + j][i]))
								MYABORT();
							break;
						case J_SMD_TYPE_STRING:
							count++;
							if (!bson_append_utf8(bson, varname_strbuf, -1, namespace_varvalues_string_const[namespace_varvalues_string[random_values.namespace][random_values.name][random_values.values.value_index + j][i]], -1))
								MYABORT();
							break;
						case J_SMD_TYPE_INVALID:
						case _J_SMD_TYPE_COUNT:
						default:
							MYABORT();
						}
					}
					else
					{ //TODO test other types for the invalid extra column - should fail on the column name anyway
						sprintf(varname_strbuf, AFL_VARNAME_FORMAT, AFL_LIMIT_SCHEMA_VARIABLES);
						bson_append_int32(bson, varname_strbuf, -1, 1); //not existent varname
						ret_expected = FALSE;
					}
				}
			}
			if (random_values.values.multiple_values_insert && allow_multiple)
				bson_append_document_end(&bson_child, &bson_child2);
		}
		if (random_values.values.multiple_values_insert && allow_multiple)
			bson_append_array_end(metadata, &bson_child);
	}
	else
	{
		sprintf(varname_strbuf, AFL_VARNAME_FORMAT, AFL_LIMIT_SCHEMA_VARIABLES);
		bson_append_int32(metadata, varname_strbuf, -1, 1); //not existent namespace & not existent varname
		ret_expected = FALSE;
	}
	J_DEBUG_BSON(metadata);
	return ret_expected && count;
}
static void
event_query_single(void)
{
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	bson_t bson;
	bson_t bson_child;
	bson_t bson_child2;
	bson_iter_t iter;
	guint i;
	gboolean ret;
	gboolean ret_expected = TRUE;
	gpointer iterator = 0;
	J_DEBUG("afl_event_query_single %d", random_values.values.value_index);
	J_DEBUG("ret_expected %d", ret_expected);
	if (random_values.values.invalid_bson_selector % 6)
	{
		switch (random_values.values.invalid_bson_selector % 6)
		{
		case 5: //NULL iterator
			build_selector_single(0, random_values.values.value_index);
			ret = j_smd_query(namespace_strbuf, name_strbuf, selector, NULL, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 4: //invalid bson - value of not allowed bson type
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_document_begin(selector, varname_strbuf, -1, &bson_child);
			bson_append_document_begin(&bson_child, "value", -1, &bson_child2);
			bson_append_document_end(&bson_child, &bson_child2);
			bson_append_document_end(selector, &bson_child);
			ret = j_smd_query(namespace_strbuf, name_strbuf, selector, &iterator, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			ret = j_smd_iterate(iterator, &bson);
			if (ret)
				MYABORT();
			break;
		case 3: //invalid bson - operator undefined enum
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_document_begin(selector, varname_strbuf, -1, &bson_child);
			bson_append_int32(&bson_child, "operator", -1, _J_SMD_OPERATOR_COUNT + 1);
			bson_append_document_end(selector, &bson_child);
			ret = j_smd_query(namespace_strbuf, name_strbuf, selector, &iterator, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			ret = j_smd_iterate(iterator, &bson);
			if (ret)
				MYABORT();
			break;
		case 2: //invalid bson - operator of invalid type
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_document_begin(selector, varname_strbuf, -1, &bson_child);
			bson_append_document_begin(&bson_child, "operator", -1, &bson_child2);
			bson_append_document_end(&bson_child, &bson_child2);
			bson_append_document_end(selector, &bson_child);
			ret = j_smd_query(namespace_strbuf, name_strbuf, selector, &iterator, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			ret = j_smd_iterate(iterator, &bson);
			if (ret)
				MYABORT();
			break;
		case 1: //invalid bson - key of type something else than a document
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_int32(selector, varname_strbuf, -1, 0);
			ret = j_smd_query(namespace_strbuf, name_strbuf, selector, &iterator, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			ret = j_smd_iterate(iterator, &bson);
			if (ret)
				MYABORT();
			break;
		case 0:
		default:;
		}
		if (selector)
		{
			bson_destroy(selector);
			selector = NULL;
		}
	}
	random_values.values.existent = random_values.values.existent % 2;
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		random_values.values.value_index = random_values.values.value_index % AFL_LIMIT_SCHEMA_VALUES;
		ret_expected = namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index] && ret_expected;
		J_DEBUG("ret_expected %d", ret_expected);
		if (random_values.values.existent)
		{
			ret_expected = build_selector_single(0, random_values.values.value_index) && ret_expected;
			J_DEBUG("ret_expected %d", ret_expected);
		}
		else
		{
			ret_expected = build_selector_single(0, AFL_LIMIT_SCHEMA_VALUES) && ret_expected;
			J_DEBUG("ret_expected %d", ret_expected);
			ret_expected = FALSE;
			J_DEBUG("ret_expected %d", ret_expected);
		}
	}
	else
	{
		ret_expected = FALSE;
		J_DEBUG("ret_expected %d", ret_expected);
	}
	ret = j_smd_query(namespace_strbuf, name_strbuf, selector, &iterator, batch);
	ret = j_batch_execute(batch) && ret;
	if (!ret)
		MYABORT();
	if (selector)
	{
		bson_destroy(selector);
		selector = NULL;
	}
	if (ret_expected)
	{
		ret = j_smd_iterate(iterator, &bson);
		if (!ret)
			MYABORT();
		if (!bson_iter_init(&iter, &bson))
			MYABORT();
		if (!bson_iter_find(&iter, "_id"))
			MYABORT();
		for (i = 0; i < AFL_LIMIT_SCHEMA_VARIABLES; i++)
		{
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, i);
			if (!bson_iter_init(&iter, &bson))
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
					if (!G_APPROX_VALUE((gfloat)bson_iter_double(&iter), (gfloat)namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index][i], 0.001f))
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
					if (!G_APPROX_VALUE((gdouble)bson_iter_double(&iter), (gdouble)namespace_varvalues_double[random_values.namespace][random_values.name][random_values.values.value_index][i], 001))
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
		selector = NULL;
	}
	ret = j_smd_iterate(iterator, &bson);
	if (ret)
		MYABORT();
}
static void
event_query_all(void)
{
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	guint i;
	J_DEBUG("afl_event_all%d", 0);
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
	//TODO delete ALL at once using empty bson and NULL
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	bson_t bson_child;
	bson_t bson_child2;
	gboolean ret;
	gboolean ret_expected = TRUE;
	J_DEBUG("afl_event_delete%d", 0);
	if (random_values.values.invalid_bson_selector % 7)
	{
		switch (random_values.values.invalid_bson_selector % 7)
		{
		case 4: //invalid bson - value of not allowed bson type
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_document_begin(selector, varname_strbuf, -1, &bson_child);
			bson_append_document_begin(&bson_child, "value", -1, &bson_child2);
			bson_append_document_end(&bson_child, &bson_child2);
			bson_append_document_end(selector, &bson_child);
			ret = j_smd_delete(namespace_strbuf, name_strbuf, selector, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 3: //invalid bson - operator undefined enum
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_document_begin(selector, varname_strbuf, -1, &bson_child);
			bson_append_int32(&bson_child, "operator", -1, _J_SMD_OPERATOR_COUNT + 1);
			bson_append_document_end(selector, &bson_child);
			ret = j_smd_delete(namespace_strbuf, name_strbuf, selector, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 2: //invalid bson - operator of invalid type
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_document_begin(selector, varname_strbuf, -1, &bson_child);
			bson_append_document_begin(&bson_child, "operator", -1, &bson_child2);
			bson_append_document_end(&bson_child, &bson_child2);
			bson_append_document_end(selector, &bson_child);
			ret = j_smd_delete(namespace_strbuf, name_strbuf, selector, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 1: //invalid bson - key of type something else than a document
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_int32(selector, varname_strbuf, -1, 0);
			ret = j_smd_delete(namespace_strbuf, name_strbuf, selector, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 0:
		default:;
		}
		if (selector)
		{
			bson_destroy(selector);
			selector = NULL;
		}
	}
	random_values.values.existent = random_values.values.existent % 2;
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		random_values.values.value_index = random_values.values.value_index % AFL_LIMIT_SCHEMA_VALUES;
		if (random_values.values.existent)
		{
			ret_expected = build_selector_single(0, random_values.values.value_index) && ret_expected; //selector only contains valid columns
			ret_expected = namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index] && ret_expected; //row exists before ?
			namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index] = 0;
		}
		else
		{
			ret_expected = build_selector_single(0, AFL_LIMIT_SCHEMA_VALUES) && ret_expected; //row does not exist before
			ret_expected = FALSE;
		}
	}
	else
	{
		ret_expected = FALSE;
	}
	ret = j_smd_delete(namespace_strbuf, name_strbuf, selector, batch);
	ret = j_batch_execute(batch) && ret;
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
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	gboolean ret;
	gboolean ret_expected = TRUE;
	J_DEBUG("afl_event_insert%d", 0);
	J_DEBUG("ret_expected %d", ret_expected);
	ret_expected = build_metadata(TRUE) && ret_expected; //inserting valid metadata should succeed
	J_DEBUG("ret_expected %d", ret_expected);
	ret = j_smd_insert(namespace_strbuf, name_strbuf, metadata, batch);
	ret = j_batch_execute(batch) && ret;
	if (ret != ret_expected)
		MYABORT();
	if (ret)
	{
		namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index] = random_values.values.value_count;
		if (random_values.values.multiple_values_insert)
			namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index + 1] = random_values.values.value_count;
	}
	else
	{
		if (namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index])
			namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index] = 1;
		if (random_values.values.multiple_values_insert)
		{
			if (namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index + 1])
				namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index + 1] = 1;
		}
	}
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
	//TODO selector useing AND/OR query elements
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	bson_t bson_child;
	bson_t bson_child2;
	gboolean ret;
	gboolean ret_expected = TRUE;
	J_DEBUG("afl_event_update%d", 0);
	random_values.values.multiple_values_insert = 0;
	if (random_values.values.invalid_bson_selector % 7)
	{
		build_metadata(FALSE);
		switch (random_values.values.invalid_bson_selector % 7)
		{
		case 6: //invalid bson - value of not allowed bson type
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_document_begin(selector, varname_strbuf, -1, &bson_child);
			bson_append_document_begin(&bson_child, "value", -1, &bson_child2);
			bson_append_document_end(&bson_child, &bson_child2);
			bson_append_document_end(selector, &bson_child);
			ret = j_smd_update(namespace_strbuf, name_strbuf, selector, metadata, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 5: //invalid bson - operator undefined enum
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_document_begin(selector, varname_strbuf, -1, &bson_child);
			bson_append_int32(&bson_child, "operator", -1, _J_SMD_OPERATOR_COUNT + 1);
			bson_append_document_end(selector, &bson_child);
			ret = j_smd_update(namespace_strbuf, name_strbuf, selector, metadata, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 4: //invalid bson - operator of invalid type
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_document_begin(selector, varname_strbuf, -1, &bson_child);
			bson_append_document_begin(&bson_child, "operator", -1, &bson_child2);
			bson_append_document_end(&bson_child, &bson_child2);
			bson_append_document_end(selector, &bson_child);
			ret = j_smd_update(namespace_strbuf, name_strbuf, selector, metadata, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 3: //invalid bson - key of type something else than a document
			selector = bson_new();
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson_append_int32(selector, varname_strbuf, -1, 0);
			ret = j_smd_update(namespace_strbuf, name_strbuf, selector, metadata, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 2: //empty bson
			selector = bson_new();
			ret = j_smd_update(namespace_strbuf, name_strbuf, selector, metadata, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 1: //NULL selector
			ret = j_smd_update(namespace_strbuf, name_strbuf, NULL, metadata, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 0:
		default:;
		}
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
	J_DEBUG("ret_expected %d", ret_expected);
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		random_values.values.value_index = random_values.values.value_index % AFL_LIMIT_SCHEMA_VALUES;
		if (random_values.values.existent)
		{
			ret_expected = build_selector_single(0, random_values.values.value_index) && ret_expected; //update a (maybe) existent row
			J_DEBUG("ret_expected %d", ret_expected);
			ret_expected = namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index] && ret_expected; //row to update exists
			J_DEBUG("ret_expected %d", ret_expected);
		}
		else
		{
			ret_expected = build_selector_single(0, AFL_LIMIT_SCHEMA_VALUES) && ret_expected; //update a definetly not existing row
			J_DEBUG("ret_expected %d", ret_expected);
			ret_expected = FALSE;
			J_DEBUG("ret_expected %d", ret_expected);
		}
	}
	else
	{
		ret_expected = FALSE; //operation on not existent namespace must fail
		J_DEBUG("ret_expected %d", ret_expected);
		selector = bson_new();
	}
	ret_expected = build_metadata(FALSE) && ret_expected; //metadata contains valid data ?
	J_DEBUG("ret_expected %d", ret_expected);
	ret = j_smd_update(namespace_strbuf, name_strbuf, selector, metadata, batch);
	ret = j_batch_execute(batch) && ret;
	if (ret != ret_expected)
		MYABORT();
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		if (ret)
			namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index] = random_values.values.value_count;
		else if (namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index])
			namespace_varvalues_valid[random_values.namespace][random_values.name][random_values.values.value_index] = 1;
	}
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
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	bson_iter_t iter;
	gboolean ret;
	bson_t* bson;
	guint i;
	J_DEBUG("afl_event_schema_get%d", 0);
	if (random_values.schema_create.invalid_bson_schema % 2)
	{
		ret = j_smd_schema_get(namespace_strbuf, name_strbuf, NULL, batch);
		ret = j_batch_execute(batch) && ret;
		if (ret != namespace_exist[random_values.namespace][random_values.name])
			MYABORT();
	}
	bson = g_new0(bson_t, 1);
	ret = j_smd_schema_get(namespace_strbuf, name_strbuf, bson, batch);
	ret = j_batch_execute(batch) && ret;
	if (namespace_exist[random_values.namespace][random_values.name])
	{
		if (ret)
		{
			J_DEBUG_BSON(bson);
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
		J_DEBUG("ret%d", ret);
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
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	gboolean ret;
	bson_t* bson;
	J_DEBUG("afl_event_schema_delete%d", 0);
	bson = bson_new();
	ret = j_smd_schema_delete(namespace_strbuf, name_strbuf, batch);
	ret = j_batch_execute(batch) && ret;
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
	//TODO test create index
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	bson_t bson_child;
	gboolean ret;
	gboolean ret_expected;
	bson_t* bson;
	guint i;
	J_DEBUG("afl_event_schema_create%d", 0);
	if (random_values.schema_create.invalid_bson_schema % 5)
	{
		switch (random_values.schema_create.invalid_bson_schema % 5)
		{
		case 4: //variable type not specified in enum
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson = bson_new();
			bson_append_int32(bson, varname_strbuf, -1, _J_SMD_TYPE_COUNT + 1);
			ret = j_smd_schema_create(namespace_strbuf, name_strbuf, bson, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			bson_destroy(bson);
			break;
		case 3: //wrong bson variable types
			sprintf(varname_strbuf, AFL_VARNAME_FORMAT, 0);
			bson = bson_new();
			bson_append_document_begin(bson, varname_strbuf, -1, &bson_child);
			bson_append_document_end(bson, &bson_child);
			ret = j_smd_schema_create(namespace_strbuf, name_strbuf, bson, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			bson_destroy(bson);
			break;
		case 2: //empty bson
			bson = bson_new();
			ret = j_smd_schema_create(namespace_strbuf, name_strbuf, bson, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			bson_destroy(bson);
			break;
		case 1: //NULL
			ret = j_smd_schema_create(namespace_strbuf, name_strbuf, NULL, batch);
			ret = j_batch_execute(batch) && ret;
			if (ret)
				MYABORT();
			break;
		case 0:
		default:
			MYABORT();
		}
	}
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
	J_DEBUG_BSON(bson);
	ret = j_smd_schema_create(namespace_strbuf, name_strbuf, bson, batch);
	ret = j_batch_execute(batch) && ret;
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
			for (i = 0; i < AFL_LIMIT_SCHEMA_VALUES; i++)
				namespace_varvalues_valid[random_values.namespace][random_values.name][i] = 0;
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
	guint tmp;
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
		sprintf(&namespace_varvalues_string_const[i][0], AFL_STRING_CONST_FORMAT, i);
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
	// this does not work with threads or network connections
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
			random_values.values.existent = 1;
			random_values.values.multiple_values_insert = random_values.values.multiple_values_insert % 2;
			if (random_values.values.multiple_values_insert)
				tmp = random_values.values.value_index % (AFL_LIMIT_SCHEMA_VALUES - 1);
			else
				tmp = random_values.values.value_index % (AFL_LIMIT_SCHEMA_VALUES);
			event_query_all();
			if (random_values.values.multiple_values_insert)
			{
				random_values.values.value_index = tmp;
				event_delete();
				random_values.values.value_index = tmp + 1;
				event_delete();
			}
			else
			{
				random_values.values.value_index = tmp;
				event_delete();
			}
			event_query_all();
			random_values.values.value_index = tmp;
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
	j_fini(); //memory leaks count as error -> free everything possible
	return 0;
}
