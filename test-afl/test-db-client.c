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
#ifndef JULEA_DB_COMPILATION
#define JULEA_DB_COMPILATION
#endif
#include <julea-config.h>
#include <stdio.h>
#include <math.h>
#include <float.h>
#include <glib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <julea.h>
#include <julea-db.h>
#include <db/jdb-internal.h>
#include "afl.h"

//configure here->
#define AFL_NAMESPACE_FORMAT "namespace_%d"
#define AFL_NAME_FORMAT "name_%d"
#define AFL_VARNAME_FORMAT "varname_%d"
#define AFL_VARVALUE_FORMAT "value_%d"
#define AFL_LIMIT_ENTRY 4
#define AFL_LIMIT_SELECTOR 4
#define AFL_LIMIT_ITERATOR 4
#define AFL_LIMIT_SCHEMA_FIELDS 4
#define AFL_LIMIT_SCHEMA_NAMESPACE 4
#define AFL_LIMIT_SCHEMA_NAME 4
#define AFL_LIMIT_STRING_LEN 15
#define AFL_LIMIT_SCHEMA_STRING_VALUES 4
//<-

enum JDBAflEvent
{
	AFL_EVENT_DB_ENTRY_NEW = 0,
	AFL_EVENT_DB_ENTRY_REF,
	AFL_EVENT_DB_ENTRY_SET_FIELD,
	AFL_EVENT_DB_ENTRY_INSERT,
	AFL_EVENT_DB_ENTRY_UPDATE,
	AFL_EVENT_DB_ENTRY_DELETE,
	AFL_EVENT_DB_ITERATOR_NEW,
	AFL_EVENT_DB_ITERATOR_REF,
	AFL_EVENT_DB_ITERATOR_NEXT,
	AFL_EVENT_DB_ITERATOR_GET_FIELD,
	AFL_EVENT_DB_SCHEMA_NEW,
	AFL_EVENT_DB_SCHEMA_REF,
	AFL_EVENT_DB_SCHEMA_ADD_FIELD,
	AFL_EVENT_DB_SCHEMA_GET_FIELD,
	AFL_EVENT_DB_SCHEMA_GET_FIELDS,
	AFL_EVENT_DB_SCHEMA_ADD_INDEX,
	AFL_EVENT_DB_SCHEMA_CREATE,
	AFL_EVENT_DB_SCHEMA_GET,
	AFL_EVENT_DB_SCHEMA_DELETE,
	AFL_EVENT_DB_SELECTOR_NEW,
	AFL_EVENT_DB_SELECTOR_REF,
	AFL_EVENT_DB_SELECTOR_ADD_FIELD,
	AFL_EVENT_DB_SELECTOR_ADD_SELECTOR,
	AFL_EVENT_DB_AFL_INIT,
	_AFL_EVENT_DB_COUNT,
};
typedef enum JDBAflEvent JDBAflEvent;
struct JDBAflRandomValues
{
	struct
	{ //schema
		guint namespace;
		guint name;
	};
	struct
	{ //fields
		guint var_name;
		JDBType var_type;
		union
		{ //values
			guint32 var_value_uint32;
			gint32 var_value_sint32;
			guint64 var_value_uint64;
			gint64 var_value_sint64;
			gfloat var_value_float32;
			gdouble var_value_float64;
			guint var_value_str;
		};
	};
	struct
	{ //entry
		guint entry;
	};
	struct
	{ //selector
		guint selector;
		guint selector_mode;
		guint selector_operator;
		guint selector_selector;
	};
	struct
	{ //iterator
		guint iterator;
	};
	guint invalid_switch;
};
typedef struct JDBAflRandomValues JDBAflRandomValues;
//schema->
static
JDBSchema* stored_schemas[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME];
#define the_stored_schema stored_schemas[random_values.namespace][random_values.name]
static
JDBType schema_field_types[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SCHEMA_FIELDS];
#define the_schema_field_type schema_field_types[random_values.namespace][random_values.name][random_values.var_name]
//<-
//entry->
static
JDBEntry* stored_entrys[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_ENTRY];
#define the_stored_entry stored_entrys[random_values.namespace][random_values.name][random_values.entry]
static
guint stored_entrys_field_set[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_ENTRY];
#define the_stored_entry_field_set stored_entrys_field_set[random_values.namespace][random_values.name][random_values.entry]
//<-
//selector->
static
JDBSelector* stored_selectors[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SELECTOR];
#define the_stored_selector stored_selectors[random_values.namespace][random_values.name][random_values.selector]
static
gboolean stored_selectors_field_count[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_SELECTOR];
#define the_stored_selector_field_count stored_selectors_field_count[random_values.namespace][random_values.name][random_values.selector]
//<-
//iterator->
static
JDBIterator* stored_iterators[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_ITERATOR];
#define the_stored_iterator stored_iterators[random_values.namespace][random_values.name][random_values.iterator]
static
gboolean stored_iterators_next_count[AFL_LIMIT_SCHEMA_NAMESPACE][AFL_LIMIT_SCHEMA_NAME][AFL_LIMIT_ITERATOR];
#define the_stored_iterator_next_count stored_iterators_next_count[random_values.namespace][random_values.name][random_values.iterator]
//<-
//allgemein->
static
char name_strbuf[AFL_LIMIT_STRING_LEN];
static
char namespace_strbuf[AFL_LIMIT_STRING_LEN];
static
char varname_strbuf[AFL_LIMIT_STRING_LEN];
static
char varvalue_strbuf[AFL_LIMIT_STRING_LEN];
static
JDBAflRandomValues random_values;
//<-

#include "test-db-entry.h"
#include "test-db-iterator.h"
#include "test-db-schema.h"
#include "test-db-selector.h"

int
main(int argc, char* argv[])
{
	GError* error = NULL;
	FILE* file;
	JDBAflEvent event;
	guint i;
	guint j;
	gboolean ret;
	guint k;
	g_autoptr(JBatch) batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	if (argc > 1)
	{
		char filename[50 + strlen(argv[1])];
		mkdir(argv[1], S_IRUSR | S_IRGRP | S_IROTH);
		sprintf(filename, "%s/start-files", argv[1]);
		mkdir(filename, S_IRUSR | S_IRGRP | S_IROTH);
		memset(&random_values, 0, sizeof(random_values));
		for (i = 0; i < _AFL_EVENT_DB_COUNT; i++)
		{
			sprintf(filename, "%s/start-files/test-db-schema-%d.bin", argv[1], i);
			file = fopen(filename, "wb");
			event = i;
			fwrite(&event, sizeof(event), 1, file);
			fwrite(&random_values, sizeof(random_values), 1, file);
			fclose(file);
		}
		goto fini;
	}
	for (i = 0; i < AFL_LIMIT_SCHEMA_NAMESPACE; i++)
	{
		for (j = 0; j < AFL_LIMIT_SCHEMA_NAME; j++)
		{
			stored_schemas[i][j] = NULL;
			for (k = 0; k < AFL_LIMIT_ENTRY; k++)
			{
				stored_entrys[i][j][k] = NULL;
				stored_entrys_field_set[i][j][k] = 0;
			}
			for (k = 0; k < AFL_LIMIT_SELECTOR; k++)
			{
				stored_selectors[i][j][k] = NULL;
				stored_selectors_field_count[i][j][k] = 0;
			}
			for (k = 0; k < AFL_LIMIT_ITERATOR; k++)
			{
				stored_iterators[i][j][k] = NULL;
				stored_iterators_next_count[i][j][k] = 0;
			}
			for (k = 0; k < AFL_LIMIT_SCHEMA_FIELDS; k++)
			{
				schema_field_types[i][j][k] = _J_DB_TYPE_COUNT;
			}
		}
		sprintf(namespace_strbuf, AFL_NAMESPACE_FORMAT, i);
		j_internal_reset(namespace_strbuf, batch, NULL);
	}
	j_batch_execute(batch);
#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
	while (__AFL_LOOP(1000))
#endif
	{
	loop:
		MY_READ_MAX(event, _AFL_EVENT_DB_COUNT);
		MY_READ(random_values);
		random_values.namespace = random_values.namespace % AFL_LIMIT_SCHEMA_NAMESPACE;
		random_values.name = random_values.name % AFL_LIMIT_SCHEMA_NAME;
		random_values.entry = random_values.entry % AFL_LIMIT_ENTRY;
		random_values.selector = random_values.selector % AFL_LIMIT_SELECTOR;
		random_values.iterator = random_values.iterator % AFL_LIMIT_ITERATOR;
		random_values.var_name = random_values.var_name % AFL_LIMIT_SCHEMA_FIELDS;
		switch (event)
		{
		case AFL_EVENT_DB_ENTRY_NEW:
			event_entry_new();
			break;
		case AFL_EVENT_DB_ENTRY_REF:
			event_entry_ref();
			break;
		case AFL_EVENT_DB_ENTRY_SET_FIELD:
			event_entry_set_field();
			break;
		case AFL_EVENT_DB_ENTRY_INSERT:
			event_entry_insert();
			break;
		case AFL_EVENT_DB_ENTRY_UPDATE:
			event_entry_update();
			break;
		case AFL_EVENT_DB_ENTRY_DELETE:
			event_entry_delete();
			break;
		case AFL_EVENT_DB_ITERATOR_NEW:
			event_iterator_new();
			break;
		case AFL_EVENT_DB_ITERATOR_REF:
			event_iterator_ref();
			break;
		case AFL_EVENT_DB_ITERATOR_NEXT:
			event_iterator_next();
			break;
		case AFL_EVENT_DB_ITERATOR_GET_FIELD:
			event_iterator_get_field();
			break;
		case AFL_EVENT_DB_SCHEMA_NEW:
			event_schema_new();
			break;
		case AFL_EVENT_DB_SCHEMA_REF:
			event_schema_ref();
			break;
		case AFL_EVENT_DB_SCHEMA_ADD_FIELD:
			event_schema_add_field();
			break;
		case AFL_EVENT_DB_SCHEMA_GET_FIELD:
			event_schema_get_field();
			break;
		case AFL_EVENT_DB_SCHEMA_GET_FIELDS:
			event_schema_get_fields();
			break;
		case AFL_EVENT_DB_SCHEMA_ADD_INDEX:
			event_schema_add_index();
			break;
		case AFL_EVENT_DB_SCHEMA_CREATE:
			event_schema_create();
			break;
		case AFL_EVENT_DB_SCHEMA_GET:
			event_schema_get();
			break;
		case AFL_EVENT_DB_SCHEMA_DELETE:
			event_schema_delete();
			break;
		case AFL_EVENT_DB_SELECTOR_NEW:
			event_selector_new();
			break;
		case AFL_EVENT_DB_SELECTOR_REF:
			event_selector_ref();
			break;
		case AFL_EVENT_DB_SELECTOR_ADD_FIELD:
			event_selector_add_field();
			break;
		case AFL_EVENT_DB_SELECTOR_ADD_SELECTOR:
			event_selector_add_selector();
			break;
		case AFL_EVENT_DB_AFL_INIT:
			//this initializes one element of each class
			event_schema_new();
			event_schema_add_field();
			event_schema_create();
			event_entry_new();
			event_entry_set_field();
			event_entry_insert();
			event_selector_new();
			event_selector_add_field();
			event_iterator_new();
			event_iterator_next();
			event_iterator_get_field();
			break;
		case _AFL_EVENT_DB_COUNT: //LCOV_EXCL_LINE
		default: //LCOV_EXCL_LINE
			MYABORT(); //LCOV_EXCL_LINE
		}
		goto loop;
	cleanup:
		for (i = 0; i < AFL_LIMIT_SCHEMA_NAMESPACE; i++)
		{
			for (j = 0; j < AFL_LIMIT_SCHEMA_NAME; j++)
			{
				random_values.namespace = i;
				random_values.name = j;
				event_schema_delete_helper();
			}
			sprintf(namespace_strbuf, AFL_NAMESPACE_FORMAT, i);
			ret = j_internal_reset(namespace_strbuf, batch, &error);
			ret = ret && j_batch_execute(batch);
			J_AFL_DEBUG_ERROR(ret, TRUE, error);
		}
	}
fini:
	return 0;
}
