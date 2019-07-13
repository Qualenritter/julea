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
#include <julea-smd-schema.h>
#include <julea-internal.h>
#include "afl.h"

#include "smd-internal-mockup.h"
//directly including the files under test to allow very fast ad explicit mockups
//this test uses mockups for all backend communication
#include "../lib/smd/jsmd-schema.c"

//configure here->
#define AFL_NAMESPACE_FORMAT "namespace_%d"
#define AFL_NAME_FORMAT "name_%d"
#define AFL_VARNAME_FORMAT "varname_%d"
#define AFL_LIMIT_SCHEMA 4
#define AFL_LIMIT_SCHEMA_NAMESPACE 4
#define AFL_LIMIT_SCHEMA_NAME 4
#define AFL_LIMIT_STRING_LEN 15
//<-

enum JSMDAflEvent
{
	AFL_EVENT_SMD_SCHEMA_NEW = 0,
	AFL_EVENT_SMD_SCHEMA_REF,
	AFL_EVENT_SMD_SCHEMA_ADD_FIELD,
	AFL_EVENT_SMD_SCHEMA_GET_FIELD,
	AFL_EVENT_SMD_SCHEMA_GET_FIELDS,
	AFL_EVENT_SMD_SCHEMA_ADD_INDEX,
	AFL_EVENT_SMD_SCHEMA_CREATE,
	AFL_EVENT_SMD_SCHEMA_GET,
	AFL_EVENT_SMD_SCHEMA_DELETE,
	_AFL_EVENT_EVENT_COUNT,
};
typedef enum JSMDAflEvent JSMDAflEvent;
struct JSMDAflRandomValues
{
	guint schema_index;
	guint namespace;
	guint name;
	guint invalid_schema;
};
typedef struct JSMDAflRandomValues JSMDAflRandomValues;
//variables->
static JSMDSchema* stored_schemas[AFL_LIMIT_SCHEMA];
//<-
//allgemein->
static char name_strbuf[AFL_LIMIT_STRING_LEN];
static char namespace_strbuf[AFL_LIMIT_STRING_LEN];
static char varname_strbuf[AFL_LIMIT_STRING_LEN];
static JSMDAflRandomValues random_values;
//<-
static void
event_schema_new(void)
{
	GError* error = NULL;
	random_values.schema_index = random_values.schema_index % AFL_LIMIT_SCHEMA;
	if (stored_schemas[random_values.schema_index])
		j_smd_schema_unref(stored_schemas[random_values.schema_index]);
	stored_schemas[random_values.schema_index] = NULL;
	random_values.namespace = random_values.namespace % AFL_LIMIT_SCHEMA_NAMESPACE;
	random_values.name = random_values.name % AFL_LIMIT_SCHEMA_NAME;
	sprintf(namespace_strbuf, AFL_NAMESPACE_FORMAT, random_values.namespace);
	sprintf(name_strbuf, AFL_NAME_FORMAT, random_values.name);
	switch (random_values.invalid_schema % 3)
	{
	case 2:
		stored_schemas[random_values.schema_index] = j_smd_schema_new(namespace_strbuf, NULL, &error);
		J_AFL_DEBUG_ERROR(stored_schemas[random_values.schema_index] != NULL, FALSE, error);
		break;
	case 1:
		stored_schemas[random_values.schema_index] = j_smd_schema_new(NULL, name_strbuf, &error);
		J_AFL_DEBUG_ERROR(stored_schemas[random_values.schema_index] != NULL, FALSE, error);
		break;
	case 0:
		stored_schemas[random_values.schema_index] = j_smd_schema_new(namespace_strbuf, name_strbuf, &error);
		J_AFL_DEBUG_ERROR(stored_schemas[random_values.schema_index] != NULL, TRUE, error);
		break;
	default:
		MYABORT();
	}
}
static void
event_schema_ref(void)
{
	GError* error = NULL;
	JSMDSchema* ptr = NULL;
	random_values.schema_index = random_values.schema_index % AFL_LIMIT_SCHEMA;
	if (stored_schemas[random_values.schema_index])
	{
		if (stored_schemas[random_values.schema_index]->ref_count != 1)
			MYABORT();
		ptr = j_smd_schema_ref(stored_schemas[random_values.schema_index], &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
		if (ptr != stored_schemas[random_values.schema_index])
			MYABORT();
		if (stored_schemas[random_values.schema_index]->ref_count != 2)
			MYABORT();
		j_smd_schema_unref(stored_schemas[random_values.schema_index]);
		if (stored_schemas[random_values.schema_index]->ref_count != 1)
			MYABORT();
	}
	else
	{
		ptr = j_smd_schema_ref(stored_schemas[random_values.schema_index], &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, FALSE, error);
	}
}
static void
event_schema_add_field(void)
{
	MYABORT();
}
static void
event_schema_get_field(void)
{
	MYABORT();
}
static void
event_schema_get_fields(void)
{
	MYABORT();
}
static void
event_schema_add_index(void)
{
	MYABORT();
}
static void
event_schema_create(void)
{
	MYABORT();
}
static void
event_schema_get(void)
{
	MYABORT();
}
static void
event_schema_delete(void)
{
	MYABORT();
}

int
main(int argc, char* argv[])
{
	FILE* file;
	JSMDAflEvent event;
	guint i;
	if (argc > 1)
	{
		char filename[50 + strlen(argv[1])];
		mkdir(argv[1], S_IRUSR | S_IRGRP | S_IROTH);
		sprintf(filename, "%s/start-files", argv[1]);
		mkdir(filename, S_IRUSR | S_IRGRP | S_IROTH);
		memset(&random_values, 0, sizeof(random_values));
		for (i = 0; i < _AFL_EVENT_EVENT_COUNT; i++)
		{
			sprintf(filename, "%s/start-files/test-smd-schema-%d.bin", argv[1], i);
			file = fopen(filename, "wb");
			event = i;
			fwrite(&event, sizeof(event), 1, file);
			fwrite(&random_values, sizeof(random_values), 1, file);
			fclose(file);
		}
		goto fini;
	}
#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
	while (__AFL_LOOP(1000))
#endif
	{
		MY_READ_MAX(event, _AFL_EVENT_EVENT_COUNT);
		MY_READ(random_values);
		switch (event)
		{

		case AFL_EVENT_SMD_SCHEMA_NEW:
			event_schema_new();
			break;
		case AFL_EVENT_SMD_SCHEMA_REF:
			event_schema_ref();
			break;
		case AFL_EVENT_SMD_SCHEMA_ADD_FIELD:
			event_schema_add_field();
			break;
		case AFL_EVENT_SMD_SCHEMA_GET_FIELD:
			event_schema_get_field();
			break;
		case AFL_EVENT_SMD_SCHEMA_GET_FIELDS:
			event_schema_get_fields();
			break;
		case AFL_EVENT_SMD_SCHEMA_ADD_INDEX:
			event_schema_add_index();
			break;
		case AFL_EVENT_SMD_SCHEMA_CREATE:
			event_schema_create();
			break;
		case AFL_EVENT_SMD_SCHEMA_GET:
			event_schema_get();
			break;
		case AFL_EVENT_SMD_SCHEMA_DELETE:
			event_schema_delete();
			break;
		case _AFL_EVENT_EVENT_COUNT:
		default:
			MYABORT();
		}
	}
cleanup:
fini:
	return 0;
}
