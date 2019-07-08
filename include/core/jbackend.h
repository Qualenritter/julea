/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2017-2019 Michael Kuhn
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

/**
 * \file
 **/

#ifndef JULEA_BACKEND_H
#define JULEA_BACKEND_H

#if !defined(JULEA_H) && !defined(JULEA_COMPILATION)
#error "Only <julea.h> can be included directly."
#endif

#include <glib.h>
#include <gmodule.h>

#include <bson.h>

#include <core/jsemantics.h>

G_BEGIN_DECLS

enum JBackendType
{
	J_BACKEND_TYPE_OBJECT,
	J_BACKEND_TYPE_KV,
	J_BACKEND_TYPE_SMD,
};

typedef enum JBackendType JBackendType;

enum JBackendComponent
{
	J_BACKEND_COMPONENT_CLIENT = 1 << 0,
	J_BACKEND_COMPONENT_SERVER = 1 << 1
};

typedef enum JBackendComponent JBackendComponent;

//! This struct contains the required functions for the different backends
struct JBackend
{
	JBackendType type;
	JBackendComponent component;

	union
	{
		struct
		{
			gboolean (*backend_init)(gchar const*);
			void (*backend_fini)(void);

			gboolean (*backend_create)(gchar const*, gchar const*, gpointer*);
			gboolean (*backend_open)(gchar const*, gchar const*, gpointer*);

			gboolean (*backend_delete)(gpointer);
			gboolean (*backend_close)(gpointer);

			gboolean (*backend_status)(gpointer, gint64*, guint64*);
			gboolean (*backend_sync)(gpointer);

			gboolean (*backend_read)(gpointer, gpointer, guint64, guint64, guint64*);
			gboolean (*backend_write)(gpointer, gconstpointer, guint64, guint64, guint64*);
		} object;

		struct
		{
			gboolean (*backend_init)(gchar const*);
			void (*backend_fini)(void);

			gboolean (*backend_batch_start)(gchar const*, JSemanticsSafety, gpointer*);
			gboolean (*backend_batch_execute)(gpointer);

			gboolean (*backend_put)(gpointer, gchar const*, gconstpointer, guint32);
			gboolean (*backend_delete)(gpointer, gchar const*);
			gboolean (*backend_get)(gpointer, gchar const*, gpointer*, guint32*);

			gboolean (*backend_get_all)(gchar const*, gpointer*);
			gboolean (*backend_get_by_prefix)(gchar const*, gchar const*, gpointer*);
			gboolean (*backend_iterate)(gpointer, gconstpointer*, guint32*);
		} kv;

		struct
		{
			gboolean (*backend_init)(gchar const*);
			void (*backend_fini)(void);
			/*!
create a schema in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to create (e.g. "files")
@param schema [in] the schema-structure to create
@verbatim
{
	"var_name1": var_type1 (int32),
	"var_name2": var_type2 (int32),
	"var_nameN": var_typeN (int32),
	"_indexes": [["var_name1", "var_name2"], ["var_name3"]],
	"_unique": [["var_name1", "var_name2"], ["var_name3"]],
}
@endverbatim
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did not exist before
	- there are variables defined in the schema
	- all var_types in the schema are valid
	- there is no variable name used multiple times
	- there is no variable called "_id"
	- _indexes columns are only on defined variables
	- _unique columns are only on defined variables
*/
			gboolean (*backend_schema_create)(gchar const* namespace, gchar const* name, bson_t const* schema);
			/*!
obtains information about a schema in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to open (e.g. "files")
@param schema [out] the schema information initially points to
 - an NOT initialized Bson
 - NULL
@verbatim
{
	"_id": (int64)
	"var_name1": var_type1 (int32),
	"var_name2": var_type2 (int32),
	"var_nameN": var_typeN (int32),
}
@endverbatim
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) exists
	- schema != NULL and contains the requested data
	- schema == NULL
*/
			gboolean (*backend_schema_get)(gchar const* namespace, gchar const* name, bson_t* schema);
			/*!
delete a schema in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to delete (e.g. "files")
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did exists before
	- (namespace, name) did not exist after
*/
			gboolean (*backend_schema_delete)(gchar const* namespace, gchar const* name);
			/*!
insert data into a schema in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to delete (e.g. "files")
@param metadata [in] the data to insert
@verbatim
{
	"var_name1": value1,
	"var_name2": value2,
	"var_nameN": valueN,
}
@endverbatim
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did exists before
	- all unique constraints are intact
	- there are no var_names which are not existent in the schema definition
*/
			gboolean (*backend_insert)(gchar const* namespace, gchar const* name, bson_t const* metadata);
			/*!
updates data in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to delete (e.g. "files")
@param selector [in] the selector to decide which data should be updated
@verbatim
selector_part_and: {
	"var_name1": {
		"operator": op1 (int32),
		"value": value1,
	},
	"var_nameN": {
		"operator": op2 (int32),
		"value": value2,
	}
	_or: bson_t(selector_part_or)
}
selector_part_or: {
	"var_name1": {
		"operator": op (int32),
		"value": value,
	},
	"var_nameN": {
		"operator": op (int32),
		"value": value,
	}
	_and: bson_t(selector_part_and)
}
@endverbatim
 - selector = selector_and
@param metadata [in] the data to write. All undefined columns will be set to NULL
@verbatim
{
        "var_name1": value1,
        "var_name2": value2,
        "var_nameN": valueN,
}
@endverbatim
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did exists before
	- all unique constraints are intact
	- the selector found at least one element
	- there are no var_names which are not existent in the schema definition
*/
			gboolean (*backend_update)(gchar const* namespace, gchar const* name, bson_t const* selector, bson_t const* metadata);
			/*!
deletes data from the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to delete (e.g. "files")
@param selector [in] the selector to decide which data should be updated
@verbatim
selector_part_and: {
	"var_name1": {
		"operator": op1 (int32),
		"value": value1,
	},
	"var_nameN": {
		"operator": op2 (int32),
		"value": value2,
	}
	_or: bson_t(selector_part_or)
}
selector_part_or: {
	"var_name1": {
		"operator": op (int32),
		"value": value,
	},
	"var_nameN": {
		"operator": op (int32),
		"value": value,
	}
	_and: bson_t(selector_part_and)
}
@endverbatim
 - selector = selector_and
 - selector = empty-bson
 - selector = NULL
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did exists before
	- there are no var_names which are not existent in the schema definition
	- there is at least one element deleted in the smd-backend
*/
			gboolean (*backend_delete)(gchar const* namespace, gchar const* name, bson_t const* selector);
			/*!
creates an iterator for the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to delete (e.g. "files")
@param selector [in] the selector to decide which data should be updated
@verbatim
selector_part_and: {
	"var_name1": {
		"operator": op1 (int32),
		"value": value1,
	},
	"var_nameN": {
		"operator": op2 (int32),
		"value": value2,
	}
	_or: bson_t(selector_part_or)
}
selector_part_or: {
	"var_name1": {
		"operator": op (int32),
		"value": value,
	},
	"var_nameN": {
		"operator": op (int32),
		"value": value,
	}
	_and: bson_t(selector_part_and)
}
@endverbatim
 - selector = selector_and
 - selector = empty-bson
 - selector = NULL
@param iterator [out] the iterator which can be used later for backend_iterate
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did exists before
	- there are no var_names which are not existent in the schema definition
	- the iterator is valid
	- the iterator contains at least one result
*/
			gboolean (*backend_query)(gchar const* namespace, gchar const* name, bson_t const* selector, gpointer* iterator);
			/*!
obtains metadata from the backend
@param iterator [inout] the iterator specifying the data to retrieve
@param metadata [out] the requested metadata initially points to a initialized empty bson
@verbatim
{
	"_id": value0,
	"var_name1": value1,
	"var_name2": value2,
	"var_nameN": valueN,
}
@endverbatim
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did exists before
	- metadata is valid
	- iterator found an element
*/
			gboolean (*backend_iterate)(gpointer iterator, bson_t* metadata);
		} smd;
	};
};

typedef struct JBackend JBackend;

JBackend* backend_info(void);

gboolean j_backend_load_client(gchar const*, gchar const*, JBackendType, GModule**, JBackend**);
gboolean j_backend_load_server(gchar const*, gchar const*, JBackendType, GModule**, JBackend**);

gboolean j_backend_object_init(JBackend*, gchar const*);
void j_backend_object_fini(JBackend*);

gboolean j_backend_object_create(JBackend*, gchar const*, gchar const*, gpointer*);
gboolean j_backend_object_open(JBackend*, gchar const*, gchar const*, gpointer*);

gboolean j_backend_object_delete(JBackend*, gpointer);
gboolean j_backend_object_close(JBackend*, gpointer);

gboolean j_backend_object_status(JBackend*, gpointer, gint64*, guint64*);
gboolean j_backend_object_sync(JBackend*, gpointer);

gboolean j_backend_object_read(JBackend*, gpointer, gpointer, guint64, guint64, guint64*);
gboolean j_backend_object_write(JBackend*, gpointer, gconstpointer, guint64, guint64, guint64*);

gboolean j_backend_kv_init(JBackend*, gchar const*);
void j_backend_kv_fini(JBackend*);

gboolean j_backend_kv_batch_start(JBackend*, gchar const*, JSemanticsSafety, gpointer*);
gboolean j_backend_kv_batch_execute(JBackend*, gpointer);

gboolean j_backend_kv_put(JBackend*, gpointer, gchar const*, gconstpointer, guint32);
gboolean j_backend_kv_delete(JBackend*, gpointer, gchar const*);
gboolean j_backend_kv_get(JBackend*, gpointer, gchar const*, gpointer*, guint32*);

gboolean j_backend_kv_get_all(JBackend*, gchar const*, gpointer*);
gboolean j_backend_kv_get_by_prefix(JBackend*, gchar const*, gchar const*, gpointer*);
gboolean j_backend_kv_iterate(JBackend*, gpointer, gconstpointer*, guint32*);

gboolean j_backend_smd_init(JBackend*, gchar const*);
void j_backend_smd_fini(JBackend*);
gboolean j_backend_smd_schema_create(JBackend*, gchar const* namespace, gchar const* name, bson_t const* schema);
gboolean j_backend_smd_schema_get(JBackend*, gchar const* namespace, gchar const* name, bson_t* schema);
gboolean j_backend_smd_schema_delete(JBackend*, gchar const* namespace, gchar const* name);
gboolean j_backend_smd_insert(JBackend*, gchar const* namespace, gchar const* name, bson_t const* metadata);
gboolean j_backend_smd_update(JBackend*, gchar const* namespace, gchar const* name, bson_t const* selector, bson_t const* metadata);
gboolean j_backend_smd_delete(JBackend*, gchar const* namespace, gchar const* name, bson_t const* selector);
gboolean j_backend_smd_query(JBackend*, gchar const* namespace, gchar const* name, bson_t const* selector, gpointer* iterator);
gboolean j_backend_smd_iterate(JBackend*, gpointer iterator, bson_t* metadata);
G_END_DECLS

#endif
