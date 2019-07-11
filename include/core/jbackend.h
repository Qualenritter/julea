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
#include <core/jmessage.h>

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
			gboolean (*backend_batch_start)(gchar const* namespace, JSemanticsSafety safety, gpointer* batch); //TODO check not null on module load
			gboolean (*backend_batch_execute)(gpointer batch); //TODO check not null on module load
			/*!
create a schema in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to create (e.g. "files")
@param schema [in] the schema-structure to create. points to
 - an initialized bson containing "structure"
@verbatim
structure{
	"var_name1": var_type1 (int32),
	"var_name2": var_type2 (int32),
	"var_nameN": var_typeN (int32),
	"_indexes": [["var_name1", "var_name2"], ["var_name3"]],
}
@endverbatim
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did not exist before
	- there are variables defined in the schema
	- all var_types in the schema are valid
	- there is no variable name used multiple times
	- there is no variable called "_id"
	- _indexes columns are only on defined variables
*/
			gboolean (*backend_schema_create)(gpointer batch, gchar const* name, bson_t const* schema);
			/*!
obtains information about a schema in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to open (e.g. "files")
@param schema [out] the schema information initially points to
 - an allocated, but NOT initialized Bson
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
			gboolean (*backend_schema_get)(gpointer batch, gchar const* name, bson_t* schema);
			/*!
delete a schema in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to delete (e.g. "files")
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did exists before
	- (namespace, name) did not exist after
*/
			gboolean (*backend_schema_delete)(gpointer batch, gchar const* name);
			/*!
insert data into a schema in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to delete (e.g. "files")
@param metadata [in] the data to insert. points to
 - an initialized bson_t containing "data"
 - an initialized bson_t containing "arr_data"
@verbatim
data{
	"var_name1": value1,
	"var_name2": value2,
	"var_nameN": valueN,
}
arr_data{
	"_arr" : [
		"0": bson_t(data),
		"1": bson_t(data),
		"N": bson_t(data),
	]
}
@endverbatim
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did exists before
	- there are no var_names which are not existent in the schema definition
	- metadata is not NULL
	- metadata is not an empty bson
*/
			gboolean (*backend_insert)(gpointer batch, gchar const* name, bson_t const* metadata);
			/*!
updates data in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to delete (e.g. "files")
@param selector [in] the selector to decide which data should be updated. points to
 - an initialized bson containing "selector_part_and"
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
	- the selector found at least one element
	- the selector is not NULL
	- the selector is not the empty bson
	- there are no var_names which are not existent in the schema definition
*/
			gboolean (*backend_update)(gpointer batch, gchar const* name, bson_t const* selector, bson_t const* metadata);
			/*!
deletes data from the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to delete (e.g. "files")
@param selector [in] the selector to decide which data should be updated. points to
 - an initialized bson containing "selector_part_and"
 - an empty bson
 - NULL
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
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did exists before
	- there are no var_names which are not existent in the schema definition
	- there is at least one element deleted in the smd-backend
*/
			gboolean (*backend_delete)(gpointer batch, gchar const* name, bson_t const* selector);
			/*!
creates an iterator for the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to delete (e.g. "files")
@param selector [in] the selector to decide which data should be updated. points to
 - an initialized bson containing "selector_part_and"
 - an empty bson
 - NULL
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
@param iterator [out] the iterator which can be used later for backend_iterate
@return TRUE if all following statements are TRUE otherwise FALSE
	- (namespace, name) did exists before
	- there are no var_names which are not existent in the schema definition
	- the iterator is valid
*/
			gboolean (*backend_query)(gpointer batch, gchar const* name, bson_t const* selector, gpointer* iterator);
			/*!
obtains metadata from the backend
backend_iterate should be called until the returned value is NULL due to no more elements found - this allowes the backend to free potentially 
allocated caches.
@param iterator [inout] the iterator specifying the data to retrieve
@param metadata [out] the requested metadata initially points to
 - an initialized bson - ready to write a document
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
	- metadata was not NULL
	- iterator pointed to an existing element
	- metadata contains requested element fround by iterator
	- iterator is updated to point to next element (if next element exists)
*/
			gboolean (*backend_iterate)(gpointer iterator, bson_t* metadata);
		} smd;
	};
};
typedef struct JBackend JBackend;

enum JBackend_smd_parameter_type
{
	J_SMD_PARAM_TYPE_STR = 0,
	J_SMD_PARAM_TYPE_BLOB,
	J_SMD_PARAM_TYPE_BSON,
	_J_SMD_PARAM_TYPE_COUNT,
};
typedef enum JBackend_smd_parameter_type JBackend_smd_parameter_type;
struct JBackend_smd_operation_data
{
	GArray* in; //into network message
	GArray* out; //retrieve from network message
};
typedef struct JBackend_smd_operation_data JBackend_smd_operation_data;
struct JBackend_smd_operation_in
{
	gconstpointer ptr;
	gint len;
	JBackend_smd_parameter_type type;
};
typedef struct JBackend_smd_operation_in JBackend_smd_operation_in;
struct JBackend_smd_operation_out
{
	gpointer ptr;
	gint len;
	JBackend_smd_parameter_type type;
};
typedef struct JBackend_smd_operation_out JBackend_smd_operation_out;
gboolean j_backend_smd_message_from_data(JMessage* message, JBackend_smd_operation_data* data);
gboolean j_backend_smd_message_to_data(JMessage* message, JBackend_smd_operation_data* data);

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
gboolean j_backend_smd_schema_create(JBackend*, gpointer batch, JBackend_smd_operation_data* data);
gboolean j_backend_smd_schema_get(JBackend*, gpointer batch, JBackend_smd_operation_data* data);
gboolean j_backend_smd_schema_delete(JBackend*, gpointer batch, JBackend_smd_operation_data* data);
gboolean j_backend_smd_insert(JBackend*, gpointer batch, JBackend_smd_operation_data* data);
gboolean j_backend_smd_update(JBackend*, gpointer batch, JBackend_smd_operation_data* data);
gboolean j_backend_smd_delete(JBackend*, gpointer batch, JBackend_smd_operation_data* data);
gboolean j_backend_smd_get_all(JBackend*, gpointer batch, JBackend_smd_operation_data* data);
G_END_DECLS

#endif
