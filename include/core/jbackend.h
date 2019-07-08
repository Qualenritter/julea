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
	- _indexes columns are only on defined variables
	- _unique columns are only on defined variables
*/
			gboolean (*backend_schema_create)(gchar const* namespace, gchar const* name, bson_t const* schema);
/*!
optains information about a schema in the smd-backend
@param namespace [in] different usecases (e.g. "adios", "hdf5")
@param name [in] schema name to open (e.g. "files")
@param schema [out] the schema information
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



			// namespace = unterschiedliche Use Cases (z.B. "adios2", "hdf5")
			// name = eigentlicher Schema-Name (z.B. "files")
			// metadata = BSON-kodierte Metadaten (kann ein Array enthalten? ansonsten brauchen wir Batches [siehe KV])
			gboolean (*backend_insert)(gchar const* namespace, gchar const* name, bson_t const* metadata);

			// namespace = unterschiedliche Use Cases (z.B. "adios2", "hdf5")
			// name = eigentlicher Schema-Name (z.B. "files")
			// selector = BSON-kodierter Query
			// metadata = BSON-kodierte Metadaten
			gboolean (*backend_update)(gchar const* namespace, gchar const* name, bson_t const* selector, bson_t const* metadata);

			// namespace = unterschiedliche Use Cases (z.B. "adios2", "hdf5")
			// name = eigentlicher Schema-Name (z.B. "files")
			// selector = BSON-kodierter Query
			gboolean (*backend_delete)(gchar const* namespace, gchar const* name, bson_t const* selector);

			// namespace = unterschiedliche Use Cases (z.B. "adios2", "hdf5")
			// name = eigentlicher Schema-Name (z.B. "files")
			// selector = BSON-kodierter Query (kann leer sein, dann werden alle Einträge zurückgegeben)
			// iterator = ist Backend-spezifisch, wird an backend_iterate übergeben
			gboolean (*backend_query)(gchar const* namespace, gchar const* name, bson_t const* selector, gpointer* iterator);

			// iterator = ist Backend-spezifisch, kommt von backend_query
			// metadata = BSON-kodierte Metadaten (einzelne Einträge)
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
