#include <julea-config.h>
#include <glib.h>
#include <gmodule.h>
#include <sqlite3.h>
#include <julea.h>
#include <julea-internal.h>
#include <julea-smd.h>

static gboolean
backend_init(gchar const* path)
{
	(void)path;
	return TRUE;
}
static void
backend_fini(void)
{
}
static gboolean
backend_file_delete(const char* name)
{
	(void)name;
	return TRUE;
}
static gboolean
backend_file_create(const char* name, bson_t* bson, void* key)
{
	(void)name;
	(void)bson;
	(void)key;
	return TRUE;
}
static gboolean
backend_file_open(const char* name, bson_t* bson, void* key)
{
	(void)name;
	(void)bson;
	(void)key;
	return TRUE;
}
static gboolean
backend_scheme_delete(const char* name, void* parent)
{
	(void)name;
	(void)parent;
	return TRUE;
}
static gboolean
backend_scheme_create(const char* name, void* parent, const void* _space, const void* _type, guint distribution, void* key)
{
	(void)name;
	(void)parent;
	(void)_space;
	(void)_type;
	(void)distribution;
	(void)key;
	return TRUE;
}
static gboolean
backend_scheme_open(const char* name, void* parent, void* _space, void* _type, guint* distribution, void* key)
{
	(void)name;
	(void)parent;
	(void)_space;
	(void)_type;
	(void)distribution;
	(void)key;
	return TRUE;
}
static gboolean
backend_scheme_read(void* key, void* buf, guint offset, guint size)
{
	(void)key;
	(void)buf;
	(void)offset;
	(void)size;
	return TRUE;
}
static gboolean
backend_scheme_write(void* key, const void* buf, guint offset, guint size)
{
	(void)key;
	(void)buf;
	(void)offset;
	(void)size;
	return TRUE;
}
static JBackend null_backend = { .type = J_BACKEND_TYPE_SMD, //
	.component = J_BACKEND_COMPONENT_SERVER, //
	.smd = { //
		.backend_init = backend_init, //
		.backend_fini = backend_fini, //
		.backend_scheme_read = backend_scheme_read, //
		.backend_scheme_write = backend_scheme_write, //
		.backend_file_create = backend_file_create, //
		.backend_file_delete = backend_file_delete, //
		.backend_file_open = backend_file_open, //
		.backend_scheme_create = backend_scheme_create, //
		.backend_scheme_delete = backend_scheme_delete, //
		.backend_scheme_open = backend_scheme_open } };
G_MODULE_EXPORT
JBackend*
backend_info(void)
{
	return &null_backend;
}
