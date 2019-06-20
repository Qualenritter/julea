static gboolean
backend_file_delete(const char* name)
{
	GArray* arr;
	gint ret;
	guint i;
	sqlite3_int64 tmp;
	arr = g_array_new(FALSE, FALSE, sizeof(sqlite3_int64));
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_text(stmt_file_delete0, 1, name, -1);
	J_CRITICAL("types to delete %lld %s", -1, name);
	do
	{
		ret = sqlite3_step(stmt_file_delete0);
		if (ret == SQLITE_ROW)
		{
			tmp = sqlite3_column_int64(stmt_file_delete0, 0);
			J_CRITICAL("types to delete %lld", tmp);
			g_array_append_val(arr, tmp);
		}
		else if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	} while (ret != SQLITE_DONE);
	j_sqlite3_reset(stmt_file_delete0);
	j_sqlite3_bind_text(stmt_file_delete1, 1, name, -1);
	j_sqlite3_step_and_reset_check_done(stmt_file_delete1);
	for (i = 0; i < arr->len; i++)
	{
		j_sqlite3_bind_int64(stmt_type_delete, 1, g_array_index(arr, sqlite3_int64, i));
		j_sqlite3_step_and_reset_check_done(stmt_type_delete);
	}
	j_sqlite3_transaction_commit();
	g_array_free(arr, TRUE);
	return TRUE;
}
static gboolean
backend_file_create(const char* name, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 file_key = 0;
	file_key = g_atomic_int_add(&smd_schemes_primary_key, 1);
	memcpy(key, &file_key, sizeof(file_key));
	g_return_val_if_fail(name != NULL, FALSE);
	backend_file_delete(name);
	{
		sqlite3_prepare_v2(backend_db, "INSERT INTO smd_schemes (key,parent_key,file_key,name,meta_type) VALUES (?1,?1,?1,?2,?3);", -1, &stmt, NULL);
		j_sqlite3_bind_int(stmt, 1, file_key);
		j_sqlite3_bind_text(stmt, 2, name, -1);
		j_sqlite3_bind_int(stmt, 3, SMD_METATYPE_FILE);
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		sqlite3_finalize(stmt);
	}
	(void)bson;
	return TRUE;
}
static gboolean
backend_file_open(const char* name, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;
	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key FROM smd_schemes WHERE name = ? AND meta_type = ?;", -1, &stmt, NULL);
	j_sqlite3_bind_text(stmt, 1, name, -1);
	j_sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
	ret = sqlite3_step(stmt);
	memset(key, 0, SMD_KEY_LENGTH);
	bson_init(bson);
	if (ret == SQLITE_ROW)
	{
		result = sqlite3_column_int64(stmt, 0);
		memcpy(key, &result, sizeof(result));
	}
	else if (ret == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		return FALSE;
	}
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	return TRUE;
}
