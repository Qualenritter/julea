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
	do
	{
		ret = sqlite3_step(stmt_file_delete0);
		if (ret == SQLITE_ROW)
		{
			tmp = sqlite3_column_int64(stmt_file_delete0, 0);
			g_array_append_val(arr, tmp);
		}
		else if (ret != SQLITE_DONE)
		{
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
			exit(1);
		}
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
	gint ret;
	sqlite3_int64 file_key = 0;
	file_key = g_atomic_int_add(&smd_schemes_primary_key, 1);
	j_sqlite3_transaction_begin();
	memcpy(key, &file_key, sizeof(file_key));
	j_sqlite3_bind_int(stmt_file_create, 1, file_key);
	j_sqlite3_bind_text(stmt_file_create, 2, name, -1);
	ret = sqlite3_step(stmt_file_create);
	if (ret == SQLITE_CONSTRAINT)
	{
		j_sqlite3_reset(stmt_file_create);
		j_sqlite3_transaction_abort();
		return FALSE;
	}
	else if (ret != SQLITE_DONE)
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		exit(1);
	}
	j_sqlite3_reset(stmt_file_create);
	j_sqlite3_transaction_commit();
	(void)bson;
	return TRUE;
}
static gboolean
backend_file_open(const char* name, bson_t* bson, char* key)
{
	gint ret;
	sqlite3_int64 result = 0;
	bson_init(bson);
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_text(stmt_file_open, 1, name, -1);
	ret = sqlite3_step(stmt_file_open);
	if (ret == SQLITE_ROW)
	{
		result = sqlite3_column_int64(stmt_file_open, 0);
		memset(key, 0, SMD_KEY_LENGTH);
		memcpy(key, &result, sizeof(result));
	}
	else if (ret == SQLITE_DONE)
	{
		j_sqlite3_reset(stmt_file_open);
		j_sqlite3_transaction_abort();
		return FALSE;
	}
	else
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		exit(1);
	}
	j_sqlite3_reset(stmt_file_open);
	j_sqlite3_transaction_commit();
	return TRUE;
}
