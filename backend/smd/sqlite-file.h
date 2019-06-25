static gboolean
backend_file_delete(const char* name)
{
	//TODO delete data in object-store if any
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
	J_DEBUG("file delete success %s", name);
	return TRUE;
}
static gboolean
backend_file_create(const char* name, bson_t* bson, void* key)
{
	gint ret0;
	gint ret1;
	sqlite3_int64 file_key = 0;
	memset(key, 0, sizeof(file_key));
	file_key = g_atomic_int_add(&smd_schemes_primary_key, 1);
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_int(stmt_file_create0, 1, file_key);
	j_sqlite3_bind_text(stmt_file_create0, 2, name, -1);
	ret0 = sqlite3_step(stmt_file_create0);
	j_sqlite3_bind_int(stmt_file_create1, 1, file_key);
	j_sqlite3_bind_text(stmt_file_create1, 2, name, -1);
	ret1 = sqlite3_step(stmt_file_create1);
	if (ret1 == SQLITE_CONSTRAINT)
	{
		j_sqlite3_reset_constraint(stmt_file_create0);
		j_sqlite3_reset_constraint(stmt_file_create1);
		j_sqlite3_transaction_abort();
		J_DEBUG("file create failed %s", name);
		return FALSE;
	}
	else if (ret0 != SQLITE_DONE || ret1 != SQLITE_DONE)
	{
		J_CRITICAL("sql_error %d %d %s", ret0, ret1, sqlite3_errmsg(backend_db));
		exit(1);
	}
	j_sqlite3_reset(stmt_file_create0);
	j_sqlite3_reset(stmt_file_create1);
	j_sqlite3_transaction_commit();
	(void)bson;
	J_DEBUG("file create success %s %lld", name, file_key);
	memcpy(key, &file_key, sizeof(file_key));
	return TRUE;
}
static gboolean
backend_file_open(const char* name, bson_t* bson, void* key)
{
	gint ret;
	sqlite3_int64 file_key = 0;
	bson_init(bson);
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_text(stmt_file_open, 1, name, -1);
	ret = sqlite3_step(stmt_file_open);
	if (ret == SQLITE_ROW)
	{
		file_key = sqlite3_column_int64(stmt_file_open, 0);
		memset(key, 0, SMD_KEY_LENGTH);
		memcpy(key, &file_key, sizeof(file_key));
	}
	else if (ret == SQLITE_DONE)
	{
		j_sqlite3_reset(stmt_file_open);
		j_sqlite3_transaction_abort();
		J_DEBUG("file open failed %s", name);
		return FALSE;
	}
	else
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		exit(1);
	}
	j_sqlite3_reset(stmt_file_open);
	j_sqlite3_transaction_commit();
	J_DEBUG("file open success %s %lld", name, file_key);
	return TRUE;
}
