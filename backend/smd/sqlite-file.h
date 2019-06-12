static gboolean
backend_file_delete(const char* name)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;

	J_DEBUG("%s", name);

	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND meta_type = ?;", -1, &stmt, NULL);
	ret = sqlite3_bind_text(stmt, 1, name, -1, NULL);
	if (ret != SQLITE_OK)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	ret = sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
	if (ret != SQLITE_OK)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
	{
		result = sqlite3_column_int64(stmt, 0);
	}
	else
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	}
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "DELETE FROM smd WHERE file_key = ?1;", -1, &stmt, NULL);
	ret = sqlite3_bind_int64(stmt, 1, result);
	if (ret != SQLITE_OK)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	}
	sqlite3_finalize(stmt);
	/*TODO delete type if no file uses it*/
	J_DEBUG("%s", name);
	return TRUE;
}
static gboolean
backend_file_create(const char* name, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;

	J_DEBUG("%s %s", name, bson_as_json(bson, NULL));

	g_return_val_if_fail(name != NULL, FALSE);
	{ /*delete old file first*/
		sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND meta_type = ?;", -1, &stmt, NULL);
		ret = sqlite3_bind_text(stmt, 1, name, -1, NULL);
		if (ret != SQLITE_OK)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		ret = sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
		if (ret != SQLITE_OK)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			backend_file_delete(name);
		}
		else if (ret != SQLITE_DONE)
		{
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		}
		sqlite3_finalize(stmt);
	}
	{ // insert new file
		sqlite3_prepare_v2(backend_db, "INSERT INTO smd (name,meta_type) VALUES (?,?);", -1, &stmt, NULL);
		ret = sqlite3_bind_text(stmt, 1, name, -1, NULL);
		if (ret != SQLITE_OK)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		ret = sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
		if (ret != SQLITE_OK)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_DONE)
		{
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		}
		sqlite3_finalize(stmt);
	}
	{ // extract the primary key
		sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND meta_type = ?;", -1, &stmt, NULL);
		ret = sqlite3_bind_text(stmt, 1, name, -1, NULL);
		if (ret != SQLITE_OK)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		ret = sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
		if (ret != SQLITE_OK)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		ret = sqlite3_step(stmt);
		memset(key, 0, SMD_KEY_LENGTH);
		if (ret == SQLITE_ROW)
		{
			result = sqlite3_column_int64(stmt, 0);
			memcpy(key, &result, sizeof(result));
		}
		else
		{
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		}
		sqlite3_finalize(stmt);
	}
	{ // set the parent pointers to this file
		sqlite3_prepare_v2(backend_db, "UPDATE smd SET parent_key = ?1, file_key = ?1 WHERE key = ?1;", -1, &stmt, NULL);
		ret = sqlite3_bind_int64(stmt, 1, result);
		if (ret != SQLITE_OK)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_DONE)
		{
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		}
		sqlite3_finalize(stmt);
	}
	(void)bson;
	J_DEBUG("%s", name);
	return TRUE;
}
static gboolean
backend_file_open(const char* name, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;
	J_DEBUG("%s", name);
	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND meta_type = ?;", -1, &stmt, NULL);
	ret = sqlite3_bind_text(stmt, 1, name, -1, NULL);
	if (ret != SQLITE_OK)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	ret = sqlite3_bind_int(stmt, 2, SMD_METATYPE_FILE);
	if (ret != SQLITE_OK)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
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
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	}
	sqlite3_finalize(stmt);
	J_DEBUG("%s %s", name, bson_as_json(bson, NULL));
	return TRUE;
}
