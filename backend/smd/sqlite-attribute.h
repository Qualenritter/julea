static gboolean
backend_attr_delete(const char* name, char* parent)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;
	J_DEBUG("%s", name);
	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND parent_key = ?;", -1, &stmt, NULL);
	j_sqlite3_bind_text(stmt, 1, name, -1);
	j_sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
		result = sqlite3_column_int64(stmt, 0);
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "DELETE FROM smd WHERE key = ?;", -1, &stmt, NULL);
	j_sqlite3_bind_int64(stmt, 1, result);
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	/*TODO delete everything below*/
	J_DEBUG("%s", name);
	return TRUE;
}
static gboolean
backend_attr_create(const char* name, char* parent, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 metadata_key = 0;
	sqlite3_int64 file_key;
	sqlite3_int64 type_key;
	bson_iter_t iter;
	bson_iter_t iter_space_type;
	guint var_ndims;
	guint var_dims[4];
	bson_iter_t iter_data_type;
	bson_iter_t iter_data_dims;
	guint i;
	J_DEBUG("%s %s", name, bson_as_json(bson, NULL));
	g_return_val_if_fail(name != NULL, FALSE);
	bson_iter_init(&iter, bson);
	var_ndims = 0;
	var_dims[0] = 0;
	var_dims[1] = 0;
	var_dims[2] = 0;
	var_dims[3] = 0;
	{ // extract ndims,dims
		while (bson_iter_next(&iter))
		{
			if (strcmp("space_type", bson_iter_key(&iter)) == 0)
			{
				bson_iter_recurse(&iter, &iter_space_type);
				while (bson_iter_next(&iter_space_type))
				{
					if (strcmp("ndims", bson_iter_key(&iter_space_type)) == 0)
					{
						var_ndims = bson_iter_int32(&iter_space_type);
						if (var_ndims > 4)
							return FALSE;
					}
					else if (strcmp("dims", bson_iter_key(&iter_space_type)) == 0)
					{
						bson_iter_recurse(&iter_space_type, &iter_data_dims);
						for (i = 0; bson_iter_next(&iter_data_dims) && i < 4; i++)
							var_dims[i] = bson_iter_int32(&iter_data_dims);
					}
				}
			}
			else if (strcmp("data_type", bson_iter_key(&iter)) == 0)
			{
				bson_iter_recurse(&iter, &iter_data_type);
				type_key = create_type(&iter_data_type);
			}
		}
	}
	{ // extract the file key
		sqlite3_prepare_v2(backend_db, "SELECT file_key FROM smd WHERE key = ?;", -1, &stmt, NULL);
		j_sqlite3_bind_int64(stmt, 1, *((sqlite3_int64*)parent));
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
			file_key = sqlite3_column_int64(stmt, 0);
		else
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		//TODO check exactly one row returned
		sqlite3_finalize(stmt);
	}
	{ /*delete old attr first*/
		sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND parent_key = ? AND file_key = ?;", -1, &stmt, NULL);
		j_sqlite3_bind_text(stmt, 1, name, -1);
		j_sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
		j_sqlite3_bind_int64(stmt, 3, file_key);
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
			backend_attr_delete(name, parent);
		else if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		sqlite3_finalize(stmt);
	}
	{ // insert new attr
		sqlite3_prepare_v2(backend_db, "INSERT INTO smd (name,meta_type,parent_key,file_key,ndims,dims0,dims1,dims2,dims3,type_key) VALUES (?,?,?,?,?,?,?,?,?,?);", -1, &stmt, NULL);
		j_sqlite3_bind_text(stmt, 1, name, -1);
		j_sqlite3_bind_int(stmt, 2, SMD_METATYPE_DATA);
		j_sqlite3_bind_int64(stmt, 3, *((sqlite3_int64*)parent));
		j_sqlite3_bind_int64(stmt, 4, file_key);
		j_sqlite3_bind_int(stmt, 5, var_ndims);
		j_sqlite3_bind_int(stmt, 6, var_dims[0]);
		j_sqlite3_bind_int(stmt, 7, var_dims[1]);
		j_sqlite3_bind_int(stmt, 8, var_dims[2]);
		j_sqlite3_bind_int(stmt, 9, var_dims[3]);
		j_sqlite3_bind_int64(stmt, 10, type_key);
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		sqlite3_finalize(stmt);
	}
	{ // extract the primary key
		sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND parent_key = ? AND file_key = ?;", -1, &stmt, NULL);
		j_sqlite3_bind_text(stmt, 1, name, -1);
		j_sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
		j_sqlite3_bind_int64(stmt, 3, file_key);
		ret = sqlite3_step(stmt);
		memset(key, 0, SMD_KEY_LENGTH);
		if (ret == SQLITE_ROW)
		{
			metadata_key = sqlite3_column_int64(stmt, 0);
			memcpy(key, &metadata_key, sizeof(metadata_key));
		}
		else
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		sqlite3_finalize(stmt);
	}
	J_DEBUG("%s", name);
	return TRUE;
}
static gboolean
backend_attr_open(const char* name, char* parent, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 metadata_key = 0;
	sqlite3_int64 type_key = 0;
	bson_t b_datatype[1];
	bson_t b_arr[1];
	char key_buf[16];
	const char* _key;
	J_DEBUG("%s", name);
	bson_init(bson);
	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key, ndims, dims0, dims1, dims2, dims3,type_key FROM smd WHERE name = ? AND parent_key = ?;", -1, &stmt, NULL);
	j_sqlite3_bind_text(stmt, 1, name, -1);
	j_sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
	ret = sqlite3_step(stmt);
	memset(key, 0, SMD_KEY_LENGTH);
	if (ret == SQLITE_ROW)
	{
		metadata_key = sqlite3_column_int64(stmt, 0);
		memcpy(key, &metadata_key, sizeof(metadata_key));
		bson_append_document_begin(bson, "space_type", -1, b_datatype);
		bson_append_int32(b_datatype, "ndims", -1, sqlite3_column_int(stmt, 1));
		bson_append_array_begin(b_datatype, "dims", -1, b_arr);
		bson_uint32_to_string(0, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt, 2));
		bson_uint32_to_string(1, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt, 3));
		bson_uint32_to_string(2, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt, 4));
		bson_uint32_to_string(3, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt, 5));
		bson_append_array_end(b_datatype, b_arr);
		bson_append_document_end(bson, b_datatype);
		type_key = sqlite3_column_int64(stmt, 6);
	}
	else if (ret == SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		return FALSE;
	}
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	bson_append_document_begin(bson, "data_type", -1, b_datatype);
	load_type(b_datatype, type_key);
	bson_append_document_end(bson, b_datatype);
	J_DEBUG("%s %s", name, bson_as_json(bson, NULL));
	return TRUE;
}
static gboolean
backend_attr_read(char* key, char* buf, guint offset, guint size)
{
	read_type(*((sqlite3_int64*)key), buf, offset, size);
	return TRUE;
}
static gboolean
backend_attr_write(char* key, const char* buf, guint offset, guint size)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 type_key;
	sqlite3_prepare_v2(backend_db, "SELECT type_key FROM smd WHERE key = ?;", -1, &stmt, NULL);
	j_sqlite3_bind_int64(stmt, 1, *((sqlite3_int64*)key));
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
		type_key = sqlite3_column_int64(stmt, 0);
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	write_type(type_key, *((sqlite3_int64*)key), buf, offset, size, 0, 0);
	return TRUE;
}
