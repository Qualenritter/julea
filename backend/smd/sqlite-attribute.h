static gboolean
backend_attr_delete(const char* name, char* parent)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;

	J_CRITICAL("%s", name);

	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND parent_key = ?;", -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, NULL);
	sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
	{
		result = sqlite3_column_int64(stmt, 0);
	}
	else
	{
		J_CRITICAL("sql_error %s", sqlite3_errmsg(backend_db));
	}
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "DELETE FROM smd WHERE key = ?;", -1, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, result);
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_OK)
	{
		J_CRITICAL("sql_error %s", sqlite3_errmsg(backend_db));
	}
	sqlite3_finalize(stmt);
	/*TODO delete everything below*/
	J_CRITICAL("%s", name);
	return TRUE;
}
static gboolean
backend_attr_create(const char* name, char* parent, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 metadata_key = 0;
	sqlite3_int64 file_key;
	bson_iter_t iter;
	bson_iter_t iter_space_type;
	guint var_ndims;
	guint var_dims[4];
	bson_iter_t iter_data_type;
	bson_iter_t iter_data_arr;
	bson_iter_t iter_data_var;
	bson_iter_t iter_data_dims;
	guint var_offset;
	guint var_size;
	guint var_type;
	guint var_count;
	const char* var_name;
	guint i;

	J_CRITICAL("%s %s", name, bson_as_json(bson, NULL));

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
						{
							return FALSE;
						}
					}
					else if (strcmp("dims", bson_iter_key(&iter_space_type)) == 0)
					{
						bson_iter_recurse(&iter_space_type, &iter_data_dims);
						i = 0;
						while (bson_iter_next(&iter_data_dims) && i < 4)
						{
							var_dims[i] = bson_iter_int32(&iter_data_dims);
							i++;
						}
					}
				}
			}
		}
	}
	{ // extract the file key
		sqlite3_prepare_v2(backend_db, "SELECT file_key FROM smd WHERE key = ?;", -1, &stmt, NULL);
		sqlite3_bind_int64(stmt, 1, *((sqlite3_int64*)parent));
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			file_key = sqlite3_column_int64(stmt, 0);
		}
		else
		{
			J_CRITICAL("sql_error %s", sqlite3_errmsg(backend_db));
		}
		sqlite3_finalize(stmt);
	}
	{ /*delete old attribute first*/
		sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND parent_key = ? AND file_key = ?;", -1, &stmt, NULL);
		sqlite3_bind_text(stmt, 1, name, -1, NULL);
		sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
		sqlite3_bind_int64(stmt, 3, file_key);
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			backend_attr_delete(name, parent);
		}
		else
		{
			J_CRITICAL("sql_error %s", sqlite3_errmsg(backend_db));
		}
		sqlite3_finalize(stmt);
	}
	{ // insert new attribute
		sqlite3_prepare_v2(backend_db, "INSERT INTO smd (name,meta_type,parent_key,file_key,ndims,dims0,dims1,dims2,dims3) VALUES (?,?,?,?,?,?,?,?,?);",
			-1, &stmt, NULL);
		sqlite3_bind_text(stmt, 1, name, -1, NULL);
		sqlite3_bind_int(stmt, 2, SMD_METATYPE_DATA);
		sqlite3_bind_int64(stmt, 3, *((sqlite3_int64*)parent));
		sqlite3_bind_int64(stmt, 4, file_key);
		sqlite3_bind_int(stmt, 5, var_ndims);
		sqlite3_bind_int(stmt, 6, var_dims[0]);
		sqlite3_bind_int(stmt, 7, var_dims[1]);
		sqlite3_bind_int(stmt, 8, var_dims[2]);
		sqlite3_bind_int(stmt, 9, var_dims[3]);
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_OK)
		{
			J_CRITICAL("sql_error %s", sqlite3_errmsg(backend_db));
		}
		sqlite3_finalize(stmt);
	}
	{ // extract the primary key
		sqlite3_prepare_v2(backend_db, "SELECT key FROM smd WHERE name = ? AND parent_key = ? AND file_key = ?;", -1, &stmt, NULL);
		sqlite3_bind_text(stmt, 1, name, -1, NULL);
		sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
		sqlite3_bind_int64(stmt, 3, file_key);
		ret = sqlite3_step(stmt);
		memset(key, 0, SMD_KEY_LENGTH);
		if (ret == SQLITE_ROW)
		{
			metadata_key = sqlite3_column_int64(stmt, 0);
			memcpy(key, &metadata_key, sizeof(metadata_key));
		}
		else
		{
			J_CRITICAL("sql_error %s", sqlite3_errmsg(backend_db));
		}
		sqlite3_finalize(stmt);
	}
	{
		bson_iter_init(&iter, bson);

		while (bson_iter_next(&iter))
		{
			if (strcmp("data_type", bson_iter_key(&iter)) == 0)
			{
				bson_iter_recurse(&iter, &iter_data_type);
				while (bson_iter_next(&iter_data_type))
				{
					if (strcmp("arr", bson_iter_key(&iter_data_type)) == 0)
					{
						bson_iter_recurse(&iter_data_type, &iter_data_arr);
						while (bson_iter_next(&iter_data_arr))
						{
							var_offset = 0;
							var_size = 0;
							var_type = var_type;
							var_name = NULL;
							var_ndims = 0;
							var_dims[0] = 0;
							var_dims[1] = 0;
							var_dims[2] = 0;
							var_dims[3] = 0;
							var_count = 1;
							bson_iter_recurse(&iter_data_arr, &iter_data_var);
							while (bson_iter_next(&iter_data_var))
							{
								if (strcmp("offset", bson_iter_key(&iter_data_var)) == 0)
								{
									var_offset = bson_iter_int32(&iter_data_var);
								}
								else if (strcmp("size", bson_iter_key(&iter_data_var)) == 0)
								{
									var_size = bson_iter_int32(&iter_data_var);
								}
								else if (strcmp("type", bson_iter_key(&iter_data_var)) == 0)
								{
									var_type = bson_iter_int32(&iter_data_var);
								}
								else if (strcmp("ndims", bson_iter_key(&iter_data_var)) == 0)
								{
									var_ndims = bson_iter_int32(&iter_data_var);
								}
								else if (strcmp("name", bson_iter_key(&iter_data_var)) == 0)
								{
									var_name = bson_iter_utf8(&iter_data_var, NULL);
								}
								else if (strcmp("dims", bson_iter_key(&iter_data_var)) == 0)
								{
									bson_iter_recurse(&iter_data_var, &iter_data_dims);
									i = 0;
									while (bson_iter_next(&iter_data_dims) && i < 4)
									{
										var_dims[i] = bson_iter_int32(&iter_data_dims);
										var_count *= var_dims[i];
										i++;
									}
								}
							}

							sqlite3_prepare_v2(backend_db,
								"INSERT INTO smd_types ( meta_key, file_key, name, type, offset, size, count, ndims, dims0, dims1, dims2, dims3) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
								-1, &stmt, NULL);
							sqlite3_bind_int64(stmt, 1, metadata_key);
							sqlite3_bind_int64(stmt, 2, file_key);
							sqlite3_bind_text(stmt, 3, var_name, -1, NULL);
							sqlite3_bind_int(stmt, 4, var_type);
							sqlite3_bind_int(stmt, 5, var_offset);
							sqlite3_bind_int(stmt, 6, var_size);
							sqlite3_bind_int(stmt, 7, var_count);
							sqlite3_bind_int(stmt, 8, var_ndims);
							sqlite3_bind_int(stmt, 9, var_dims[0]);
							sqlite3_bind_int(stmt, 10, var_dims[1]);
							sqlite3_bind_int(stmt, 11, var_dims[2]);
							sqlite3_bind_int(stmt, 12, var_dims[3]);
							ret = sqlite3_step(stmt);
							if (ret != SQLITE_OK)
							{
								J_CRITICAL("sql_error %s", sqlite3_errmsg(backend_db));
							}
							sqlite3_finalize(stmt);
						}
					}
				}
			}
		}
	}
	J_CRITICAL("%s", name);
	return TRUE;
}
static gboolean
backend_attr_open(const char* name, char* parent, bson_t* bson, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 metadata_key = 0;
	bson_t b_datatype[1];
	bson_t b_arr[1];
	bson_t b_var[1];
	bson_t b_dims[1];
	guint i, j;
	char key_buf[16];
	const char* _key;

	J_CRITICAL("%s", name);
	bson_init(bson);
	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key, ndims, dims0, dims1, dims2, dims3 FROM smd WHERE name = ? AND parent_key = ?;", -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, NULL);
	sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
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
	}
	else
	{
		J_CRITICAL("sql_error %s", sqlite3_errmsg(backend_db));
	}
	sqlite3_finalize(stmt);

	sqlite3_prepare_v2(backend_db, "SELECT name, type, offset, size, ndims, dims0, dims1, dims2, dims3 FROM smd_types WHERE meta_key = ? AND file_key = ?;", -1,
		&stmt, NULL);
	sqlite3_bind_int64(stmt, 1, metadata_key);
	sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
	bson_append_document_begin(bson, "data_type", -1, b_datatype);
	bson_append_array_begin(b_datatype, "arr", -1, b_arr);
	i = 0;
	do
	{
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			bson_uint32_to_string(i, &_key, key_buf, sizeof(key_buf));
			bson_append_document_begin(b_arr, _key, -1, b_var);
			bson_append_int32(b_var, "offset", -1, sqlite3_column_int(stmt, 2));
			bson_append_int32(b_var, "size", -1, sqlite3_column_int(stmt, 3));
			bson_append_int32(b_var, "type", -1, sqlite3_column_int(stmt, 1));
			bson_append_utf8(b_var, "name", -1, (const char*)sqlite3_column_text(stmt, 0), -1);
			bson_append_int32(b_var, "ndims", -1, sqlite3_column_int(stmt, 4));
			bson_append_array_begin(b_var, "dims", -1, b_dims);
			for (j = 0; j < 4; j++)
			{
				bson_uint32_to_string(j, &_key, key_buf, sizeof(key_buf));
				bson_append_int32(b_dims, _key, -1, sqlite3_column_int(stmt, 5 + j));
			}
			bson_append_array_end(b_var, b_dims);
			bson_append_document_end(b_arr, b_var);
			i++;
		}
	} while (ret != SQLITE_DONE);
	bson_append_array_end(b_datatype, b_arr);
	bson_append_document_end(bson, b_datatype);

	sqlite3_finalize(stmt);

	J_CRITICAL("%s %s", name, bson_as_json(bson, NULL));
	return TRUE;
}

static gboolean
backend_attr_read(char* key, bson_t* bson)
{
	J_CRITICAL("%d", *((int*)key));
	(void)bson;
	(void)key;
	bson_init(bson);
	J_CRITICAL("%d %s", *((int*)key), bson_as_json(bson, NULL));
	return TRUE;
}
static gboolean
backend_attr_write(char* key, bson_t* bson)
{
	J_CRITICAL("%d %s", *((int*)key), bson_as_json(bson, NULL));
	(void)key;
	(void)bson;
	return TRUE;
}
