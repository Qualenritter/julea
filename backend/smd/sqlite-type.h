static sqlite3_int64
create_type(bson_iter_t* iter_data_type)
{
	sqlite3_stmt* stmt;
	gint ret;
	guint i;
	guint var_ndims;
	guint var_dims[4];
	bson_iter_t iter_data_arr;
	bson_iter_t iter_data_var;
	bson_iter_t iter_data_val;
	bson_iter_t iter_data_dims;
	guint var_offset;
	guint var_size;
	guint var_type;
	guint var_count;
	const char* var_name;
	sqlite3_int64 header_key;
	sqlite3_int64 subtype_key;
	sqlite3_prepare_v2(backend_db,
		"INSERT INTO smd_type_header ( hash ) VALUES(0)",
		-1,
		&stmt, NULL); /*TODO something else here*/
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	}
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "SELECT key FROM smd_type_header WHERE hash = 0", -1, &stmt, NULL);
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
	{
		header_key = sqlite3_column_int64(stmt, 0);
	}
	else
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	}
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "UPDATE smd_type_header SET hash = key where hash = 0", -1, &stmt, NULL);
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	}
	sqlite3_finalize(stmt);
	while (bson_iter_next(iter_data_type))
	{
		if (strcmp("arr", bson_iter_key(iter_data_type)) == 0)
		{
			bson_iter_recurse(iter_data_type, &iter_data_arr);
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
				subtype_key = 0;
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
					else if (strcmp("subtype", bson_iter_key(&iter_data_var)) == 0)
					{
						bson_iter_recurse(&iter_data_var, &iter_data_val);
						subtype_key = create_type(&iter_data_val);
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
					"INSERT INTO smd_types ( header_key, name, type, offset, size, count, ndims, dims0, dims1, dims2, dims3,subtype_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12);",
					-1, &stmt, NULL);
				sqlite3_bind_int64(stmt, 1, header_key);
				sqlite3_bind_text(stmt, 2, var_name, -1, NULL);
				sqlite3_bind_int(stmt, 3, var_type);
				sqlite3_bind_int(stmt, 4, var_offset);
				sqlite3_bind_int(stmt, 5, var_size);
				sqlite3_bind_int(stmt, 6, var_count);
				sqlite3_bind_int(stmt, 7, var_ndims);
				sqlite3_bind_int(stmt, 8, var_dims[0]);
				sqlite3_bind_int(stmt, 9, var_dims[1]);
				sqlite3_bind_int(stmt, 10, var_dims[2]);
				sqlite3_bind_int(stmt, 11, var_dims[3]);
				sqlite3_bind_int64(stmt, 12, subtype_key);
				ret = sqlite3_step(stmt);
				if (ret != SQLITE_DONE)
				{
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				}
				sqlite3_finalize(stmt);
			}
		}
	}
	return header_key;
}
static gboolean
load_type(bson_t* b_datatype, sqlite3_int64 type_key)
{
	J_CRITICAL("load_type %d", type_key);
	sqlite3_stmt* stmt;
	bson_t b_arr[1];
	bson_t b_dims[1];
	bson_t b_var[1];
	bson_t bson1[1];
	gint ret;
	char key_buf[16];
	const char* _key;
	guint i, j;
	sqlite3_prepare_v2(backend_db, "SELECT name, type, offset, size, ndims, dims0, dims1, dims2, dims3, subtype_key FROM smd_types WHERE header_key = ?;", -1,
		&stmt, NULL);
	sqlite3_bind_int64(stmt, 1, type_key);
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
			if (sqlite3_column_int(stmt, 1) == SMD_TYPE_SUB_TYPE)
			{
				bson_append_document_begin(b_var, "subtype", -1, bson1);
				load_type(bson1, sqlite3_column_int(stmt, 9));
				bson_append_document_end(b_var, bson1);
			}
			bson_append_document_end(b_arr, b_var);
			i++;
		}
	} while (ret != SQLITE_DONE);
	bson_append_array_end(b_datatype, b_arr);

	sqlite3_finalize(stmt);
	return TRUE;
}
