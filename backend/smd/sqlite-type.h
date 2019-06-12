static guint64
strnlen_s(const char* b, guint64 maxlen)
{
	guint64 len = 0;
	if (!b)
		return 0;
	while (*b && len < maxlen)
		len++;
	return len;
}

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

	sqlite3_prepare_v2(backend_db, "INSERT INTO smd_type_header ( hash ) VALUES(0)", -1, &stmt, NULL); /*TODO something else here*/
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
				sqlite3_prepare_v2(backend_db, "INSERT INTO smd_types ( header_key, name, type, offset, size, count, ndims, dims0, dims1, dims2, dims3,subtype_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12);", -1, &stmt, NULL);
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
	sqlite3_stmt* stmt;
	bson_t b_arr[1];
	bson_t b_dims[1];
	bson_t b_var[1];
	bson_t bson1[1];
	gint ret;
	char key_buf[16];
	const char* _key;
	guint i, j;
	sqlite3_prepare_v2(backend_db, "SELECT name, type, offset, size, ndims, dims0, dims1, dims2, dims3, subtype_key FROM smd_types WHERE header_key = ?;", -1, &stmt, NULL);
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
		else if (ret != SQLITE_DONE)
		{
			return FALSE;
		}
	} while (ret != SQLITE_DONE);
	bson_append_array_end(b_datatype, b_arr);

	sqlite3_finalize(stmt);
	return TRUE;
}
static gboolean
write_type(sqlite3_int64 type_key, sqlite3_int64 attribute_key, const char* buf, guint buf_offset, guint buf_len, guint struct_size)
{
	gint64 value_int;
	gdouble value_float;
	sqlite3_int64 subtype_key;
	sqlite3_stmt* stmt_structure;
	sqlite3_stmt* stmt_data;
	sqlite3_stmt* stmt_size;
	gint ret;
	const guint buf_end = buf_offset + buf_len;
	const char* location;
	guint array_length;
	guint i;
	guint offset;
	guint offset_local;
	J_SMD_Variable_t var;
	if (struct_size == 0)
	{
		sqlite3_prepare_v2(backend_db, "SELECT t.size, t.offset, t.ndims, t.dims0, t.dims1, t.dims2, t.dims3 WHERE header_key = ?1 ORDER BY t.offset DESC LIMIT 1", -1, &stmt_size, NULL);
		sqlite3_bind_int64(stmt_size, 1, type_key);
		sqlite3_bind_int(stmt_size, 2, struct_size);
		ret = sqlite3_step(stmt_size);
		if (ret == SQLITE_ROW)
		{
			struct_size = sqlite3_column_int64(stmt_size, 0);
			for (i = 0; i < sqlite3_column_int64(stmt_size, 2); i++)
			{
				struct_size *= sqlite3_column_int64(stmt_size, 3 + i);
			}
			struct_size += sqlite3_column_int64(stmt_size, 1);
		}
		else
		{
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		}
		sqlite3_finalize(stmt_size);
	}
	sqlite3_prepare_v2(backend_db, "SELECT t.type, t.offset, t.size, t.ndims, t.dims0, t.dims1, t.dims2, t.dims3, t.subtype_key FROM smd_types t WHERE header_key = ?1 ORDER BY t.offset;", -1, &stmt_structure, NULL);
	sqlite3_bind_int64(stmt_structure, 1, type_key);
	sqlite3_prepare_v2(backend_db, "INSERT INTO smd_attributes (attribute_key,type_key,offset,value_int,value_float,value_text,value_blob) VALUES (?,?,?,?,?,?,?)", -1, &stmt_data, NULL);
	sqlite3_bind_int64(stmt_data, 1, attribute_key);
	sqlite3_bind_int64(stmt_data, 2, type_key);
	do
	{
		ret = sqlite3_step(stmt_structure);
		if (ret == SQLITE_ROW)
		{
			var.offset = sqlite3_column_int(stmt_structure, 1);
			var.size = sqlite3_column_int(stmt_structure, 2);
			var.type = sqlite3_column_int(stmt_structure, 0);
			var.space.ndims = sqlite3_column_int(stmt_structure, 3);
			var.space.dims[0] = sqlite3_column_int(stmt_structure, 4);
			var.space.dims[1] = sqlite3_column_int(stmt_structure, 5);
			var.space.dims[2] = sqlite3_column_int(stmt_structure, 6);
			var.space.dims[3] = sqlite3_column_int(stmt_structure, 7);
			subtype_key = sqlite3_column_int64(stmt_structure, 8);
			array_length = var.space.dims[0];
			for (i = 1; i < var.space.ndims; i++)
			{
				array_length *= var.space.dims[1];
			}
			offset = var.offset;
			while (offset < buf_offset)
				offset += struct_size; /*TODO faster required???*/

			while (offset + var.size < buf_end)
			{
				offset_local = offset;
				for (i = 0; i < array_length; i++)
				{
					/*only write complete objects TODO maybe allow writing of half variables?*/
					sqlite3_bind_int64(stmt_data, 3, offset_local);
					location = buf + offset_local - buf_offset;
					switch (var.type)
					{
					case SMD_TYPE_INT:
					{
						switch (var.size)
						{ /*TODO signed|unsigned*/
						case 8:
							value_int = *((const gint64*)location);
							break;
						case 4:
							value_int = *((const gint32*)location);
							break;
						case 2:
							value_int = *((const gint16*)location);
							break;
						case 1:
							value_int = *((const gint8*)location);
							break;
						default:
						{
							J_CRITICAL("this should never happen type=%d", var.type);
						}
							value_float = value_int;
						}
						sqlite3_bind_int64(stmt_data, 4, value_int);
						sqlite3_bind_int64(stmt_data, 5, value_float);
						sqlite3_bind_null(stmt_data, 6);
						sqlite3_bind_null(stmt_data, 7);
						ret = sqlite3_step(stmt_data);
					}
					break;
					case SMD_TYPE_FLOAT:
					{
						switch (var.size)
						{
						case 8:
							value_float = *((const gdouble*)location);
							break;
						case 4:
							value_float = *((const gfloat*)location);
							break;
						default:
						{
							J_CRITICAL("this should never happen type=%d", var.type);
						}
						}
						value_int = value_float;
						sqlite3_bind_int64(stmt_data, 4, value_int);
						sqlite3_bind_int64(stmt_data, 5, value_float);
						sqlite3_bind_null(stmt_data, 6);
						sqlite3_bind_null(stmt_data, 7);
						ret = sqlite3_step(stmt_data);
					}
					break;
					case SMD_TYPE_BLOB:
					{
						sqlite3_bind_null(stmt_data, 4);
						sqlite3_bind_null(stmt_data, 5);
						sqlite3_bind_text(stmt_data, 6, location, strnlen_s(location, var.size), NULL);
						sqlite3_bind_blob(stmt_data, 7, location, var.size, NULL);
						ret = sqlite3_step(stmt_data);
					}
					break;
					case SMD_TYPE_SUB_TYPE:
					{

						write_type(subtype_key, attribute_key, buf, buf_offset, buf_len, struct_size);
					}
					break;
					default:
					{
						J_CRITICAL("this should never happen type=%d", var.type);
					}
					}
					if (ret != SQLITE_DONE)
					{
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					}
					offset_local += var.size;
				}
				offset += struct_size;
			}
		}
		else if (ret != SQLITE_DONE)
		{
			return FALSE;
		}
	} while (ret != SQLITE_DONE);

	sqlite3_finalize(stmt_data);
	sqlite3_finalize(stmt_structure);
	return TRUE;
}
