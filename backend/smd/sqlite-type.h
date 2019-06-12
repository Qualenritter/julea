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
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "SELECT key FROM smd_type_header WHERE hash = 0", -1, &stmt, NULL);
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
		header_key = sqlite3_column_int64(stmt, 0);
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "UPDATE smd_type_header SET hash = key where hash = 0", -1, &stmt, NULL);
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
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
						var_offset = bson_iter_int32(&iter_data_var);
					else if (strcmp("size", bson_iter_key(&iter_data_var)) == 0)
						var_size = bson_iter_int32(&iter_data_var);
					else if (strcmp("type", bson_iter_key(&iter_data_var)) == 0)
						var_type = bson_iter_int32(&iter_data_var);
					else if (strcmp("ndims", bson_iter_key(&iter_data_var)) == 0)
						var_ndims = bson_iter_int32(&iter_data_var);
					else if (strcmp("name", bson_iter_key(&iter_data_var)) == 0)
						var_name = bson_iter_utf8(&iter_data_var, NULL);
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
				ret = sqlite3_bind_int64(stmt, 1, header_key);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_text(stmt, 2, var_name, -1, NULL);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 3, var_type);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 4, var_offset);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 5, var_size);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 6, var_count);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 7, var_ndims);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 8, var_dims[0]);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 9, var_dims[1]);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 10, var_dims[2]);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 11, var_dims[3]);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 12, subtype_key);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_step(stmt);
				if (ret != SQLITE_DONE)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
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
	ret = sqlite3_bind_int64(stmt, 1, type_key);
	if (ret != SQLITE_OK)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	bson_append_array_begin(b_datatype, "arr", -1, b_arr);
	i = 0;
	do
	{
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			bson_uint32_to_string(i, &_key, key_buf, sizeof(key_buf));
			bson_append_document_begin(b_arr, _key, -1, b_var);
			bson_append_int32(b_var, "offset", -1, sqlite3_column_int64(stmt, 2));
			bson_append_int32(b_var, "size", -1, sqlite3_column_int64(stmt, 3));
			bson_append_int32(b_var, "type", -1, sqlite3_column_int64(stmt, 1));
			bson_append_utf8(b_var, "name", -1, (const char*)sqlite3_column_text(stmt, 0), -1);
			bson_append_int32(b_var, "ndims", -1, sqlite3_column_int64(stmt, 4));
			bson_append_array_begin(b_var, "dims", -1, b_dims);
			for (j = 0; j < 4; j++)
			{
				bson_uint32_to_string(j, &_key, key_buf, sizeof(key_buf));
				bson_append_int32(b_dims, _key, -1, sqlite3_column_int64(stmt, 5 + j));
			}
			bson_append_array_end(b_var, b_dims);
			if (sqlite3_column_int64(stmt, 1) == SMD_TYPE_SUB_TYPE)
			{
				bson_append_document_begin(b_var, "subtype", -1, bson1);
				load_type(bson1, sqlite3_column_int64(stmt, 9));
				bson_append_document_end(b_var, bson1);
			}
			bson_append_document_end(b_arr, b_var);
			i++;
		}
		else if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	} while (ret != SQLITE_DONE);
	bson_append_array_end(b_datatype, b_arr);
	sqlite3_finalize(stmt);
	return TRUE;
}
const char* buf_root;
static gboolean
write_type(sqlite3_int64 type_key, sqlite3_int64 attribute_key, const char* buf, guint buf_offset, guint buf_len, guint struct_size, guint parent_offset)
{
	gint64 value_int;
	gdouble value_float;
	sqlite3_stmt* stmt;
	gint ret;
	const guint buf_end = buf_offset + buf_len;
	const char* location;
	guint array_length;
	guint i, j, k;
	guint offset;
	guint64 offset_local;
	GArray* arr;
	J_SMD_Variable_t* var;
	arr = g_array_new(FALSE, TRUE, sizeof(J_SMD_Variable_t*));
	if (struct_size == 0)
	{
		buf_root = buf;
		sqlite3_prepare_v2(backend_db, "SELECT t.size, t.offset, t.ndims, t.dims0, t.dims1, t.dims2, t.dims3 FROM smd_types t WHERE header_key = ?1 ORDER BY t.offset DESC LIMIT 1", -1, &stmt, NULL);
		ret = sqlite3_bind_int64(stmt, 1, type_key);
		if (ret != SQLITE_OK)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			struct_size = sqlite3_column_int64(stmt, 0);
			for (i = 0; i < sqlite3_column_int64(stmt, 2); i++)
				struct_size *= sqlite3_column_int64(stmt, 3 + i);
			struct_size += sqlite3_column_int64(stmt, 1);
		}
		else
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		sqlite3_finalize(stmt);
	}
	sqlite3_prepare_v2(backend_db, "SELECT t.type, t.offset, t.size, t.ndims, t.dims0, t.dims1, t.dims2, t.dims3, t.subtype_key FROM smd_types t WHERE header_key = ?1 ORDER BY t.offset;", -1, &stmt, NULL);
	ret = sqlite3_bind_int64(stmt, 1, type_key);
	if (ret != SQLITE_OK)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	do
	{
		ret = sqlite3_step(stmt);
		if (ret == SQLITE_ROW)
		{
			var = g_new(J_SMD_Variable_t, 1);
			var->offset = sqlite3_column_int64(stmt, 1);
			var->size = sqlite3_column_int64(stmt, 2);
			var->type = sqlite3_column_int64(stmt, 0);
			var->space.ndims = sqlite3_column_int64(stmt, 3);
			var->space.dims[0] = sqlite3_column_int64(stmt, 4);
			var->space.dims[1] = sqlite3_column_int64(stmt, 5);
			var->space.dims[2] = sqlite3_column_int64(stmt, 6);
			var->space.dims[3] = sqlite3_column_int64(stmt, 7);
			(*((sqlite3_int64*)var->sub_type_key)) = sqlite3_column_int64(stmt, 8);
			g_array_append_val(arr, var);
		}
		else if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	} while (ret != SQLITE_DONE);
	sqlite3_finalize(stmt);
	for (i = 0; i < arr->len; i++)
	{
		var = g_array_index(arr, J_SMD_Variable_t*, i);
		array_length = var->space.dims[0];
		for (j = 1; j < var->space.ndims; j++)
			array_length *= var->space.dims[j];
		offset = var->offset;
		while (offset < buf_offset)
			offset += struct_size; /*TODO faster required???*/
		k = 0;
		while (offset + var->size < buf_end)
		{
			offset_local = offset;
			for (j = 0; j < array_length; j++)
			{
				/*only write complete objects TODO maybe allow writing of half variables?*/

				sqlite3_prepare_v2(backend_db, "INSERT INTO smd_attributes (attribute_key,type_key,offset,value_int,value_float,value_text,value_blob) VALUES (?1,?2,?3,?4,?5,?6,?7)", -1, &stmt, NULL);
				ret = sqlite3_bind_int64(stmt, 1, attribute_key);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				ret = sqlite3_bind_int64(stmt, 2, type_key);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));

				ret = sqlite3_bind_int64(stmt, 3, offset_local + parent_offset + j * var->size);
				if (ret != SQLITE_OK)
					J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
				location = buf + offset_local - buf_offset + parent_offset + j * var->size;
				J_DEBUG("location read : %ld displayed : %d", location - buf_root, offset_local + parent_offset + j * var->size);
				switch (var->type)
				{
				case SMD_TYPE_INT:
				{
					switch (var->size)
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
						J_CRITICAL("this should never happen type=%d", var->type);
					}
					value_float = value_int;
					ret = sqlite3_bind_int64(stmt, 4, value_int);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_bind_double(stmt, 5, value_float);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_bind_null(stmt, 6);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_bind_null(stmt, 7);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_step(stmt);
					if (ret != SQLITE_DONE)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					sqlite3_finalize(stmt);
				}
				break;
				case SMD_TYPE_FLOAT:
				{
					switch (var->size)
					{
					case 8:
						value_float = *((const gdouble*)location);
						break;
					case 4:
						value_float = *((const gfloat*)location);
						break;
					default:
						J_CRITICAL("this should never happen type=%d", var->type);
					}
					value_int = value_float;
					ret = sqlite3_bind_int64(stmt, 4, value_int);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_bind_double(stmt, 5, value_float);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_bind_null(stmt, 6);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_bind_null(stmt, 7);
					if (ret != SQLITE_OK)
					{
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
						exit(0);
					}
					ret = sqlite3_step(stmt);
					if (ret != SQLITE_DONE)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					sqlite3_finalize(stmt);
				}
				break;
				case SMD_TYPE_BLOB:
				{
					ret = sqlite3_bind_null(stmt, 4);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_bind_null(stmt, 5);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_bind_text(stmt, 6, location, strnlen_s(location, var->size), NULL);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_bind_blob(stmt, 7, location, var->size, NULL);
					if (ret != SQLITE_OK)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					ret = sqlite3_step(stmt);
					if (ret != SQLITE_DONE)
						J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
					sqlite3_finalize(stmt);
				}
				break;
				case SMD_TYPE_SUB_TYPE:
					if ((k == 0)) /*subtypes calculate the offset themselves - only call them once*/
					{
						guint calc_offset;
						calc_offset = location - buf;
						write_type(*((sqlite3_int64*)var->sub_type_key), attribute_key, buf, buf_offset, buf_len, struct_size, parent_offset + calc_offset);
					}
					break;
				default:
					J_CRITICAL("this should never happen type=%d", var->type);
				}
				//	offset_local += var->size;
			}
			offset += struct_size;
			k++;
		}
	}
	for (i = 0; i < arr->len; i++)
		g_free(g_array_index(arr, J_SMD_Variable_t*, i));
	return TRUE;
}
