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
	const char* var_name;
	guint header_key = 0;
	sqlite3_int64 subtype_key = 0;
	j_smd_timer_start(create_type);
	header_key = g_atomic_int_add(&smd_scheme_type_primary_key, 1);
	j_sqlite3_bind_int64(stmt_type_create_header, 1, header_key);
	j_sqlite3_step_and_reset_check_done(stmt_type_create_header);
	while (bson_iter_next(iter_data_type))
	{
		if (strcmp("arr", bson_iter_key(iter_data_type)) == 0)
		{
			bson_iter_recurse(iter_data_type, &iter_data_arr);
			while (bson_iter_next(&iter_data_arr))
			{
				var_offset = 0;
				var_size = 0;
				var_type = 0;
				var_name = NULL;
				var_ndims = 0;
				var_dims[0] = 0;
				var_dims[1] = 0;
				var_dims[2] = 0;
				var_dims[3] = 0;
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
						j_smd_timer_stop(create_type);
						subtype_key = create_type(&iter_data_val);
						j_smd_timer_start(create_type);
					}
					else if (strcmp("dims", bson_iter_key(&iter_data_var)) == 0)
					{
						bson_iter_recurse(&iter_data_var, &iter_data_dims);
						for (i = 0; bson_iter_next(&iter_data_dims) && i < 4; i++)
						{
							var_dims[i] = bson_iter_int32(&iter_data_dims);
						}
					}
				}
				j_smd_timer_start(create_type_sql);
				j_sqlite3_bind_int64(stmt_type_create, 1, header_key);
				j_sqlite3_bind_text(stmt_type_create, 2, var_name, -1);
				j_sqlite3_bind_int64(stmt_type_create, 3, var_type);
				j_sqlite3_bind_int64(stmt_type_create, 4, var_offset);
				j_sqlite3_bind_int64(stmt_type_create, 5, var_size);
				j_sqlite3_bind_int64(stmt_type_create, 6, var_ndims);
				j_sqlite3_bind_int64(stmt_type_create, 7, var_dims[0]);
				j_sqlite3_bind_int64(stmt_type_create, 8, var_dims[1]);
				j_sqlite3_bind_int64(stmt_type_create, 9, var_dims[2]);
				j_sqlite3_bind_int64(stmt_type_create, 10, var_dims[3]);
				if (var_type != SMD_TYPE_SUB_TYPE)
					j_sqlite3_bind_null(stmt_type_create, 11);
				else
					j_sqlite3_bind_int64(stmt_type_create, 11, subtype_key);
				j_sqlite3_step_and_reset_check_done(stmt_type_create);
				j_smd_timer_stop(create_type_sql);
			}
		}
	}
	j_smd_timer_stop(create_type);
	return header_key;
}
static gboolean
load_type(bson_t* b_datatype, sqlite3_int64 type_key)
{
	bson_t b_arr[1];
	bson_t b_dims[1];
	bson_t b_var[1];
	bson_t bson1[1];
	gint ret;
	char key_buf[16];
	const char* _key;
	guint i, j;
	guint next_offset = 0;
	sqlite3_int64 subtype_key;
	j_smd_timer_start(load_type);
	bson_append_array_begin(b_datatype, "arr", -1, b_arr);
	i = 0;
_start:
	j_sqlite3_bind_int64(stmt_type_load, 1, type_key);
	j_sqlite3_bind_int64(stmt_type_load, 2, next_offset);
	do
	{
		j_smd_timer_start(load_type_sql);
		ret = sqlite3_step(stmt_type_load);
		j_smd_timer_stop(load_type_sql);
		if (ret == SQLITE_ROW)
		{
			bson_uint32_to_string(i, &_key, key_buf, sizeof(key_buf));
			i++;
			bson_append_document_begin(b_arr, _key, -1, b_var);
			bson_append_int32(b_var, "offset", -1, sqlite3_column_int64(stmt_type_load, 2));
			next_offset = 1 + sqlite3_column_int64(stmt_type_load, 2);
			bson_append_int32(b_var, "size", -1, sqlite3_column_int64(stmt_type_load, 3));
			bson_append_int32(b_var, "type", -1, sqlite3_column_int64(stmt_type_load, 1));
			bson_append_utf8(b_var, "name", -1, (const char*)sqlite3_column_text(stmt_type_load, 0), -1);
			bson_append_int32(b_var, "ndims", -1, sqlite3_column_int64(stmt_type_load, 4));
			bson_append_array_begin(b_var, "dims", -1, b_dims);
			for (j = 0; j < 4; j++)
			{
				bson_uint32_to_string(j, &_key, key_buf, sizeof(key_buf));
				bson_append_int32(b_dims, _key, -1, sqlite3_column_int64(stmt_type_load, 5 + j));
			}
			bson_append_array_end(b_var, b_dims);
			if (sqlite3_column_int64(stmt_type_load, 1) == SMD_TYPE_SUB_TYPE)
			{
				bson_append_document_begin(b_var, "subtype", -1, bson1);
				subtype_key = sqlite3_column_int64(stmt_type_load, 9);
				j_sqlite3_reset(stmt_type_load);
				j_smd_timer_stop(load_type);
				load_type(bson1, subtype_key);
				j_smd_timer_start(load_type);
				bson_append_document_end(b_var, bson1);
				bson_append_document_end(b_arr, b_var);
				goto _start;
			}
			bson_append_document_end(b_arr, b_var);
		}
		else if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	} while (ret != SQLITE_DONE);
	bson_append_array_end(b_datatype, b_arr);
	j_sqlite3_reset(stmt_type_load);
	j_smd_timer_stop(load_type);
	return TRUE;
}
static guint
calculate_struct_size(sqlite3_int64 type_key)
{
	gint ret;
	guint i;
	guint struct_size;
	j_smd_timer_start(calculate_struct_size);
	j_sqlite3_bind_int64(stmt_type_struct_size, 1, type_key);
	ret = sqlite3_step(stmt_type_struct_size);
	if (ret == SQLITE_ROW)
	{
		struct_size = sqlite3_column_int64(stmt_type_struct_size, 0);
		for (i = 0; i < sqlite3_column_int64(stmt_type_struct_size, 2); i++)
			struct_size *= sqlite3_column_int64(stmt_type_struct_size, 3 + i);
		struct_size += sqlite3_column_int64(stmt_type_struct_size, 1);
	}
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	j_sqlite3_reset(stmt_type_struct_size);
	j_smd_timer_stop(calculate_struct_size);
	return struct_size;
}
static GArray*
get_type_structure(sqlite3_int64 type_key)
{
	GArray* arr;
	gint ret;
	J_SMD_Variable_t* var;
	j_smd_timer_start(get_type_structure);
	arr = g_array_new(FALSE, TRUE, sizeof(J_SMD_Variable_t*));
	j_sqlite3_bind_int64(stmt_type_write_get_structure, 1, type_key);
	do
	{
		ret = sqlite3_step(stmt_type_write_get_structure);
		if (ret == SQLITE_ROW)
		{
			var = g_new(J_SMD_Variable_t, 1);
			var->offset = sqlite3_column_int64(stmt_type_write_get_structure, 1);
			var->size = sqlite3_column_int64(stmt_type_write_get_structure, 2);
			var->type = sqlite3_column_int64(stmt_type_write_get_structure, 0);
			var->space.ndims = sqlite3_column_int64(stmt_type_write_get_structure, 3);
			var->space.dims[0] = sqlite3_column_int64(stmt_type_write_get_structure, 4);
			var->space.dims[1] = sqlite3_column_int64(stmt_type_write_get_structure, 5);
			var->space.dims[2] = sqlite3_column_int64(stmt_type_write_get_structure, 6);
			var->space.dims[3] = sqlite3_column_int64(stmt_type_write_get_structure, 7);
			if (var->type == SMD_TYPE_SUB_TYPE)
				(*((sqlite3_int64*)var->sub_type_key)) = sqlite3_column_int64(stmt_type_write_get_structure, 8);
			else
				(*((sqlite3_int64*)var->sub_type_key)) = sqlite3_column_int64(stmt_type_write_get_structure, 9);
			g_array_append_val(arr, var);
		}
		else if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	} while (ret != SQLITE_DONE);
	j_sqlite3_reset(stmt_type_write_get_structure);
	j_smd_timer_stop(get_type_structure);
	return arr;
}
static gboolean
write_type(sqlite3_int64 type_key, sqlite3_int64 scheme_key, const char* buf, guint buf_offset, guint buf_len, guint struct_size, guint parent_offset)
{
	gint64 value_int = 0;
	gdouble value_float = 0;
	const guint buf_end = buf_offset + buf_len;
	const char* location;
	guint array_length;
	guint i, j, k;
	guint offset;
	guint64 offset_local;
	GArray* arr;
	J_SMD_Variable_t* var;
	j_smd_timer_start(write_type);
	if (struct_size == 0)
		struct_size = calculate_struct_size(type_key);
	arr = get_type_structure(type_key);
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
		while (offset + var->size <= buf_end)
		{
			offset_local = offset;
			for (j = 0; j < array_length; j++)
			{
				/*TODO upsert faster than replace ?!? https://www.sqlite.org/lang_UPSERT.html*/
				j_sqlite3_bind_int64(stmt_type_write, 1, scheme_key);
				j_sqlite3_bind_int64(stmt_type_write, 2, (*((sqlite3_int64*)var->sub_type_key)));
				j_sqlite3_bind_int64(stmt_type_write, 3, offset_local + parent_offset + j * var->size);
				location = buf + offset_local - buf_offset + parent_offset + j * var->size;
				switch (var->type)
				{
				case SMD_TYPE_INT:
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
					j_sqlite3_bind_int64(stmt_type_write, 4, value_int);
					j_sqlite3_bind_double(stmt_type_write, 5, value_float);
					j_sqlite3_bind_null(stmt_type_write, 6);
					j_sqlite3_bind_null(stmt_type_write, 7);
					j_sqlite3_step_and_reset_check_done(stmt_type_write);
					break;
				case SMD_TYPE_FLOAT:
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
					j_sqlite3_bind_int64(stmt_type_write, 4, value_int);
					j_sqlite3_bind_double(stmt_type_write, 5, value_float);
					j_sqlite3_bind_null(stmt_type_write, 6);
					j_sqlite3_bind_null(stmt_type_write, 7);
					j_sqlite3_step_and_reset_check_done(stmt_type_write);
					break;
				case SMD_TYPE_BLOB:
					j_sqlite3_bind_null(stmt_type_write, 4);
					j_sqlite3_bind_null(stmt_type_write, 5);
					j_sqlite3_bind_text(stmt_type_write, 6, location, strnlen_s(location, var->size));
					j_sqlite3_bind_blob(stmt_type_write, 7, location, var->size);
					j_sqlite3_step_and_reset_check_done(stmt_type_write);
					break;
				case SMD_TYPE_SUB_TYPE:
					if ((k == 0)) /*subtypes calculate the offset themselves - only call them once*/
					{
						guint calc_offset;
						calc_offset = location - buf;
						j_smd_timer_stop(write_type);
						write_type(*((sqlite3_int64*)var->sub_type_key), scheme_key, buf, buf_offset, buf_len, struct_size, parent_offset + calc_offset);
						j_smd_timer_start(write_type);
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
	j_smd_timer_stop(write_type);
	return TRUE;
}
static gboolean
read_type(sqlite3_int64 scheme_key, char* buf, guint buf_offset, guint buf_len)
{
	gint ret;
	char* location;
	guint64 offset;
	j_smd_timer_start(read_type);
	j_sqlite3_bind_int64(stmt_type_read, 1, scheme_key);
	j_sqlite3_bind_int64(stmt_type_read, 2, buf_offset);
	j_sqlite3_bind_int64(stmt_type_read, 3, buf_offset + buf_len);
	do
	{
		ret = sqlite3_step(stmt_type_read);
		if (ret == SQLITE_ROW)
		{
			offset = sqlite3_column_int64(stmt_type_read, 0) - buf_offset;
			location = buf + offset;
			switch (sqlite3_column_int64(stmt_type_read, 4))
			{
			case SMD_TYPE_INT:
				switch (sqlite3_column_int64(stmt_type_read, 5))
				{ /*TODO signed|unsigned*/
				case 8:
					*((gint64*)location) = sqlite3_column_int64(stmt_type_read, 1);
					break;
				case 4:
					*((gint32*)location) = sqlite3_column_int64(stmt_type_read, 1);
					break;
				case 2:
					*((gint16*)location) = sqlite3_column_int64(stmt_type_read, 1);
					break;
				case 1:
					*((gint8*)location) = sqlite3_column_int64(stmt_type_read, 1);
					break;
				default:
					J_CRITICAL("this should never happen type=%lld", sqlite3_column_int64(stmt_type_read, 5));
				}
				break;
			case SMD_TYPE_FLOAT:
				switch (sqlite3_column_int64(stmt_type_read, 5))
				{
				case 8:
					*((gdouble*)location) = sqlite3_column_double(stmt_type_read, 1);
					break;
				case 4:
					*((gfloat*)location) = sqlite3_column_double(stmt_type_read, 1);
					break;
				default:
					J_CRITICAL("this should never happen type=%lld", sqlite3_column_int64(stmt_type_read, 5));
				}
				break;
			case SMD_TYPE_BLOB:
				memcpy(location, sqlite3_column_blob(stmt_type_read, 7), sqlite3_column_int64(stmt_type_read, 5));
				break;
			default:
				J_CRITICAL("this should never happen type=%lld", sqlite3_column_int64(stmt_type_read, 5));
			}
		}
		else if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	} while (ret != SQLITE_DONE);
	j_sqlite3_reset(stmt_type_read);
	j_smd_timer_stop(read_type);
	return TRUE;
}
