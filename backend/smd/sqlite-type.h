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
create_type(const J_SMD_Variable_t* type)
{
	const J_SMD_Variable_t* var = type;
	gint ret;
	guint header_key = 0;
	sqlite3_int64 subtype_key;
	j_smd_timer_start(create_type);
	header_key = g_atomic_int_add(&smd_scheme_type_primary_key, 1);
	j_sqlite3_bind_int64(stmt_type_create_header, 1, header_key);
	j_sqlite3_step_and_reset_check_done(stmt_type_create_header);
start:
	subtype_key = 0;
	if (var->type == SMD_TYPE_SUB_TYPE)
	{
		j_smd_timer_stop(create_type);
		subtype_key = create_type(var + var->subtypeindex); //TODO unroll recoursion of this function
		if (!subtype_key)
			return 0;
		j_smd_timer_start(create_type);
	}
	j_smd_timer_start(create_type_sql);
	j_sqlite3_bind_int64(stmt_type_create, 1, header_key);
	j_sqlite3_bind_text(stmt_type_create, 2, var->name, -1);
	j_sqlite3_bind_int64(stmt_type_create, 3, var->type);
	j_sqlite3_bind_int64(stmt_type_create, 4, var->offset);
	j_sqlite3_bind_int64(stmt_type_create, 5, var->size);
	j_sqlite3_bind_int64(stmt_type_create, 6, var->space.ndims);
	j_sqlite3_bind_int64(stmt_type_create, 7, var->space.dims[0]);
	j_sqlite3_bind_int64(stmt_type_create, 8, var->space.dims[1]);
	j_sqlite3_bind_int64(stmt_type_create, 9, var->space.dims[2]);
	j_sqlite3_bind_int64(stmt_type_create, 10, var->space.dims[3]);
	if (var->type != SMD_TYPE_SUB_TYPE)
		j_sqlite3_bind_null(stmt_type_create, 11);
	else
		j_sqlite3_bind_int64(stmt_type_create, 11, subtype_key);
	ret = sqlite3_step(stmt_type_create);
	if (ret == SQLITE_CONSTRAINT)
		return 0;
	else
		_j_done_check(ret);
	j_sqlite3_reset(stmt_type_create);
	j_smd_timer_stop(create_type_sql);
	if (var->nextindex)
	{
		var += var->nextindex;
		goto start;
	}
	j_smd_timer_stop(create_type);
	return header_key;
}
static gboolean
load_type(J_SMD_Type_t* type, sqlite3_int64 type_key)
{
	J_SMD_Type_t* subtype;
	J_SMD_Variable_t var;
	gint ret;
	guint next_offset = 0;
	sqlite3_int64 subtype_key;
	j_smd_timer_start(load_type);
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
			var.space.dims[0] = sqlite3_column_int64(stmt_type_load, 5);
			var.space.dims[1] = sqlite3_column_int64(stmt_type_load, 6);
			var.space.dims[2] = sqlite3_column_int64(stmt_type_load, 7);
			var.space.dims[3] = sqlite3_column_int64(stmt_type_load, 8);
			strcpy(var.name, (const char*)sqlite3_column_text(stmt_type_load, 0));
			var.space.ndims = sqlite3_column_int64(stmt_type_load, 4);
			var.size = sqlite3_column_int64(stmt_type_load, 3);
			var.offset = sqlite3_column_int64(stmt_type_load, 2);
			var.type = sqlite3_column_int64(stmt_type_load, 1);
			if (var.type != SMD_TYPE_SUB_TYPE)
			{
				j_smd_type_add_atomic_type(type, var.name, var.offset, var.size, var.type, var.space.ndims, var.space.dims);
			}
			else
			{
				next_offset = 1 + sqlite3_column_int64(stmt_type_load, 2);
				subtype_key = sqlite3_column_int64(stmt_type_load, 9);
				j_sqlite3_reset(stmt_type_load);
				j_smd_timer_stop(load_type);
				subtype = j_smd_type_create();
				load_type(subtype, subtype_key);
				j_smd_timer_start(load_type);
				j_smd_type_add_compound_type(type, var.name, var.offset, var.size, subtype, var.space.ndims, var.space.dims);
				j_smd_type_unref(subtype);
				goto _start;
			}
		}
		else if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	} while (ret != SQLITE_DONE);
	j_sqlite3_reset(stmt_type_load);
	j_smd_timer_stop(load_type);
	return TRUE;
}
static guint
calculate_struct_size(sqlite3_int64 type_key)
{
	gint ret;
	guint i;
	guint struct_size = 0;
	j_smd_timer_start(calculate_struct_size);
	j_sqlite3_bind_int64(stmt_type_struct_size, 1, type_key);
	ret = sqlite3_step(stmt_type_struct_size);
	if (ret == SQLITE_ROW)
	{
		struct_size = sqlite3_column_int64(stmt_type_struct_size, 0);
		for (i = 0; i < sqlite3_column_int64(stmt_type_struct_size, 2); i++)
		{
			struct_size *= sqlite3_column_int64(stmt_type_struct_size, 3 + i);
		}
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
write_type(sqlite3_int64 type_key, sqlite3_int64 scheme_key, const char* buf, guint buf_offset, guint buf_len, guint struct_size, guint type_offset)
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
		{
			offset += struct_size; /*TODO faster required???*/
		}
		k = 0;
		while (offset + var->size <= buf_end)
		{
			offset_local = offset;
			for (j = 0; j < array_length; j++)
			{
				j_sqlite3_bind_int64(stmt_type_write, 1, scheme_key);
				j_sqlite3_bind_int64(stmt_type_write, 2, (*((sqlite3_int64*)var->sub_type_key)));
				j_sqlite3_bind_int64(stmt_type_write, 3, offset_local + j * var->size + type_offset);
				location = buf + offset_local - buf_offset + j * var->size + type_offset;
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
						j_smd_timer_stop(write_type);
						write_type(*((sqlite3_int64*)var->sub_type_key), scheme_key, buf, buf_offset, buf_len, struct_size, type_offset + var->offset);
						j_smd_timer_start(write_type);
					}
					break;
				case _SMD_TYPE_COUNT:
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
