static gboolean
backend_scheme_delete(const char* name, char* parent)
{
	GArray* arr;
	guint i;
	guint ret;
	sqlite3_int64 tmp;
	arr = g_array_new(FALSE, FALSE, sizeof(sqlite3_int64)); //TODO cache array
	j_smd_timer_start(backend_scheme_delete);
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_text(stmt_scheme_delete0, 1, name, -1);
	j_sqlite3_bind_int64(stmt_scheme_delete0, 2, *((sqlite3_int64*)parent));
	do
	{
		ret = sqlite3_step(stmt_scheme_delete0);
		if (ret == SQLITE_ROW)
		{
			tmp = sqlite3_column_int64(stmt_scheme_delete0, 0);
			g_array_append_val(arr, tmp);
		}
		else if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	} while (ret != SQLITE_DONE);
	j_sqlite3_reset(stmt_scheme_delete0);
	j_sqlite3_bind_text(stmt_scheme_delete1, 1, name, -1);
	j_sqlite3_bind_int64(stmt_scheme_delete1, 2, *((sqlite3_int64*)parent));
	j_sqlite3_step_and_reset_check_done(stmt_scheme_delete1);
	for (i = 0; i < arr->len; i++)
	{
		j_sqlite3_bind_int64(stmt_type_delete, 1, g_array_index(arr, sqlite3_int64, i));
		j_sqlite3_step_and_reset_check_done_constraint(stmt_type_delete);
	}
	j_sqlite3_transaction_commit();
	j_smd_timer_stop(backend_scheme_delete);
	g_array_free(arr, TRUE);
	return TRUE;
}
static gboolean
backend_scheme_create(const char* name, char* parent, bson_t* bson, guint distribution, char* key)
{
	sqlite3_int64 scheme_key = 0;
	sqlite3_int64 type_key = 0;
	bson_iter_t iter;
	bson_iter_t iter_space_type;
	guint var_ndims;
	guint var_dims[4];
	bson_iter_t iter_data_type;
	bson_iter_t iter_data_dims;
	guint i;
	guint ret;
	memset(key, 0, SMD_KEY_LENGTH);
	j_smd_timer_start(backend_scheme_create);
	j_sqlite3_transaction_begin();
	bson_iter_init(&iter, bson);
	var_ndims = 0;
	var_dims[0] = 0;
	var_dims[1] = 0;
	var_dims[2] = 0;
	var_dims[3] = 0;
	{ // extract ndims,dims,distribution
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
	scheme_key = g_atomic_int_add(&smd_schemes_primary_key, 1);
	j_sqlite3_bind_text(stmt_scheme_create, 1, name, -1);
	j_sqlite3_bind_int(stmt_scheme_create, 2, SMD_METATYPE_DATA);
	j_sqlite3_bind_int64(stmt_scheme_create, 3, *((sqlite3_int64*)parent));
	j_sqlite3_bind_int(stmt_scheme_create, 4, var_ndims);
	j_sqlite3_bind_int(stmt_scheme_create, 5, var_dims[0]);
	j_sqlite3_bind_int(stmt_scheme_create, 6, var_dims[1]);
	j_sqlite3_bind_int(stmt_scheme_create, 7, var_dims[2]);
	j_sqlite3_bind_int(stmt_scheme_create, 8, var_dims[3]);
	j_sqlite3_bind_int(stmt_scheme_create, 9, distribution);
	j_sqlite3_bind_int64(stmt_scheme_create, 10, type_key);
	j_sqlite3_bind_int64(stmt_scheme_create, 11, scheme_key);
	ret = sqlite3_step(stmt_scheme_create);
	if (ret == SQLITE_DONE)
	{
		ret = sqlite3_reset(stmt_scheme_create);
		_j_ok_check(ret);
		memcpy(key, &scheme_key, sizeof(scheme_key));
		j_sqlite3_transaction_commit();
	}
	else if (ret == SQLITE_CONSTRAINT)
	{
		ret = sqlite3_reset(stmt_scheme_create);
		_j_ok_constraint_check(ret);
		j_sqlite3_transaction_abort();
		J_CRITICAL("create scheme failed %s %lld", name, *((sqlite3_int64*)parent));
		return FALSE;
	}
	else
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		exit(1);
	}
	j_smd_timer_stop(backend_scheme_create);
	return TRUE;
}
static gboolean
backend_scheme_open(const char* name, char* parent, bson_t* bson, guint* distribution, char* key)
{
	bson_t b_datatype[1];
	gint ret;
	sqlite3_int64 scheme_key = 0;
	sqlite3_int64 type_key = 0;
	bson_t b_arr[1];
	char key_buf[16];
	const char* _key;
	bson_init(bson);
	j_smd_timer_start(backend_scheme_open);
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_text(stmt_scheme_open, 1, name, -1);
	j_sqlite3_bind_int64(stmt_scheme_open, 2, *((sqlite3_int64*)parent));
	ret = sqlite3_step(stmt_scheme_open);
	memset(key, 0, SMD_KEY_LENGTH);
	if (ret == SQLITE_ROW)
	{
		scheme_key = sqlite3_column_int64(stmt_scheme_open, 0);
		memcpy(key, &scheme_key, sizeof(scheme_key));
		bson_append_document_begin(bson, "space_type", -1, b_datatype);
		bson_append_int32(b_datatype, "ndims", -1, sqlite3_column_int(stmt_scheme_open, 1));
		bson_append_array_begin(b_datatype, "dims", -1, b_arr);
		bson_uint32_to_string(0, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt_scheme_open, 2));
		bson_uint32_to_string(1, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt_scheme_open, 3));
		bson_uint32_to_string(2, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt_scheme_open, 4));
		bson_uint32_to_string(3, &_key, key_buf, sizeof(key_buf));
		bson_append_int32(b_arr, key, -1, sqlite3_column_int(stmt_scheme_open, 5));
		bson_append_array_end(b_datatype, b_arr);
		bson_append_document_end(bson, b_datatype);
		*distribution = sqlite3_column_int(stmt_scheme_open, 6);
		type_key = sqlite3_column_int64(stmt_scheme_open, 7);
	}
	else if (ret == SQLITE_DONE)
	{
		j_sqlite3_reset(stmt_scheme_open);
		j_sqlite3_transaction_abort();
		j_smd_timer_stop(backend_scheme_open);
		return FALSE;
	}
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	j_sqlite3_reset(stmt_scheme_open);
	bson_append_document_begin(bson, "data_type", -1, b_datatype);
	load_type(b_datatype, type_key);
	bson_append_document_end(bson, b_datatype);
	j_sqlite3_transaction_commit();
	j_smd_timer_stop(backend_scheme_open);
	return TRUE;
}
static gboolean
backend_scheme_read(char* key, char* buf, guint offset, guint size)
{
	j_smd_timer_start(backend_scheme_read);
	read_type(*((sqlite3_int64*)key), buf, offset, size);
	j_smd_timer_stop(backend_scheme_read);
	return TRUE;
}
static gboolean
backend_scheme_write(char* key, const char* buf, guint offset, guint size)
{
	gint ret;
	sqlite3_int64 type_key = 0;
	j_smd_timer_start(backend_scheme_write);
	j_sqlite3_bind_int64(stmt_scheme_get_type_key, 1, *((sqlite3_int64*)key));
	ret = sqlite3_step(stmt_scheme_get_type_key);
	if (ret == SQLITE_ROW)
		type_key = sqlite3_column_int64(stmt_scheme_get_type_key, 0);
	else
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	j_sqlite3_reset(stmt_scheme_get_type_key);
	write_type(type_key, *((sqlite3_int64*)key), buf, offset, size, 0, 0);
	j_smd_timer_stop(backend_scheme_write);
	return TRUE;
}
