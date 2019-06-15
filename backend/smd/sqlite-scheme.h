static gboolean
backend_scheme_delete(const char* name, char* parent)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 result = 0;
	sqlite3_int64 type_key = 0;
	J_DEBUG("%s %lld", name, *((sqlite3_int64*)parent));
	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key,type_key FROM smd_schemes WHERE name = ? AND parent_key = ?;", -1, &stmt, NULL);
	j_sqlite3_bind_text(stmt, 1, name, -1);
	j_sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW)
	{
		result = sqlite3_column_int64(stmt, 0);
		type_key = sqlite3_column_int64(stmt, 1); /*TODO chekc if reused somewhere else later*/
	}
	else if (ret != SQLITE_DONE)
		J_CRITICAL("sql_error %s %lld  - %d %s", name, *((sqlite3_int64*)parent), ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "DELETE FROM smd_schemes WHERE key = ?;", -1, &stmt, NULL);
	j_sqlite3_bind_int64(stmt, 1, result);
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "DELETE FROM smd_scheme_data WHERE scheme_key = ?;", -1, &stmt, NULL);
	j_sqlite3_bind_int64(stmt, 1, result);
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	sqlite3_prepare_v2(backend_db, "DELETE FROM smd_scheme_type WHERE header_key = ?;", -1, &stmt, NULL);
	j_sqlite3_bind_int64(stmt, 1, type_key);
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE)
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
	sqlite3_finalize(stmt);
	/*TODO delete everything below*/
	J_DEBUG("%s", name);
	return TRUE;
}
static gboolean
backend_scheme_create(const char* name, char* parent, bson_t* bson, guint distribution, char* key)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 scheme_key = 0;
	sqlite3_int64 type_key = 0;
	bson_iter_t iter;
	bson_iter_t iter_space_type;
	guint var_ndims;
	guint var_dims[4];
	bson_iter_t iter_data_type;
	bson_iter_t iter_data_dims;
	guint i;
	{
		char* _t = bson_as_json(bson, NULL);
		J_DEBUG("%s %s", name, _t);
		free(_t);
	}
	j_sqlite3_transaction_begin();
	g_return_val_if_fail(name != NULL, FALSE);
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
	backend_scheme_delete(name, parent);
	scheme_key = g_atomic_int_add(&smd_schemes_primary_key, 1);
	memcpy(key, &scheme_key, sizeof(scheme_key));
	{ // insert new scheme
		sqlite3_prepare_v2(backend_db, "INSERT INTO smd_schemes (name,meta_type,parent_key,file_key,ndims,dims0,dims1,dims2,dims3,distribution,type_key,key) VALUES (?1,?2,?3,(SELECT file_key FROM smd_schemes WHERE key = ?3),?4,?5,?6,?7,?8,?9,?10,?11);", -1, &stmt, NULL);
		j_sqlite3_bind_text(stmt, 1, name, -1);
		j_sqlite3_bind_int(stmt, 2, SMD_METATYPE_DATA);
		j_sqlite3_bind_int64(stmt, 3, *((sqlite3_int64*)parent));
		j_sqlite3_bind_int(stmt, 4, var_ndims);
		j_sqlite3_bind_int(stmt, 5, var_dims[0]);
		j_sqlite3_bind_int(stmt, 6, var_dims[1]);
		j_sqlite3_bind_int(stmt, 7, var_dims[2]);
		j_sqlite3_bind_int(stmt, 8, var_dims[3]);
		j_sqlite3_bind_int(stmt, 9, distribution);
		j_sqlite3_bind_int64(stmt, 10, type_key);
		j_sqlite3_bind_int64(stmt, 11, scheme_key);
		ret = sqlite3_step(stmt);
		if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		sqlite3_finalize(stmt);
	}
	j_sqlite3_transaction_commit();
	J_DEBUG("%s", name);
	return TRUE;
}
static gboolean
backend_scheme_open(const char* name, char* parent, bson_t* bson, guint* distribution, char* key)
{
	sqlite3_stmt* stmt;
	bson_t b_datatype[1];
	gint ret;
	sqlite3_int64 scheme_key = 0;
	sqlite3_int64 type_key = 0;
	bson_t b_arr[1];
	char key_buf[16];
	const char* _key;
	J_DEBUG("%s", name);
	bson_init(bson);
	g_return_val_if_fail(name != NULL, FALSE);
	sqlite3_prepare_v2(backend_db, "SELECT key, ndims, dims0, dims1, dims2, dims3, distribution,type_key FROM smd_schemes WHERE name = ? AND parent_key = ?;", -1, &stmt, NULL);
	j_sqlite3_bind_text(stmt, 1, name, -1);
	j_sqlite3_bind_int64(stmt, 2, *((sqlite3_int64*)parent));
	ret = sqlite3_step(stmt);
	memset(key, 0, SMD_KEY_LENGTH);
	if (ret == SQLITE_ROW)
	{
		scheme_key = sqlite3_column_int64(stmt, 0);
		memcpy(key, &scheme_key, sizeof(scheme_key));
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
		*distribution = sqlite3_column_int(stmt, 6);
		type_key = sqlite3_column_int64(stmt, 7);
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
	{
		char* _t = bson_as_json(bson, NULL);
		J_DEBUG("%s %s", name, _t);
		free(_t);
	}
	return TRUE;
}
static gboolean
backend_scheme_read(char* key, char* buf, guint offset, guint size)
{
	read_type(*((sqlite3_int64*)key), buf, offset, size);
	return TRUE;
}
static gboolean
backend_scheme_write(char* key, const char* buf, guint offset, guint size)
{
	sqlite3_stmt* stmt;
	gint ret;
	sqlite3_int64 type_key = 0;
	sqlite3_prepare_v2(backend_db, "SELECT type_key FROM smd_schemes WHERE key = ?;", -1, &stmt, NULL);
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
