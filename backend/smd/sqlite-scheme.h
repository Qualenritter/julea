static gboolean
backend_scheme_delete(const char* name, char* parent)
{
	//TODO delete data in object-store if any
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
backend_scheme_create(const char* name, char* parent, const char* _space, const char* _type, guint distribution, char* key)
{
	const J_SMD_Space_t* space = _space;
	const J_SMD_Type_t2* type = _type;

	sqlite3_int64 scheme_key = 0;
	sqlite3_int64 type_key = 0;
	guint ret;
	memset(key, 0, SMD_KEY_LENGTH);
	j_smd_timer_start(backend_scheme_create);
	j_sqlite3_transaction_begin();
	if (type->arr2->len == 0)
		type_key = 0;
	else
		type_key = create_type(&g_array_index(type->arr2, J_SMD_Variable_t2, type->first_index2));
	scheme_key = g_atomic_int_add(&smd_schemes_primary_key, 1);
	j_sqlite3_bind_text(stmt_scheme_create, 1, name, -1);
	j_sqlite3_bind_int64(stmt_scheme_create, 2, *((sqlite3_int64*)parent));
	j_sqlite3_bind_int(stmt_scheme_create, 3, space->ndims);
	j_sqlite3_bind_int(stmt_scheme_create, 4, space->dims[0]);
	j_sqlite3_bind_int(stmt_scheme_create, 5, space->dims[1]);
	j_sqlite3_bind_int(stmt_scheme_create, 6, space->dims[2]);
	j_sqlite3_bind_int(stmt_scheme_create, 7, space->dims[3]);
	j_sqlite3_bind_int(stmt_scheme_create, 8, distribution);
	j_sqlite3_bind_int64(stmt_scheme_create, 9, type_key);
	j_sqlite3_bind_int64(stmt_scheme_create, 10, scheme_key);
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
backend_scheme_open(const char* name, char* parent, char* _space, char* _type, guint* distribution, char* key)
{
	J_SMD_Space_t* space = _space;
	J_SMD_Type_t2* type = _type;
	gint ret;
	sqlite3_int64 scheme_key = 0;
	sqlite3_int64 type_key = 0;
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
		space->ndims = sqlite3_column_int(stmt_scheme_open, 1);
		space->dims[0] = sqlite3_column_int(stmt_scheme_open, 2);
		space->dims[1] = sqlite3_column_int(stmt_scheme_open, 3);
		space->dims[2] = sqlite3_column_int(stmt_scheme_open, 4);
		space->dims[3] = sqlite3_column_int(stmt_scheme_open, 5);
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
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		exit(1);
	}
	j_sqlite3_reset(stmt_scheme_open);
	load_type(type, type_key);
	j_sqlite3_transaction_commit();
	j_smd_timer_stop(backend_scheme_open);
	return TRUE;
}
static gboolean
backend_scheme_read(char* key, char* buf, guint offset, guint size)
{
	j_smd_timer_start(backend_scheme_read);
	j_sqlite3_transaction_begin();
	read_type(*((sqlite3_int64*)key), buf, offset, size);
	j_sqlite3_transaction_commit();
	j_smd_timer_stop(backend_scheme_read);
	return TRUE;
}
static gboolean
backend_scheme_write(char* key, const char* buf, guint offset, guint size)
{
	gint ret;
	sqlite3_int64 type_key = 0;
	j_smd_timer_start(backend_scheme_write);
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_int64(stmt_scheme_get_type_key, 1, *((sqlite3_int64*)key));
	ret = sqlite3_step(stmt_scheme_get_type_key);
	if (ret == SQLITE_ROW)
		type_key = sqlite3_column_int64(stmt_scheme_get_type_key, 0);
	else if (ret == SQLITE_DONE)
	{
		return FALSE;
	}
	else
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		exit(1);
	}
	j_sqlite3_reset(stmt_scheme_get_type_key);
	write_type(type_key, *((sqlite3_int64*)key), buf, offset, size, 0, 0);
	j_sqlite3_transaction_commit();
	j_smd_timer_stop(backend_scheme_write);
	return TRUE;
}
