static gboolean
backend_scheme_delete(const char* name, void* parent)
{
	JDistribution* distribution;
	JDistributedObject* object;
	JBatch* batch;
	char buf[SMD_KEY_LENGTH * 2 + 1];
	char key[SMD_KEY_LENGTH];
	GArray* arr;
	guint i;
	guint ret;
	sqlite3_int64 tmp;
	arr = g_array_new(FALSE, FALSE, sizeof(sqlite3_int64)); //TODO cache array
	j_smd_timer_start(backend_scheme_delete);
	j_sqlite3_transaction_begin();
	{
		/* delete data from objectstore - if it exist */
		j_sqlite3_bind_text(stmt_scheme_open, 1, name, -1);
		j_sqlite3_bind_int64(stmt_scheme_open, 2, *((sqlite3_int64*)parent));
		ret = sqlite3_step(stmt_scheme_open);
		if (ret == SQLITE_ROW)
		{
			i = sqlite3_column_int64(stmt_scheme_open, 6);
			if (i != J_DISTRIBUTION_DATABASE)
			{

				memset(key, 0, SMD_KEY_LENGTH);
				tmp = sqlite3_column_int64(stmt_scheme_open, 0);
				memcpy(key, &tmp, sizeof(sqlite3_int64));
				SMD_BUF_TO_HEX(key, buf, SMD_KEY_LENGTH);
				distribution = j_distribution_new(i);
				object = j_distributed_object_new("smd", buf, distribution);
				batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
				j_distributed_object_delete(object, batch);
				j_distributed_object_unref(object);
				j_distribution_unref(distribution);
				j_batch_execute(batch);
			}
		}
		else if (ret != SQLITE_DONE)
			J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		j_sqlite3_reset(stmt_scheme_open);
	}
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
	J_DEBUG("scheme delete success %s %lld", name, *((sqlite3_int64*)parent));
	return TRUE;
}
static gboolean
backend_scheme_create(const char* name, void* parent, const void* _space, const void* _type, guint _distribution, void* key)
{
	char buf[SMD_KEY_LENGTH * 2 + 1];
	const J_SMD_Space_t* space = _space;
	const J_SMD_Type_t* type = _type;
	JDistributedObject* object;
	JDistribution* distribution;
	JBatch* batch;
	sqlite3_int64 scheme_key = 0;
	sqlite3_int64 type_key = 0;
	guint ret;
	memset(key, 0, SMD_KEY_LENGTH);
	j_smd_timer_start(backend_scheme_create);

	j_sqlite3_transaction_begin();
	if (type->arr->len == 0)
		type_key = 0;
	else
		type_key = create_type(&g_array_index(type->arr, J_SMD_Variable_t, type->first_index));
	if (!type_key)
	{
		j_sqlite3_transaction_abort();
		J_DEBUG("scheme create failed %s %lld", name, *((sqlite3_int64*)parent));
		return FALSE;
	}

	scheme_key = g_atomic_int_add(&smd_schemes_primary_key, 1);
	j_sqlite3_bind_text(stmt_scheme_create, 1, name, -1);
	j_sqlite3_bind_int64(stmt_scheme_create, 2, *((sqlite3_int64*)parent));
	j_sqlite3_bind_int(stmt_scheme_create, 3, space->ndims);
	j_sqlite3_bind_int(stmt_scheme_create, 4, space->dims[0]);
	j_sqlite3_bind_int(stmt_scheme_create, 5, space->dims[1]);
	j_sqlite3_bind_int(stmt_scheme_create, 6, space->dims[2]);
	j_sqlite3_bind_int(stmt_scheme_create, 7, space->dims[3]);
	j_sqlite3_bind_int(stmt_scheme_create, 8, _distribution);
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
		J_DEBUG("scheme create failed %s %lld", name, *((sqlite3_int64*)parent));
		return FALSE;
	}
	else
	{
		J_CRITICAL("sql_error %d %s", ret, sqlite3_errmsg(backend_db));
		exit(1);
	}
	if (_distribution != J_DISTRIBUTION_DATABASE)
	{
		distribution = j_distribution_new(_distribution);
		SMD_BUF_TO_HEX(key, buf, SMD_KEY_LENGTH);
		object = j_distributed_object_new("smd", buf, distribution);
		batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
		j_distributed_object_create(object, batch);
		j_distributed_object_unref(object);
		j_batch_execute(batch);
		j_distribution_unref(distribution);
	}
	j_smd_timer_stop(backend_scheme_create);
	J_DEBUG("scheme create success %s %lld %lld", name, *((sqlite3_int64*)parent), scheme_key);
	return TRUE;
}
static gboolean
backend_scheme_open(const char* name, void* parent, void* _space, void* _type, guint* distribution, void* key)
{
	J_SMD_Space_t* space = _space;
	J_SMD_Type_t* type = _type;
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
		J_DEBUG("scheme open failed %s %lld", name, *((sqlite3_int64*)parent));
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
	J_DEBUG("scheme open success %s %lld %lld", name, *((sqlite3_int64*)parent), scheme_key);
	return TRUE;
}
static gboolean
backend_scheme_read(void* key, void* buf, guint offset, guint size)
{
	j_smd_timer_start(backend_scheme_read);
	j_sqlite3_transaction_begin();
	memset(buf, 0, size);
	read_type(*((sqlite3_int64*)key), buf, offset, size);
	j_sqlite3_transaction_commit();
	j_smd_timer_stop(backend_scheme_read);
	J_DEBUG("scheme read success %lld", *((sqlite3_int64*)key));
	return TRUE;
}
static gboolean
backend_scheme_write(void* key, const void* buf, guint offset, guint size)
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
		J_DEBUG("scheme write failed %lld", *((sqlite3_int64*)key));
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
	J_DEBUG("scheme write success %lld", *((sqlite3_int64*)key));
	return TRUE;
}
static gboolean
backend_scheme_set_valid(void* key, guint offset, guint size)
{
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_int64(stmt_scheme_set_valid, 1, *((sqlite3_int64*)key));
	j_sqlite3_bind_int64(stmt_scheme_set_valid, 2, offset);
	j_sqlite3_bind_int64(stmt_scheme_set_valid, 3, size);
	j_sqlite3_step_and_reset_check_done(stmt_scheme_set_valid);
	j_sqlite3_transaction_commit();
	J_DEBUG("scheme set_valid success %lld", *((sqlite3_int64*)key));
	return TRUE;
}
