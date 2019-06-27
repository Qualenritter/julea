static gboolean
backend_scheme_delete(const char* name, void* parent)
{
	JDistribution* distribution;
	JDistributedObject* object;
	g_autoptr(JBatch) batch;
	char buf[SMD_KEY_LENGTH * 2 + 1];
	char key[SMD_KEY_LENGTH];
	guint i;
	guint ret;
	sqlite3_int64 tmp;
	j_smd_timer_start(backend_scheme_delete);
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	j_sqlite3_transaction_begin();
	//delete data from object store ->
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
			j_distributed_object_delete(object, batch);
			j_distributed_object_unref(object);
			j_distribution_unref(distribution);
		}
	}
	else
		j_debug_check(ret, SQLITE_DONE);
	j_sqlite3_reset(stmt_scheme_open);
	j_batch_execute(batch);
	//delete type ->
	j_sqlite3_bind_text(stmt_scheme_delete0, 1, name, -1);
	j_sqlite3_bind_int64(stmt_scheme_delete0, 2, *((sqlite3_int64*)parent));
	ret = sqlite3_step(stmt_scheme_delete0);
	if (ret == SQLITE_ROW)
	{
		tmp = sqlite3_column_int64(stmt_scheme_delete0, 0);
		if (g_hash_table_add(smd_cache.types_to_delete_keys, GINT_TO_POINTER(tmp)))
			g_array_append_val(smd_cache.types_to_delete, tmp);
	}
	else
		j_debug_check(ret, SQLITE_DONE);
	j_sqlite3_reset(stmt_scheme_delete0);
	//delete scheme ->
	j_sqlite3_bind_text(stmt_scheme_delete1, 1, name, -1);
	j_sqlite3_bind_int64(stmt_scheme_delete1, 2, *((sqlite3_int64*)parent));
	j_sqlite3_step_and_reset_check_done(stmt_scheme_delete1);
	j_sqlite3_transaction_commit();
	j_smd_timer_stop(backend_scheme_delete);
	J_DEBUG("scheme delete success %s %lld", name, *((sqlite3_int64*)parent));
	return TRUE;
}
static gboolean
backend_scheme_create(const char* name, void* parent, const void* _space, const void* _type, guint _distribution, void* key)
{
	char buf[SMD_KEY_LENGTH * 2 + 1];
	const J_SMD_Space_t* space = _space;
	const J_SMD_Type_t* type = _type;
	JDistributedObject* object = NULL;
	JDistribution* distribution = NULL;
	g_autoptr(JBatch) batch = NULL;
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
	if (!g_hash_table_lookup(smd_cache.types_cached, GINT_TO_POINTER(type_key)))
		g_hash_table_insert(smd_cache.types_cached, GINT_TO_POINTER(type_key), j_smd_type_ref(_type));
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
		j_debug_check(ret, SQLITE_OK);
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
		j_debug_check(ret, SQLITE_DONE);
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
	J_SMD_Type_t* type_tmp;
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
		j_debug_check(ret, SQLITE_DONE);
	j_sqlite3_reset(stmt_scheme_open);
	type_tmp = g_hash_table_lookup(smd_cache.types_cached, GINT_TO_POINTER(type_key));
	if (type_tmp)
	{
		j_smd_type_copy2(type, type_tmp);
	}
	else
	{
		load_type(type, type_key);
		g_hash_table_insert(smd_cache.types_cached, GINT_TO_POINTER(type_key), j_smd_type_ref(type));
	}
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
		j_debug_check(ret, SQLITE_DONE);
	j_sqlite3_reset(stmt_scheme_get_type_key);
	write_type(type_key, *((sqlite3_int64*)key), buf, offset, size, 0, 0);
	j_sqlite3_transaction_commit();
	j_smd_timer_stop(backend_scheme_write);
	J_DEBUG("scheme write success %lld", *((sqlite3_int64*)key));
	return TRUE;
}
static gboolean
backend_scheme_get_valid(void* key, guint offset, guint size, void* result)
{
	guint ret;
	J_SMD_Range_t range;
	GArray* arr = result;
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_int64(stmt_scheme_get_valid, 1, *((sqlite3_int64*)key));
	j_sqlite3_bind_int64(stmt_scheme_get_valid, 2, offset + size);
	j_sqlite3_bind_int64(stmt_scheme_get_valid, 3, offset);
	do
	{
		ret = sqlite3_step(stmt_scheme_get_valid);
		if (ret == SQLITE_ROW)
		{
			range.start = sqlite3_column_int64(stmt_scheme_get_valid, 0);
			range.end = sqlite3_column_int64(stmt_scheme_get_valid, 1);
			J_DEBUG("found valid %d %d", range.start, range.end);
			g_array_append_val(arr, range);
		}
		else
			j_debug_check(ret, SQLITE_DONE);
	} while (ret != SQLITE_DONE);
	j_sqlite3_reset(stmt_scheme_get_valid);
	if (arr->len)
	{
		if (g_array_index(arr, J_SMD_Range_t, 0).start < offset)
			g_array_index(arr, J_SMD_Range_t, 0).start = offset;
		if (g_array_index(arr, J_SMD_Range_t, arr->len - 1).start > offset + size)
			g_array_index(arr, J_SMD_Range_t, arr->len - 1).end = offset + size;
	}
	j_sqlite3_transaction_commit();
	return TRUE;
}
static gboolean
backend_scheme_set_valid(void* key, guint offset, guint size)
{
	guint ret;
	guint start;
	guint end;
	guint start_new;
	guint end_new;
	guint count = 0;
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_int64(stmt_scheme_get_valid_max, 1, *((sqlite3_int64*)key));
	j_sqlite3_bind_int64(stmt_scheme_get_valid_max, 2, offset + size);
	j_sqlite3_bind_int64(stmt_scheme_get_valid_max, 3, offset);
	ret = sqlite3_step(stmt_scheme_get_valid_max);
	if (ret == SQLITE_ROW)
	{
		start = sqlite3_column_int64(stmt_scheme_get_valid_max, 0);
		end = sqlite3_column_int64(stmt_scheme_get_valid_max, 1);
		count = sqlite3_column_int64(stmt_scheme_get_valid_max, 2);
	}
	else
		j_debug_check(ret, SQLITE_DONE);
	j_sqlite3_reset(stmt_scheme_get_valid_max);
	if (count == 0)
	{
		j_sqlite3_bind_int64(stmt_scheme_set_valid, 1, *((sqlite3_int64*)key));
		j_sqlite3_bind_int64(stmt_scheme_set_valid, 2, offset);
		j_sqlite3_bind_int64(stmt_scheme_set_valid, 3, offset + size);
		j_sqlite3_step_and_reset_check_done(stmt_scheme_set_valid);
		j_sqlite3_transaction_commit();
		J_DEBUG("scheme set_valid success first entry %lld %d %d", *((sqlite3_int64*)key), offset, offset + size);
		return TRUE;
	}
	if (count == 1 && start <= offset && end >= offset + size)
	{
		j_sqlite3_transaction_commit();
		J_DEBUG("scheme set_valid success without change %lld %d %d", *((sqlite3_int64*)key), offset, offset + size);
		return TRUE;
	}
	start_new = start;
	end_new = end;
	if (start > offset)
		start_new = offset;
	if (end < offset + size)
		end_new = offset + size;
	if (count == 1)
	{
		j_sqlite3_bind_int64(stmt_scheme_update_valid, 1, *((sqlite3_int64*)key));
		j_sqlite3_bind_int64(stmt_scheme_update_valid, 2, start);
		j_sqlite3_bind_int64(stmt_scheme_update_valid, 3, end);
		j_sqlite3_bind_int64(stmt_scheme_update_valid, 4, start_new);
		j_sqlite3_bind_int64(stmt_scheme_update_valid, 5, end_new);
		j_sqlite3_step_and_reset_check_done(stmt_scheme_update_valid);
		j_sqlite3_transaction_commit();
		J_DEBUG("scheme set_valid success update single %lld %d %d %d %d", *((sqlite3_int64*)key), start, end, start_new, end_new);
		return TRUE;
	}
	j_sqlite3_bind_int64(stmt_scheme_delete_valid, 1, *((sqlite3_int64*)key));
	j_sqlite3_bind_int64(stmt_scheme_delete_valid, 2, offset + size);
	j_sqlite3_bind_int64(stmt_scheme_delete_valid, 3, offset);
	j_sqlite3_step_and_reset_check_done(stmt_scheme_delete_valid);
	j_sqlite3_bind_int64(stmt_scheme_set_valid, 1, *((sqlite3_int64*)key));
	j_sqlite3_bind_int64(stmt_scheme_set_valid, 2, start_new);
	j_sqlite3_bind_int64(stmt_scheme_set_valid, 3, end_new);
	j_sqlite3_step_and_reset_check_done(stmt_scheme_set_valid);
	j_sqlite3_transaction_commit();
	J_DEBUG("scheme set_valid success merge %lld %d %d %d %d", *((sqlite3_int64*)key), offset, offset + size, start_new, end_new);
	return TRUE;
}
