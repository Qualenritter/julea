static gboolean
backend_file_delete(const char* name)
{
	JDistribution* distribution;
	JDistributedObject* object;
	g_autoptr(JBatch) batch;
	char buf[SMD_KEY_LENGTH * 2 + 1];
	char key[SMD_KEY_LENGTH];
	gint ret;
	guint i;
	sqlite3_int64 tmp;
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	j_sqlite3_transaction_begin();
	//delete data from object store ->
	j_sqlite3_bind_text(stmt_scheme_open_all_in_file, 1, name, -1);
	do
	{
		ret = sqlite3_step(stmt_scheme_open_all_in_file);
		if (ret == SQLITE_ROW)
		{
			i = sqlite3_column_int64(stmt_scheme_open_all_in_file, 6);
			if (i != J_DISTRIBUTION_DATABASE)
			{
				memset(key, 0, SMD_KEY_LENGTH);
				tmp = sqlite3_column_int64(stmt_scheme_open_all_in_file, 0);
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
	} while (ret != SQLITE_DONE);
	j_sqlite3_reset(stmt_scheme_open_all_in_file);
	j_batch_execute(batch);
	//delete type ->
	j_sqlite3_bind_text(stmt_file_delete0, 1, name, -1);
	do
	{
		ret = sqlite3_step(stmt_file_delete0);
		if (ret == SQLITE_ROW)
		{
			tmp = sqlite3_column_int64(stmt_file_delete0, 0);
			if (g_hash_table_add(smd_cache.types_to_delete_keys, GINT_TO_POINTER(tmp)))
				g_array_append_val(smd_cache.types_to_delete, tmp);
		}
		else
			j_debug_check(ret, SQLITE_DONE);
	} while (ret != SQLITE_DONE);
	j_sqlite3_reset(stmt_file_delete0);
	//delete file ->
	j_sqlite3_bind_text(stmt_file_delete2, 1, name, -1);
	j_sqlite3_step_and_reset_check_done(stmt_file_delete2);
	j_sqlite3_transaction_commit();
	J_DEBUG("file delete success %s", name);
	return TRUE;
}
static gboolean
backend_file_create(const char* name, bson_t* bson, void* key)
{
	gint ret0;
	gint ret1;
	sqlite3_int64 file_key = 0;
	memset(key, 0, sizeof(file_key));
	file_key = g_atomic_int_add(&smd_schemes_primary_key, 1);
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_int(stmt_file_create0, 1, file_key);
	j_sqlite3_bind_text(stmt_file_create0, 2, name, -1);
	ret0 = sqlite3_step(stmt_file_create0);
	j_sqlite3_bind_int(stmt_file_create1, 1, file_key);
	j_sqlite3_bind_text(stmt_file_create1, 2, name, -1);
	ret1 = sqlite3_step(stmt_file_create1);
	if (ret1 == SQLITE_CONSTRAINT)
	{
		j_sqlite3_reset_constraint(stmt_file_create0);
		j_sqlite3_reset_constraint(stmt_file_create1);
		j_sqlite3_transaction_abort();
		J_DEBUG("file create failed %s", name);
		return FALSE;
	}
	else
	{
		j_debug_check(ret0, SQLITE_DONE);
		j_debug_check(ret1, SQLITE_DONE);
	}
	j_sqlite3_reset(stmt_file_create0);
	j_sqlite3_reset(stmt_file_create1);
	j_sqlite3_transaction_commit();
	(void)bson;
	J_DEBUG("file create success %s %lld", name, file_key);
	memcpy(key, &file_key, sizeof(file_key));
	return TRUE;
}
static gboolean
backend_file_open(const char* name, bson_t* bson, void* key)
{
	gint ret;
	sqlite3_int64 file_key = 0;
	bson_init(bson);
	j_sqlite3_transaction_begin();
	j_sqlite3_bind_text(stmt_file_open, 1, name, -1);
	ret = sqlite3_step(stmt_file_open);
	if (ret == SQLITE_ROW)
	{
		file_key = sqlite3_column_int64(stmt_file_open, 0);
		memset(key, 0, SMD_KEY_LENGTH);
		memcpy(key, &file_key, sizeof(file_key));
	}
	else if (ret == SQLITE_DONE)
	{
		j_sqlite3_reset(stmt_file_open);
		j_sqlite3_transaction_abort();
		J_DEBUG("file open failed %s", name);
		return FALSE;
	}
	else
		j_debug_check(ret, SQLITE_DONE);
	j_sqlite3_reset(stmt_file_open);
	j_sqlite3_transaction_commit();
	J_DEBUG("file open success %s %lld", name, file_key);
	return TRUE;
}
