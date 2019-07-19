static void
event_entry_new(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	if (the_stored_entry_synced)
	{
		//TODO delete in backend
		the_stored_entry_synced = FALSE;
	}
	if (the_stored_entry)
		j_db_entry_unref(the_stored_entry);
	switch (random_values.invalid_switch % 2)
	{
	case 1: //schema NULL
		the_stored_entry = j_db_entry_new(NULL, &error);
		ret = the_stored_entry != NULL;
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0: //success
		ret_expected = the_stored_schema != NULL;
		the_stored_entry = j_db_entry_new(the_stored_schema, &error);
		ret = the_stored_entry != NULL;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
	default:
		MYABORT();
	}
}
static void
event_entry_ref(void)
{
	GError* error = NULL;
	JDBEntry* ptr = NULL;
	if (the_stored_entry)
	{
		if (the_stored_entry->ref_count != 1)
			MYABORT();
		ptr = j_db_entry_ref(the_stored_entry, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
		if (ptr != the_stored_entry)
			MYABORT();
		if (the_stored_entry->ref_count != 2)
			MYABORT();
		j_db_entry_unref(the_stored_entry);
		if (the_stored_entry->ref_count != 1)
			MYABORT();
	}
	else
	{
		ptr = j_db_entry_ref(the_stored_entry, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, FALSE, error);
	}
}
static void
event_entry_set_field(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	JDBType type;
	ret_expected = the_stored_entry != NULL;
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, random_values.var_name);
	switch (random_values.invalid_switch % 1)
	{
	case 0:
		//TODO verify set field effect
		ret_expected = ret_expected && the_schema_field_type != _J_DB_TYPE_COUNT;
		ret = j_db_schema_get_field(the_stored_entry->schema, varname_strbuf, &type, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		switch (type)
		{
		case J_DB_TYPE_SINT32:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_sint32, 4, &error);
			break;
		case J_DB_TYPE_UINT32:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_uint32, 4, &error);
			break;
		case J_DB_TYPE_FLOAT32:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_float32, 4, &error);
			break;
		case J_DB_TYPE_SINT64:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_sint64, 8, &error);
			break;
		case J_DB_TYPE_UINT64:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_uint64, 8, &error);
			break;
		case J_DB_TYPE_FLOAT64:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_float64, 8, &error);
			break;
		case J_DB_TYPE_STRING:
		case J_DB_TYPE_BLOB:
			//TODO
			break;
		default:
			MYABORT();
		}
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
	default:
		MYABORT();
	}
}
static void
event_entry_insert(void)
{
	//TODO
}
static void
event_entry_update(void)
{
	//TODO
}
static void
event_entry_delete(void)
{
	//TODO
}
