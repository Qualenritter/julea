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
	random_values.var_type = random_values.var_type % (_J_DB_TYPE_COUNT + 1);
	switch (random_values.invalid_switch % 1)
	{
	case 0:
		//TODO verify set field effect
		type = random_values.var_type;
		ret_expected = ret_expected && the_schema_field_type != _J_DB_TYPE_COUNT;
		if (the_stored_entry)
			ret = j_db_schema_get_field(the_stored_entry->schema, varname_strbuf, &type, &error);
		else
			ret = j_db_schema_get_field(NULL, varname_strbuf, &type, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		switch (type)
		{
		case J_DB_TYPE_SINT32:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_sint32, 4, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			break;
		case J_DB_TYPE_UINT32:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_uint32, 4, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			break;
		case J_DB_TYPE_FLOAT32:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_float32, 4, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			break;
		case J_DB_TYPE_SINT64:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_sint64, 8, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			break;
		case J_DB_TYPE_UINT64:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_uint64, 8, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			break;
		case J_DB_TYPE_FLOAT64:
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, &random_values.var_value_float64, 8, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			break;
		case J_DB_TYPE_STRING:
		case J_DB_TYPE_BLOB:
			J_DEBUG("AFL_EVENT_DB_ENTRY_SET_FIELD %d %d %d", random_values.namespace, random_values.name, random_values.entry);
			sprintf(varvalue_strbuf, AFL_VARVALUE_FORMAT, random_values.var_value_str % AFL_LIMIT_SCHEMA_STRING_VALUES);
			J_DEBUG("AFL_EVENT_DB_ENTRY_SET_FIELD %d %d %d", random_values.namespace, random_values.name, random_values.entry);
			J_DEBUG("%p", varname_strbuf);
			J_DEBUG("%p", varvalue_strbuf);
			J_DEBUG("%p", error);
			J_DEBUG("%p", the_stored_entry);
			ret = j_db_entry_set_field(the_stored_entry, varname_strbuf, varvalue_strbuf, strlen(varvalue_strbuf) + 1, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			break;
		case _J_DB_TYPE_COUNT:
			ret = FALSE;
			if (ret_expected)
				MYABORT();
			break;
		default:
			MYABORT();
		}
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
