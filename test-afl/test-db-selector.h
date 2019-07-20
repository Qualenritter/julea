static void
event_selector_new(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	j_db_selector_unref(the_stored_selector);
	the_stored_selector = NULL;
	the_stored_selector_field_count = 0;
	random_values.selector_mode = random_values.selector_mode % (_J_DB_SELECTOR_MODE_COUNT + 1);
	switch (random_values.invalid_switch % 2)
	{
	case 1: //schema NULL
		the_stored_selector = j_db_selector_new(NULL, random_values.selector_mode, &error);
		ret = the_stored_selector != NULL;
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0: //success
		ret_expected = the_stored_schema != NULL;
		ret_expected = ret_expected && (random_values.selector_mode != _J_DB_SELECTOR_MODE_COUNT);
		the_stored_selector = j_db_selector_new(the_stored_schema, random_values.selector_mode, &error);
		ret = the_stored_selector != NULL;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
	default:
		MYABORT();
	}
}
static void
event_selector_ref(void)
{
	GError* error = NULL;
	JDBSelector* ptr = NULL;
	gint ref_count;
	if (the_stored_selector)
	{
		ref_count = the_stored_selector->ref_count;
		ptr = j_db_selector_ref(the_stored_selector, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
		if (ptr != the_stored_selector)
			MYABORT();
		if (the_stored_selector->ref_count != ref_count + 1)
			MYABORT();
		j_db_selector_unref(the_stored_selector);
		if (the_stored_selector->ref_count != ref_count)
			MYABORT();
	}
	else
	{
		ptr = j_db_selector_ref(NULL, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, FALSE, error);
	}
}
static void
event_selector_add_field(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	JDBType type;
	ret_expected = the_stored_selector != NULL;
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, random_values.var_name);
	random_values.var_type = random_values.var_type % (_J_DB_TYPE_COUNT + 1);
	switch (random_values.invalid_switch % 5)
	{
	case 4: //not existing varname
		if (the_stored_selector)
			ret = j_db_schema_get_field(the_stored_selector->schema, "_not_existing_name_", &type, &error);
		else
			ret = j_db_schema_get_field(NULL, "_not_existing_name_", &type, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 3: //NULL varname
		if (the_stored_selector)
			ret = j_db_schema_get_field(the_stored_selector->schema, NULL, &type, &error);
		else
			ret = j_db_schema_get_field(NULL, NULL, &type, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 2: //NULL selector
		ret = j_db_schema_get_field(NULL, varname_strbuf, &type, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //NULL type
		if (the_stored_selector)
			ret = j_db_schema_get_field(the_stored_selector->schema, varname_strbuf, NULL, &error);
		else
			ret = j_db_schema_get_field(NULL, varname_strbuf, NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		type = random_values.var_type;
		ret_expected = ret_expected && (the_schema_field_type != _J_DB_TYPE_COUNT);
		if (the_stored_selector)
			ret = j_db_schema_get_field(the_stored_selector->schema, varname_strbuf, &type, &error);
		else
			ret = j_db_schema_get_field(NULL, varname_strbuf, &type, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		switch (type)
		{
		case J_DB_TYPE_SINT32:
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, type, &random_values.var_value_sint32, 4, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_selector_field_count++;
			break;
		case J_DB_TYPE_UINT32:
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, type, &random_values.var_value_uint32, 4, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_selector_field_count++;
			break;
		case J_DB_TYPE_FLOAT32:
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, type, &random_values.var_value_float32, 4, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_selector_field_count++;
			break;
		case J_DB_TYPE_SINT64:
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, type, &random_values.var_value_sint64, 8, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_selector_field_count++;
			break;
		case J_DB_TYPE_UINT64:
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, type, &random_values.var_value_uint64, 8, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_selector_field_count++;
			break;
		case J_DB_TYPE_FLOAT64:
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, type, &random_values.var_value_float64, 8, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_selector_field_count++;
			break;
		case J_DB_TYPE_STRING:
		case J_DB_TYPE_BLOB:
			sprintf(varvalue_strbuf, AFL_VARVALUE_FORMAT, random_values.var_value_str % AFL_LIMIT_SCHEMA_STRING_VALUES);
			ret = j_db_selector_add_field(the_stored_selector, varname_strbuf, type, varvalue_strbuf, strlen(varvalue_strbuf) + 1, &error);
			J_AFL_DEBUG_ERROR(ret, ret_expected, error);
			if (ret)
				the_stored_selector_field_count++;
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
event_selector_add_selector(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	random_values.selector_selector = random_values.selector_selector % AFL_LIMIT_SELECTOR;
	ret_expected = the_stored_selector != NULL;
	switch (random_values.invalid_switch % 1)
	{
	case 0:
		ret_expected = ret_expected && (stored_selectors[random_values.namespace][random_values.name][random_values.selector_selector] != NULL);
		ret = j_db_selector_add_selector(the_stored_selector, stored_selectors[random_values.namespace][random_values.name][random_values.selector_selector], &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
			the_stored_selector_field_count += stored_selectors_field_count[random_values.namespace][random_values.name][random_values.selector_selector];
		break;
	default:
		MYABORT();
	}
}
