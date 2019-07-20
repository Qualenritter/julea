static void
event_iterator_new(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	j_db_iterator_unref(the_stored_iterator);
	the_stored_iterator_next_count = 0;
	switch (random_values.invalid_switch % 3)
	{
	case 2: //schema NULL
		the_stored_iterator = j_db_iterator_new(NULL, the_stored_selector, &error);
		ret = the_stored_iterator != NULL;
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //selector NULL - is allowed - should get everything
		ret_expected = the_stored_schema != NULL;
		if (the_stored_schema)
			ret_expected = ret_expected && the_stored_schema->server_side;
		the_stored_iterator = j_db_iterator_new(the_stored_schema, NULL, &error);
		ret = the_stored_iterator != NULL;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
	case 0: //success
		ret_expected = the_stored_schema != NULL;
		if (the_stored_schema)
			ret_expected = ret_expected && the_stored_schema->server_side;
		the_stored_iterator = j_db_iterator_new(the_stored_schema, the_stored_selector, &error);
		ret = the_stored_iterator != NULL;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
	default:
		MYABORT();
	}
}
static void
event_iterator_ref(void)
{
	GError* error = NULL;
	JDBIterator* ptr = NULL;
	gint ref_count;
	if (the_stored_iterator)
	{
		ref_count = the_stored_iterator->ref_count;
		ptr = j_db_iterator_ref(the_stored_iterator, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, TRUE, error);
		if (ptr != the_stored_iterator)
			MYABORT();
		if (the_stored_iterator->ref_count != ref_count + 1)
			MYABORT();
		j_db_iterator_unref(the_stored_iterator);
		if (the_stored_iterator->ref_count != ref_count)
			MYABORT();
	}
	else
	{
		ptr = j_db_iterator_ref(the_stored_iterator, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, FALSE, error);
	}
}
static void
event_iterator_next(void)
{
	GError* error = NULL;
	guint ret;
	switch (random_values.invalid_switch % 2)
	{
	case 1: //null iterator
		ret = j_db_iterator_next(NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		ret = j_db_iterator_next(the_stored_iterator, &error);
		J_AFL_DEBUG_ERROR_NO_EXPECT(ret, error);
		if (ret)
			the_stored_iterator_next_count++;
		if (!ret)
		{
			ret = j_db_iterator_next(the_stored_iterator, &error);
			J_AFL_DEBUG_ERROR(ret, FALSE, error);
		}
		break;
	default:
		MYABORT();
	}
}
static void
event_iterator_get_field(void)
{
	JDBType type;
	gpointer value = NULL;
	guint64 length;
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	random_values.var_name = random_values.var_name % AFL_LIMIT_SCHEMA_FIELDS;
	sprintf(varname_strbuf, AFL_VARNAME_FORMAT, random_values.var_name);
	ret_expected = the_stored_iterator != NULL;
	ret_expected = ret_expected && the_schema_field_type != _J_DB_TYPE_COUNT;
	switch (random_values.invalid_switch % 6)
	{
	case 5: //iterator null
		ret = j_db_iterator_get_field(NULL, varname_strbuf, &type, &value, &length, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 4: //varname null
		ret = j_db_iterator_get_field(the_stored_iterator, NULL, &type, &value, &length, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 3: //type null
		ret = j_db_iterator_get_field(the_stored_iterator, varname_strbuf, NULL, &value, &length, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 2: //value NULL
		ret = j_db_iterator_get_field(the_stored_iterator, varname_strbuf, &type, NULL, &length, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //length NULL
		ret = j_db_iterator_get_field(the_stored_iterator, varname_strbuf, &type, &value, NULL, &error);
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 0:
		ret = j_db_iterator_get_field(the_stored_iterator, varname_strbuf, &type, &value, &length, &error);
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		if (ret)
		{
			if (type == _J_DB_TYPE_COUNT)
				MYABORT();
			if (!value)
				MYABORT();
		}
		break;
	default:
		MYABORT();
	}
	if (value)
		g_free(value);
}
