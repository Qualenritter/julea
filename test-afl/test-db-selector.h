static void
event_selector_new(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	j_db_selector_unref(the_stored_selector);
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
		J_DEBUG("%d", ret_expected);
		ret_expected = ret_expected && (random_values.selector_mode != _J_DB_SELECTOR_MODE_COUNT);
		J_DEBUG("%d", ret_expected);
		J_DEBUG("%d", random_values.selector_mode);
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
		ptr = j_db_selector_ref(the_stored_selector, &error);
		J_AFL_DEBUG_ERROR(ptr != NULL, FALSE, error);
	}
}
static void
event_selector_add_field(void)
{
	//TODO event_selector_add_field same as entry add field
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
			the_stored_selector_field_count++;
		break;
	default:
		MYABORT();
	}
}
