static void
event_iterator_new(void)
{
	GError* error = NULL;
	guint ret;
	guint ret_expected;
	j_db_iterator_unref(the_stored_iterator);
	the_stored_iterator_field_count = 0;
	switch (random_values.invalid_switch % 3)
	{
	case 2: //schema NULL
		the_stored_iterator = j_db_iterator_new(NULL, the_stored_selector, &error);
		ret = the_stored_iterator != NULL;
		J_AFL_DEBUG_ERROR(ret, FALSE, error);
		break;
	case 1: //selector NULL - is allowed - should get everything
		ret_expected = the_stored_schema != NULL;
		the_stored_iterator = j_db_iterator_new(the_stored_schema, NULL, &error);
		ret = the_stored_iterator != NULL;
		J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
	case 0: //success
		ret_expected = the_stored_schema != NULL;
		ret_expected = ret_expected && the_stored_selector != NULL;
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
	//TODO event_iterator_next
}
static void
event_iterator_get_field(void)
{
	//TODO event_iterator_get_field
}
