static void
event_entry_new(void)
{
	GError* error = NULL;
	guint ret;
	gboolean ret_expected;
	if(stored_entrys_synced[random_values.namespace][random_values.name][random_values.entry]){
		//TODO delete
		stored_entrys_synced[random_values.namespace][random_values.name][random_values.entry]=FALSE;
	}
	if(stored_entrys[random_values.namespace][random_values.name][random_values.entry])
	j_db_entry_unref(stored_entrys[random_values.namespace][random_values.name][random_values.entry]);
	switch (random_values.invalid_switch%2){
case 1:
stored_entrys[random_values.namespace][random_values.name][random_values.entry]=j_db_entry_new(NULL,&error);
ret=stored_entrys[random_values.namespace][random_values.name][random_values.entry]!=NULL;
J_AFL_DEBUG_ERROR(ret,FALSE, error);
break;
		case 0:
		ret_expected = stored_schemas[random_values.namespace][random_values.name]!=NULL;
		stored_entrys[random_values.namespace][random_values.name][random_values.entry]=j_db_entry_new(stored_schemas[random_values.namespace][random_values.name],&error);
ret=stored_entrys[random_values.namespace][random_values.name][random_values.entry]!=NULL;
	J_AFL_DEBUG_ERROR(ret, ret_expected, error);
		break;
		default:
		MYABORT();
	}
}
static void
event_entry_ref(void)
{
	//TODO
}
static void
event_entry_set_field(void)
{
	//TODO
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
