#include <julea-config.h>

#include <glib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <julea.h>
#include <julea-smd.h>
#include <julea-internal.h>
enum smd_afl_event_t
{
	SMD_AFL_SPACE_CREATE = 0,
	SMD_AFL_SPACE_GET,
	SMD_AFL_SPACE_UNREF,
	SMD_AFL_SPACE_REF,
	SMD_AFL_TYPE_CREATE,
	SMD_AFL_TYPE_VARIABLE_COUNT,
	SMD_AFL_TYPE_ADD_ATOMIC,
	SMD_AFL_TYPE_ADD_COMPOUND,
	SMD_AFL_TYPE_REMOVE_VARIABLE,
	SMD_AFL_TYPE_UNREF,
	SMD_AFL_TYPE_REF,
	SMD_AFL_TYPE_COPY,
	//SMD_AFL_TYPE_LIST
	SMD_AFL_FILE_CREATE,
	SMD_AFL_FILE_OPEN,
	SMD_AFL_FILE_DELETE,
	SMD_AFL_FILE_UNREF,
	SMD_AFL_FILE_REF,
	//SMD_AFL_FILE_GET_SCHEMES,
	//SMD_AFL_FILE_LIST,
	SMD_AFL_SCHEME_CREATE,
	SMD_AFL_SCHEME_OPEN,
	SMD_AFL_SCHEME_UNREF,
	SMD_AFL_SCHEME_DELETE,
	SMD_AFL_SCHEME_REF,
	_SMD_AFL_EVENT_COUNT
};
//configure here->
#define AFL_LIMIT_SPACE_COUNT 16
#define AFL_LIMIT_SPACE_DIMS_SIZE 10
#define AFL_LIMIT_TYPE_COUNT 16
#define AFL_LIMIT_TYPE_MAX_NAMES 16
#define AFL_LIMIT_TYPE_MAX_VARIABLES 16
#define AFL_LIMIT_FILE_COUNT 16
#define AFL_LIMIT_SCHEME_COUNT 16
//<-
#define MY_READ(var)                                                              \
	do                                                                        \
	{                                                                         \
		if (read(STDIN_FILENO, &var, sizeof(var)) < (ssize_t)sizeof(var)) \
			goto cleanup;                                             \
	} while (0)
#define MY_READ_MAX(var, max)      \
	do                         \
	{                          \
		MY_READ(var);      \
		var = var % (max); \
	} while (0)
#define MYABORT()                      \
	do                             \
	{                              \
		J_DEBUG("error%d", 0); \
		abort();               \
	} while (0)
void create_raw_test_files(const char* base_folder);
int
main(int argc, char* argv[])
{
	//between any tests ref_count == 1 OR pointers are NULL
	//space
	J_SMD_Space_t* space[AFL_LIMIT_SPACE_COUNT];
	guint space_ndims[AFL_LIMIT_SPACE_COUNT];
	guint space_dims[AFL_LIMIT_SPACE_COUNT][SMD_MAX_NDIMS];
	guint ndims;
	guint* dims;
	//type
	J_SMD_Type_t* type[AFL_LIMIT_TYPE_COUNT];
	guint type_var_count[AFL_LIMIT_TYPE_COUNT];
	guint type_last_offset[AFL_LIMIT_TYPE_COUNT];
	guint type_ndims;
	guint type_dims[SMD_MAX_NDIMS];
	char type_strbuf[SMD_MAX_NAME_LENGTH]; //TODO test NULL | too long
	//file
	J_Scheme_t* file[AFL_LIMIT_FILE_COUNT];
	char file_strbuf[SMD_MAX_NAME_LENGTH]; //TODO test NULL | too long
	//scheme
	J_Scheme_t* scheme[AFL_LIMIT_FILE_COUNT][AFL_LIMIT_SCHEME_COUNT];
	J_SMD_Type_t* scheme_type[AFL_LIMIT_FILE_COUNT][AFL_LIMIT_SCHEME_COUNT];
	J_SMD_Space_t* scheme_space[AFL_LIMIT_FILE_COUNT][AFL_LIMIT_SCHEME_COUNT];
	char scheme_strbuf[SMD_MAX_NAME_LENGTH]; //TODO test NULL | too long
	//shared
	g_autoptr(JBatch) batch = NULL;
	void* ptr;
	enum smd_afl_event_t event;
	guint idx;
	guint idx2;
	guint idx3;
	guint idx4;
	guint i, j;
	gboolean res;
	gboolean res_expected;
	if (argc > 1)
	{
		create_raw_test_files(argv[1]);
		return 0;
	}
	j_smd_debug_init();
	batch = j_batch_new_for_template(J_SEMANTICS_TEMPLATE_DEFAULT);
	for (i = 0; i < AFL_LIMIT_SPACE_COUNT; i++)
		space[i] = NULL;
	for (i = 0; i < AFL_LIMIT_TYPE_COUNT; i++)
		type[i] = NULL;
	for (i = 0; i < AFL_LIMIT_FILE_COUNT; i++)
	{
		file[i] = NULL;
		for (j = 0; j < AFL_LIMIT_SCHEME_COUNT; j++)
		{
			scheme[i][j] = NULL;
			scheme_type[i][j] = NULL;
			scheme_space[i][j] = NULL;
		}
	}
loop:
	MY_READ_MAX(event, _SMD_AFL_EVENT_COUNT);
	switch (event)
	{
	case SMD_AFL_SPACE_CREATE:
		MY_READ_MAX(idx, AFL_LIMIT_SPACE_COUNT);
		MY_READ_MAX(space_ndims[idx], SMD_MAX_NDIMS + 1);
		J_DEBUG("SMD_AFL_SPACE_CREATE idx=%d ndims=%d", idx, space_ndims[idx]);
		for (i = 0; i < SMD_MAX_NDIMS; i++)
		{
			if (i < space_ndims[idx])
				MY_READ_MAX(space_dims[idx][i], AFL_LIMIT_SPACE_DIMS_SIZE);
			else
				space_dims[idx][i] = 0;
		}
		if (space[idx])
		{
			res = j_smd_space_unref(space[idx]);
			if (res != FALSE)
				MYABORT();
		}
		space[idx] = j_smd_space_create(space_ndims[idx], space_dims[idx]);
		if (!space[idx] && space_ndims[idx] > 0 && space_ndims[idx] <= SMD_MAX_NDIMS)
			MYABORT();
		break;
	case SMD_AFL_SPACE_GET:
		MY_READ_MAX(idx, AFL_LIMIT_SPACE_COUNT);
		J_DEBUG("SMD_AFL_SPACE_GET idx=%d", idx);
		if (space[idx])
		{
			dims = NULL;
			res = j_smd_space_get(space[idx], &ndims, &dims);
			if (res == FALSE)
				MYABORT();
			if (ndims != space_ndims[idx])
				MYABORT();
			if (!dims)
				MYABORT();
			for (i = 0; i < ndims; i++)
				if (dims[i] != space_dims[idx][i])
					MYABORT();
			g_free(dims);
		}
		else
		{
			dims = NULL;
			res = j_smd_space_get(space[idx], &ndims, &dims);
			if (res != FALSE)
				MYABORT();
			if (dims)
				MYABORT();
		}
		break;
	case SMD_AFL_SPACE_UNREF:
		MY_READ_MAX(idx, AFL_LIMIT_SPACE_COUNT);
		J_DEBUG("SMD_AFL_SPACE_UNREF idx=%d", idx);
		res = j_smd_space_unref(space[idx]);
		if (res != FALSE)
			MYABORT();
		space[idx] = NULL;
		break;
	case SMD_AFL_SPACE_REF:
		MY_READ_MAX(idx, AFL_LIMIT_SPACE_COUNT);
		J_DEBUG("SMD_AFL_SPACE_REF idx=%d", idx);
		if (space[idx])
		{
			ptr = j_smd_space_ref(space[idx]);
			if (!ptr)
				MYABORT();
			res = j_smd_space_unref(space[idx]);
			if (res == FALSE)
				MYABORT();
		}
		else
		{
			ptr = j_smd_space_ref(space[idx]);
			if (ptr)
				MYABORT();
		}
		break;
	case SMD_AFL_TYPE_CREATE:
		MY_READ_MAX(idx, AFL_LIMIT_TYPE_COUNT);
		J_DEBUG("SMD_AFL_TYPE_CREATE idx=%d", idx);
		if (type[idx])
		{
			res = j_smd_type_unref(type[idx]);
			if (res != FALSE)
				MYABORT();
		}
		type[idx] = j_smd_type_create();
		if (!type[idx])
			MYABORT();
		type_var_count[idx] = 0;
		type_last_offset[idx] = 0;
		break;
	case SMD_AFL_TYPE_VARIABLE_COUNT:
		MY_READ_MAX(idx, AFL_LIMIT_TYPE_COUNT);
		J_DEBUG("SMD_AFL_TYPE_VARIABLE_COUNT idx=%d", idx);
		if (!type[idx])
		{
			if (j_smd_type_get_variable_count(type[idx]) != 0)
				MYABORT();
		}
		else
		{
			if (j_smd_type_get_variable_count(type[idx]) != type_var_count[idx])
				MYABORT();
		}
		break;
	case SMD_AFL_TYPE_ADD_COMPOUND:
		MY_READ_MAX(idx2, AFL_LIMIT_TYPE_COUNT);
		;
	case SMD_AFL_TYPE_ADD_ATOMIC:
		MY_READ_MAX(idx, AFL_LIMIT_TYPE_COUNT);
		if (event == SMD_AFL_TYPE_ADD_ATOMIC)
		{
			J_DEBUG("SMD_AFL_TYPE_ADD_ATOMIC idx=%d", idx);
		}
		else
		{
			J_DEBUG("SMD_AFL_TYPE_ADD_COMPOUND idx=%d idx2=%d", idx, idx2);
		}
		if (type[idx] && type_var_count[idx] == AFL_LIMIT_TYPE_MAX_VARIABLES)
		{
			res = j_smd_type_remove_variable(type[idx], g_array_index(type[idx]->arr, J_SMD_Variable_t, type[idx]->first_index).name);
			type_var_count[idx]--;
			if (res == FALSE)
				MYABORT();
			if (type_var_count[idx] != j_smd_type_get_variable_count(type[idx]))
				MYABORT();
		}
		MY_READ_MAX(type_ndims, SMD_MAX_NDIMS + 1);
		for (i = 0; i < SMD_MAX_NDIMS; i++)
		{
			if (i < type_ndims)
				MY_READ_MAX(type_dims[i], AFL_LIMIT_SPACE_DIMS_SIZE);
			else
				type_dims[i] = 0;
		}
		MY_READ_MAX(i, AFL_LIMIT_TYPE_MAX_NAMES);
		sprintf(type_strbuf, "var_%d", i);
		res_expected = TRUE;
		res_expected = res_expected && type[idx];
		res_expected = res_expected && type_ndims > 0 && type_ndims <= SMD_MAX_NDIMS;
		for (i = 0; i < type_ndims; i++)
			res_expected = res_expected && type_dims[i] > 0;
		//TODO duplicate variable names -> error
		//TODO duplicate offset -> error
		if (event == SMD_AFL_TYPE_ADD_ATOMIC)
		{
			res = j_smd_type_add_atomic_type(type[idx], type_strbuf, type_last_offset[idx], 4, SMD_TYPE_INT, type_ndims, type_dims);
		}
		else
		{
			res_expected = res_expected && type[idx2];
			res_expected = res_expected && idx != idx2;
			res_expected = res_expected && j_smd_type_get_variable_count(type[idx2]) > 0;
			res = j_smd_type_add_compound_type(type[idx], type_strbuf, type_last_offset[idx], 4, type[idx2], type_ndims, type_dims);
		}
		if (res != res_expected)
			MYABORT();
		if (res)
		{
			type_last_offset[idx] += 4;
			type_var_count[idx]++;
			if (type_var_count[idx] != j_smd_type_get_variable_count(type[idx]))
				MYABORT();
		}
		break;
	case SMD_AFL_TYPE_REMOVE_VARIABLE:
		MY_READ_MAX(idx, AFL_LIMIT_TYPE_COUNT);
		J_DEBUG("SMD_AFL_TYPE_REMOVE_VARIABLE idx=%d", idx);
		if (type[idx] && type_var_count[idx])
		{
			MY_READ_MAX(i, 3);
			switch (i)
			{
			case 0: //delete front
				res = j_smd_type_remove_variable(type[idx], g_array_index(type[idx]->arr, J_SMD_Variable_t, type[idx]->first_index).name);
				break;
			case 1: //delete last
				res = j_smd_type_remove_variable(type[idx], g_array_index(type[idx]->arr, J_SMD_Variable_t, type[idx]->last_index).name);
				break;
			case 2: //delete middle
				i = type[idx]->first_index + g_array_index(type[idx]->arr, J_SMD_Variable_t, type[idx]->first_index).nextindex;
				res = j_smd_type_remove_variable(type[idx], g_array_index(type[idx]->arr, J_SMD_Variable_t, i).name);
				break;
			default:
				MYABORT();
			}
			J_DEBUG("i %d", i);
			//TODO delete not existing member
			type_var_count[idx]--;
			if (res == FALSE)
				MYABORT();
			if (type_var_count[idx] != j_smd_type_get_variable_count(type[idx]))
				MYABORT();
		}
		break;
	case SMD_AFL_TYPE_UNREF:
		MY_READ_MAX(idx, AFL_LIMIT_TYPE_COUNT);
		J_DEBUG("SMD_AFL_TYPE_UNREF idx=%d", idx);
		res = j_smd_type_unref(type[idx]);
		if (res != FALSE)
			MYABORT();
		type[idx] = NULL;
		break;
	case SMD_AFL_TYPE_REF:
		MY_READ_MAX(idx, AFL_LIMIT_TYPE_COUNT);
		J_DEBUG("SMD_AFL_TYPE_REF idx=%d", idx);
		if (type[idx])
		{
			ptr = j_smd_type_ref(type[idx]);
			if (!ptr)
				MYABORT();
			res = j_smd_type_unref(type[idx]);
			if (res == FALSE)
				MYABORT();
		}
		else
		{
			ptr = j_smd_type_ref(type[idx]);
			if (ptr)
				MYABORT();
		}
		break;
	case SMD_AFL_TYPE_COPY:
		MY_READ_MAX(idx, AFL_LIMIT_TYPE_COUNT);
		J_DEBUG("SMD_AFL_TYPE_COPY idx=%d", idx);
		if (type[idx])
		{
			ptr = j_smd_type_copy(type[idx]);
			if (!ptr)
				MYABORT();
			res = j_smd_type_equals(ptr, type[idx]);
			if (res == FALSE)
				MYABORT();
			res = j_smd_type_unref(ptr);
			if (res != FALSE)
				MYABORT();
		}
		else
		{
			ptr = j_smd_type_copy(type[idx]);
			if (ptr)
				MYABORT();
		}
		break;
	case SMD_AFL_FILE_CREATE:
		MY_READ_MAX(idx, AFL_LIMIT_FILE_COUNT);
		J_DEBUG("SMD_AFL_FILE_CREATE idx=%d", idx);
		sprintf(file_strbuf, "file_%d", idx);
		if (file[idx])
		{
			j_smd_file_delete(file_strbuf, batch);
			j_batch_execute(batch);
			res = j_smd_file_unref(file[idx]);
			if (res != FALSE)
				MYABORT();
			for (j = 0; j < AFL_LIMIT_SCHEME_COUNT; j++)
			{
				res = j_smd_scheme_unref(scheme[idx][j]);
				if (res != FALSE)
					MYABORT();
				scheme[idx][j] = NULL;
			}
		}
		file[idx] = j_smd_file_create(file_strbuf, batch);
		if (!file[idx])
			MYABORT();
		j_batch_execute(batch);
		if (!j_smd_is_initialized(file[idx]))
			MYABORT();
		break;
	case SMD_AFL_FILE_UNREF:
	case SMD_AFL_FILE_DELETE:
		MY_READ_MAX(idx, AFL_LIMIT_FILE_COUNT);
		J_DEBUG("SMD_AFL_FILE_DELETE|UNREF idx=%d", idx);
		sprintf(file_strbuf, "file_%d", idx);
		res = j_smd_file_delete(file_strbuf, batch);
		j_batch_execute(batch);
		if (res == FALSE)
			MYABORT();
		res = j_smd_file_unref(file[idx]);
		if (res != FALSE)
			MYABORT();
		if (file[idx])
		{
			for (j = 0; j < AFL_LIMIT_SCHEME_COUNT; j++)
			{
				res = j_smd_scheme_unref(scheme[idx][j]);
				if (res != FALSE)
					MYABORT();
				scheme[idx][j] = NULL;
			}
		}
		file[idx] = NULL;
		break;
	case SMD_AFL_FILE_OPEN:
		MY_READ_MAX(idx, AFL_LIMIT_FILE_COUNT);
		J_DEBUG("SMD_AFL_FILE_OPEN idx=%d", idx);
		sprintf(file_strbuf, "file_%d", idx);
		ptr = file[idx];
		file[idx] = j_smd_file_open(file_strbuf, batch);
		j_batch_execute(batch);
		if (file[idx] == NULL)
			MYABORT();
		if ((j_smd_is_initialized(file[idx])) != (ptr != NULL))
			MYABORT();
		if (ptr)
		{
			res = j_smd_file_unref(ptr);
			if (res != FALSE)
				MYABORT();
		}
		else
		{
			res = j_smd_file_unref(file[idx]);
			if (res != FALSE)
				MYABORT();
			file[idx] = NULL;
		}
		break;
	case SMD_AFL_FILE_REF:
		MY_READ_MAX(idx, AFL_LIMIT_FILE_COUNT);
		J_DEBUG("SMD_AFL_FILE_REF idx=%d", idx);
		if (file[idx])
		{
			ptr = j_smd_file_ref(file[idx]);
			if (!ptr)
				MYABORT();
			res = j_smd_file_unref(file[idx]);
			if (res == FALSE)
				MYABORT();
		}
		else
		{
			ptr = j_smd_file_ref(file[idx]);
			if (ptr)
				MYABORT();
		}
		break;
	case SMD_AFL_SCHEME_DELETE:
	case SMD_AFL_SCHEME_UNREF:
		MY_READ_MAX(idx, AFL_LIMIT_FILE_COUNT);
		MY_READ_MAX(idx2, AFL_LIMIT_SCHEME_COUNT);
		J_DEBUG("SMD_AFL_SCHEME_DELETE|UNREF idx=%d idx2=%d", idx, idx2);
		sprintf(scheme_strbuf, "scheme_%d", idx2);
		if (file[idx] && scheme[idx][idx2])
		{
			res = j_smd_scheme_delete(scheme_strbuf, file[idx], batch);
			j_batch_execute(batch);
			if (res == FALSE)
				MYABORT();
		}
		res = j_smd_scheme_unref(scheme[idx][idx2]);
		if (res != FALSE)
			MYABORT();
		scheme[idx][idx2] = NULL;
		break;
	case SMD_AFL_SCHEME_REF:
		MY_READ_MAX(idx, AFL_LIMIT_FILE_COUNT);
		MY_READ_MAX(idx2, AFL_LIMIT_SCHEME_COUNT);
		J_DEBUG("SMD_AFL_SCHEME_REF idx=%d idx2=%d", idx, idx2);
		if (scheme[idx][idx2])
		{
			ptr = j_smd_scheme_ref(scheme[idx][idx2]);
			if (!ptr)
				MYABORT();
			res = j_smd_scheme_unref(scheme[idx][idx2]);
			if (res == FALSE)
				MYABORT();
		}
		else
		{
			ptr = j_smd_scheme_ref(scheme[idx][idx2]);
			if (ptr)
				MYABORT();
		}
		break;
	case SMD_AFL_SCHEME_CREATE:
		MY_READ_MAX(idx, AFL_LIMIT_FILE_COUNT);
		MY_READ_MAX(idx2, AFL_LIMIT_SCHEME_COUNT);
		MY_READ_MAX(idx3, AFL_LIMIT_TYPE_COUNT);
		MY_READ_MAX(idx4, AFL_LIMIT_SPACE_COUNT);
		J_DEBUG("SMD_AFL_SCHEME_CREATE idx=%d idx2=%d idx3=%d idx4=%d", idx, idx2, idx3, idx4);
		sprintf(scheme_strbuf, "scheme_%d", idx2);
		ptr = scheme[idx][idx2];
		res = j_smd_type_unref(scheme_type[idx][idx2]);
		if (res != FALSE)
			MYABORT();
		res = j_smd_space_unref(scheme_space[idx][idx2]);
		if (res != FALSE)
			MYABORT();
		scheme_type[idx][idx2] = j_smd_type_copy(type[idx3]);
		if (space[idx4])
			scheme_space[idx][idx2] = j_smd_space_create(space[idx4]->ndims, space[idx4]->dims);
		else
			scheme_space[idx][idx2] = NULL;
		scheme[idx][idx2] = j_smd_scheme_create(scheme_strbuf, file[idx], scheme_type[idx][idx2], scheme_space[idx][idx2], J_DISTRIBUTION_DATABASE, batch);
		if (!scheme[idx][idx2] && file[idx] && scheme_type[idx][idx2] && scheme_space[idx][idx2] && j_smd_type_get_variable_count(scheme_type[idx][idx2]))
			MYABORT();
		j_batch_execute(batch);
		if (scheme[idx][idx2] && ((j_smd_is_initialized(scheme[idx][idx2])) == (ptr != NULL)))
			MYABORT();
		if (ptr)
		{
			res = j_smd_scheme_delete(scheme_strbuf, file[idx], batch);
			if (res == FALSE)
				MYABORT();
			j_batch_execute(batch);
			res = j_smd_type_unref(scheme_type[idx][idx2]);
			if (res != FALSE)
				MYABORT();
			res = j_smd_space_unref(scheme_space[idx][idx2]);
			if (res != FALSE)
				MYABORT();
			res = j_smd_scheme_unref(scheme[idx][idx2]);
			if (res != FALSE)
				MYABORT();
		}
		res = j_smd_scheme_unref(ptr);
		if (res != FALSE)
			MYABORT();
		break;
	case SMD_AFL_SCHEME_OPEN:
		MY_READ_MAX(idx, AFL_LIMIT_FILE_COUNT);
		MY_READ_MAX(idx2, AFL_LIMIT_SCHEME_COUNT);
		J_DEBUG("SMD_AFL_SCHEME_OPEN idx=%d idx2=%d", idx, idx2);
		sprintf(scheme_strbuf, "scheme_%d", idx2);
		ptr = scheme[idx][idx2];
		scheme[idx][idx2] = j_smd_scheme_open(scheme_strbuf, file[idx], batch);
		if (scheme[idx][idx2] && (!file[idx]))
			MYABORT();
		if (!scheme[idx][idx2] && (file[idx]))
			MYABORT();
		j_batch_execute(batch);
		if (scheme[idx][idx2] && ((j_smd_is_initialized(scheme[idx][idx2])) != (ptr != NULL)))
			MYABORT();
		if (ptr)
		{
			res = j_smd_scheme_unref(ptr);
			if (res != FALSE)
				MYABORT();
			ptr = j_smd_scheme_get_type(scheme[idx][idx2]);
			if (!ptr)
				MYABORT();
			if (!j_smd_type_equals(ptr, scheme_type[idx][idx2]))
				MYABORT();
			res = j_smd_type_unref(ptr);
			if (res != FALSE)
				MYABORT();
			ptr = j_smd_scheme_get_space(scheme[idx][idx2]);
			if (!ptr)
				MYABORT();
			if (!j_smd_space_equals(ptr, scheme_space[idx][idx2]))
				MYABORT();
			res = j_smd_space_unref(ptr);
			if (res != FALSE)
				MYABORT();
		}
		else
		{
			res = j_smd_scheme_unref(scheme[idx][idx2]);
			if (res != FALSE)
				MYABORT();
			scheme[idx][idx2] = NULL;
		}
		break;
	case _SMD_AFL_EVENT_COUNT:
	default:
		J_DEBUG("invalid event %d", event);
		MYABORT();
	}
	goto loop;
cleanup:
	for (i = 0; i < AFL_LIMIT_SPACE_COUNT; i++)
	{
		res = j_smd_space_unref(space[i]);
		if (res != FALSE)
			MYABORT();
	}
	for (i = 0; i < AFL_LIMIT_TYPE_COUNT; i++)
	{
		res = j_smd_type_unref(type[i]);
		if (res != FALSE)
			MYABORT();
	}
	for (i = 0; i < AFL_LIMIT_FILE_COUNT; i++)
	{
		res = j_smd_file_unref(file[i]);
		if (res != FALSE)
			MYABORT();
		for (j = 0; j < AFL_LIMIT_SCHEME_COUNT; j++)
		{
			res = j_smd_scheme_unref(scheme[i][j]);
			if (res != FALSE)
				MYABORT();
			res = j_smd_type_unref(scheme_type[i][j]);
			if (res != FALSE)
				MYABORT();
			res = j_smd_space_unref(scheme_space[i][j]);
			if (res != FALSE)
				MYABORT();
		}
	}
	j_smd_debug_exit();
	return 0;
}

void
create_raw_test_files(const char* base_folder)
{
	enum smd_afl_event_t event;
	char filename[50 + strlen(base_folder)];
	guint i, j, k;
	FILE* file;
	mkdir(base_folder, S_IRUSR | S_IRGRP | S_IROTH);
	sprintf(filename, "%s/start-files", base_folder);
	mkdir(filename, S_IRUSR | S_IRGRP | S_IROTH);
	{
		for (i = 0; i <= SMD_MAX_NDIMS; i++)
		{
			sprintf(filename, "%s/start-files/SMD_AFL_SPACE_CREATE_%d.bin", base_folder, i);
			file = fopen(filename, "wb");
			event = SMD_AFL_SPACE_CREATE;
			fwrite(&event, sizeof(event), 1, file);
			fwrite(&i, sizeof(i), 1, file);
			fwrite(&i, sizeof(i), 1, file);
			for (j = 0; j < i; j++)
			{
				k = i + j;
				fwrite(&k, sizeof(k), 1, file);
			}
			fclose(file);
		}
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_SPACE_GET.bin", base_folder);
		file = fopen(filename, "wb");
		event = SMD_AFL_SPACE_GET;
		fwrite(&event, sizeof(event), 1, file);
		i = 0;
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_SPACE_UNREF.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_SPACE_UNREF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_SPACE_REF.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_SPACE_REF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_TYPE_CREATE.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_TYPE_CREATE;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_TYPE_VARIABLE_COUNT.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_TYPE_VARIABLE_COUNT;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		for (i = 0; i <= SMD_MAX_NDIMS; i++)
		{
			sprintf(filename, "%s/start-files/SMD_AFL_TYPE_ADD_ATOMIC_%d.bin", base_folder, i);
			file = fopen(filename, "wb");
			event = SMD_AFL_TYPE_ADD_ATOMIC;
			fwrite(&event, sizeof(event), 1, file);
			fwrite(&i, sizeof(i), 1, file);
			fwrite(&i, sizeof(i), 1, file);
			for (j = 0; j < i; j++)
			{
				k = i + j;
				fwrite(&k, sizeof(k), 1, file);
			}
			fwrite(&i, sizeof(i), 1, file);
			fclose(file);
			sprintf(filename, "%s/start-files/SMD_AFL_TYPE_ADD_COMPOUND_%d.bin", base_folder, i);
			file = fopen(filename, "wb");
			event = SMD_AFL_TYPE_ADD_COMPOUND;
			fwrite(&event, sizeof(event), 1, file);
			fwrite(&i, sizeof(i), 1, file);
			fwrite(&i, sizeof(i), 1, file);
			fwrite(&i, sizeof(i), 1, file);
			for (j = 0; j < i; j++)
			{
				k = i + j;
				fwrite(&k, sizeof(k), 1, file);
			}
			fwrite(&i, sizeof(i), 1, file);
			fclose(file);
		}
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_TYPE_REMOVE_VARIABLE.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_TYPE_REMOVE_VARIABLE;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_TYPE_UNREF.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_TYPE_UNREF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_TYPE_REF.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_TYPE_REF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_TYPE_COPY.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_TYPE_COPY;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_FILE_CREATE.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_FILE_CREATE;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_FILE_DELETE.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_FILE_DELETE;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_FILE_OPEN.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_FILE_OPEN;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_FILE_UNREF.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_FILE_UNREF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_FILE_REF.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_FILE_REF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_SCHEME_UNREF.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_SCHEME_UNREF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_SCHEME_DELETE.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_SCHEME_UNREF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_SCHEME_REF.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_SCHEME_REF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_SCHEME_CREATE.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_SCHEME_CREATE;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
}
