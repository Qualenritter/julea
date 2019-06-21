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
	SMD_AFL_EVENT_COUNT
};
//configure here->
#define AFL_LIMIT_SPACE_COUNT 16
#define AFL_LIMIT_SPACE_DIMS_SIZE 10
#define AFL_LIMIT_TYPE_COUNT 16
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
void create_raw_test_files(const char* base_folder);
int
main(int argc, char* argv[])
{
	//space
	J_SMD_Space_t* space[AFL_LIMIT_SPACE_COUNT]; //ASSUME ref_count == 1 OR pointer to NULL
	guint space_ndims[AFL_LIMIT_SPACE_COUNT];
	guint space_dims[AFL_LIMIT_SPACE_COUNT][SMD_MAX_NDIMS];
	guint ndims;
	guint* dims;
	//type
	J_SMD_Type_t* type[AFL_LIMIT_TYPE_COUNT];
	guint type_var_count[AFL_LIMIT_TYPE_COUNT];
	guint type_last_offset[AFL_LIMIT_TYPE_COUNT];
	//shared
	void* ptr;
	enum smd_afl_event_t event;
	guint idx;
	guint i;
	gboolean res;

	if (argc > 1)
	{
		create_raw_test_files(argv[1]);
		return 0;
	}
	for (i = 0; i < AFL_LIMIT_SPACE_COUNT; i++)
		space[i] = NULL;
	for (i = 0; i < AFL_LIMIT_TYPE_COUNT; i++)
		type[i] = NULL;
loop:
	MY_READ_MAX(event, SMD_AFL_EVENT_COUNT);
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
				abort();
		}
		space[idx] = j_smd_space_create(space_ndims[idx], space_dims[idx]);
		if (!space[idx] && space_ndims[idx] > 0 && space_ndims[idx] <= SMD_MAX_NDIMS)
			abort();
		break;
	case SMD_AFL_SPACE_GET:
		MY_READ_MAX(idx, AFL_LIMIT_SPACE_COUNT);
		J_DEBUG("SMD_AFL_SPACE_GET idx=%d", idx);
		if (space[idx])
		{
			res = j_smd_space_get(space[idx], &ndims, &dims);
			if (res == FALSE)
				abort();
			if (!*dims)
				abort();
			if (ndims != space_ndims[idx])
				abort();
			for (i = 0; i < ndims; i++)
				if (dims[i] != space_dims[idx][i])
					abort();
			g_free(dims);
		}
		else
		{
			dims = NULL;
			res = j_smd_space_get(space[idx], &ndims, &dims);
			if (res != FALSE)
				abort();
			if (dims)
				abort();
		}
		break;
	case SMD_AFL_SPACE_UNREF:
		MY_READ_MAX(idx, AFL_LIMIT_SPACE_COUNT);
		J_DEBUG("SMD_AFL_SPACE_UNREF idx=%d", idx);
		if (space[idx])
		{
			res = j_smd_space_unref(space[idx]);
			space[idx] = NULL;
			if (res != FALSE)
				abort();
		}
		break;
	case SMD_AFL_SPACE_REF:
		MY_READ_MAX(idx, AFL_LIMIT_SPACE_COUNT);
		J_DEBUG("SMD_AFL_SPACE_REF idx=%d", idx);
		if (space[idx])
		{
			ptr = j_smd_space_ref(space[idx]);
			if (!ptr)
				abort();
			res = j_smd_space_unref(space[idx]);
			if (res == FALSE)
				abort();
		}
		else
		{
			ptr = j_smd_space_ref(space[idx]);
			if (ptr)
				abort();
		}
		break;
	case SMD_AFL_TYPE_CREATE:
		MY_READ_MAX(idx, AFL_LIMIT_TYPE_COUNT);
		J_DEBUG("SMD_AFL_TYPE_CREATE idx=%d", idx);
		if (type[idx])
		{
			res = j_smd_type_unref(type[i]);
			if (res == FALSE)
				abort();
		}
		type[idx] = j_smd_type_create();
		if (!type[idx])
			abort();
		type_var_count[idx] = 0;
		type_last_offset[idx] = 0;
		break;
	case SMD_AFL_TYPE_VARIABLE_COUNT:
		MY_READ_MAX(idx, AFL_LIMIT_TYPE_COUNT);
		J_DEBUG("SMD_AFL_TYPE_VARIABLE_COUNT idx=%d", idx);
		if (!type[idx])
		{
			type[idx] = j_smd_type_create();
			type_var_count[idx] = 0;
			type_last_offset[idx] = 0;
			if (!type[idx])
				abort();
		}
		i = j_smd_type_get_variable_count(type[idx]);
		if (i != type_var_count[idx])
			abort();
		break;
	case SMD_AFL_EVENT_COUNT:
	default:
		J_DEBUG("invalid event %d", event);
		abort();
	}
	goto loop;
cleanup:
	for (i = 0; i < AFL_LIMIT_SPACE_COUNT; i++)
	{
		res = j_smd_space_unref(space[i]);
		if (res != FALSE)
			abort();
	}
	for (i = 0; i < AFL_LIMIT_TYPE_COUNT; i++)
	{
		res = j_smd_type_unref(type[i]);
		if (res != FALSE)
			abort();
	}
	return 0; //return value does not matter
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
		for (i = 1; i < SMD_MAX_NDIMS; i++)
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
		event = SMD_AFL_SPACE_CREATE;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		event = SMD_AFL_SPACE_UNREF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_SPACE_REF_NULL.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_SPACE_REF;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fclose(file);
	}
	{
		sprintf(filename, "%s/start-files/SMD_AFL_SPACE_REF.bin", base_folder);
		file = fopen(filename, "wb");
		i = 1;
		event = SMD_AFL_SPACE_CREATE;
		fwrite(&event, sizeof(event), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fwrite(&i, sizeof(i), 1, file);
		fwrite(&i, sizeof(i), 1, file);
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
}
