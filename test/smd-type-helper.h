#ifndef SMD_TYPE_TESTING_HELPER
#define SMD_TYPE_TESTING_HELPER

#include <julea-smd.h>

struct test_type_0
{
	int a;
};
struct test_type_1
{
	float a;
};
struct test_type_2
{
	char a[20];
};
struct test_type_3
{
	char a[10];
	char b[20];
};
struct test_type_4
{
	int a;
	float b[2][3];
};
struct test_type_5
{
	int a;
	float b[2][3];
	int c;
};
struct test_type_6
{
	int a;
	struct test_type_0 b;
	int c;
};
struct test_type_7
{
	int a;
	struct test_type_0 b[2][3];
	float c;
};
static guint _one = 1;

static void

_create_test_types(void*** _types, guint* count)
{
	guint two[] = { 2, 3 };
	guint i;
	void** types;
	*count = 8;
	*_types = g_new(void*, *count);
	types = *_types;
	for (i = 0; i < *count; i++)
	{
		types[i] = j_smd_type_create();
	}
	{
		J_SMD_TYPE_ADD_ATOMIC(types[0], struct test_type_0, a);
	}
	{
		J_SMD_TYPE_ADD_ATOMIC(types[1], struct test_type_1, a);
	}
	{
		J_SMD_TYPE_ADD_ATOMIC(types[2], struct test_type_2, a);
	}
	{
		J_SMD_TYPE_ADD_ATOMIC(types[3], struct test_type_2, a);
	}
	{
		J_SMD_TYPE_ADD_ATOMIC(types[4], struct test_type_4, a);
		J_SMD_TYPE_ADD_ATOMIC_DIMS2(types[4], struct test_type_4, b, two);
	}
	{
		J_SMD_TYPE_ADD_ATOMIC(types[5], struct test_type_5, a);
		J_SMD_TYPE_ADD_ATOMIC_DIMS2(types[5], struct test_type_5, b, two);
		J_SMD_TYPE_ADD_ATOMIC(types[5], struct test_type_5, c);
	}
	{
		J_SMD_TYPE_ADD_ATOMIC(types[6], struct test_type_6, a);
		J_SMD_TYPE_ADD_COMPOUND(types[6], struct test_type_6, b, types[0]);
		J_SMD_TYPE_ADD_ATOMIC(types[6], struct test_type_6, c);
	}
	{
		J_SMD_TYPE_ADD_ATOMIC(types[7], struct test_type_7, a);
		J_SMD_TYPE_ADD_COMPOUND_DIMS2(types[7], struct test_type_7, b, two, types[0]);
		J_SMD_TYPE_ADD_ATOMIC(types[7], struct test_type_7, c);
	}
}
#endif
