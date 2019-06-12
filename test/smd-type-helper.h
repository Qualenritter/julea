#ifndef SMD_TYPE_TESTING_HELPER
#define SMD_TYPE_TESTING_HELPER

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
	char* a;
};
struct test_type_3
{
	char* a;
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
static guint _one = 1;

#define J_SMD_GET_TYPE_HELPER(a) _Generic((a),              \
					  int               \
					  : SMD_TYPE_INT,   \
					  float             \
					  : SMD_TYPE_FLOAT, \
					  char*             \
					  : SMD_TYPE_BLOB,  \
					  default           \
					  : SMD_TYPE_UNKNOWN)

#define J_SMD_TYPE_ADD_ATOMIC(type, parent, var_name) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(((parent*)0)->var_name), J_SMD_GET_TYPE_HELPER(((parent*)0)->var_name), 1, &_one);
#define J_SMD_TYPE_ADD_ATOMIC_STRING(type, parent, var_name) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(((parent*)0)->var_name), SMD_TYPE_STRING, 1, &_one);
#define J_SMD_TYPE_ADD_ATOMIC_DIMS1(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(*((parent*)0)->var_name), J_SMD_GET_TYPE_HELPER(*((parent*)0)->var_name), 1, var_dims);
#define J_SMD_TYPE_ADD_ATOMIC_STRING_DIMS1(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(*((parent*)0)->var_name), SMD_TYPE_STRING, 1, var_dims);
#define J_SMD_TYPE_ADD_ATOMIC_DIMS2(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(**((parent*)0)->var_name), J_SMD_GET_TYPE_HELPER(**((parent*)0)->var_name), 2, var_dims);
#define J_SMD_TYPE_ADD_ATOMIC_STRING_DIMS2(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(**((parent*)0)->var_name), SMD_TYPE_STRING, 2, var_dims);
#define J_SMD_TYPE_ADD_ATOMIC_DIMS3(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(***((parent*)0)->var_name), J_SMD_GET_TYPE_HELPER(***((parent*)0)->var_name), 3, var_dims);
#define J_SMD_TYPE_ADD_ATOMIC_STRING_DIMS3(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(***((parent*)0)->var_name), SMD_TYPE_STRING, 3, var_dims);
#define J_SMD_TYPE_ADD_ATOMIC_DIMS4(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(****((parent*)0)->var_name), J_SMD_GET_TYPE_HELPER(****((parent*)0)->var_name), 4, var_dims);
#define J_SMD_TYPE_ADD_ATOMIC_STRING_DIMS4(type, parent, var_name, var_dims) \
	j_smd_type_add_atomic_type(type, #var_name, ((size_t) & ((parent*)0)->var_name), sizeof(****((parent*)0)->var_name), SMD_TYPE_STRING, 4, var_dims);

static void
_create_test_types(void*** _types, int* count)
{
	guint two[] = { 2, 3 };
	int i;
	void** types;
	*count = 6;
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
		J_SMD_TYPE_ADD_ATOMIC_STRING(types[3], struct test_type_3, a);
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
}
#endif
