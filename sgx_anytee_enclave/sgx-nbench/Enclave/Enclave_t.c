#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_test_function_t {
	const char* ms_str;
	size_t ms_str_len;
} ms_test_function_t;

typedef struct ms_add_t {
	int ms_retval;
	int ms_x;
	int ms_y;
} ms_add_t;

typedef struct ms_encl_AllocateMemory_t {
	size_t ms_size;
} ms_encl_AllocateMemory_t;

typedef struct ms_encl_AllocateMemory2_t {
	size_t ms_size;
} ms_encl_AllocateMemory2_t;

typedef struct ms_encl_AllocateMemory3_t {
	size_t ms_size;
} ms_encl_AllocateMemory3_t;

typedef struct ms_encl_AllocateMemory4_t {
	size_t ms_size;
} ms_encl_AllocateMemory4_t;

typedef struct ms_encl_AllocateMemory5_t {
	size_t ms_size;
} ms_encl_AllocateMemory5_t;

typedef struct ms_encl_LoadNumArrayWithRand_t {
	unsigned long int ms_arraysize;
	unsigned int ms_numarrays;
} ms_encl_LoadNumArrayWithRand_t;

typedef struct ms_encl_NumHeapSort_t {
	unsigned long int ms_base_offset;
	unsigned long int ms_bottom;
	unsigned long int ms_top;
} ms_encl_NumHeapSort_t;

typedef struct ms_encl_LoadStringArray_t {
	unsigned long int ms_retval;
	unsigned int ms_numarrays;
	unsigned long int ms_arraysize;
} ms_encl_LoadStringArray_t;

typedef struct ms_encl_call_StrHeapSort_t {
	unsigned long int ms_nstrings;
	unsigned int ms_numarrays;
	unsigned long int ms_arraysize;
} ms_encl_call_StrHeapSort_t;

typedef struct ms_encl_bitSetup_t {
	unsigned long int ms_retval;
	long int ms_bitfieldarraysize;
	long int ms_bitoparraysize;
} ms_encl_bitSetup_t;

typedef struct ms_encl_ToggleBitRun_t {
	unsigned long int ms_bit_addr;
	unsigned long int ms_nbits;
	unsigned int ms_val;
} ms_encl_ToggleBitRun_t;

typedef struct ms_encl_FlipBitRun_t {
	long int ms_bit_addr;
	long int ms_nbits;
} ms_encl_FlipBitRun_t;

typedef struct ms_encl_SetupCPUEmFloatArrays_t {
	unsigned long int ms_arraysize;
} ms_encl_SetupCPUEmFloatArrays_t;

typedef struct ms_encl_DoEmFloatIteration_t {
	unsigned long int ms_arraysize;
	unsigned long int ms_loops;
} ms_encl_DoEmFloatIteration_t;

typedef struct ms_encl_DoFPUTransIteration_t {
	unsigned long int ms_arraysize;
} ms_encl_DoFPUTransIteration_t;

typedef struct ms_encl_LoadAssignArrayWithRand_t {
	unsigned long int ms_numarrays;
} ms_encl_LoadAssignArrayWithRand_t;

typedef struct ms_encl_call_AssignmentTest_t {
	unsigned int ms_numarrays;
} ms_encl_call_AssignmentTest_t;

typedef struct ms_encl_app_loadIDEA_t {
	unsigned long int ms_arraysize;
} ms_encl_app_loadIDEA_t;

typedef struct ms_encl_callIDEA_t {
	unsigned long int ms_arraysize;
	unsigned short int* ms_Z;
	unsigned short int* ms_DK;
	unsigned long int ms_nloops;
} ms_encl_callIDEA_t;

typedef struct ms_encl_set_numpats_t {
	int ms_npats;
} ms_encl_set_numpats_t;

typedef struct ms_encl_get_in_pats_t {
	double ms_retval;
	int ms_patt;
	int ms_element;
} ms_encl_get_in_pats_t;

typedef struct ms_encl_set_in_pats_t {
	int ms_patt;
	int ms_element;
	double ms_val;
} ms_encl_set_in_pats_t;

typedef struct ms_encl_set_out_pats_t {
	int ms_patt;
	int ms_element;
	double ms_val;
} ms_encl_set_out_pats_t;

typedef struct ms_encl_DoNNetIteration_t {
	unsigned long int ms_nloops;
} ms_encl_DoNNetIteration_t;

typedef struct ms_encl_moveSeedArrays_t {
	unsigned long int ms_numarrays;
} ms_encl_moveSeedArrays_t;

typedef struct ms_encl_call_lusolve_t {
	unsigned long int ms_numarrays;
} ms_encl_call_lusolve_t;

typedef struct ms_encl_callHuffman_t {
	unsigned long int ms_nloops;
	unsigned long int ms_arraysize;
} ms_encl_callHuffman_t;

typedef struct ms_encl_buildHuffman_t {
	unsigned long int ms_arraysize;
} ms_encl_buildHuffman_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL sgx_test_function(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_test_function_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_test_function_t* ms = SGX_CAST(ms_test_function_t*, pms);
	ms_test_function_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_test_function_t), ms, sizeof(ms_test_function_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_str = __in_ms.ms_str;
	size_t _len_str = __in_ms.ms_str_len ;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str, _len_str, _tmp_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str[_len_str - 1] = '\0';
		if (_len_str != strlen(_in_str) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	test_function((const char*)_in_str);

err:
	if (_in_str) free(_in_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_add(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_add_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_add_t* ms = SGX_CAST(ms_add_t*, pms);
	ms_add_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_add_t), ms, sizeof(ms_add_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = add(__in_ms.ms_x, __in_ms.ms_y);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_nothing(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	nothing();
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_AllocateMemory(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_AllocateMemory_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_AllocateMemory_t* ms = SGX_CAST(ms_encl_AllocateMemory_t*, pms);
	ms_encl_AllocateMemory_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_AllocateMemory_t), ms, sizeof(ms_encl_AllocateMemory_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_AllocateMemory(__in_ms.ms_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_AllocateMemory2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_AllocateMemory2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_AllocateMemory2_t* ms = SGX_CAST(ms_encl_AllocateMemory2_t*, pms);
	ms_encl_AllocateMemory2_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_AllocateMemory2_t), ms, sizeof(ms_encl_AllocateMemory2_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_AllocateMemory2(__in_ms.ms_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_AllocateMemory3(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_AllocateMemory3_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_AllocateMemory3_t* ms = SGX_CAST(ms_encl_AllocateMemory3_t*, pms);
	ms_encl_AllocateMemory3_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_AllocateMemory3_t), ms, sizeof(ms_encl_AllocateMemory3_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_AllocateMemory3(__in_ms.ms_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_AllocateMemory4(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_AllocateMemory4_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_AllocateMemory4_t* ms = SGX_CAST(ms_encl_AllocateMemory4_t*, pms);
	ms_encl_AllocateMemory4_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_AllocateMemory4_t), ms, sizeof(ms_encl_AllocateMemory4_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_AllocateMemory4(__in_ms.ms_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_AllocateMemory5(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_AllocateMemory5_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_AllocateMemory5_t* ms = SGX_CAST(ms_encl_AllocateMemory5_t*, pms);
	ms_encl_AllocateMemory5_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_AllocateMemory5_t), ms, sizeof(ms_encl_AllocateMemory5_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_AllocateMemory5(__in_ms.ms_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_FreeMemory(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	encl_FreeMemory();
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_FreeMemory2(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	encl_FreeMemory2();
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_FreeMemory3(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	encl_FreeMemory3();
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_FreeMemory4(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	encl_FreeMemory4();
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_FreeMemory5(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	encl_FreeMemory5();
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_LoadNumArrayWithRand(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_LoadNumArrayWithRand_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_LoadNumArrayWithRand_t* ms = SGX_CAST(ms_encl_LoadNumArrayWithRand_t*, pms);
	ms_encl_LoadNumArrayWithRand_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_LoadNumArrayWithRand_t), ms, sizeof(ms_encl_LoadNumArrayWithRand_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_LoadNumArrayWithRand(__in_ms.ms_arraysize, __in_ms.ms_numarrays);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_NumHeapSort(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_NumHeapSort_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_NumHeapSort_t* ms = SGX_CAST(ms_encl_NumHeapSort_t*, pms);
	ms_encl_NumHeapSort_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_NumHeapSort_t), ms, sizeof(ms_encl_NumHeapSort_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_NumHeapSort(__in_ms.ms_base_offset, __in_ms.ms_bottom, __in_ms.ms_top);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_LoadStringArray(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_LoadStringArray_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_LoadStringArray_t* ms = SGX_CAST(ms_encl_LoadStringArray_t*, pms);
	ms_encl_LoadStringArray_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_LoadStringArray_t), ms, sizeof(ms_encl_LoadStringArray_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned long int _in_retval;


	_in_retval = encl_LoadStringArray(__in_ms.ms_numarrays, __in_ms.ms_arraysize);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_call_StrHeapSort(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_call_StrHeapSort_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_call_StrHeapSort_t* ms = SGX_CAST(ms_encl_call_StrHeapSort_t*, pms);
	ms_encl_call_StrHeapSort_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_call_StrHeapSort_t), ms, sizeof(ms_encl_call_StrHeapSort_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_call_StrHeapSort(__in_ms.ms_nstrings, __in_ms.ms_numarrays, __in_ms.ms_arraysize);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_bitSetup(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_bitSetup_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_bitSetup_t* ms = SGX_CAST(ms_encl_bitSetup_t*, pms);
	ms_encl_bitSetup_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_bitSetup_t), ms, sizeof(ms_encl_bitSetup_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned long int _in_retval;


	_in_retval = encl_bitSetup(__in_ms.ms_bitfieldarraysize, __in_ms.ms_bitoparraysize);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_ToggleBitRun(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_ToggleBitRun_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_ToggleBitRun_t* ms = SGX_CAST(ms_encl_ToggleBitRun_t*, pms);
	ms_encl_ToggleBitRun_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_ToggleBitRun_t), ms, sizeof(ms_encl_ToggleBitRun_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_ToggleBitRun(__in_ms.ms_bit_addr, __in_ms.ms_nbits, __in_ms.ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_FlipBitRun(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_FlipBitRun_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_FlipBitRun_t* ms = SGX_CAST(ms_encl_FlipBitRun_t*, pms);
	ms_encl_FlipBitRun_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_FlipBitRun_t), ms, sizeof(ms_encl_FlipBitRun_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_FlipBitRun(__in_ms.ms_bit_addr, __in_ms.ms_nbits);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_SetupCPUEmFloatArrays(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_SetupCPUEmFloatArrays_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_SetupCPUEmFloatArrays_t* ms = SGX_CAST(ms_encl_SetupCPUEmFloatArrays_t*, pms);
	ms_encl_SetupCPUEmFloatArrays_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_SetupCPUEmFloatArrays_t), ms, sizeof(ms_encl_SetupCPUEmFloatArrays_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_SetupCPUEmFloatArrays(__in_ms.ms_arraysize);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_DoEmFloatIteration(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_DoEmFloatIteration_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_DoEmFloatIteration_t* ms = SGX_CAST(ms_encl_DoEmFloatIteration_t*, pms);
	ms_encl_DoEmFloatIteration_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_DoEmFloatIteration_t), ms, sizeof(ms_encl_DoEmFloatIteration_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_DoEmFloatIteration(__in_ms.ms_arraysize, __in_ms.ms_loops);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_DoFPUTransIteration(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_DoFPUTransIteration_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_DoFPUTransIteration_t* ms = SGX_CAST(ms_encl_DoFPUTransIteration_t*, pms);
	ms_encl_DoFPUTransIteration_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_DoFPUTransIteration_t), ms, sizeof(ms_encl_DoFPUTransIteration_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_DoFPUTransIteration(__in_ms.ms_arraysize);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_LoadAssignArrayWithRand(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_LoadAssignArrayWithRand_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_LoadAssignArrayWithRand_t* ms = SGX_CAST(ms_encl_LoadAssignArrayWithRand_t*, pms);
	ms_encl_LoadAssignArrayWithRand_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_LoadAssignArrayWithRand_t), ms, sizeof(ms_encl_LoadAssignArrayWithRand_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_LoadAssignArrayWithRand(__in_ms.ms_numarrays);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_call_AssignmentTest(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_call_AssignmentTest_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_call_AssignmentTest_t* ms = SGX_CAST(ms_encl_call_AssignmentTest_t*, pms);
	ms_encl_call_AssignmentTest_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_call_AssignmentTest_t), ms, sizeof(ms_encl_call_AssignmentTest_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_call_AssignmentTest(__in_ms.ms_numarrays);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_app_loadIDEA(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_app_loadIDEA_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_app_loadIDEA_t* ms = SGX_CAST(ms_encl_app_loadIDEA_t*, pms);
	ms_encl_app_loadIDEA_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_app_loadIDEA_t), ms, sizeof(ms_encl_app_loadIDEA_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_app_loadIDEA(__in_ms.ms_arraysize);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_callIDEA(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_callIDEA_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_callIDEA_t* ms = SGX_CAST(ms_encl_callIDEA_t*, pms);
	ms_encl_callIDEA_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_callIDEA_t), ms, sizeof(ms_encl_callIDEA_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned short int* _tmp_Z = __in_ms.ms_Z;
	size_t _len_Z = 52 * sizeof(unsigned short int);
	unsigned short int* _in_Z = NULL;
	unsigned short int* _tmp_DK = __in_ms.ms_DK;
	size_t _len_DK = 52 * sizeof(unsigned short int);
	unsigned short int* _in_DK = NULL;

	if (sizeof(*_tmp_Z) != 0 &&
		52 > (SIZE_MAX / sizeof(*_tmp_Z))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_DK) != 0 &&
		52 > (SIZE_MAX / sizeof(*_tmp_DK))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_Z, _len_Z);
	CHECK_UNIQUE_POINTER(_tmp_DK, _len_DK);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_Z != NULL && _len_Z != 0) {
		if ( _len_Z % sizeof(*_tmp_Z) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_Z = (unsigned short int*)malloc(_len_Z);
		if (_in_Z == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_Z, _len_Z, _tmp_Z, _len_Z)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_DK != NULL && _len_DK != 0) {
		if ( _len_DK % sizeof(*_tmp_DK) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_DK = (unsigned short int*)malloc(_len_DK);
		if (_in_DK == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_DK, _len_DK, _tmp_DK, _len_DK)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	encl_callIDEA(__in_ms.ms_arraysize, _in_Z, _in_DK, __in_ms.ms_nloops);

err:
	if (_in_Z) free(_in_Z);
	if (_in_DK) free(_in_DK);
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_set_numpats(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_set_numpats_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_set_numpats_t* ms = SGX_CAST(ms_encl_set_numpats_t*, pms);
	ms_encl_set_numpats_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_set_numpats_t), ms, sizeof(ms_encl_set_numpats_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_set_numpats(__in_ms.ms_npats);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_get_in_pats(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_get_in_pats_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_get_in_pats_t* ms = SGX_CAST(ms_encl_get_in_pats_t*, pms);
	ms_encl_get_in_pats_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_get_in_pats_t), ms, sizeof(ms_encl_get_in_pats_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	double _in_retval;


	_in_retval = encl_get_in_pats(__in_ms.ms_patt, __in_ms.ms_element);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_set_in_pats(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_set_in_pats_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_set_in_pats_t* ms = SGX_CAST(ms_encl_set_in_pats_t*, pms);
	ms_encl_set_in_pats_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_set_in_pats_t), ms, sizeof(ms_encl_set_in_pats_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_set_in_pats(__in_ms.ms_patt, __in_ms.ms_element, __in_ms.ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_set_out_pats(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_set_out_pats_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_set_out_pats_t* ms = SGX_CAST(ms_encl_set_out_pats_t*, pms);
	ms_encl_set_out_pats_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_set_out_pats_t), ms, sizeof(ms_encl_set_out_pats_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_set_out_pats(__in_ms.ms_patt, __in_ms.ms_element, __in_ms.ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_DoNNetIteration(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_DoNNetIteration_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_DoNNetIteration_t* ms = SGX_CAST(ms_encl_DoNNetIteration_t*, pms);
	ms_encl_DoNNetIteration_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_DoNNetIteration_t), ms, sizeof(ms_encl_DoNNetIteration_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_DoNNetIteration(__in_ms.ms_nloops);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_moveSeedArrays(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_moveSeedArrays_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_moveSeedArrays_t* ms = SGX_CAST(ms_encl_moveSeedArrays_t*, pms);
	ms_encl_moveSeedArrays_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_moveSeedArrays_t), ms, sizeof(ms_encl_moveSeedArrays_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_moveSeedArrays(__in_ms.ms_numarrays);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_call_lusolve(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_call_lusolve_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_call_lusolve_t* ms = SGX_CAST(ms_encl_call_lusolve_t*, pms);
	ms_encl_call_lusolve_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_call_lusolve_t), ms, sizeof(ms_encl_call_lusolve_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_call_lusolve(__in_ms.ms_numarrays);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_build_problem(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	encl_build_problem();
	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_callHuffman(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_callHuffman_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_callHuffman_t* ms = SGX_CAST(ms_encl_callHuffman_t*, pms);
	ms_encl_callHuffman_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_callHuffman_t), ms, sizeof(ms_encl_callHuffman_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_callHuffman(__in_ms.ms_nloops, __in_ms.ms_arraysize);


	return status;
}

static sgx_status_t SGX_CDECL sgx_encl_buildHuffman(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encl_buildHuffman_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encl_buildHuffman_t* ms = SGX_CAST(ms_encl_buildHuffman_t*, pms);
	ms_encl_buildHuffman_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encl_buildHuffman_t), ms, sizeof(ms_encl_buildHuffman_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	encl_buildHuffman(__in_ms.ms_arraysize);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[37];
} g_ecall_table = {
	37,
	{
		{(void*)(uintptr_t)sgx_test_function, 0, 0},
		{(void*)(uintptr_t)sgx_add, 0, 0},
		{(void*)(uintptr_t)sgx_nothing, 0, 0},
		{(void*)(uintptr_t)sgx_encl_AllocateMemory, 0, 0},
		{(void*)(uintptr_t)sgx_encl_AllocateMemory2, 0, 0},
		{(void*)(uintptr_t)sgx_encl_AllocateMemory3, 0, 0},
		{(void*)(uintptr_t)sgx_encl_AllocateMemory4, 0, 0},
		{(void*)(uintptr_t)sgx_encl_AllocateMemory5, 0, 0},
		{(void*)(uintptr_t)sgx_encl_FreeMemory, 0, 0},
		{(void*)(uintptr_t)sgx_encl_FreeMemory2, 0, 0},
		{(void*)(uintptr_t)sgx_encl_FreeMemory3, 0, 0},
		{(void*)(uintptr_t)sgx_encl_FreeMemory4, 0, 0},
		{(void*)(uintptr_t)sgx_encl_FreeMemory5, 0, 0},
		{(void*)(uintptr_t)sgx_encl_LoadNumArrayWithRand, 0, 0},
		{(void*)(uintptr_t)sgx_encl_NumHeapSort, 0, 0},
		{(void*)(uintptr_t)sgx_encl_LoadStringArray, 0, 0},
		{(void*)(uintptr_t)sgx_encl_call_StrHeapSort, 0, 0},
		{(void*)(uintptr_t)sgx_encl_bitSetup, 0, 0},
		{(void*)(uintptr_t)sgx_encl_ToggleBitRun, 0, 0},
		{(void*)(uintptr_t)sgx_encl_FlipBitRun, 0, 0},
		{(void*)(uintptr_t)sgx_encl_SetupCPUEmFloatArrays, 0, 0},
		{(void*)(uintptr_t)sgx_encl_DoEmFloatIteration, 0, 0},
		{(void*)(uintptr_t)sgx_encl_DoFPUTransIteration, 0, 0},
		{(void*)(uintptr_t)sgx_encl_LoadAssignArrayWithRand, 0, 0},
		{(void*)(uintptr_t)sgx_encl_call_AssignmentTest, 0, 0},
		{(void*)(uintptr_t)sgx_encl_app_loadIDEA, 0, 0},
		{(void*)(uintptr_t)sgx_encl_callIDEA, 0, 0},
		{(void*)(uintptr_t)sgx_encl_set_numpats, 0, 0},
		{(void*)(uintptr_t)sgx_encl_get_in_pats, 0, 0},
		{(void*)(uintptr_t)sgx_encl_set_in_pats, 0, 0},
		{(void*)(uintptr_t)sgx_encl_set_out_pats, 0, 0},
		{(void*)(uintptr_t)sgx_encl_DoNNetIteration, 0, 0},
		{(void*)(uintptr_t)sgx_encl_moveSeedArrays, 0, 0},
		{(void*)(uintptr_t)sgx_encl_call_lusolve, 0, 0},
		{(void*)(uintptr_t)sgx_encl_build_problem, 0, 0},
		{(void*)(uintptr_t)sgx_encl_callHuffman, 0, 0},
		{(void*)(uintptr_t)sgx_encl_buildHuffman, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][37];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

