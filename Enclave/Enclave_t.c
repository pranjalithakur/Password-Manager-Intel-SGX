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


typedef struct ms_ecall_get_account_t {
	int* ms_result;
} ms_ecall_get_account_t;

typedef struct ms_ecall_auth_t {
	const char* ms_master_pass;
	size_t ms_master_pass_size;
} ms_ecall_auth_t;

typedef struct ms_ecall_verify_master_password_t {
	const char* ms_input;
	size_t ms_input_len;
	const char* ms_actual;
	size_t ms_actual_len;
	int* ms_result;
} ms_ecall_verify_master_password_t;

typedef struct ms_seal_t {
	sgx_status_t ms_retval;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_len;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_seal_t;

typedef struct ms_unseal_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	uint8_t* ms_plaintext;
	uint32_t ms_plaintext_len;
} ms_unseal_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_read_file_t {
	int* ms_err_code;
	const char* ms_file_path;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_ocall_read_file_t;

typedef struct ms_ocall_get_string_t {
	int* ms_result;
	char* ms_str_buffer;
	size_t ms_buffer_size;
} ms_ocall_get_string_t;

typedef struct ms_ocall_remove_file_t {
	const char* ms_file_path;
} ms_ocall_remove_file_t;

static sgx_status_t SGX_CDECL sgx_ecall_get_account(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_account_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_account_t* ms = SGX_CAST(ms_ecall_get_account_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_result = ms->ms_result;
	size_t _len_result = sizeof(int);
	int* _in_result = NULL;

	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (int*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ecall_get_account(_in_result);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_account(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_create_account();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_auth(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_auth_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_auth_t* ms = SGX_CAST(ms_ecall_auth_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_pass = ms->ms_master_pass;
	size_t _tmp_master_pass_size = ms->ms_master_pass_size;
	size_t _len_master_pass = _tmp_master_pass_size;
	char* _in_master_pass = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_pass, _len_master_pass);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_pass != NULL && _len_master_pass != 0) {
		if ( _len_master_pass % sizeof(*_tmp_master_pass) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_master_pass = (char*)malloc(_len_master_pass);
		if (_in_master_pass == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_pass, _len_master_pass, _tmp_master_pass, _len_master_pass)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_auth((const char*)_in_master_pass, _tmp_master_pass_size);

err:
	if (_in_master_pass) free(_in_master_pass);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_verify_master_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_verify_master_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_verify_master_password_t* ms = SGX_CAST(ms_ecall_verify_master_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_input = ms->ms_input;
	size_t _tmp_input_len = ms->ms_input_len;
	size_t _len_input = _tmp_input_len;
	char* _in_input = NULL;
	const char* _tmp_actual = ms->ms_actual;
	size_t _tmp_actual_len = ms->ms_actual_len;
	size_t _len_actual = _tmp_actual_len;
	char* _in_actual = NULL;
	int* _tmp_result = ms->ms_result;
	size_t _len_result = sizeof(int);
	int* _in_result = NULL;

	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_actual, _len_actual);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input != NULL && _len_input != 0) {
		if ( _len_input % sizeof(*_tmp_input) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_input = (char*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_input, _len_input, _tmp_input, _len_input)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_actual != NULL && _len_actual != 0) {
		if ( _len_actual % sizeof(*_tmp_actual) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_actual = (char*)malloc(_len_actual);
		if (_in_actual == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_actual, _len_actual, _tmp_actual, _len_actual)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (int*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}

	ecall_verify_master_password((const char*)_in_input, _tmp_input_len, (const char*)_in_actual, _tmp_actual_len, _in_result);
	if (_in_result) {
		if (memcpy_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_input) free(_in_input);
	if (_in_actual) free(_in_actual);
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_t* ms = SGX_CAST(ms_seal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	size_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_plaintext = (uint8_t*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plaintext, _len_plaintext, _tmp_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ((_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}

	ms->ms_retval = seal(_in_plaintext, _tmp_plaintext_len, _in_sealed_data, _tmp_sealed_size);
	if (_in_sealed_data) {
		if (memcpy_s(_tmp_sealed_data, _len_sealed_data, _in_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_plaintext) free(_in_plaintext);
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_unseal_t* ms = SGX_CAST(ms_unseal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	uint32_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_plaintext = (uint8_t*)malloc(_len_plaintext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plaintext, 0, _len_plaintext);
	}

	ms->ms_retval = unseal(_in_sealed_data, _tmp_sealed_size, _in_plaintext, _tmp_plaintext_len);
	if (_in_plaintext) {
		if (memcpy_s(_tmp_plaintext, _len_plaintext, _in_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_plaintext) free(_in_plaintext);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_ecall_get_account, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_account, 1, 0},
		{(void*)(uintptr_t)sgx_ecall_auth, 1, 0},
		{(void*)(uintptr_t)sgx_ecall_verify_master_password, 0, 0},
		{(void*)(uintptr_t)sgx_seal, 0, 0},
		{(void*)(uintptr_t)sgx_unseal, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[4][6];
} g_dyn_entry_table = {
	4,
	{
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
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

sgx_status_t SGX_CDECL ocall_read_file(int* err_code, const char* file_path, uint8_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_err_code = sizeof(int);
	size_t _len_file_path = file_path ? strlen(file_path) + 1 : 0;
	size_t _len_sealed_data = sealed_size;

	ms_ocall_read_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_file_t);
	void *__tmp = NULL;

	void *__tmp_err_code = NULL;
	void *__tmp_sealed_data = NULL;

	CHECK_ENCLAVE_POINTER(err_code, _len_err_code);
	CHECK_ENCLAVE_POINTER(file_path, _len_file_path);
	CHECK_ENCLAVE_POINTER(sealed_data, _len_sealed_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (err_code != NULL) ? _len_err_code : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_path != NULL) ? _len_file_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_data != NULL) ? _len_sealed_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_file_t));
	ocalloc_size -= sizeof(ms_ocall_read_file_t);

	if (err_code != NULL) {
		ms->ms_err_code = (int*)__tmp;
		__tmp_err_code = __tmp;
		if (_len_err_code % sizeof(*err_code) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_err_code, 0, _len_err_code);
		__tmp = (void *)((size_t)__tmp + _len_err_code);
		ocalloc_size -= _len_err_code;
	} else {
		ms->ms_err_code = NULL;
	}
	
	if (file_path != NULL) {
		ms->ms_file_path = (const char*)__tmp;
		if (_len_file_path % sizeof(*file_path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, file_path, _len_file_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_file_path);
		ocalloc_size -= _len_file_path;
	} else {
		ms->ms_file_path = NULL;
	}
	
	if (sealed_data != NULL) {
		ms->ms_sealed_data = (uint8_t*)__tmp;
		__tmp_sealed_data = __tmp;
		if (_len_sealed_data % sizeof(*sealed_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_sealed_data, 0, _len_sealed_data);
		__tmp = (void *)((size_t)__tmp + _len_sealed_data);
		ocalloc_size -= _len_sealed_data;
	} else {
		ms->ms_sealed_data = NULL;
	}
	
	ms->ms_sealed_size = sealed_size;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (err_code) {
			if (memcpy_s((void*)err_code, _len_err_code, __tmp_err_code, _len_err_code)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (sealed_data) {
			if (memcpy_s((void*)sealed_data, _len_sealed_data, __tmp_sealed_data, _len_sealed_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_string(int* result, char* str_buffer, size_t buffer_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_result = sizeof(int);
	size_t _len_str_buffer = buffer_size;

	ms_ocall_get_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_string_t);
	void *__tmp = NULL;

	void *__tmp_result = NULL;
	void *__tmp_str_buffer = NULL;

	CHECK_ENCLAVE_POINTER(result, _len_result);
	CHECK_ENCLAVE_POINTER(str_buffer, _len_str_buffer);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (result != NULL) ? _len_result : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str_buffer != NULL) ? _len_str_buffer : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_string_t));
	ocalloc_size -= sizeof(ms_ocall_get_string_t);

	if (result != NULL) {
		ms->ms_result = (int*)__tmp;
		__tmp_result = __tmp;
		if (_len_result % sizeof(*result) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_result, 0, _len_result);
		__tmp = (void *)((size_t)__tmp + _len_result);
		ocalloc_size -= _len_result;
	} else {
		ms->ms_result = NULL;
	}
	
	if (str_buffer != NULL) {
		ms->ms_str_buffer = (char*)__tmp;
		__tmp_str_buffer = __tmp;
		if (_len_str_buffer % sizeof(*str_buffer) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_str_buffer, 0, _len_str_buffer);
		__tmp = (void *)((size_t)__tmp + _len_str_buffer);
		ocalloc_size -= _len_str_buffer;
	} else {
		ms->ms_str_buffer = NULL;
	}
	
	ms->ms_buffer_size = buffer_size;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (result) {
			if (memcpy_s((void*)result, _len_result, __tmp_result, _len_result)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (str_buffer) {
			if (memcpy_s((void*)str_buffer, _len_str_buffer, __tmp_str_buffer, _len_str_buffer)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_remove_file(const char* file_path)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file_path = file_path ? strlen(file_path) + 1 : 0;

	ms_ocall_remove_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_remove_file_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(file_path, _len_file_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_path != NULL) ? _len_file_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_remove_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_remove_file_t));
	ocalloc_size -= sizeof(ms_ocall_remove_file_t);

	if (file_path != NULL) {
		ms->ms_file_path = (const char*)__tmp;
		if (_len_file_path % sizeof(*file_path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, file_path, _len_file_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_file_path);
		ocalloc_size -= _len_file_path;
	} else {
		ms->ms_file_path = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

