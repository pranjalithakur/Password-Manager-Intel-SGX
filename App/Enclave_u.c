#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read_file(void* pms)
{
	ms_ocall_read_file_t* ms = SGX_CAST(ms_ocall_read_file_t*, pms);
	ocall_read_file(ms->ms_err_code, ms->ms_file_path, ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_string(void* pms)
{
	ms_ocall_get_string_t* ms = SGX_CAST(ms_ocall_get_string_t*, pms);
	ocall_get_string(ms->ms_result, ms->ms_str_buffer, ms->ms_buffer_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_remove_file(void* pms)
{
	ms_ocall_remove_file_t* ms = SGX_CAST(ms_ocall_remove_file_t*, pms);
	ocall_remove_file(ms->ms_file_path);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[4];
} ocall_table_Enclave = {
	4,
	{
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_read_file,
		(void*)Enclave_ocall_get_string,
		(void*)Enclave_ocall_remove_file,
	}
};
sgx_status_t ecall_get_account(sgx_enclave_id_t eid, int* result)
{
	sgx_status_t status;
	ms_ecall_get_account_t ms;
	ms.ms_result = result;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_create_account(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_auth(sgx_enclave_id_t eid, const char* master_pass, size_t master_pass_size)
{
	sgx_status_t status;
	ms_ecall_auth_t ms;
	ms.ms_master_pass = master_pass;
	ms.ms_master_pass_size = master_pass_size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_verify_master_password(sgx_enclave_id_t eid, const char* input, size_t input_len, const char* actual, size_t actual_len, int* result)
{
	sgx_status_t status;
	ms_ecall_verify_master_password_t ms;
	ms.ms_input = input;
	ms.ms_input_len = input_len;
	ms.ms_actual = actual;
	ms.ms_actual_len = actual_len;
	ms.ms_result = result;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status;
	ms_seal_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len)
{
	sgx_status_t status;
	ms_unseal_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

