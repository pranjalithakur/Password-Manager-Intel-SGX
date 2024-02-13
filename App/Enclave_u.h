#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef OCALL_READ_FILE_DEFINED__
#define OCALL_READ_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_file, (int* err_code, const char* file_path, uint8_t* sealed_data, size_t sealed_size));
#endif
#ifndef OCALL_GET_STRING_DEFINED__
#define OCALL_GET_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_string, (int* result, char* str_buffer, size_t buffer_size));
#endif
#ifndef OCALL_REMOVE_FILE_DEFINED__
#define OCALL_REMOVE_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_remove_file, (const char* file_path));
#endif

sgx_status_t ecall_get_account(sgx_enclave_id_t eid, int* result);
sgx_status_t ecall_create_account(sgx_enclave_id_t eid);
sgx_status_t ecall_auth(sgx_enclave_id_t eid, const char* master_pass, size_t master_pass_size);
sgx_status_t ecall_verify_master_password(sgx_enclave_id_t eid, const char* input, size_t input_len, const char* actual, size_t actual_len, int* result);
sgx_status_t seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t unseal(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
