#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_get_account(int* result);
void ecall_create_account(void);
void ecall_auth(const char* master_pass, size_t master_pass_size);
void ecall_verify_master_password(const char* input, size_t input_len, const char* actual, size_t actual_len, int* result);
sgx_status_t seal(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size);
sgx_status_t unseal(sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_read_file(int* err_code, const char* file_path, uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL ocall_get_string(int* result, char* str_buffer, size_t buffer_size);
sgx_status_t SGX_CDECL ocall_remove_file(const char* file_path);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
