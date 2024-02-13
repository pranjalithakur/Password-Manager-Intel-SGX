#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>

sgx_enclave_id_t global_eid = 0;

const char* sealed_file_path = "sealed_data.bin";

void ecall_get_account(int* result) {
    sgx_status_t status, retval;
    uint8_t unsealed_master_password[1024] = {0};  // Buffer for the unsealed master password
    uint32_t unsealed_master_password_size = sizeof(unsealed_master_password);

    sgx_sealed_data_t file_contents[1024] = {0};
    size_t file_size = sizeof(file_contents);
    uint8_t* s_data = (uint8_t*)malloc(file_size);
    int err_code = 0;
    ocall_read_file(&err_code, sealed_file_path, s_data, file_size);
    
    if (err_code == 0) {
        *result = 1;
            unseal(reinterpret_cast<sgx_sealed_data_t*>(s_data), file_size, unsealed_master_password, unsealed_master_password_size);
            ocall_print(reinterpret_cast<char*>(unsealed_master_password));
            ecall_auth(reinterpret_cast<char*>(unsealed_master_password), unsealed_master_password_size);
    } else {
        *result = 0;
            ecall_create_account();
    }
}

void ecall_auth(const char* master_pass, size_t master_pass_size){
    int res;
    bool authenticated = false;
    int failed_attempts = 0;
    char password_buffer[1024];
    int result;

    do
    {  
       ocall_print("Please enter your master password: "); 
       ocall_get_string(&res, password_buffer, sizeof(password_buffer));
     if (res == 0) {
       ecall_verify_master_password(password_buffer, strlen(password_buffer), master_pass, strlen(password_buffer), &result);
      if(result == 1)
      {
        ocall_print("Authentication successful!\n");
        authenticated = true;
        failed_attempts = 0;
      }
      else {
           ocall_print("Authentication failed!\n");
           failed_attempts++;
           if(failed_attempts >= 3)
           {
            ocall_print("Too many failed attempts. Account is deleted.\n");
            ocall_remove_file(sealed_file_path);
            break;
           }
      }
     }

    }
    while(!authenticated);

}

void ecall_verify_master_password(const char* input, size_t input_len, const char* actual, size_t actual_len, int* result) {

    if (memcmp(input, actual, input_len) == 0) {
        *result = 1;
    }
    else {
        *result = 0;
    }
}

void ecall_create_account()
{
    ocall_print("No Account found, a account must be created.\n");
    ocall_print("No master password set. Please set a new master password: ");

}