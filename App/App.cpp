#include <stdio.h>
#include <iostream>
#include <fstream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

#define MAX_TRIES 3

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;


// OCall implementations
void ocall_print(const char* str) {
    printf("%s", str);
}

void ocall_read_file(int* err_code,const char* file_path, uint8_t* sealed_data, size_t sealed_size) {
    sgx_sealed_data_t file_contents[1024] = {0};
    size_t file_size = sizeof(file_contents);
    std::ifstream sealed_file(file_path, std::ios::in | std::ios::binary);
    if(sealed_file.fail()){
        *err_code = 1;
        return;
    }
    sealed_file.read(reinterpret_cast<char*>(file_contents), file_size);

    // Calculate the actual number of bytes read
    std::streamsize bytes_read = sealed_file.gcount();

    // Check if sealed_size is large enough to hold the read data
    if (bytes_read > static_cast<std::streamsize>(sealed_size)) {
        *err_code = 2; // example error code for buffer overflow
        sealed_file.close();
        return;
    }
    memcpy(sealed_data, file_contents, bytes_read);

    sealed_file.close();
    *err_code = 0; // Indicate succes
}

void ocall_get_string(int *result, char* str_buffer, size_t buffer_size) {
    std::string input_str;
    std::getline(std::cin, input_str);  // Using getline to handle spaces if any

    // Ensure the input password fits into the buffer
    if (input_str.length() + 1 > buffer_size) {
        *result = -1;  // Indicate error if password is too long
        return;
    }

    // Copy the input password to the buffer
    strncpy(str_buffer, input_str.c_str(), buffer_size);
    str_buffer[buffer_size - 1] = '\0'; // Ensure null termination

    *result = 0; // Indicate success
}

void ocall_remove_file(const char* file_path){
    if(remove(file_path) != 0){
        std::cout<<"error";
    }
}


int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }


    sgx_status_t status, retval;

    int ret;
    ecall_get_account(global_eid, &ret);
    std::ifstream sealed_file("sealed_data.bin", std::ios::in | std::ios::binary);
    if (ret == 1) {

    } else {
        // std::cerr << "Sealed data file not found, a new master password must be set." << std::endl;
        // File not found, prompt the user to set a new master password
        std::string new_master_password;
        // std::cout << "No master password set. Please set a new master password: ";
        std::cin >> new_master_password;


        size_t payload_size = new_master_password.length();

        size_t sealed_data_size = sizeof(sgx_sealed_data_t) + payload_size;
        sgx_sealed_data_t* sealed_data_buffer = (sgx_sealed_data_t*)malloc (sealed_data_size);
        if(sealed_data_buffer == nullptr){
            std::cout << "failed";
            return 1;
        }

        status = seal(global_eid, &retval, (uint8_t*)new_master_password.c_str(), new_master_password.length(), sealed_data_buffer, sealed_data_size);
        if (!is_ecall_successful(status, "Sealing failed :(", retval))
        {
           return 1;
        }
        if (sealed_data_buffer != nullptr) {
        // Sealing succeeded, now write the sealed data to a file
        std::ofstream sealed_file("sealed_data.bin", std::ios::out | std::ios::binary);
        if (sealed_file.is_open()) {
            sealed_file.write(reinterpret_cast<char*>(sealed_data_buffer), sealed_data_size);
            sealed_file.close();
            std::cout << "Master password sealed and stored successfully." << std::endl;
        } else {
            std::cerr << "Failed to open file for writing sealed data" << strerror(errno) << std::endl;
            free(sealed_data_buffer);
            return 1;
        }
        free(sealed_data_buffer); // Don't forget to free the memory
         } else {
        std::cerr << "Memory allocation for sealed data buffer failed." << std::endl;
        return 1;
         }
    }
    return 0;
}


