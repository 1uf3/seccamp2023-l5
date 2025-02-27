#include "Enclave_t.h"
#include <sgx_trts.h>
#include "sgx_tseal.h"
#include <cstring>

int ecall_check_master_password(uint8_t* password_u, size_t password_size) {
    size_t stored_password_size = 0;
    sgx_status_t status = ocall_get_sealed_master_password_len(&stored_password_size);
        ocall_print_status(status);
    uint8_t* stored_password = new uint8_t[stored_password_size];
    status = ocall_get_master_password(stored_password, stored_password_size);
        ocall_print_status(status);
    size_t valid_password_size = stored_password_size;
    if(valid_password_size < password_size) {
        valid_password_size = password_size;
    }
    if (memcmp(password_u, stored_password, valid_password_size) != 0) {
        return 0;
    }
    return 1;
}

int ecall_seal_data(uint8_t* plain_data, size_t plain_data_size, 
                        uint8_t* sealed_data, size_t* sealed_data_size) {
    ocall_print_str((char*)plain_data);
	*sealed_data_size = sgx_calc_sealed_data_size(0, plain_data_size);
    ocall_print_size(*sealed_data_size);
	sgx_status_t status = sgx_seal_data(
		0, 
		NULL, 
		plain_data_size, 
		plain_data,
		*sealed_data_size,
		(sgx_sealed_data_t*)sealed_data
        );
    ocall_print_status(status);
    return 0;
}

int ecall_random_password_generate(size_t passwordSize, uint8_t* createdPassword) {
    sgx_status_t status = sgx_read_rand(createdPassword, passwordSize);
    if (SGX_SUCCESS != status) {
        ocall_print_status(status);
    }
    // to ascii
    for (int i=0; i<passwordSize; i++) {
        createdPassword[i] = createdPassword[i] % (0x7D - 0x20) + 0x21;
    }
    return 0;
}

int ecall_register_password(uint8_t* key_u, size_t key_size,
                                uint8_t* plain_password, size_t plain_password_size) {
	uint32_t sealed_password_size = sgx_calc_sealed_data_size(0, plain_password_size);
    //    ocall_print_32size(sealed_password_size);
    uint8_t sealed_password[sealed_password_size];
	sgx_status_t status = sgx_seal_data(
		0, 
		NULL, 
		plain_password_size, 
		plain_password,
		sealed_password_size,
		(sgx_sealed_data_t*)sealed_password
        );
    if (SGX_SUCCESS != status) {
        ocall_print_status(status);
    }
    int retval = 0;
    status = ocall_store_password(&retval, key_u, key_size, sealed_password, (size_t)sealed_password_size);
    if (SGX_SUCCESS != status) {
        ocall_print_status(status);
    }
    return retval;
}

int ecall_retrive_password(uint8_t* key_u, size_t key_size,
                            uint8_t* plain_password) {
    size_t sealed_password_size = 0;
    sgx_status_t status = ocall_get_sealed_password_len(&sealed_password_size, key_u, key_size);
    if (SGX_SUCCESS != status) {
        ocall_print_status(status);
    }
    //    ocall_print_size(sealed_password_size);
    uint8_t* sealed_password = new uint8_t[sealed_password_size];
    status = ocall_get_password(key_u, key_size, sealed_password, sealed_password_size);
    if (SGX_SUCCESS != status) {
        ocall_print_status(status);
    }
    //    ocall_print_uint8_t(sealed_password, sealed_password_size);
    uint32_t plain_password_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t*)sealed_password);
    //    ocall_print_32size(plain_password_size);
    status = sgx_unseal_data((sgx_sealed_data_t*)sealed_password, NULL, 0, plain_password, &plain_password_size);
    if (SGX_SUCCESS != status) {
        ocall_print_status(status);
    }
    return 0;
}

test_struct_t ecall_bleed() {
    uint8_t* buf = new uint8_t[1000];
    memset(buf, 'a', 1000);
    delete buf;
    test_struct_t* st = new test_struct_t[1];
    *st = test_struct_t{0, 0, 0};
    return *st;
}
