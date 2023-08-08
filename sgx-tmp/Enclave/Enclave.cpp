#include "Enclave_t.h"
#include <sgx_trts.h>
#include "sgx_tseal.h"
#include <string.h>

#define SEALED_DATA_SIZE 1024 

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

int ecall_unseal_data(uint8_t* sealed_data, size_t sealed_data_size,
                        uint8_t* plain_data, uint32_t* plain_data_size) {
    *plain_data_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);
    ocall_print_32size(*plain_data_size);
    sgx_status_t status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, 0, plain_data, plain_data_size);
    ocall_print_status(status);
    return 0;
}
