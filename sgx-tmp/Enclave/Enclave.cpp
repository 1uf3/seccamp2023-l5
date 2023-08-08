#include "Enclave_t.h"
#include <sgx_trts.h>
#include "sgx_tseal.h"

#define SEALED_DATA_SIZE 512


int ecall_seal_data(const char* plain_data_str, size_t plain_data_size, 
                    uint8_t* sealed_data, size_t sealed_data_size) {
    uint8_t* plain_data = (uint8_t*)atoi(plain_data_str);
	sealed_data_size = sgx_calc_sealed_data_size(0, plain_data_size);
    uint8_t sealed_data_array[sealed_data_size];
	sgx_status_t status = sgx_seal_data(
		0, 
		NULL, 
		plain_data_size, 
		plain_data,
		sealed_data_size,
		(sgx_sealed_data_t*)sealed_data
        );
    sealed_data = sealed_data_array;
    return 0;
}

int ecall_unseal_data(uint8_t* sealed_data_u, size_t sealed_data_size,
                        char* plain_data, size_t plain_data_size) {
    sgx_sealed_data_t* sealed_data = (sgx_sealed_data_t*)sealed_data_u;
    plain_data_size = sgx_get_encrypt_txt_len(sealed_data);
    uint8_t* plain_data_u = new uint8_t[plain_data_size]();
    sgx_status_t status = sgx_unseal_data(sealed_data, NULL, 0, plain_data_u, (uint32_t*)plain_data_size);
    plain_data = (char*)plain_data_u;
    return 0;
}

// int ecall_seal_data(const char* plain_data, size_t plain_data_size) {
//     uint8_t sealed_data[SEALED_DATA_SIZE] = {0};
//     size_t sealed_data_size = 0;
//     sgx_status_t status = seal_data(plain_data, plain_data_size, sealed_data, &sealed_data_size);
//     return 0;
// }
// 
// int ecall_unseal_data(const uint8_t* sealed_data, size_t sealed_data_size) {
//     uint8_t plain_data[SEALED_DATA_SIZE] = {0};
//     size_t plain_data_size = 0;
//     sgx_status_t status = unseal_data(sealed_data, sealed_data_size, plain_data, &plain_data_size);
//     return 0;
// }