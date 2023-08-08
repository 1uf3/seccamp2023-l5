#include <cstdio>
#include <cstring>
#include <iostream>
#include <chrono>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.hpp"
#include <openssl/bio.h>
#include <sgx_uswitchless.h>

#define ENCLAVE_FILENAME "enclave.signed.so"
#define N 1000000
#define DATA_SIZE 1024

sgx_enclave_id_t global_eid = 0;


void ocall_print_str(const char* str) {
	std::cout << "Output from OCALL: " << std::endl;
	std::cout << str << std::endl;
}

void ocall_print_size(size_t size) {
	std::cout << size << std::endl;
}

void ocall_print_32size(uint32_t size) {
	std::cout << size << std::endl;
}

void ocall_print_status(sgx_status_t s) {
	print_sgx_status(s);
}

int initialize_enclave() {
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_SUCCESS;
	int updated = 0;


	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave \n", ret);
		return -1;
	}
    //0埋めしたダミーの起動トークンでEnclaveを作成する
	return 0;
}

int initialize_enclave_ex() {
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_SUCCESS;
	int updated = 0;

	sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
	void* enclave_ex_p[32] = {0};
	enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = &us_config;

	ret = sgx_create_enclave_ex(
		ENCLAVE_FILENAME, 
		SGX_DEBUG_FLAG, 
		&token, 
		&updated, 
		&global_eid, 
		NULL, 
		SGX_CREATE_ENCLAVE_EX_SWITCHLESS, 
		(const void**)enclave_ex_p
		);
	if (ret != SGX_SUCCESS) {
		print_sgx_status(ret);
		return -1;
	}
    //0埋めしたダミーの起動トークンでEnclaveを作成する
	return 0;
}

int main() {
	/* 以下の処理を実装する：
	 * - Enclaveの作成（初期化）
	 * - ECALL関数の呼び出し
	 * - ECALL結果のSGXステータス及び戻り値の出力
	 */
	initialize_enclave_ex();

	const char* message = "Hello Enclave.";
	int retval = 0;
	sgx_status_t ret = SGX_SUCCESS;
	uint8_t* sealed_data = new uint8_t[DATA_SIZE];
	size_t sealed_data_size = 0;

	ret = ecall_seal_data(global_eid, &retval, (uint8_t*)message, strlen(message), sealed_data, &sealed_data_size);
	if (SGX_SUCCESS != ret) {
		print_sgx_status(ret);
		return -1;
	}
	printf("Returned integer from ECALL is: %d\n", retval);

	BIO_dump_fp(stdout, (char*)sealed_data, sealed_data_size);

	uint8_t* plain_data = new uint8_t[DATA_SIZE];
	uint32_t plain_data_size = 0;

	ret = ecall_unseal_data(global_eid, &retval, sealed_data, sealed_data_size, plain_data, &plain_data_size);
	if (SGX_SUCCESS != ret) {
		print_sgx_status(ret);
		return -1;
	}
	printf("Returned integer from ECALL is: %d\n", retval);

	BIO_dump_fp(stdout, (char*)plain_data, plain_data_size);
	 
	if (SGX_SUCCESS != sgx_destroy_enclave(global_eid)) {
		puts("App: error, failed to destroy enclave \n");
		return -1;
	}

	return 0;
}
