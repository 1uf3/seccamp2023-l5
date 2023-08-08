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
	uint8_t sealed_data[DATA_SIZE] = {0};
	size_t sealed_data_size = 0;

	ret = ecall_seal_data(global_eid, &retval, message, strlen(message), sealed_data, sealed_data_size);
	if (SGX_SUCCESS != ret) {
		print_sgx_status(ret);
		return -1;
	}
	printf("Returned integer from ECALL is: %d\n", retval);

	char plain_data[DATA_SIZE] = {0};
	size_t plain_data_size = 0;

	ret = ecall_unseal_data(global_eid, &retval, sealed_data, sealed_data_size, plain_data, plain_data_size);
	if (SGX_SUCCESS != ret) {
		print_sgx_status(ret);
		return -1;
	}
	printf("Returned integer from ECALL is: %d\n", retval);
	 
	if (SGX_SUCCESS != sgx_destroy_enclave(global_eid)) {
		puts("App: error, failed to destroy enclave \n");
		return -1;
	}

	return 0;
}
