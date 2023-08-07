#include <cstdio>
#include <cstring>
#include <iostream>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.hpp"
#include <openssl/bio.h>
#include <sgx_uswitchless.h>

#define ENCLAVE_FILENAME "enclave.signed.so"

sgx_enclave_id_t global_eid = 0;

void ocall_print(const char* str) {
	std::cout << "Output from OCALL: " << std::endl;
	std::cout << str << std::endl;
}

/* Enclave initialization function */
int initialize_enclave() {
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
	initialize_enclave();

	const char* message = "Hello Enclave.";
	int retval;

	sgx_status_t ret = ecall_test(global_eid, &retval, message, strlen(message));
	print_sgx_status(ret);
	printf("Returned integer from ECALL is: %d\n", retval);
	 
	if (SGX_SUCCESS != sgx_destroy_enclave(global_eid)) {
		printf("App: error %#x, failed to destroy enclave \n", ret);
		return -1;
	}
	 
	 return 0;
}
