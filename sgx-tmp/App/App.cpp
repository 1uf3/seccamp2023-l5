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

sgx_enclave_id_t global_eid = 0;

void ocall_print(const char* str) {
	std::cout << "Output from OCALL: " << std::endl;
	std::cout << str << std::endl;
}

void ocall_print_ex(const char* str) {
	std::cout << "Output from OCALL: " << std::endl;
	std::cout << str << std::endl;
}

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
	sgx_status_t ret_ex = SGX_SUCCESS;

	std::chrono::system_clock::time_point  start_ex, end_ex;
	start_ex = std::chrono::system_clock::now(); // 計測開始時間
	for (int i=0; i<N; i++) {
		ret_ex = ecall_test_ex(global_eid, &retval, message, strlen(message));
	}
 	end_ex = std::chrono::system_clock::now();  // 計測終了時間
 	double elapsed_ex = std::chrono::duration_cast<std::chrono::milliseconds>(end_ex-start_ex).count(); //処理に要した時間をミリ秒に変換
	printf("uSwitchless time: %lf\n", elapsed_ex);

	print_sgx_status(ret_ex);
	printf("Returned integer from ECALL is: %d\n", retval);
	 
	if (SGX_SUCCESS != sgx_destroy_enclave(global_eid)) {
		printf("App: error %#x, failed to destroy enclave \n", ret_ex);
		return -1;
	}

	// =========== //

	retval = 0;
	sgx_status_t ret = SGX_SUCCESS;

	initialize_enclave();
	std::chrono::system_clock::time_point  start, end; 
	start = std::chrono::system_clock::now(); // 計測開始時間
	for (int i=0; i<N; i++) {
		ret = ecall_test(global_eid, &retval, message, strlen(message));
	}
 	end = std::chrono::system_clock::now();  // 計測終了時間
 	double elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count(); //処理に要した時間をミリ秒に変換
	printf("non-uSwitchless time: %lf\n", elapsed);

	print_sgx_status(ret);
	printf("Returned integer from ECALL is: %d\n", retval);
	 
	if (SGX_SUCCESS != sgx_destroy_enclave(global_eid)) {
		printf("App: error %#x, failed to destroy enclave \n", ret);
		return -1;
	}
	 
	 return 0;
}
