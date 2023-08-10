#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <chrono>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.hpp"
#include <openssl/bio.h>
#include <sgx_uswitchless.h>
#include <sys/stat.h>

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

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <chrono>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.hpp"
#include <openssl/bio.h>
#include <sgx_uswitchless.h>
#include <sys/stat.h>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <unistd.h>


const std::string homeDir = std::getenv("HOME");
const std::string exDir = homeDir + "/.ex_vault";
const std::string credentialFile = exDir + "/credentials";

typedef struct {
    std::string key;
    std::string password;
}key_password;

#define ENCLAVE_FILENAME "enclave.signed.so"
#define DATA_SIZE 1024

sgx_enclave_id_t global_eid = 0;

sgx_status_t initialize_enclave_ex() {
    //0埋めしたダミーの起動トークンでEnclaveを作成する
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
	return ret;
}

int main() {
	/* 以下の処理を実装する：
	 * - Enclaveの作成（初期化）
	 * - ECALL関数の呼び出し
	 * - ECALL結果のSGXステータス及び戻り値の出力
	 */
	sgx_status_t ret = SGX_SUCCESS;

	ret = initialize_enclave_ex();
	if (SGX_SUCCESS != ret) {
		print_sgx_status(ret);
		return -1;
	}

//	const char* message = "HelloEnclave";
	int retval = 0;

// int random_password_size = 10;
// uint8_t* random_password = new uint8_t[random_password_size];
// uint8_t* sealed_data = new uint8_t[random_password_size];
// size_t sealed_data_size = 0;

// OK
// 	ret = ecall_random_password_generate(global_eid, &retval, random_password_size, random_password);
//  	if (SGX_SUCCESS != ret) {
//  		print_sgx_status(ret);
//  		return -1;
//  	}
// 
// 	BIO_dump_fp(stdout, (char*)random_password, random_password_size);

//	ret = ecall_register_password(global_eid, &retval, (uint8_t*)message, strlen(message));
// 	if (SGX_SUCCESS != ret) {
// 		print_sgx_status(ret);
// 		return -1;
// 	}
//
//	uint8_t* plain_password = new uint8_t[100];
//	ret = ecall_retrive_password(global_eid, &retval, plain_password);
// 	if (SGX_SUCCESS != ret) {
// 		print_sgx_status(ret);
// 		return -1;
// 	}
//    std::cout << (char*)plain_password << std::endl;

// 	test_struct_t bleed = test_struct_t{
// 		0, 0, 0
// 	};
// 	sgx_status_t status = ecall_bleed(global_eid, &bleed);
//  	if (SGX_SUCCESS != status) {
//  		print_sgx_status(status);
//  		return -1;
//  	}
// 	BIO_dump_fp(stdout, (char*)&bleed, 32);

	if (SGX_SUCCESS != sgx_destroy_enclave(global_eid)) {
		puts("App: error, failed to destroy enclave \n");
		return -1;
	}

	return 0;
}


// Define ocall function

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
void ocall_print_uint8_t(uint8_t* s, size_t s_size) {
	BIO_dump_fp(stdout, (char*)s, s_size);
}

int storeCredential(const std::string password) {
    std::ofstream file(credentialFile, std::ios_base::app);
    if (file.is_open()) {
            file << password << std::endl;
        file.close();
    } else {
        std::cerr << "Error: Could not store credentials." << std::endl;
		return -2;
    }
	return 0;
}

#include "base64.hpp"
int ocall_store_password(uint8_t* sealed_password, size_t sealed_password_size) {
	const char* password_base64 = base64_encode<char, uint8_t>(sealed_password, sealed_password_size);
	return storeCredential(password_base64);
}

std::string getCredential() {
    std::ifstream file(credentialFile);
    std::string password;
    if (file.is_open()) {
		std::getline(file, password);
        file.close();
    } else {
        std::cerr << "Error: Credential file not found." << std::endl;
    }
    return password;
}

size_t ocall_get_sealed_password_len() {
	std::string password_base64 = getCredential();
	// std::cout << (char*)password_base64.c_str() << std::endl;
	size_t sealed_password_size = 0;
	base64_decode<uint8_t, char>((char*)password_base64.c_str(), sealed_password_size);
	return sealed_password_size;
}

void ocall_get_password(uint8_t* sealed_password, size_t sealed_password_size) {
	std::string password_base64 = getCredential();
	// std::cout << (char*)password_base64.c_str() << std::endl;
	uint8_t* decoded_password = base64_decode<uint8_t, char>((char*)password_base64.c_str(), sealed_password_size);
	memcpy(sealed_password, decoded_password, sealed_password_size);
}