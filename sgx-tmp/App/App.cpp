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
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <map>
#include <unistd.h>
#include "base64.hpp"

#define ENCLAVE_FILENAME "enclave.signed.so"
#define DATA_SIZE 1024

const std::string homeDir = std::getenv("HOME");
const std::string exDir = homeDir + "/.ex_vault";
const std::string masterCredentialFile = exDir + "/master_credential";
const std::string credentialFile = exDir + "/credentials";

sgx_enclave_id_t global_eid = 0;

std::string generateRandomPassword(size_t length) {
	int retval = 0;
	if ((size_t)100 < length) {
        std::cerr << "Error: Max Password Length 100." << std::endl;
		return "";
	}
	uint8_t* createdPassword = new uint8_t[length];
	sgx_status_t status = ecall_random_password_generate(global_eid, &retval, length, createdPassword);
	if (SGX_SUCCESS != status) {
		print_sgx_status(status);
		return "";
	}
	std::string password(reinterpret_cast<char*>(createdPassword), length);
    return password;
}

bool fileExists(const std::string &filename) {
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

int createExDirectory() {
	if (mkdir(exDir.c_str(), 0700) != 0) {
		if (errno != EEXIST) {
       		std::cerr << "Error: creating directory." << std::endl;
			return -1;
		}
	}
	return 0;
}

int createMasterCredentialFile(const std::string &password) {
    std::ofstream file(masterCredentialFile);
    if (!file.is_open()) {
       	std::cerr << "Error: Creating master_credential File." << std::endl;
		return -1;
	}

	file << password;
	file.close();
	std::cout << "Master credential file created and password stored." << std::endl;
	return 0;
}

std::string sealMasterPassword(const std::string &password) {
	const uint8_t* password_u = reinterpret_cast<const uint8_t*>(password.c_str());
	int retval = 0;
	uint8_t* sealed_password_u = new uint8_t[1024];
	size_t sealed_password_u_size = 0;
	sgx_status_t status = ecall_seal_data(global_eid, &retval, (uint8_t*)password_u, password.size(), sealed_password_u, &sealed_password_u_size);
	if (SGX_SUCCESS != status) {
		print_sgx_status(status);
		return "";
	}
	std::string password_base64 = base64_encode<char, uint8_t>(sealed_password_u, sealed_password_u_size);
	return password_base64;
}

int createCredentialFile() {
    std::ofstream file(credentialFile);
    if (!file.is_open()) {
       	std::cerr << "Error: Creating master_credential File." << std::endl;
		return -1;
	}
	file.close();
	std::cout << "credential File created." << std::endl;
	return 0;
}

std::string readPassword() {
    std::cout << "Enter master password (up to 100 characters): ";
    std::string password;
    std::cin.ignore(); // Clear the newline character from previous input
    std::getline(std::cin, password); // Read the entire line

    // Limit the password to 100 characters
    if (password.size() > 100) {
        password = password.substr(0, 100);
    }

    return password;
}

int initialize() {
	if(createExDirectory() != 0) {
		return -1;
	}
	if(!fileExists(masterCredentialFile)) {
		if(createMasterCredentialFile(readPassword()) != 0) {
			return -1;
		}
	}
	if(!fileExists(credentialFile)) {
		if(createCredentialFile() != 0) {
			return -1;
		}
	}
	return 0;
}

int check_master_password() {
	std::string input_password = readPassword();
	const uint8_t* password_u = reinterpret_cast<const uint8_t*>(input_password.c_str());
	int retval = 0;
	sgx_status_t status = ecall_check_master_password(global_eid, &retval, (uint8_t*)password_u, input_password.size());
	if (SGX_SUCCESS != status) {
		print_sgx_status(status);
		return retval;
	}
	return retval;
}

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


int main(int argc, char* argv[]) {

	if (initialize() != 0) {
		std::cout << "initialize failed." << std::endl;
		return -1;
	}

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <option>" << std::endl;
        return -1;
    }

	if(check_master_password() != 1) {
		std::cout << "Mistyped Master Password." << std::endl;
		return -1;
	}

    std::string option = argv[1];

	sgx_status_t ret = SGX_SUCCESS;
	ret = initialize_enclave_ex();
	if (SGX_SUCCESS != ret) {
		print_sgx_status(ret);
		return -1;
	}

    if (option == "add") {
        if (argc != 4) {
            std::cerr << "Usage: " << argv[0] << " add <key> <password>" << std::endl;
            return 1;
        }
		std::string key = argv[2];
		const uint8_t* key_u = reinterpret_cast<const uint8_t*>(key.c_str());
		std::string password = argv[3];
		const uint8_t* password_u = reinterpret_cast<const uint8_t*>(password.c_str());
		int retval = 0;
		sgx_status_t status = ecall_register_password(global_eid, &retval, (uint8_t*)key_u, key.size(), (uint8_t*)password_u, password.size());
		if (SGX_SUCCESS != status) {
			print_sgx_status(status);
			return -1;
		}
        std::cout << "Password added." << std::endl;
    } else if (option == "generate") {
        if (argc != 3) {
            std::cerr << "Usage: " << argv[0] << " generate" << std::endl;
            return 1;
        }

		std::cout << "Generate 15 length password." << std::endl;
        std::string password = generateRandomPassword(15); // Change length as needed
		std::cout << "Generated Password is : " << password << std::endl;

        std::cout << "Generated password: " << password << std::endl;
    } else if (option == "get") {
        if (argc != 3) {
            std::cerr << "Usage: " << argv[0] << " get <key>" << std::endl;
            return 1;
        }

        std::string key = argv[2];
		const uint8_t* key_u = reinterpret_cast<const uint8_t*>(key.c_str());
		int retval = 0;
		uint8_t* password_u = new uint8_t[100];
		ecall_retrive_password(global_eid, &retval, (uint8_t*)key_u, key.size(), password_u);
		std::string password(reinterpret_cast<char*>(password_u), 100);

        std::cout << "Password for key '" << key << "': " << password << std::endl;
    } else if (option == "list") {
    } else {
        std::cerr << "Invalid option." << std::endl;
        return 1;
    }

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

std::map<std::string, std::string> readPasswords() {
    std::map<std::string, std::string> passwordMap;
    std::ifstream file(credentialFile);

    if (!file.is_open()) {
        std::cerr << "Error opening file." << std::endl;
        return passwordMap;
    }

    std::string line;
    while (std::getline(file, line)) {
        size_t separatorPos = line.find(":");
        if (separatorPos != std::string::npos) {
            std::string key = line.substr(0, separatorPos);
            std::string password = line.substr(separatorPos + 1);
            passwordMap[key] = password;
        }
    }

    file.close();
    return passwordMap;
}

std::string getPasswordForKey(const std::string& key) {
	const std::map<std::string, std::string> passwordMap = readPasswords();
    auto it = passwordMap.find(key);
    if (it != passwordMap.end()) {
        return it->second;
    }
    return ""; // キーが見つからなかった場合は空の文字列を返す
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

int ocall_store_password(uint8_t* key_u, size_t key_size, uint8_t* sealed_password, size_t sealed_password_size) {
	std::string key(reinterpret_cast<char*>(key_u), key_size);
	std::string password_base64 = base64_encode<char, uint8_t>(sealed_password, sealed_password_size);
	if (getPasswordForKey(key) != "") {
        std::cerr << "Error: Password Already Existed." << std::endl;
		return -1;
	}
	return storeCredential(key + ":" + password_base64);
}

size_t ocall_get_sealed_password_len(uint8_t* key_u, size_t key_size) {
	std::string key(reinterpret_cast<char*>(key_u), key_size);
	std::string password_base64 = getPasswordForKey(key);
	// std::cout << (char*)password_base64.c_str() << std::endl;
	size_t sealed_password_size = 0;
	base64_decode<uint8_t, char>((char*)password_base64.c_str(), sealed_password_size);
	return sealed_password_size;
}

void ocall_get_password(uint8_t* key_u, size_t key_size,
							uint8_t* sealed_password, size_t sealed_password_size) {
	std::string key(reinterpret_cast<char*>(key_u), key_size);
	std::string password_base64 = getPasswordForKey(key);
	// std::cout << (char*)password_base64.c_str() << std::endl;
	uint8_t* decoded_password = base64_decode<uint8_t, char>((char*)password_base64.c_str(), sealed_password_size);
	memcpy(sealed_password, decoded_password, sealed_password_size);
}

size_t ocall_get_sealed_master_password_len() {
    std::ifstream file(masterCredentialFile);

    if (!file.is_open()) {
        std::cerr << "Error opening file." << std::endl;
        return (size_t)1;
    }

    std::string password;
    std::getline(file, password);
    file.close();

	size_t decoded_password_size = 0;
	uint8_t* decoded_password = base64_decode<uint8_t, char>((char*)password.c_str(), decoded_password_size);
	return decoded_password_size;
}

void ocall_get_master_password(uint8_t* sealed_password, size_t sealed_password_size) {
    std::ifstream file(masterCredentialFile);

    if (!file.is_open()) {
        std::cerr << "Error opening file." << std::endl;
    }

    std::string password;
    std::getline(file, password);
    file.close();

	size_t decoded_password_size = 0;
	uint8_t* decoded_password = base64_decode<uint8_t, char>((char*)password.c_str(), decoded_password_size);
	memcpy(sealed_password, decoded_password, sealed_password_size);
}