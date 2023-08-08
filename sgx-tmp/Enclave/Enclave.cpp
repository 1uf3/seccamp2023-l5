#include "Enclave_t.h"
#include <sgx_trts.h>

int ecall_test(const char* message, size_t message_len) {
    // ocall_print(message);
    return 19;
}

int ecall_test_ex(const char* message, size_t message_len) {
    // ocall_print(message);
    return 20;
}
