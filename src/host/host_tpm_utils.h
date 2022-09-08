#ifndef HOST_HOST_TPM_UTILS_H
#define HOST_HOST_TPM_UTILS_H

#include <string>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

typedef int CounterID;

#if RUN_OUTSIDE_SGX
void ocall_create_counter(uint32_t* index);
void ocall_start_auth_session(void* nonce_buffer, int nonce_buf_size, 
    void* encrypted_salt_buffer, int salt_buf_size, 
    void* nonce_tpm_buffer, uint32_t* session_handle);

void ocall_add_counter(uint32_t session_handle, uint32_t nv_handle,
    void* nonce_buffer, int nonce_buf_size,
    uint8_t* hmac_in_buffer, int hmac_size,
    uint8_t* nonce_tpm_buffer,
    uint8_t* hmac_out_buffer);

void ocall_read_counter(uint32_t session_handle, uint32_t nv_handle,
    void* nonce_buffer, int nonce_buf_size,
    uint8_t* hmac_in_buffer, int hmac_size,
    uint8_t* nonce_tpm_buffer,
    uint8_t* hmac_out_buffer, 
    void* read_data, int read_data_size);

#else
#include "interface_u.h"
#endif

#endif