#include "host/host_tpm_utils.h"
#include <iostream>
#include "duplicated_things.h"

void ocall_create_counter(uint32_t* counter_id) {
    LOG(ERROR) << "TPM utilites is removed from the host!!!";
    return ;
}

//- Receive nonce_caller, encrypted_salt from the enclave
//- Return nonce_tpm and session handle
void ocall_start_auth_session(
    void* nonce_buffer, int nonce_buf_size, 
    void* encrypted_salt_buffer, int encrypted_salt_buf_size, 
    void* nonce_tpm_buffer,
    uint32_t* session_handle) {
    LOG(ERROR) << "TPM utilites is removed from the host!!!";
    return ;
}


void ocall_add_counter(uint32_t session_handle, uint32_t nv_handle,
    void* nonce_buffer, int nonce_buf_size, //- Pointer to the whole nonce struct
    uint8_t* hmac_in_buffer, int hmac_size,
    uint8_t* nonce_tpm_buffer,
    uint8_t* hmac_out_buffer) {
    LOG(ERROR) << "TPM utilites is removed from the host!!!";
    return ;
}

//- read_data is a pointer to the whole TPM2B_MAX_NV_BUFFER struct
//- nonce_buffer is a pointer to the whole TPM2B_NONCE struct
void ocall_read_counter(uint32_t session_handle, uint32_t nv_handle,
    void* nonce_buffer, int nonce_buf_size,
    uint8_t* hmac_in_buffer, int hmac_size,
    uint8_t* nonce_tpm_buffer, uint8_t* hmac_out_buffer,     
    void* read_data, int read_data_size) {
    LOG(ERROR) << "TPM utilites is removed from the host!!!";
    return ;
}

