#ifdef SGX_USE_REMOTE_ATTESTATION
#ifndef SGX_BUTIL_ATTESTATION_HELPER_H_
#define SGX_BUTIL_ATTESTATION_HELPER_H_

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/enclave.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include <stdio.h>

#include "sgxbutil/logging.h"
const unsigned char certificate_subject_name[] =
    "CN=Open Enclave SDK,O=OESDK TLS,C=US";
struct AttestationCertBuffer{
    uint8_t* cert_buffer;
    int buffer_len;
};
static const oe_claim_t* find_claim(const oe_claim_t* claims, size_t claims_size,
                                    const char* name);
static bool verify_signer_id(const char* pem_key_buffer, size_t pem_key_buffer_len,
                            uint8_t* expected_signer, size_t expected_signer_size);    
int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);
oe_result_t enclave_claims_verifier(oe_claim_t* claims, size_t claims_length, void* arg);
oe_result_t verify_claim_value(const oe_claim_t* claim);

oe_result_t load_tls_certificates_and_keys(SSL_CTX* ctx, X509*& certificate, 
                                            EVP_PKEY*& pkey);

oe_result_t generate_key_pair(uint8_t** public_key, size_t* public_key_size,
                            uint8_t** private_key, size_t* private_key_size);

int get_global_cert_and_pkey();

int performance_test_generate_evidence();
int performance_test_verify_evidence();
#endif //SGX_BUTIL_ATTESTATION_HELPER_H_
#endif //- SGX_USE_REMOTE_ATTESTATION