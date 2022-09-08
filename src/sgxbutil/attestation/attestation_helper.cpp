#ifdef SGX_USE_REMOTE_ATTESTATION
#include "sgxbutil/attestation/attestation_helper.h"
#include <vector>
X509* raft_node_cert = NULL;
EVP_PKEY* raft_node_pkey = NULL;
//- The MRENCLACE of current enclave
uint8_t SELF_MRENCLAVE[32];
//- The verified certs of remote parties
// std::vector<AttestationCertBuffer> verified_certs;
// SGX Remote Attestation UUID.
static oe_uuid_t _uuid_sgx_ecdsa = {OE_FORMAT_UUID_SGX_ECDSA};

//- Generate certificate and pkey and then store them in
// global vars (raft_node_cert and raft_node_pkey)
int get_global_cert_and_pkey() {
    //- Befor get cert and pkey, create a report and then extract the MRENCLAVE
    //- from it. Thus we can vefiry the MRENCLAVE later.
    uint8_t* report;
    size_t report_size = 0;
    int rc = oe_get_report_v2(0, NULL, 0, NULL, 0, &report, &report_size);
    if (rc != OE_OK) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " oe_get_report_v2 failed.";
        return -1;
    }
    oe_report_t parsed_report = {0};
    rc = oe_parse_report(report, report_size, &parsed_report);
    if (rc != OE_OK) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " oe_parse_report failed.";
        return -1;
    }
    memcpy(SELF_MRENCLAVE, parsed_report.identity.unique_id, 32);
    oe_free_report(report);

    //- Now, get cert and pkey
    oe_result_t result = OE_FAILURE;
    uint8_t* output_certificate = nullptr;
    size_t output_certificate_size = 0;
    uint8_t* private_key_buffer = nullptr;
    size_t private_key_buffer_size = 0;
    uint8_t* public_key_buffer = nullptr;
    size_t public_key_buffer_size = 0;
    uint8_t* optional_parameters = nullptr;
    size_t optional_parameters_size = 0;
    const unsigned char* certificate_buffer_ptr = nullptr;
    BIO* mem = nullptr;

    result = generate_key_pair(
        &public_key_buffer,
        &public_key_buffer_size,
        &private_key_buffer,
        &private_key_buffer_size);
    if (result != OE_OK) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " generate_key_pair failed."
            << oe_result_str(result);
        goto done;
    }

    // printf("public_key_buf_size:[%ld]\n", public_key_buffer_size);
    // printf("public key used:\n[%s]", public_key_buffer);

    oe_attester_initialize();
    result = oe_get_attestation_certificate_with_evidence_v2(
        &_uuid_sgx_ecdsa,
        certificate_subject_name,
        private_key_buffer,
        private_key_buffer_size,
        public_key_buffer,
        public_key_buffer_size,
        optional_parameters,
        optional_parameters_size,
        &output_certificate,
        &output_certificate_size);
    if (result != OE_OK) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " oe_get_attestation_certificate_with_evidence_v2 failed." << oe_result_str(result);
        goto done;
    }

    // temporary buffer required as if d2i_x509 call is successful
    // certificate_buffer_ptr is incremented to the byte following the parsed
    // data. sending certificate_buffer_ptr as argument will keep
    // output_certificate pointer undisturbed.
    certificate_buffer_ptr = output_certificate;

    if ((raft_node_cert = d2i_X509(
             nullptr,
             &certificate_buffer_ptr,
             (long)output_certificate_size)) == nullptr)
    {
        printf("Failed to convert DER format certificate to X509 structure\n");
        goto done;
    }
    mem = BIO_new_mem_buf((void*)private_key_buffer, -1);
    if (!mem)
    {
        printf("Failed to convert private key buf into BIO_mem\n");
        goto done;
    }
    if ((raft_node_pkey = PEM_read_bio_PrivateKey(mem, nullptr, 0, nullptr)) == nullptr)
    {
        printf("Failed to convert private key buffer into EVP_KEY format\n");
        goto done;
    }

    result = OE_OK;
done:
    certificate_buffer_ptr = nullptr;
    BIO_free(mem);
    oe_free_key(private_key_buffer, private_key_buffer_size, nullptr, 0);
    oe_free_key(public_key_buffer, public_key_buffer_size, nullptr, 0);
    oe_free_attestation_certificate(output_certificate);
    return result;         
}    

// input: input_data and input_data_len
// output: key, key_size
//- TODO: Change printf to LOG_INFO
oe_result_t generate_key_pair(uint8_t** public_key, size_t* public_key_size,
                            uint8_t** private_key, size_t* private_key_size) {
    oe_result_t result = OE_FAILURE;
    oe_asymmetric_key_params_t params;
    char user_data[] = "test user data!";
    size_t user_data_size = sizeof(user_data) - 1;

    // Call oe_get_public_key_by_policy() to generate key pair derived from an
    // enclave's seal key If an enclave does not want to have this key pair tied
    // to enclave instance, it can generate its own key pair using any chosen
    // crypto API

    params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1; // MBEDTLS_ECP_DP_SECP256R1
    params.format = OE_ASYMMETRIC_KEY_PEM;
    params.user_data = user_data;
    params.user_data_size = user_data_size;
    //- TODO: Which key policy should we use?
    result = oe_get_public_key_by_policy(
        OE_SEAL_POLICY_UNIQUE,
        // OE_SEAL_POLICY_PRODUCT,
        &params,
        public_key,
        public_key_size,
        NULL,
        NULL);
    if (result != OE_OK) {
        printf(
            "oe_get_public_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
            oe_result_str(result));
        goto done;
    }

    //- TODO: Which key policy should we use?
    result = oe_get_private_key_by_policy(
        OE_SEAL_POLICY_UNIQUE,
        &params,
        private_key,
        private_key_size,
        NULL,
        NULL);
    if (result != OE_OK) {
        printf(
            "oe_get_private_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
            oe_result_str(result));
        goto done;
    }

done:
    return result;
}


// This is the evidence claims validation callback. A TLS connecting party
// (client or server) can verify the passed in "identity" information to decide
// whether to accept the connection request from a tls server running inside a
// specific enclave. In a real app, custom identity validation should be done
// inside this routine.
oe_result_t enclave_claims_verifier(
    oe_claim_t* claims,
    size_t claims_length,
    void* arg)
{    
    LOG(INFO) << "Func: " << __FUNCTION__ << " Trying to verify the claims";
    oe_result_t result = OE_VERIFY_FAILED;
    const oe_claim_t* claim;
    (void)arg;
    // Dump an identity information: unique ID, signer ID and Product ID
    // They are MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves.

    // 1. Enclave's security version
    if ((claim = find_claim(
             claims, claims_length, OE_CLAIM_SECURITY_VERSION)) == nullptr) {
        LOG(INFO) << "Func: " << __FUNCTION__ 
            << " could not find OE_CLAIM_SECURITY_VERSION";
        goto done;
    }
    if (claim->value_size != sizeof(uint32_t)) {
        LOG(INFO) << "Func: " << __FUNCTION__ 
            << " security_version size(" << claim->value_size << ") checking failed";
        goto done;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " security_version = " << *claim->value;

    // 2. The unique ID for the enclave (i.e., the MRENCLAVE value)
    if ((claim = find_claim(claims, claims_length, OE_CLAIM_UNIQUE_ID)) ==
        nullptr) {
        LOG(INFO) << "Func: " << __FUNCTION__ 
            << " could not find OE_CLAIM_UNIQUE_ID";
        goto done;
    }
    if (claim->value_size != OE_UNIQUE_ID_SIZE) {
        LOG(INFO) << "Func: " << __FUNCTION__ 
            << " unique_id size(" << claim->value_size << ") checking failed";
        goto done;
    }
    //- Conduct the verification of this enclave's MRENCLAVE value
    if (verify_claim_value(claim) != OE_OK) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " failed: MRENCLAVE not equal";
        goto done;
    }

    // 3. The Product ID for the enclave, for SGX enclaves, this is the ISVPRODID value
    if ((claim = find_claim(claims, claims_length, OE_CLAIM_PRODUCT_ID)) ==
        nullptr) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " could not find OE_CLAIM_PRODUCT_ID";
        goto done;
    }
    if (claim->value_size != OE_PRODUCT_ID_SIZE) {
        LOG(INFO) << "Func: " << __FUNCTION__ 
            << " product_id size(" << claim->value_size << ") checking failed";
        goto done;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " product_id extracted.";
    // for (size_t i = 0; i < claim->value_size; i++) {
    //     // printf("0x%0x ", (uint8_t)claim->value[i]);
    //     LOG(INFO) << "Func: " << __FUNCTION__ << " value[" << i << "] = 0x"
    //         << (uint8_t)claim->value[i];
    // }

    // 4. The signer ID for the enclave (i.e., the MRSIGNER value)
    if ((claim = find_claim(claims, claims_length, OE_CLAIM_SIGNER_ID)) == nullptr) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " could not find OE_CLAIM_SIGNER_ID";
        goto done;
    }
    if (claim->value_size != OE_SIGNER_ID_SIZE) {
        LOG(INFO) << "Func: " << __FUNCTION__ 
            << " signer_id size(" << claim->value_size << ") checking failed";
        goto done;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " signer_id extracted.";
    // for (size_t i = 0; i < claim->value_size; i++) {
    //     // printf("0x%0x ", (uint8_t)claim->value[i]);
    //     LOG(INFO) << "Func: " << __FUNCTION__ << " value[" << i << "] = 0x"
    //         << (uint8_t)claim->value[i];
    // }

    //- TODO: We have completed MRENCLAVE verification. Do we need to
    //- vefiry the signer here?
    // if (!verify_signer_id(
    //         (char*)OTHER_ENCLAVE_PUBLIC_KEY,
    //         sizeof(OTHER_ENCLAVE_PUBLIC_KEY),
    //         claim->value,
    //         claim->value_size))
    // {
    //     printf(TLS_CLIENT "failed: signer_id not equal\n");
    //     goto done;
    // }
    LOG(INFO) << "Func: " << __FUNCTION__ << "signer_id validation passed.";
    LOG(INFO) << "Func: " << __FUNCTION__ << " Return success";
    result = OE_OK;
done:
    return result;
}

//- This func helps to avoid re-verification of a cert buffer
//- If a cert buffer has been already verified, return true, false otherwise
// bool verify_cert_buf(uint8_t* in_buf, int in_len) {
//     int size = verified_certs.size();    
//     bool flag = false;
//     for (int i = 0; i < size; i++) {
//         if (verified_certs[i].buffer_len != in_len) {
//             continue;
//         }
//         if (memcmp(in_buf, verified_certs[i].cert_buffer, in_len) != 0) {
//             continue;
//         }
//         flag = true;
//         break;
//     }
//     // LOG(INFO) << "Func: " << __FUNCTION__ << " size = " << size;
//     return flag;
// }

// The return value of verify_callback controls the strategy of the further
// verification process. If verify_callback returns 0, the verification process
// is immediately stopped with "verification failed" state and A verification
// failure alert is sent to the peer and the TLS/SSL handshake is terminated. If
// verify_callback returns 1, the verification process is continued.
int verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
    // return 1;
    sgxbutil::Timer timer;
    int ret = 0;
    int der_len = 0;
    unsigned char* der = nullptr;
    unsigned char* buff = nullptr;

    //- This will be saved in verified_certs if verified successfully
    // AttestationCertBuffer tmp_struct;
    // uint8_t* tmp_buf = nullptr;
    // int has_been_verified = 0;

    oe_result_t result = OE_FAILURE;
    X509* crt = nullptr;
    int err = X509_V_ERR_UNSPECIFIED;

    LOG(INFO) << "Func: " << __FUNCTION__ 
        << " verify_callback called with preverify_ok = " << preverify_ok;
    crt = X509_STORE_CTX_get_current_cert(ctx);
    if (crt == nullptr) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " failed to retrieve certificate";
        goto done;
    }
    
    if (preverify_ok == 0) {
        err = X509_STORE_CTX_get_error(ctx);
        if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            // A self-signed certificate is expected, return 1 to continue the
            // verification process
            LOG(INFO) << "Func: " << __FUNCTION__ << " self-signed certificated detected";
            ret = 1;
            goto done;
        }
    }

    // convert a cert into a buffer in DER format
    der_len = i2d_X509(crt, nullptr);
    buff = (unsigned char*)malloc((size_t)der_len);
    
    if (buff == nullptr) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " malloc failed (der_len = " 
            << der_len;
        goto done;
    }
    der = buff;    

    der_len = i2d_X509(crt, &buff);
    if (der_len < 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " i2d_X509 failed (der_len = " 
            << der_len;
        goto done;
    }

    LOG(INFO) << "Func: " << __FUNCTION__ << " verifying certificate start";    

    timer.start();
    // verify tls certificate
    oe_verifier_initialize();
    result = oe_verify_attestation_certificate_with_evidence(
        der, (size_t)der_len, enclave_claims_verifier, nullptr);
    // return 1;
    timer.stop();
    if (result != OE_OK) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " result = " << oe_result_str(result);
        goto done;
    }
    // VLOG(85) << "Func: " << __FUNCTION__ << " verifying certificate end TIME_OF verify cert = " << timer.m_elapsed(0.0) << " ms";
    ret = 1;

done:
    if (der) {
        free(der);
    }        

    if (err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
        LOG(INFO) << "Func: " << __FUNCTION__ 
            << " verifying SGX certificate extensions " << (ret ? "succeeded" : "failed");
    }
    oe_verifier_shutdown();
    return ret;
}

//- Verify that the remote party's enclave is the same
oe_result_t verify_claim_value(const oe_claim_t* claim) {
    // return OE_OK;
    oe_result_t result = OE_OK;
    LOG(INFO) << "Func: " << __FUNCTION__ << " verify unique_id:";
    for (int i = 0; i < claim->value_size; i++) {
    //     fprintf(stdout, "SELF_MRENCLAVE[%d]: %02x, claim->value[%d]: %02x\n",
    //         i, SELF_MRENCLAVE[i], i, (uint8_t)claim->value[i]);
        if (SELF_MRENCLAVE[i] != claim->value[i]) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " verify unique_id failed at byte-" 
                << i;
            result = OE_FAILURE;
            break;
        }
    }
    return result;
}



/**
 * Helper function used to make the claim-finding process more convenient. Given
 * the claim name, claim list, and its size, returns the claim with that claim
 * name in the list.
 */
static const oe_claim_t* find_claim(
    const oe_claim_t* claims,
    size_t claims_size,
    const char* name)
{
    for (size_t i = 0; i < claims_size; i++)
    {
        if (strcmp(claims[i].name, name) == 0)
            return &(claims[i]);
    }
    return nullptr;
}

/**
 * Help to verify the signer.
 */
static bool verify_signer_id(
    const char* pem_key_buffer,
    size_t pem_key_buffer_len,
    uint8_t* expected_signer,
    size_t expected_signer_size)
{
    LOG(INFO) << "Func: " << __FUNCTION__ << " verify connecting server's identity";

    uint8_t calculated_signer[OE_SIGNER_ID_SIZE];
    size_t calculated_signer_size = sizeof(calculated_signer);
    if (oe_sgx_get_signer_id_from_public_key(
            pem_key_buffer,
            pem_key_buffer_len,
            calculated_signer,
            &calculated_signer_size) != OE_OK) {
        LOG(INFO) << "Func: " << __FUNCTION__ 
            << " oe_sgx_get_signer_id_from_public_key failed";
        return false;
    }

    // validate against
    if (memcmp(calculated_signer, expected_signer, expected_signer_size) != 0) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " signer_id is not equal";
        for (size_t i = 0; i < expected_signer_size; i++) {
            //- TODO: Use printf or LOG_INFO?
            printf(
                "0x%x - 0x%x\n",
                (uint8_t)expected_signer[i],
                (uint8_t)calculated_signer[i]);
        }
        return false;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " signer_id was successfully validated";
    return true;
}

int performance_test_generate_evidence() {
    //- Befor get cert and pkey, create a report and then extract the MRENCLAVE
    //- from it. Thus we can vefiry the MRENCLAVE later.
    uint8_t* report;
    size_t report_size = 0;
    int rc = oe_get_report_v2(0, NULL, 0, NULL, 0, &report, &report_size);
    if (rc != OE_OK) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " oe_get_report_v2 failed.";
        return -1;
    }
    oe_report_t parsed_report = {0};
    rc = oe_parse_report(report, report_size, &parsed_report);
    if (rc != OE_OK) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " oe_parse_report failed.";
        return -1;
    }
    memcpy(SELF_MRENCLAVE, parsed_report.identity.unique_id, 32);
    oe_free_report(report);

    //- Now, get cert and pkey
    oe_result_t result = OE_FAILURE;
    uint8_t* output_certificate = nullptr;
    size_t output_certificate_size = 0;
    uint8_t* private_key_buffer = nullptr;
    size_t private_key_buffer_size = 0;
    uint8_t* public_key_buffer = nullptr;
    size_t public_key_buffer_size = 0;
    uint8_t* optional_parameters = nullptr;
    size_t optional_parameters_size = 0;
    const unsigned char* certificate_buffer_ptr = nullptr;
    BIO* mem = nullptr;

    result = generate_key_pair(
        &public_key_buffer,
        &public_key_buffer_size,
        &private_key_buffer,
        &private_key_buffer_size);
    if (result != OE_OK) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " generate_key_pair failed."
            << oe_result_str(result);
        goto done;
    }

    // printf("public_key_buf_size:[%ld]\n", public_key_buffer_size);
    // printf("public key used:\n[%s]", public_key_buffer);

    oe_attester_initialize();
    result = oe_get_attestation_certificate_with_evidence_v2(
        &_uuid_sgx_ecdsa,
        certificate_subject_name,
        private_key_buffer,
        private_key_buffer_size,
        public_key_buffer,
        public_key_buffer_size,
        optional_parameters,
        optional_parameters_size,
        &output_certificate,
        &output_certificate_size);
    if (result != OE_OK) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " oe_get_attestation_certificate_with_evidence_v2 failed." << oe_result_str(result);
        goto done;
    }

    // temporary buffer required as if d2i_x509 call is successful
    // certificate_buffer_ptr is incremented to the byte following the parsed
    // data. sending certificate_buffer_ptr as argument will keep
    // output_certificate pointer undisturbed.
    certificate_buffer_ptr = output_certificate;

    if ((raft_node_cert = d2i_X509(
             nullptr,
             &certificate_buffer_ptr,
             (long)output_certificate_size)) == nullptr)
    {
        printf("Failed to convert DER format certificate to X509 structure\n");
        goto done;
    }
    mem = BIO_new_mem_buf((void*)private_key_buffer, -1);
    if (!mem)
    {
        printf("Failed to convert private key buf into BIO_mem\n");
        goto done;
    }
    if ((raft_node_pkey = PEM_read_bio_PrivateKey(mem, nullptr, 0, nullptr)) == nullptr)
    {
        printf("Failed to convert private key buffer into EVP_KEY format\n");
        goto done;
    }

    result = OE_OK;
done:
    certificate_buffer_ptr = nullptr;
    BIO_free(mem);
    oe_free_key(private_key_buffer, private_key_buffer_size, nullptr, 0);
    oe_free_key(public_key_buffer, public_key_buffer_size, nullptr, 0);
    oe_free_attestation_certificate(output_certificate);
    return result;   
}

int performance_test_verify_evidence() {
    oe_verifier_initialize();
    size_t der_len = 5257;
    unsigned char der[5257] = {48, 130, 20, 133, 48, 130, 20, 42, 160, 3, 2, 1, 2, 2, 1, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 60, 49, 25, 48, 23, 6, 3, 85, 4, 3, 12, 16, 79, 112, 101, 110, 32, 69, 110, 99, 108, 97, 118, 101, 32, 83, 68, 75, 49, 18, 48, 16, 6, 3, 85, 4, 10, 12, 9, 79, 69, 83, 68, 75, 32, 84, 76, 83, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 48, 34, 24, 15, 50, 48, 49, 57, 48, 53, 48, 49, 48, 48, 48, 48, 48, 48, 90, 24, 15, 50, 48, 53, 48, 49, 50, 51, 49, 50, 51, 53, 57, 53, 57, 90, 48, 60, 49, 25, 48, 23, 6, 3, 85, 4, 3, 12, 16, 79, 112, 101, 110, 32, 69, 110, 99, 108, 97, 118, 101, 32, 83, 68, 75, 49, 18, 48, 16, 6, 3, 85, 4, 10, 12, 9, 79, 69, 83, 68, 75, 32, 84, 76, 83, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 26, 69, 231, 155, 202, 255, 232, 9, 229, 79, 85, 249, 54, 243, 175, 155, 202, 155, 72, 148, 242, 85, 215, 140, 235, 123, 77, 200, 83, 1, 151, 196, 250, 183, 77, 154, 98, 167, 224, 221, 51, 124, 171, 17, 219, 114, 84, 14, 103, 53, 194, 239, 228, 30, 73, 33, 127, 131, 129, 36, 148, 80, 186, 118, 163, 130, 19, 23, 48, 130, 19, 19, 48, 9, 6, 3, 85, 29, 19, 4, 2, 48, 0, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 37, 245, 254, 235, 137, 152, 186, 150, 15, 224, 158, 202, 77, 184, 192, 6, 78, 22, 56, 195, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 37, 245, 254, 235, 137, 152, 186, 150, 15, 224, 158, 202, 77, 184, 192, 6, 78, 22, 56, 195, 48, 130, 18, 196, 6, 9, 43, 6, 1, 4, 1, 130, 55, 105, 2, 4, 130, 18, 181, 3, 0, 0, 0, 163, 162, 30, 135, 27, 77, 64, 20, 183, 10, 161, 37, 210, 251, 205, 140, 0, 0, 0, 0, 149, 18, 0, 0, 0, 0, 0, 0, 3, 0, 2, 0, 0, 0, 0, 0, 6, 0, 11, 0, 147, 154, 114, 51, 247, 156, 76, 169, 148, 10, 13, 179, 149, 127, 6, 7, 203, 71, 137, 215, 41, 238, 134, 9, 158, 183, 87, 59, 161, 161, 248, 223, 0, 0, 0, 0, 11, 11, 255, 13, 255, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 184, 212, 9, 204, 103, 255, 210, 8, 45, 179, 233, 148, 64, 29, 143, 116, 187, 228, 89, 21, 214, 158, 183, 191, 78, 26, 16, 75, 182, 229, 139, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 214, 147, 113, 81, 138, 29, 33, 142, 128, 107, 121, 50, 208, 236, 76, 152, 59, 245, 197, 85, 149, 86, 79, 207, 47, 151, 87, 60, 77, 90, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 235, 2, 19, 231, 172, 110, 21, 203, 157, 197, 191, 206, 161, 151, 156, 243, 217, 255, 48, 169, 139, 161, 208, 46, 210, 180, 132, 57, 36, 250, 216, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 46, 16, 0, 0, 185, 185, 114, 253, 68, 238, 181, 96, 116, 47, 206, 64, 97, 96, 106, 220, 97, 141, 83, 66, 80, 82, 56, 206, 95, 129, 79, 188, 34, 169, 80, 178, 209, 145, 146, 217, 231, 179, 0, 128, 200, 41, 22, 108, 110, 192, 139, 100, 70, 119, 27, 117, 33, 229, 120, 74, 167, 10, 45, 143, 16, 119, 131, 66, 222, 37, 234, 147, 181, 150, 89, 144, 228, 56, 152, 113, 154, 58, 17, 98, 192, 57, 33, 211, 53, 157, 63, 207, 202, 63, 233, 128, 170, 212, 207, 108, 250, 144, 62, 239, 99, 172, 14, 56, 7, 220, 87, 108, 72, 16, 156, 72, 203, 247, 43, 245, 3, 107, 198, 235, 106, 248, 80, 162, 32, 249, 60, 2, 11, 11, 255, 13, 255, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 92, 96, 105, 59, 147, 130, 82, 3, 109, 99, 207, 128, 157, 173, 5, 210, 170, 29, 205, 26, 78, 13, 223, 249, 17, 81, 48, 186, 218, 36, 38, 62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 140, 79, 87, 117, 215, 150, 80, 62, 150, 19, 127, 119, 198, 138, 130, 154, 0, 86, 172, 141, 237, 112, 20, 11, 8, 27, 9, 68, 144, 197, 123, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47, 21, 211, 207, 170, 87, 141, 27, 235, 242, 56, 38, 129, 227, 250, 40, 242, 88, 24, 149, 254, 225, 104, 120, 223, 75, 23, 97, 136, 34, 249, 228, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57, 246, 217, 233, 252, 167, 130, 207, 136, 24, 108, 214, 81, 188, 158, 48, 69, 178, 52, 0, 176, 91, 228, 53, 203, 194, 62, 160, 231, 58, 95, 46, 50, 255, 241, 224, 66, 233, 238, 131, 243, 49, 186, 52, 65, 25, 249, 145, 61, 142, 129, 66, 48, 4, 130, 114, 2, 146, 106, 241, 136, 86, 39, 76, 32, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 5, 0, 198, 13, 0, 0, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 77, 73, 73, 69, 103, 84, 67, 67, 66, 67, 97, 103, 65, 119, 73, 66, 65, 103, 73, 85, 79, 75, 80, 120, 53, 56, 57, 110, 119, 118, 43, 101, 89, 98, 110, 116, 43, 111, 85, 87, 73, 51, 52, 57, 108, 87, 69, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 73, 119, 99, 84, 69, 106, 77, 67, 69, 71, 65, 49, 85, 69, 10, 65, 119, 119, 97, 83, 87, 53, 48, 90, 87, 119, 103, 85, 48, 100, 89, 73, 70, 66, 68, 83, 121, 66, 81, 99, 109, 57, 106, 90, 88, 78, 122, 98, 51, 73, 103, 81, 48, 69, 120, 71, 106, 65, 89, 66, 103, 78, 86, 66, 65, 111, 77, 69, 85, 108, 117, 100, 71, 86, 115, 73, 69, 78, 118, 99, 110, 66, 118, 99, 109, 70, 48, 97, 87, 57, 117, 10, 77, 82, 81, 119, 69, 103, 89, 68, 86, 81, 81, 72, 68, 65, 116, 84, 89, 87, 53, 48, 89, 83, 66, 68, 98, 71, 70, 121, 89, 84, 69, 76, 77, 65, 107, 71, 65, 49, 85, 69, 67, 65, 119, 67, 81, 48, 69, 120, 67, 122, 65, 74, 66, 103, 78, 86, 66, 65, 89, 84, 65, 108, 86, 84, 77, 66, 52, 88, 68, 84, 73, 120, 77, 68, 99, 119, 10, 77, 122, 65, 53, 77, 122, 73, 122, 77, 70, 111, 88, 68, 84, 73, 52, 77, 68, 99, 119, 77, 122, 65, 53, 77, 122, 73, 122, 77, 70, 111, 119, 99, 68, 69, 105, 77, 67, 65, 71, 65, 49, 85, 69, 65, 119, 119, 90, 83, 87, 53, 48, 90, 87, 119, 103, 85, 48, 100, 89, 73, 70, 66, 68, 83, 121, 66, 68, 90, 88, 74, 48, 97, 87, 90, 112, 10, 89, 50, 70, 48, 90, 84, 69, 97, 77, 66, 103, 71, 65, 49, 85, 69, 67, 103, 119, 82, 83, 87, 53, 48, 90, 87, 119, 103, 81, 50, 57, 121, 99, 71, 57, 121, 89, 88, 82, 112, 98, 50, 52, 120, 70, 68, 65, 83, 66, 103, 78, 86, 66, 65, 99, 77, 67, 49, 78, 104, 98, 110, 82, 104, 73, 69, 78, 115, 89, 88, 74, 104, 77, 81, 115, 119, 10, 67, 81, 89, 68, 86, 81, 81, 73, 68, 65, 74, 68, 81, 84, 69, 76, 77, 65, 107, 71, 65, 49, 85, 69, 66, 104, 77, 67, 86, 86, 77, 119, 87, 84, 65, 84, 66, 103, 99, 113, 104, 107, 106, 79, 80, 81, 73, 66, 66, 103, 103, 113, 104, 107, 106, 79, 80, 81, 77, 66, 66, 119, 78, 67, 65, 65, 82, 73, 118, 85, 119, 105, 88, 85, 116, 47, 10, 98, 117, 71, 50, 80, 114, 54, 67, 106, 67, 113, 50, 76, 118, 82, 86, 120, 86, 50, 104, 98, 75, 56, 110, 107, 66, 85, 47, 84, 105, 103, 76, 77, 71, 121, 80, 55, 102, 56, 105, 99, 107, 66, 65, 86, 57, 87, 110, 76, 75, 73, 73, 109, 47, 69, 85, 53, 90, 118, 112, 56, 74, 88, 87, 68, 87, 106, 97, 98, 43, 48, 117, 100, 100, 79, 121, 10, 111, 52, 73, 67, 109, 122, 67, 67, 65, 112, 99, 119, 72, 119, 89, 68, 86, 82, 48, 106, 66, 66, 103, 119, 70, 111, 65, 85, 48, 79, 105, 113, 50, 110, 88, 88, 43, 83, 53, 74, 70, 53, 103, 56, 101, 120, 82, 108, 48, 78, 88, 121, 87, 85, 48, 119, 88, 119, 89, 68, 86, 82, 48, 102, 66, 70, 103, 119, 86, 106, 66, 85, 111, 70, 75, 103, 10, 85, 73, 90, 79, 97, 72, 82, 48, 99, 72, 77, 54, 76, 121, 57, 104, 99, 71, 107, 117, 100, 72, 74, 49, 99, 51, 82, 108, 90, 72, 78, 108, 99, 110, 90, 112, 89, 50, 86, 122, 76, 109, 108, 117, 100, 71, 86, 115, 76, 109, 78, 118, 98, 83, 57, 122, 90, 51, 103, 118, 89, 50, 86, 121, 100, 71, 108, 109, 97, 87, 78, 104, 100, 71, 108, 118, 10, 98, 105, 57, 50, 77, 105, 57, 119, 89, 50, 116, 106, 99, 109, 119, 47, 89, 50, 69, 57, 99, 72, 74, 118, 89, 50, 86, 122, 99, 50, 57, 121, 77, 66, 48, 71, 65, 49, 85, 100, 68, 103, 81, 87, 66, 66, 83, 51, 76, 54, 81, 103, 80, 97, 51, 84, 102, 74, 110, 112, 85, 56, 110, 97, 43, 116, 67, 88, 86, 52, 103, 53, 43, 84, 65, 79, 10, 66, 103, 78, 86, 72, 81, 56, 66, 65, 102, 56, 69, 66, 65, 77, 67, 66, 115, 65, 119, 68, 65, 89, 68, 86, 82, 48, 84, 65, 81, 72, 47, 66, 65, 73, 119, 65, 68, 67, 67, 65, 100, 81, 71, 67, 83, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 83, 67, 65, 99, 85, 119, 103, 103, 72, 66, 77, 66, 52, 71, 67, 105, 113, 71, 10, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 69, 69, 69, 69, 69, 76, 78, 97, 119, 120, 112, 67, 79, 66, 114, 90, 77, 55, 97, 122, 49, 68, 55, 52, 99, 119, 103, 103, 70, 107, 66, 103, 111, 113, 104, 107, 105, 71, 43, 69, 48, 66, 68, 81, 69, 67, 77, 73, 73, 66, 86, 68, 65, 81, 66, 103, 115, 113, 104, 107, 105, 71, 43, 69, 48, 66, 10, 68, 81, 69, 67, 65, 81, 73, 66, 67, 122, 65, 81, 66, 103, 115, 113, 104, 107, 105, 71, 43, 69, 48, 66, 68, 81, 69, 67, 65, 103, 73, 66, 67, 122, 65, 81, 66, 103, 115, 113, 104, 107, 105, 71, 43, 69, 48, 66, 68, 81, 69, 67, 65, 119, 73, 66, 65, 106, 65, 81, 66, 103, 115, 113, 104, 107, 105, 71, 43, 69, 48, 66, 68, 81, 69, 67, 10, 66, 65, 73, 66, 65, 106, 65, 81, 66, 103, 115, 113, 104, 107, 105, 71, 43, 69, 48, 66, 68, 81, 69, 67, 66, 81, 73, 66, 65, 106, 65, 82, 66, 103, 115, 113, 104, 107, 105, 71, 43, 69, 48, 66, 68, 81, 69, 67, 66, 103, 73, 67, 65, 73, 65, 119, 69, 65, 89, 76, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 103, 99, 67, 10, 65, 81, 65, 119, 69, 65, 89, 76, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 103, 103, 67, 65, 81, 65, 119, 69, 65, 89, 76, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 103, 107, 67, 65, 81, 65, 119, 69, 65, 89, 76, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 103, 111, 67, 65, 81, 65, 119, 10, 69, 65, 89, 76, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 103, 115, 67, 65, 81, 65, 119, 69, 65, 89, 76, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 103, 119, 67, 65, 81, 65, 119, 69, 65, 89, 76, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 103, 48, 67, 65, 81, 65, 119, 69, 65, 89, 76, 10, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 103, 52, 67, 65, 81, 65, 119, 69, 65, 89, 76, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 103, 56, 67, 65, 81, 65, 119, 69, 65, 89, 76, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 104, 65, 67, 65, 81, 65, 119, 69, 65, 89, 76, 75, 111, 90, 73, 10, 104, 118, 104, 78, 65, 81, 48, 66, 65, 104, 69, 67, 65, 81, 115, 119, 72, 119, 89, 76, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 65, 104, 73, 69, 69, 65, 115, 76, 65, 103, 73, 67, 103, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 119, 69, 65, 89, 75, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 10, 65, 119, 81, 67, 65, 65, 65, 119, 70, 65, 89, 75, 75, 111, 90, 73, 104, 118, 104, 78, 65, 81, 48, 66, 66, 65, 81, 71, 65, 75, 66, 108, 85, 81, 65, 65, 77, 65, 56, 71, 67, 105, 113, 71, 83, 73, 98, 52, 84, 81, 69, 78, 65, 81, 85, 75, 65, 81, 65, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 73, 68, 10, 83, 81, 65, 119, 82, 103, 73, 104, 65, 76, 55, 109, 122, 80, 43, 75, 105, 105, 74, 81, 102, 115, 98, 75, 54, 88, 116, 113, 76, 113, 90, 50, 51, 65, 47, 85, 54, 122, 86, 118, 107, 53, 97, 111, 70, 56, 48, 114, 68, 51, 53, 87, 65, 105, 69, 65, 57, 67, 108, 105, 89, 103, 80, 99, 104, 66, 50, 119, 54, 77, 114, 121, 65, 53, 48, 43, 10, 86, 90, 113, 73, 99, 112, 116, 77, 117, 51, 57, 117, 87, 114, 83, 102, 67, 49, 53, 109, 73, 120, 99, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 77, 73, 73, 67, 108, 122, 67, 67, 65, 106, 54, 103, 65, 119, 73, 66, 65, 103, 73, 86, 65, 78, 68, 111, 113, 116, 112, 49, 49, 47, 107, 117, 83, 82, 101, 89, 80, 72, 115, 85, 90, 100, 68, 86, 56, 108, 108, 78, 77, 65, 111, 71, 67, 67, 113, 71, 83, 77, 52, 57, 66, 65, 77, 67, 10, 77, 71, 103, 120, 71, 106, 65, 89, 66, 103, 78, 86, 66, 65, 77, 77, 69, 85, 108, 117, 100, 71, 86, 115, 73, 70, 78, 72, 87, 67, 66, 83, 98, 50, 57, 48, 73, 69, 78, 66, 77, 82, 111, 119, 71, 65, 89, 68, 86, 81, 81, 75, 68, 66, 70, 74, 98, 110, 82, 108, 98, 67, 66, 68, 10, 98, 51, 74, 119, 98, 51, 74, 104, 100, 71, 108, 118, 98, 106, 69, 85, 77, 66, 73, 71, 65, 49, 85, 69, 66, 119, 119, 76, 85, 50, 70, 117, 100, 71, 69, 103, 81, 50, 120, 104, 99, 109, 69, 120, 67, 122, 65, 74, 66, 103, 78, 86, 66, 65, 103, 77, 65, 107, 78, 66, 77, 81, 115, 119, 10, 67, 81, 89, 68, 86, 81, 81, 71, 69, 119, 74, 86, 85, 122, 65, 101, 70, 119, 48, 120, 79, 68, 65, 49, 77, 106, 69, 120, 77, 68, 81, 49, 77, 68, 104, 97, 70, 119, 48, 122, 77, 122, 65, 49, 77, 106, 69, 120, 77, 68, 81, 49, 77, 68, 104, 97, 77, 72, 69, 120, 73, 122, 65, 104, 10, 66, 103, 78, 86, 66, 65, 77, 77, 71, 107, 108, 117, 100, 71, 86, 115, 73, 70, 78, 72, 87, 67, 66, 81, 81, 48, 115, 103, 85, 72, 74, 118, 89, 50, 86, 122, 99, 50, 57, 121, 73, 69, 78, 66, 77, 82, 111, 119, 71, 65, 89, 68, 86, 81, 81, 75, 68, 66, 70, 74, 98, 110, 82, 108, 10, 98, 67, 66, 68, 98, 51, 74, 119, 98, 51, 74, 104, 100, 71, 108, 118, 98, 106, 69, 85, 77, 66, 73, 71, 65, 49, 85, 69, 66, 119, 119, 76, 85, 50, 70, 117, 100, 71, 69, 103, 81, 50, 120, 104, 99, 109, 69, 120, 67, 122, 65, 74, 66, 103, 78, 86, 66, 65, 103, 77, 65, 107, 78, 66, 10, 77, 81, 115, 119, 67, 81, 89, 68, 86, 81, 81, 71, 69, 119, 74, 86, 85, 122, 66, 90, 77, 66, 77, 71, 66, 121, 113, 71, 83, 77, 52, 57, 65, 103, 69, 71, 67, 67, 113, 71, 83, 77, 52, 57, 65, 119, 69, 72, 65, 48, 73, 65, 66, 76, 57, 113, 43, 78, 77, 112, 50, 73, 79, 103, 10, 116, 100, 108, 49, 98, 107, 47, 117, 87, 90, 53, 43, 84, 71, 81, 109, 56, 97, 67, 105, 56, 122, 55, 56, 102, 115, 43, 102, 75, 67, 81, 51, 100, 43, 117, 68, 122, 88, 110, 86, 84, 65, 84, 50, 90, 104, 68, 67, 105, 102, 121, 73, 117, 74, 119, 118, 78, 51, 119, 78, 66, 112, 57, 105, 10, 72, 66, 83, 83, 77, 74, 77, 74, 114, 66, 79, 106, 103, 98, 115, 119, 103, 98, 103, 119, 72, 119, 89, 68, 86, 82, 48, 106, 66, 66, 103, 119, 70, 111, 65, 85, 73, 109, 85, 77, 49, 108, 113, 100, 78, 73, 110, 122, 103, 55, 83, 86, 85, 114, 57, 81, 71, 122, 107, 110, 66, 113, 119, 119, 10, 85, 103, 89, 68, 86, 82, 48, 102, 66, 69, 115, 119, 83, 84, 66, 72, 111, 69, 87, 103, 81, 52, 90, 66, 97, 72, 82, 48, 99, 72, 77, 54, 76, 121, 57, 106, 90, 88, 74, 48, 97, 87, 90, 112, 89, 50, 70, 48, 90, 88, 77, 117, 100, 72, 74, 49, 99, 51, 82, 108, 90, 72, 78, 108, 10, 99, 110, 90, 112, 89, 50, 86, 122, 76, 109, 108, 117, 100, 71, 86, 115, 76, 109, 78, 118, 98, 83, 57, 74, 98, 110, 82, 108, 98, 70, 78, 72, 87, 70, 74, 118, 98, 51, 82, 68, 81, 83, 53, 106, 99, 109, 119, 119, 72, 81, 89, 68, 86, 82, 48, 79, 66, 66, 89, 69, 70, 78, 68, 111, 10, 113, 116, 112, 49, 49, 47, 107, 117, 83, 82, 101, 89, 80, 72, 115, 85, 90, 100, 68, 86, 56, 108, 108, 78, 77, 65, 52, 71, 65, 49, 85, 100, 68, 119, 69, 66, 47, 119, 81, 69, 65, 119, 73, 66, 66, 106, 65, 83, 66, 103, 78, 86, 72, 82, 77, 66, 65, 102, 56, 69, 67, 68, 65, 71, 10, 65, 81, 72, 47, 65, 103, 69, 65, 77, 65, 111, 71, 67, 67, 113, 71, 83, 77, 52, 57, 66, 65, 77, 67, 65, 48, 99, 65, 77, 69, 81, 67, 73, 67, 47, 57, 106, 43, 56, 52, 84, 43, 72, 122, 116, 86, 79, 47, 115, 79, 81, 66, 87, 74, 98, 83, 100, 43, 47, 50, 117, 101, 120, 75, 10, 52, 43, 97, 65, 48, 106, 99, 70, 66, 76, 99, 112, 65, 105, 65, 51, 100, 104, 77, 114, 70, 53, 99, 68, 53, 50, 116, 54, 70, 113, 77, 118, 65, 73, 112, 106, 56, 88, 100, 71, 109, 121, 50, 98, 101, 101, 108, 106, 76, 74, 75, 43, 112, 122, 112, 99, 82, 65, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 77, 73, 73, 67, 106, 106, 67, 67, 65, 106, 83, 103, 65, 119, 73, 66, 65, 103, 73, 85, 73, 109, 85, 77, 49, 108, 113, 100, 78, 73, 110, 122, 103, 55, 83, 86, 85, 114, 57, 81, 71, 122, 107, 110, 66, 113, 119, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 73, 119, 10, 97, 68, 69, 97, 77, 66, 103, 71, 65, 49, 85, 69, 65, 119, 119, 82, 83, 87, 53, 48, 90, 87, 119, 103, 85, 48, 100, 89, 73, 70, 74, 118, 98, 51, 81, 103, 81, 48, 69, 120, 71, 106, 65, 89, 66, 103, 78, 86, 66, 65, 111, 77, 69, 85, 108, 117, 100, 71, 86, 115, 73, 69, 78, 118, 10, 99, 110, 66, 118, 99, 109, 70, 48, 97, 87, 57, 117, 77, 82, 81, 119, 69, 103, 89, 68, 86, 81, 81, 72, 68, 65, 116, 84, 89, 87, 53, 48, 89, 83, 66, 68, 98, 71, 70, 121, 89, 84, 69, 76, 77, 65, 107, 71, 65, 49, 85, 69, 67, 65, 119, 67, 81, 48, 69, 120, 67, 122, 65, 74, 10, 66, 103, 78, 86, 66, 65, 89, 84, 65, 108, 86, 84, 77, 66, 52, 88, 68, 84, 69, 52, 77, 68, 85, 121, 77, 84, 69, 119, 78, 68, 69, 120, 77, 86, 111, 88, 68, 84, 77, 122, 77, 68, 85, 121, 77, 84, 69, 119, 78, 68, 69, 120, 77, 70, 111, 119, 97, 68, 69, 97, 77, 66, 103, 71, 10, 65, 49, 85, 69, 65, 119, 119, 82, 83, 87, 53, 48, 90, 87, 119, 103, 85, 48, 100, 89, 73, 70, 74, 118, 98, 51, 81, 103, 81, 48, 69, 120, 71, 106, 65, 89, 66, 103, 78, 86, 66, 65, 111, 77, 69, 85, 108, 117, 100, 71, 86, 115, 73, 69, 78, 118, 99, 110, 66, 118, 99, 109, 70, 48, 10, 97, 87, 57, 117, 77, 82, 81, 119, 69, 103, 89, 68, 86, 81, 81, 72, 68, 65, 116, 84, 89, 87, 53, 48, 89, 83, 66, 68, 98, 71, 70, 121, 89, 84, 69, 76, 77, 65, 107, 71, 65, 49, 85, 69, 67, 65, 119, 67, 81, 48, 69, 120, 67, 122, 65, 74, 66, 103, 78, 86, 66, 65, 89, 84, 10, 65, 108, 86, 84, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 67, 54, 110, 69, 119, 77, 68, 73, 89, 90, 79, 106, 47, 105, 80, 87, 115, 67, 122, 97, 69, 75, 105, 55, 10, 49, 79, 105, 79, 83, 76, 82, 70, 104, 87, 71, 106, 98, 110, 66, 86, 74, 102, 86, 110, 107, 89, 52, 117, 51, 73, 106, 107, 68, 89, 89, 76, 48, 77, 120, 79, 52, 109, 113, 115, 121, 89, 106, 108, 66, 97, 108, 84, 86, 89, 120, 70, 80, 50, 115, 74, 66, 75, 53, 122, 108, 75, 79, 66, 10, 117, 122, 67, 66, 117, 68, 65, 102, 66, 103, 78, 86, 72, 83, 77, 69, 71, 68, 65, 87, 103, 66, 81, 105, 90, 81, 122, 87, 87, 112, 48, 48, 105, 102, 79, 68, 116, 74, 86, 83, 118, 49, 65, 98, 79, 83, 99, 71, 114, 68, 66, 83, 66, 103, 78, 86, 72, 82, 56, 69, 83, 122, 66, 74, 10, 77, 69, 101, 103, 82, 97, 66, 68, 104, 107, 70, 111, 100, 72, 82, 119, 99, 122, 111, 118, 76, 50, 78, 108, 99, 110, 82, 112, 90, 109, 108, 106, 89, 88, 82, 108, 99, 121, 53, 48, 99, 110, 86, 122, 100, 71, 86, 107, 99, 50, 86, 121, 100, 109, 108, 106, 90, 88, 77, 117, 97, 87, 53, 48, 10, 90, 87, 119, 117, 89, 50, 57, 116, 76, 48, 108, 117, 100, 71, 86, 115, 85, 48, 100, 89, 85, 109, 57, 118, 100, 69, 78, 66, 76, 109, 78, 121, 98, 68, 65, 100, 66, 103, 78, 86, 72, 81, 52, 69, 70, 103, 81, 85, 73, 109, 85, 77, 49, 108, 113, 100, 78, 73, 110, 122, 103, 55, 83, 86, 10, 85, 114, 57, 81, 71, 122, 107, 110, 66, 113, 119, 119, 68, 103, 89, 68, 86, 82, 48, 80, 65, 81, 72, 47, 66, 65, 81, 68, 65, 103, 69, 71, 77, 66, 73, 71, 65, 49, 85, 100, 69, 119, 69, 66, 47, 119, 81, 73, 77, 65, 89, 66, 65, 102, 56, 67, 65, 81, 69, 119, 67, 103, 89, 73, 10, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 73, 68, 83, 65, 65, 119, 82, 81, 73, 103, 81, 81, 115, 47, 48, 56, 114, 121, 99, 100, 80, 97, 117, 67, 70, 107, 56, 85, 80, 81, 88, 67, 77, 65, 108, 115, 108, 111, 66, 101, 55, 78, 119, 97, 81, 71, 84, 99, 100, 112, 97, 48, 69, 67, 10, 73, 81, 67, 85, 116, 56, 83, 71, 118, 120, 75, 109, 106, 112, 99, 77, 47, 122, 48, 87, 80, 57, 68, 118, 111, 56, 104, 50, 107, 53, 100, 117, 49, 105, 87, 68, 100, 66, 107, 65, 110, 43, 48, 105, 105, 65, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45, 10, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 71, 107, 88, 110, 109, 56, 114, 47, 54, 65, 110, 108, 84, 49, 88, 53, 78, 118, 79, 118, 109, 56, 113, 98, 83, 74, 84, 121, 10, 86, 100, 101, 77, 54, 51, 116, 78, 121, 70, 77, 66, 108, 56, 84, 54, 116, 48, 50, 97, 89, 113, 102, 103, 51, 84, 78, 56, 113, 120, 72, 98, 99, 108, 81, 79, 90, 122, 88, 67, 55, 43, 81, 101, 83, 83, 70, 47, 103, 52, 69, 107, 108, 70, 67, 54, 100, 103, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 0, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 73, 0, 48, 70, 2, 33, 0, 162, 28, 151, 170, 229, 146, 227, 134, 92, 255, 54, 14, 48, 118, 68, 182, 237, 45, 120, 141, 251, 83, 50, 137, 13, 213, 31, 47, 247, 193, 214, 188, 2, 33, 0, 156, 11, 67, 161, 253, 241, 81, 251, 239, 103, 230, 236, 184, 45, 142, 44, 111, 95, 65, 99, 0, 172, 95, 100, 78, 157, 137, 158, 68, 202, 197, 78};
    return oe_verify_attestation_certificate_with_evidence(
        der, (size_t)der_len, enclave_claims_verifier, nullptr);
}

#endif //- SGX_USE_REMOTE_ATTESTATION