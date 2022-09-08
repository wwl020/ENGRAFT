#include "sgxbutil/state_cont/tpm_counter.h"
#include "sgxbutil/third_party/tss2/util/tss2_endian.h"
#include "google/gflags/gflags.h"
#include "sgxbutil/strings/string_util.h" //- int_to_hex
#include "sgxbutil/scoped_lock.h"

#if !(RUN_OUTSIDE_SGX)
#include "interface_t.h"
#endif

//- The public key of the endorsement key
std::string TPM_ENDORSEMENT_KEY = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7UH5dWQL5qwJefRAsJ6O\n"
"Q13ECJLedB2bgSScKd8vWHKDXqVg/k2yesYprnSDr/5IvFf2bwK6icJwqtqQogBD\n"
"a56LZ4oxEHdokqOA10oZfpM5HGQNzwZRr+MkUJ28LI6vy/Uhy56ltd2dAWq296r9\n"
"rAZHN2f4gRXxtCcGxSdpRN7MgrmpULnUTc3Lfr9TiF8r/ApHxLEvd2GziG3+gIjJ\n"
"oSoTZ6ZSghUKh3KjvrBVnFh+3ey2udvNv9jEXVdwRzlYz4DACJTWz/7S0tALkuJu\n"
"u/dkMVMiuP1Iva1YYWIHVWgwoghzO0bhQ46H1osDum5/DPybrkkUxP4Ds4KS8NgV\n"
"eQIDAQAB\n"
"-----END PUBLIC KEY-----";
std::string TPM_ENDORSEMENT_KEY1 = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwOmztnnzjWQTflPtYNjJ\n"
"xxdH4jQotQj1Jlz7u0vCHWm/pEp1FJCpic0MpnsCPpd6Qt0uKElpaSKHHyjM8dKu\n"
"DD2J2MCxOIexIvIH5v8zBmpFa4fzqVSra8G+xEXGHy6M1EytZALZgAa/RqYKRx6a\n"
"YfTefPaNGW86wOFB/9c23flhuMQiOwKrSeRSVTZF2b2CXBFHCOJSEcgXSAo3dOj+\n"
"BZY16CKh2ij8cx7J0FYP+z3GMzYgPq+m0QdlsGHUVRxAVyDRf7tdRjgsWzjr83xc\n"
"kL4LNBzZujo6iOv09Q3KBwJB1paEMzjt3HdiGyQYWtY9p2xyX3GTxWvo2BStNWuR\n"
"nwIDAQAB\n"
"-----END PUBLIC KEY-----";
std::string TPM_ENDORSEMENT_KEY2 = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFE7GwJcCN4bjDHOhbEN\n"
"YovGintRh1sYG9tpWhAFksTd5dHbv69yD9+gDG2BbPOwiz2TwJAT5lElC2lhs+aB\n"
"EQxIvfQwEfoUYGyFWcmYLht3O2NUdU5x7h61UlNPD6tCuuH1e/6nFFxpNbfIlK+Y\n"
"W4p2qPF+kx3nOm7PMabdy0ljGv4Lq0gRJBM+GwpM5QObA/jKHetlr6RhrlBV5WYb\n"
"1sa8r9X0hJfmNjajLka9N+QeBFa+Xqi9PFBhHH2wavTypXBaolNuufku4eSi15ic\n"
"7iVTx80dTimrHgFTf+NpzCq8m2pD0BhfYOGrc7idi+FKsh3ek2+vPVwXBrWIsr+9\n"
"wwIDAQAB\n"
"-----END PUBLIC KEY-----";

DECLARE_bool(run_in_XPS_cluster);
DECLARE_int32(port);

namespace sgxbutil {
int TPMCounter::init() {
    //- Start HMAC authorization session (unbound and salted), no symmetric
    //- encryption algorithm, and SHA256 is the session's hash algorithm.
    ek_nv_handle = 0x81010010;
    tpm_key = ek_nv_handle;
    bind = TPM2_RH_NULL;
    session_type = TPM2_SE_HMAC;
    auth_hash = TPM2_ALG_SHA256;
    symmetric.algorithm = TPM2_ALG_NULL;
    //- Generate shared secret and initial nonce
    get_sgx_seal_key(16, salt.buffer, "TEST");
    salt.size = 16;
    
    get_init_vector(nonce_older.buffer, nonce_older.size);
    nonce_older.size = 32;

    //- Compute encrypted shared secret using EK
    compute_secret_cipher();
    //- Ocall to create session using shared secret
    ocall_start_auth_session(
        &nonce_older,
        nonce_older.size + 2,
        &encrypted_salt,
        encrypted_salt.size + 2,
        &nonce_newer,
        &session_handle);
    LOG(INFO) << "Func: " << __FUNCTION__ << " handle = " << int_to_hex(session_handle);

    //- Derive session key (hamc key)
    TPM2B_ENCRYPTED_SECRET key;
    key.size = 0;
    ConcatSizedByteBuffer((TPM2B_MAX_BUFFER *)&key, (TPM2B *)&salt);
    LOG(INFO) << "Func: " << __FUNCTION__ << " key.size = " << key.size;
    int rc = tpm2_KDFa_impl(
        auth_hash, // SHA-256
        (TPM2B *)&key, 
        "ATH", 
        (TPM2B *)&nonce_newer, 
        (TPM2B *)&nonce_older, 
        256,
        (TPM2B_MAX_BUFFER *)&session_key);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " tpm2_KDFa_impl failed.";
        return rc;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " Generate session key.";
    LOG(INFO) << "Func: " << __FUNCTION__ << " session key.size = " 
        << session_key.size;
    return 0;        
}

CounterID TPMCounter::get_counter() {
    CounterID index;
    ocall_create_counter((uint32_t*)&index);
    return index;
}

int TPMCounter::increase_counter(CounterID counter_index) {
    BAIDU_SCOPED_LOCK(tpm_session_mutex);
    if (internal_add_counter(counter_index) == 0) {
        counters[counter_index]++;
        return 0;
    }
    return -1;
}

CounterVal TPMCounter::read_counter(CounterID counter_index) {
    BAIDU_SCOPED_LOCK(tpm_session_mutex);
    if (counters.find(counter_index) != counters.end()) {
        return counters[counter_index];
    }
    CounterVal val;
    internal_read_counter(counter_index, val);
    counters.insert({counter_index, val});
    return val;
}

bool TPMCounter::detect_rollback(CounterID counter_index, CounterVal counter_val) {
    //- TODO:
    return false;
}

//- Here alg is always be TPM2_ALG_SHA256
int hmac(TPM2_ALG_ID alg, const void *key, int key_len,
        TPM2B_DIGEST **buffer_list, TPM2B_DIGEST *out) {
    HMAC_CTX *ctx;
    EVP_MD *evp;
    int rc = 1, i;
    unsigned int *buf = NULL, size;
    uint8_t *buf_ptr;

    ctx = HMAC_CTX_new();
    if (!ctx) {
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    evp = (EVP_MD *) EVP_sha256();
    out->size = TPM2_SHA256_DIGEST_SIZE;

    rc = 0;
    buf = (unsigned int *)calloc(1, out->size);

    if (!buf) {
        goto out;
    }            

    buf_ptr = (uint8_t *)buf;

    rc = HMAC_Init_ex(ctx, key, key_len, evp, NULL);


    if (rc != 1)
        goto out;
    for (i = 0; buffer_list[i] != 0; i++) {
        rc = HMAC_Update(ctx, buffer_list[i]->buffer, buffer_list[i]->size);
        if (rc != 1)
            goto out;
    }
    /* buf_ptr has to be 4 bytes alligned for whatever reason */
    rc = HMAC_Final(ctx, buf_ptr, &size);
    if (rc != 1)
        goto out;

    assert(size == out->size);

    memcpy(out->buffer, buf, out->size);

out:
    HMAC_CTX_free(ctx);

    if (buf) {
        free(buf);
    }

    /* In openSSL 1 means success 0 error */
    return rc == 1 ? TPM2_RC_SUCCESS : TSS2_SYS_RC_GENERAL_FAILURE;
}

int ConcatSizedByteBuffer(TPM2B_MAX_BUFFER *result, TPM2B *buf) {
    if (result->size + buf->size > TPM2_MAX_DIGEST_BUFFER)
        return TSS2_SYS_RC_BAD_VALUE;
    memmove(result->buffer + result->size,
            buf->buffer, buf->size);
    result->size += buf->size;
    return TPM2_RC_SUCCESS;
}

int CompareSizedByteBuffer(TPM2B *buffer1, TPM2B *buffer2) {
    if (buffer1->size != buffer2->size) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " Sizes don't match";
        return -1;
    }
        
    if (memcmp(buffer1->buffer, buffer2->buffer, buffer1->size))
        return TPM2_RC_FAILURE;
    return TPM2_RC_SUCCESS;
}

int tpm2_KDFa_impl(
    TPMI_ALG_HASH hash,//- Always be SHA-256
    TPM2B *key,
    const char *label,
    TPM2B *contextU,
    TPM2B *contextV,
    UINT16 bits,
    TPM2B_MAX_BUFFER *result_key) {
    TPM2B_DIGEST digest;
    TPM2B_DIGEST tpm2blabel, tpm2bbits, tpm2bctr;
    TPM2B_DIGEST *buffer_list[8];
    UINT32 counter;
    TSS2_RC rval;
    int i, j;
    UINT16 bytes = bits / 8;

    result_key->size = 0;
    tpm2bctr.size = 4;
    tpm2bbits.size = 4;
    counter = BE_TO_HOST_32(bits);
    memcpy(tpm2bbits.buffer, &counter, 4);
    tpm2blabel.size = strlen(label) + 1;
    memcpy(tpm2blabel.buffer, label, tpm2blabel.size);

    // LOG_DEBUG("KDFA, hash = %4.4x", hash);
    // LOGBLOB_DEBUG(&key->buffer[0], key->size, "KDFA, key =");
    // LOGBLOB_DEBUG(&tpm2blabel.buffer[0], tpm2blabel.size, "KDFA, tpm2blabel =");
    // LOGBLOB_DEBUG(&contextU->buffer[0], contextU->size, "KDFA, contextU =");
    // LOGBLOB_DEBUG(&contextV->buffer[0], contextV->size, "KDFA, contextV =");

    for (i = 1, j = 0; result_key->size < bytes; j = 0) {
        counter = BE_TO_HOST_32(i++);
        memcpy(tpm2bctr.buffer, &counter, 4);
        buffer_list[j++] = (TPM2B_DIGEST *)&tpm2bctr;
        buffer_list[j++] = (TPM2B_DIGEST *)&tpm2blabel;
        buffer_list[j++] = (TPM2B_DIGEST *)contextU;
        buffer_list[j++] = (TPM2B_DIGEST *)contextV;
        buffer_list[j++] = (TPM2B_DIGEST *)&tpm2bbits;
        buffer_list[j++] = NULL;

        // for (j = 0; buffer_list[j] != NULL; j++) {
        //     LOGBLOB_DEBUG(&buffer_list[j]->buffer[0], buffer_list[j]->size, "bufferlist[%d]:", j);
        //     ;
        // }

        rval = hmac(hash, key->buffer, key->size, buffer_list, &digest);
        if (rval != TPM2_RC_SUCCESS) {
            LOG(INFO) << "Func: " << __FUNCTION__ << " HMAC Failed rval = " << rval;
            return rval;
        }

        ConcatSizedByteBuffer(result_key, (TPM2B *)&digest);
    }

    /* Truncate the result to the desired size. */
    result_key->size = bytes;
    // LOGBLOB_DEBUG(result_key->buffer, result_key->size, "KDFA, key = ");
    return TPM2_RC_SUCCESS;
}

RSA* create_public_RSA(std::string key) {
    RSA *rsa = NULL;
    BIO *keybio;
    const char* c_string = key.c_str();
    keybio = BIO_new_mem_buf((void*)c_string, -1);
    if (keybio==NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    //- TODO: Should it be free now?
    // BIO_free(keybio);
    return rsa;
}

int TPMCounter::compute_secret_cipher() {
    //- Generate EK's public key
    RSA* pub_key;
    if (FLAGS_run_in_XPS_cluster) {
        if (FLAGS_port == 8100) {
            pub_key = create_public_RSA(TPM_ENDORSEMENT_KEY);
        } else if (FLAGS_port == 8101) {
            pub_key = create_public_RSA(TPM_ENDORSEMENT_KEY1);
        } else {
            pub_key = create_public_RSA(TPM_ENDORSEMENT_KEY2);
        }
    } else {
        pub_key = create_public_RSA(TPM_ENDORSEMENT_KEY);
    }
    
    
    //- Define vars
    int rc = -1;
    size_t out_size;
    //- The name algorithm of EK is SHA-256
    const EVP_MD* hashAlg = EVP_sha256();
    EVP_PKEY* evp_rsa_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_rsa_key, pub_key);

    EVP_PKEY_CTX *ctx = NULL;

    //- When encrypting salts, the encryption scheme of a key is ignored and 
    //- TPM2_ALG_OAEP is always used, and thus the padding pattern is as follows.
    int padding = RSA_PKCS1_OAEP_PADDING;

    char *label_copy = OPENSSL_strdup("SECRET");
    if (!label_copy) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " Could not duplicate OAEP label";
        return rc;
    }

    if (!(ctx = EVP_PKEY_CTX_new(evp_rsa_key, NULL))) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " Could not create evp context.";
        return rc;
    }

    if (1 != EVP_PKEY_encrypt_init(ctx)) {
        LOG(INFO) << "Func: " << __FUNCTION__ << "Could not init encrypt context.";
        return rc;
    }

    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, padding)) {
        LOG(INFO) << "Func: " << __FUNCTION__ << "Could not set RSA passing.";
        return rc;
    }

    if (1 != EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label_copy, strlen(label_copy)+1)) {
        OPENSSL_free(label_copy);
        LOG(INFO) << "Func: " << __FUNCTION__ << "Could not set RSA label.";
        return rc;
    }

    if (1 != EVP_PKEY_CTX_set_rsa_oaep_md(ctx, hashAlg)) {
        LOG(INFO) << "Func: " << __FUNCTION__ << "Could not set hash algorithm.";
        return rc;
    }

    //- Determine out size
    if (1 != EVP_PKEY_encrypt(ctx, 
                            NULL, 
                            &out_size, 
                            salt.buffer, 
                            salt.size)) {
        LOG(INFO) << "Func: " << __FUNCTION__ << "Could not determine ciper size.";
        return rc;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << "Encrypted shared secret length = " 
        << out_size;
    encrypted_salt.size = out_size;

    //- Encrypt data
    if (1 != EVP_PKEY_encrypt(ctx, 
                            encrypted_salt.secret, 
                            &out_size, 
                            salt.buffer, 
                            salt.size)) {
        LOG(INFO) << "Func: " << __FUNCTION__ << "Could not encrypt data.";
        return rc;
    }

    //- Clean up and return
    LOG(INFO) << "Func: " << __FUNCTION__ << " Encryption completed.";    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_rsa_key);
    //- TODO: This free code will return "OPENSSL refcount error".
    // RSA_free(pub_key);
    rc = 0;
    return rc;
}

int TPMCounter::internal_add_counter(uint32_t counter_index) {
    sgxbutil::Timer timer;
    timer.start();

    int rc = 0;
    roll_nonce();
    
    uint32_t command_code = TPM2_CC_NV_Increment;
    //- NOTE: Change to big end.
    command_code = HOST_TO_BE_32(command_code);

    TPM2B_NAME nv_handle_name;
    compute_nv_name(counter_index, &nv_handle_name);
    
    //- 1. After the above preparation, compute the cphash
    // cpHash = Hash (commandCode {|| HandleName1 {|| HandleName2}} {|| parameters })
    TPM2B_DIGEST cphash = TPM2B_DIGEST_INIT;
    TPM2B_MAX_BUFFER cphash_input;
    cphash_input.size = 0;
    uint8_t* cphash_input_ptr;
    cphash_input_ptr = &(cphash_input.buffer[cphash_input.size]);
    //- Append command code
    *(uint32_t*)cphash_input_ptr = command_code;
    cphash_input.size += 4;
    //- Append two identical handle name (auth handle & nv handle)
    ConcatSizedByteBuffer(&cphash_input, (TPM2B *)&nv_handle_name);
    ConcatSizedByteBuffer(&cphash_input, (TPM2B *)&nv_handle_name);
    //- There is no command params in NV_increament, so don't append params
    SHA256(cphash_input.buffer, cphash_input.size, cphash.buffer);
    cphash.size = 32;

    //- 2. Compute command authHAMC    
    TPM2B_AUTH command_hmac;
    compute_auth_hmac(&cphash, &command_hmac);    
    
    //- Send nonce_caller (newer), authHMAC and counter_index to the host
    TPM2B_AUTH returned_hmac;
    TPM2B_NONCE nonce_tpm;
    nonce_tpm.size = nonce_newer.size;

    ocall_add_counter(
        session_handle, 
        counter_index,
        &nonce_newer,
        nonce_newer.size + 2,
        command_hmac.buffer,
        command_hmac.size,
        nonce_tpm.buffer,
        returned_hmac.buffer);
    roll_nonce(nonce_tpm);
    returned_hmac.size = command_hmac.size;
    // for (int i = 0; i < command_hmac.size; i++) {
    //     fprintf(stdout, "returned_hmac-%d: %02x", i, returned_hmac.buffer[i]);
    // }
    // for (int i = 0; i < nonce_tpm.size; i++) {
    //     fprintf(stdout, "nonce_tpm-%d: %02x\n", i, nonce_tpm.buffer[i]);
    // }

    //- 3. After receive the resopnse, compute the rphash
    // rpHash = Hash (responseCode || commandCode {|| parameters })
    TPM2B_DIGEST rphash = TPM2B_DIGEST_INIT;
    TPM2B_MAX_BUFFER rphash_input;
    rphash_input.size = 0;
    uint8_t* rphash_input_ptr = &(rphash_input.buffer[rphash_input.size]);
    //- Append resopnse code. Always be 0 (success) if TPM returns response.
    *(uint32_t *)rphash_input_ptr = 0;
    rphash_input.size += 4;
    //- Append command code
    rphash_input_ptr = &(rphash_input.buffer[rphash_input.size]);
    *(uint32_t*)rphash_input_ptr = command_code;
    rphash_input.size += 4;
    //- No parameters in the response of NV_increment, so don't append
    SHA256(rphash_input.buffer, rphash_input.size, rphash.buffer);
    rphash.size = 32;
    //- 4. Compute response authHMAC
    TPM2B_AUTH response_hmac;
    compute_auth_hmac(&rphash, &response_hmac);
    rc = CompareSizedByteBuffer((TPM2B*)&response_hmac, (TPM2B*)&returned_hmac);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " ADD: The TPM is not trusted.";
        return rc;
    }
    // LOG(INFO) << "Func: " << __FUNCTION__ << " Add counter successfully.";

    timer.stop();
    VLOG(85) << "Func: " << __FUNCTION__ << " TIME_OF add_counter = " 
        << timer.m_elapsed(0.0) << " ms";

    return 0;
}

int TPMCounter::internal_read_counter(uint32_t counter_index, uint64_t &counter_value) {
    sgxbutil::Timer timer;
    timer.start();

    int rc = 0;
    roll_nonce();
    uint32_t command_code = TPM2_CC_NV_Read;
    //- NOTE: Change to big end.
    command_code = HOST_TO_BE_32(command_code);
    TPM2B_NAME nv_handle_name;
    compute_nv_name(counter_index, &nv_handle_name);
    
    //- 1. After the above preparation, compute the cphash
    // cpHash = Hash (commandCode {|| HandleName1 {|| HandleName2}} {|| parameters })
    TPM2B_DIGEST cphash = TPM2B_DIGEST_INIT;
    TPM2B_MAX_BUFFER cphash_input;
    cphash_input.size = 0;
    uint8_t* cphash_input_ptr;
    cphash_input_ptr = &(cphash_input.buffer[cphash_input.size]);
    //- Append command code
    *(uint32_t*)cphash_input_ptr = command_code;
    cphash_input.size += 4;
    //- Append two identical handle name (auth handle & nv handle)
    ConcatSizedByteBuffer(&cphash_input, (TPM2B *)&nv_handle_name);
    ConcatSizedByteBuffer(&cphash_input, (TPM2B *)&nv_handle_name);
    //- Append params for NV_read (size and offset)
    //- size = 8, (UINT16 type)
    Tss2_MU_UINT16_Marshal(8, &cphash_input.buffer[cphash_input.size], 2048, NULL);
    cphash_input.size += 2;
    //- offset = 0, (UINT16 type)
    Tss2_MU_UINT16_Marshal(0, &cphash_input.buffer[cphash_input.size], 2048, NULL);
    cphash_input.size += 2;
    //- Compute hasn
    SHA256(cphash_input.buffer, cphash_input.size, cphash.buffer);
    cphash.size = 32;

    //- 2. Compute command authHAMC    
    TPM2B_AUTH command_hmac;
    compute_auth_hmac(&cphash, &command_hmac);    
    
    //- Send nonce_caller (newer), authHMAC and counter_index to the host
    TPM2B_AUTH returned_hmac;
    TPM2B_NONCE nonce_tpm;
    nonce_tpm.size = nonce_newer.size;
    TPM2B_MAX_NV_BUFFER read_data;
    read_data.size = 8;
    ocall_read_counter(
        session_handle, 
        counter_index,
        &nonce_newer,
        nonce_newer.size + 2,
        command_hmac.buffer,
        command_hmac.size,
        nonce_tpm.buffer,
        returned_hmac.buffer,
        &read_data,
        read_data.size + 2);
    roll_nonce(nonce_tpm);
    returned_hmac.size = command_hmac.size;
    uint64_t counter_val = 0;
    Tss2_MU_UINT64_Unmarshal(read_data.buffer, read_data.size, 0, &counter_val);
    // LOG(INFO) << "Func: " << __FUNCTION__ << " counter_val = " << counter_val;

    //- 3. After receive the resopnse, compute the rphash
    // rpHash = Hash (responseCode || commandCode {|| parameters })
    TPM2B_DIGEST rphash = TPM2B_DIGEST_INIT;
    TPM2B_MAX_BUFFER rphash_input;
    rphash_input.size = 0;
    uint8_t* rphash_input_ptr = &(rphash_input.buffer[rphash_input.size]);
    //- Append resopnse code. Always be 0 (success) if TPM returns response.
    *(uint32_t *)rphash_input_ptr = 0;
    rphash_input.size += 4;
    //- Append command code
    rphash_input_ptr = &(rphash_input.buffer[rphash_input.size]);
    *(uint32_t*)rphash_input_ptr = command_code;
    rphash_input.size += 4;
    //- Append parameters
    size_t offset = 0;
    Tss2_MU_UINT16_Marshal(8, read_data.buffer, 2048, &offset);
    Tss2_MU_UINT64_Marshal(counter_val, read_data.buffer, 2048, &offset);
    for (int j = 0; j < 10; j++) {
        rphash_input.buffer[rphash_input.size + j] = read_data.buffer[j];
        // fprintf(stdout, "read_data.buffer[%d] = %02x\n", j, read_data.buffer[j]);
    }
    rphash_input.size += 10;
    //- Compute hash
    SHA256(rphash_input.buffer, rphash_input.size, rphash.buffer);
    rphash.size = 32;
    //- 4. Compute response authHMAC
    TPM2B_AUTH response_hmac;
    compute_auth_hmac(&rphash, &response_hmac);
    rc = CompareSizedByteBuffer((TPM2B*)&response_hmac, (TPM2B*)&returned_hmac);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " READ: The TPM is not trusted.";
        return rc;
    }
    counter_value = counter_val;
    // LOG(INFO) << "Func: " << __FUNCTION__ << " Read counter successfully.";

    timer.stop();
    VLOG(85) << "Func: " << __FUNCTION__ << " TIME_OF read_counter = " 
        << timer.m_elapsed(0.0) << " ms";
    return 0;
}

int TPMCounter::roll_nonce() {
    nonce_older = nonce_newer;
    get_init_vector(nonce_newer.buffer, nonce_newer.size);
    return 0;
}

int TPMCounter::roll_nonce(TPM2B_NONCE new_nonce) {
    nonce_older = nonce_newer;
    nonce_newer = new_nonce;
    return 0;
}

int TPMCounter::compute_auth_hmac(TPM2B_DIGEST* phash, TPM2B_AUTH* auth_hmac) {
    // authHMAC = HMAC ( sessionKey, (pHash || nonceNewer || nonceOlder || session_attr) )
    TPM2B_DIGEST* buffer_list[5];
    int i = 0;
    TPM2B_DIGEST session_attr_buffer = {
        .size = 1,
        .buffer = { TPMA_SESSION_CONTINUESESSION, }
    };
    buffer_list[i++] = phash;
    buffer_list[i++] = (TPM2B_DIGEST *)&nonce_newer;
    buffer_list[i++] = (TPM2B_DIGEST *)&nonce_older;
    buffer_list[i++] = (TPM2B_DIGEST *)&session_attr_buffer;
    buffer_list[i++] = 0;
    int rc = hmac(
        auth_hash, 
        session_key.buffer,
        session_key.size,
        buffer_list,
        (TPM2B_DIGEST *)auth_hmac);
    if (rc != 0) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " hmac failed.";
        return -1;
    }
    return 0;
}

//- This func simulates the behavior of Esys_TR_GetName
//- name is caller-allocated
int compute_nv_name(uint32_t nv_handle, TPM2B_NAME* name) {
    int rc;
    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0, //- Totally 14 bytes (This field doesn't affect hash, so 0 is fine.)
        .nvPublic = {
            .nvIndex = nv_handle, //- 4B
            .nameAlg = TPM2_ALG_SHA256, //- 2B
            .attributes = //- 4B
                (TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | TPMA_NV_WRITTEN |
                TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT),
            .authPolicy = {.size = 0, .buffer = {}}, //- Use 2 bytes to indicate size
            .dataSize = 8, //- 2B
        }
    };

    BYTE buffer[sizeof(TPMS_NV_PUBLIC)];
    size_t offset = 0;
    size_t len_alg_id = sizeof(TPMI_ALG_HASH);
    rc = Tss2_MU_TPMS_NV_PUBLIC_Marshal(&publicInfo.nvPublic,
                                       &buffer[0], sizeof(TPMS_NV_PUBLIC),
                                       &offset);
    if (rc != 0) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " Tss2_MU_TPMS_NV_PUBLIC_Marshal failed";
    }

    //- 1. iesys_cryptossl_hash_start
    //- Use SHA-256, totally 32 bytes.
    int hash_len = 32;
    unsigned int digest_size = 0;
    EVP_MD_CTX* ossl_context = EVP_MD_CTX_new();
    const EVP_MD* ossl_hash_alg = EVP_sha256();
    if (1 != EVP_DigestInit(ossl_context, ossl_hash_alg)) {
        LOG(ERROR) << "Func: " << __FUNCTION__ <<  " EVP_DigestInit failed.";
        rc = -1;
        goto cleanup;
    }

    //- 2. iesys_cryptossl_hash_update
    if (1 != EVP_DigestUpdate(ossl_context, buffer, offset)) {
        LOG(ERROR) << "Func: " << __FUNCTION__ <<  " EVP_DigestInit failed.";
        rc = -1;
        goto cleanup;
    }

    //- 3. iesys_cryptossl_hash_finish
    if (1 != EVP_DigestFinal(ossl_context, &name->name[len_alg_id], &digest_size)) {
        LOG(ERROR) << "Func: " << __FUNCTION__ <<  " EVP_DigestFinal failed.";
        rc = -1;
        goto cleanup;
    }

    if (digest_size != hash_len) {
        LOG(ERROR) << "Func: " << __FUNCTION__ <<  " EVP_DigestInit failed," 
            << " digest_size = " << digest_size;
        rc = -1;
        goto cleanup;
    }
    offset = 0;
    rc = Tss2_MU_TPMI_ALG_HASH_Marshal(publicInfo.nvPublic.nameAlg,
                                  &name->name[0], sizeof(TPMI_ALG_HASH),
                                  &offset);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ 
            << " Tss2_MU_TPMI_ALG_HASH_Marshal failed.";
        goto cleanup;            
    }
    name->size = hash_len + len_alg_id;

cleanup:
    if (ossl_context) {
        EVP_MD_CTX_destroy(ossl_context);
    }
    return rc;
        

}


}
