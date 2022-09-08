#include "sgxbutil/state_cont/openssl_utils.h"
#include "sgxbutil/logging.h"
#ifndef RUN_OUTSIDE_SGX
#include <openenclave/enclave.h>
#endif

namespace sgxbutil {
uint8_t* seal_key_buf = NULL;

    
int get_init_vector(unsigned char* iv, int iv_size) {
    int ret = RAND_bytes(iv, iv_size);
    
    if (ret == 1) {
        //- openssl return success
        return 0;
    } else if (ret == -1){
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Not supported by the current RAND method.";
    } else {
        unsigned long err = ERR_get_error();
        LOG(ERROR) << "Func: " << __FUNCTION__ << " error num = " << err; 
    }
    return -1;
}

int get_sgx_seal_key_128(unsigned char* key) {
    //- Check existence
    if (seal_key_buf != NULL) {
        for (int i = 0; i < 16; i++) {
            key[i] = seal_key_buf[i];
        }
        return 0;
    }
#ifndef RUN_OUTSIDE_SGX    
    size_t seal_key_size = 0;
    int res = oe_get_seal_key_by_policy_v2(
            OE_SEAL_POLICY_UNIQUE,
            &seal_key_buf,
            &seal_key_size,
            NULL,
            NULL);
    if (res != OE_OK) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " oe_get_seal_key_by_policy_v2 failed.";
        return -1;
    }
    for (int i = 0; i < 16; i++) {
        key[i] = seal_key_buf[i];
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " Generated seal key.";    
    return 0;
#else
    seal_key_buf = (uint8_t*)malloc(sizeof(uint8_t)*16);
    for (int i = 0; i < 16; i++) {
        seal_key_buf[i] = i;
        key[i] = i;
    }
    return 0;
#endif    
}

int get_sgx_seal_key(int bytes, unsigned char* key, const char* custom_message) {
    //- TODO: Shall we use custom msg to derive key?
    if (bytes == 16) {
        return get_sgx_seal_key_128(key);
    }
    return -1;
}

void handleErrors(void) {
    LOG(ERROR) << "openssl error";
    ERR_print_errors_fp(stderr);
    abort();
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
    * Set IV length if default 12 bytes (96 bits) is not appropriate
    */
    // if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    //   handleErrors();

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
    * Provide any AAD data. This can be called zero or more times as
    * required
    */
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
    * Provide the message to be encrypted, and obtain the encrypted output.
    * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
    * Finalise the encryption. Normally ciphertext bytes may be written at
    * this stage, but this does not occur in GCM mode
    */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len, unsigned char *tag,
                unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    // if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    //   handleErrors();

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
    * Provide any AAD data. This can be called zero or more times as
    * required
    */
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
    * Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /*
    * Finalise the decryption. A positive return value indicates success,
    * anything else is a failure - the plaintext is not trustworthy.
    */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

int generate_sha256_hash(unsigned char *input, int input_len, 
                            unsigned char *output) {
    unsigned char* ret_ptr = SHA256(input, input_len, output);
    if (ret_ptr != output) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " The return buffer doesn't"
            << " equal to output param!";
        return -1;
    }
    return 0;
}

// int generate_sha256_hash_salt(unsigned char *input, int input_len, 
//                             unsigned char *output, unsigned char *salt) {
//     unsigned char* ret_ptr = SHA256(input, input_len, output);
//     if (ret_ptr != output) {
//         LOG(ERROR) << "Func: " << __FUNCTION__ << " The return buffer doesn't"
//             << " equal to output param!";
//         return -1;
//     }
//     return 0;
// }

}