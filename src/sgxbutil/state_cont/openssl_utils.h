#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include "sgxbutil/logging.h"

#ifndef SGXBUTIL_OPENSSL_UTILS_H
#define SGXBUTIL_OPENSSL_UTILS_H

namespace sgxbutil {
    int get_init_vector(unsigned char* iv, int iv_size);
    int get_sgx_seal_key_128(unsigned char* key);
    int get_sgx_seal_key(int bytes, unsigned char* key, const char* custom_message);
    void handleErrors(void);
    int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                    int aad_len, unsigned char *key, unsigned char *iv, int iv_len,
                    unsigned char *ciphertext, unsigned char *tag);
    int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *aad, int aad_len, unsigned char *tag,
                    unsigned char *key, unsigned char *iv, int iv_len,
                    unsigned char *plaintext);
    
    //- The output buffer (always 32 bytes) should be allocated in the caller
    int generate_sha256_hash(unsigned char *input, int input_len, 
                            unsigned char *output);
}

#endif //SGXBUTIL_OPENSSL_UTILS_H