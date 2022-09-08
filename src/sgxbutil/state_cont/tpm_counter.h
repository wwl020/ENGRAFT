#ifndef SGXBUTIL_TPM_COUNTER_H
#define SGXBUTIL_TPM_COUNTER_H
#include "sgxbutil/state_cont/monotonic_counter.h"
#include "sgxbutil/state_cont/openssl_utils.h"
#include "sgxbutil/third_party/tss2/tss2_common.h"
#include "sgxbutil/third_party/tss2/tss2_mu.h"
#include "sgxbutil/third_party/tss2/tss2_rc.h"
#include "sgxbutil/third_party/tss2/tss2_tpm2_types.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

typedef struct {
    UINT16 size;
    BYTE buffer[];
} TPM2B;   

/*
 * tpm2b default initializers, these set the size to the max for the default
 * structure and zero's the data area.
 */
#define TPM2B_SIZE(type) (sizeof (type) - 2)
#define TPM2B_NAMED_INIT(type, field) \
    { \
        .size = TPM2B_SIZE (type), \
        .field = { 0 } \
    }
#define TPM2B_DIGEST_INIT TPM2B_NAMED_INIT (TPM2B_DIGEST, buffer)
#define TPM2B_NAME_INIT TPM2B_NAMED_INIT (TPM2B_NAME, name)

namespace sgxbutil {
class TPMCounter: public MonoCounterManager {
public:    
    int init() override;
    CounterID get_counter() override;
    int increase_counter(CounterID counter_index) override;
    CounterVal read_counter(CounterID counter_index) override;
    bool detect_rollback(CounterID counter_index, CounterVal counter_val) override;
    
private:
    pthread_mutex_t tpm_session_mutex = PTHREAD_MUTEX_INITIALIZER;
    //- Add a global map to store every counter and its value
    std::map<CounterID, CounterVal> counters;

public:
    int internal_add_counter(uint32_t counter_index);
    int internal_read_counter(uint32_t counter_index, uint64_t &counter_value);
    int compute_secret_cipher();
    //- This func assign new_nonce to old_nonce and then update 
    //- new_nonce with random value (new_nonce = nonce_caller in a command)
    int roll_nonce();
    //- This func assign new_nonce to old_nonce and then update 
    //- new_nonce with input parameter
    int roll_nonce(TPM2B_NONCE new_nonce);
    int compute_auth_hmac(TPM2B_DIGEST* phash, TPM2B_AUTH* auth_hmac);

    TPMI_DH_OBJECT ek_nv_handle;
    TPMI_DH_OBJECT tpm_key;
    TPMI_DH_ENTITY bind;
    TPM2B_ENCRYPTED_SECRET encrypted_salt;
    TPM2B_MAX_BUFFER salt;
    TPM2_SE session_type;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH auth_hash;
    TPMI_SH_AUTH_SESSION session_handle;
    // TPM2B_NONCE nonce_tpm;
    TPM2B_DIGEST session_key;
    TPM2B_DIGEST auth_value_bind;
    TPM2B_NONCE nonce_newer;
    TPM2B_NONCE nonce_older;
    TPM2B_NONCE nonce_tpm_decrypt;
    TPM2B_NONCE nonce_tpm_encrypt;
    TPM2B_NAME name;
    void *hmacPtr;
    // UT_hash_handle hh;    
};

//- Assitance function declarations
int compute_nv_name(uint32_t nv_handle, TPM2B_NAME* name);
int hmac(TPM2_ALG_ID alg, const void *key, int key_len,
        TPM2B_DIGEST **buffer_list, TPM2B_DIGEST *out);
int ConcatSizedByteBuffer(TPM2B_MAX_BUFFER *result, TPM2B *buf);
int CompareSizedByteBuffer(TPM2B *buffer1, TPM2B *buffer2);
int tpm2_KDFa_impl(
    TPMI_ALG_HASH hash,//- Always be SHA-256
    TPM2B *key,
    const char *label,
    TPM2B *contextU,
    TPM2B *contextV,
    UINT16 bits,
    TPM2B_MAX_BUFFER *result_key);
RSA* create_public_RSA(std::string key);    

}


#endif