



#ifndef SRC_NX_CRYPTO_CLONE_CLEANUP_TEST_H_
#define SRC_NX_CRYPTO_CLONE_CLEANUP_TEST_H_

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */
#ifdef __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif

#include "nx_secure_tls.h"
#include "nx_crypto.h"
#include "nx_crypto_sha2.h"

#define NX_CRYPTO_HASH_METADATA_SIZE 2048
#define NX_CRYPTO_HASH_INSTANCE_COUNT 32

typedef struct NX_CRYPTO_CLONE_CLEANUP_TEST_STRUCT
{

    UINT nx_crypto_hash_operation;
    UINT nx_crypto_hash_initialized;
    UINT nx_crypto_hash_cloned;
    UINT nx_crypto_hash_calculated;
    UINT nx_crypto_hash_algorithm;
    UCHAR nx_crypto_hash_metadata[NX_CRYPTO_HASH_METADATA_SIZE];
    
} NX_CRYPTO_CLONE_CLEANUP_TEST;

typedef struct NX_CRYPTO_HASH_CLONE_STRUCT
{

    UINT nx_crypto_hash_operation;

} NX_CRYPTO_HASH_CLONE;


UINT _nx_crypto_clone_cleanup_test_initialize(NX_CRYPTO_CLONE_CLEANUP_TEST *context, UINT algorithm);
UINT _nx_crypto_clone_cleanup_test_update(NX_CRYPTO_CLONE_CLEANUP_TEST *context, UCHAR *input_ptr, UINT input_length);
UINT _nx_crypto_clone_cleanup_test_digest_calculate(NX_CRYPTO_CLONE_CLEANUP_TEST *context, UCHAR *digest, UINT algorithm);

UINT _nx_crypto_method_clone_cleanup_test_init(struct  NX_CRYPTO_METHOD_STRUCT *method,
                                   UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                   VOID  **handle,
                                   VOID  *crypto_metadata,
                                   ULONG crypto_metadata_size);

UINT _nx_crypto_method_clone_cleanup_test_cleanup(VOID *crypto_metadata);

UINT _nx_crypto_method_clone_cleanup_test_operation(UINT op,      /* Encrypt, Decrypt, Authenticate */
                                        VOID *handle, /* Crypto handler */
                                        struct NX_CRYPTO_METHOD_STRUCT *method,
                                        UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                        UCHAR *input, ULONG input_length_in_byte,
                                        UCHAR *iv_ptr,
                                        UCHAR *output, ULONG output_length_in_byte,
                                        VOID *crypto_metadata, ULONG crypto_metadata_size,
                                        VOID *packet_ptr,
                                        VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status));

UINT nx_crypto_clone_cleanup_test_clone(VOID *dest_metadata, VOID *source_metadata, ULONG length);
UINT nx_crypto_clone_cleanup(VOID *metadata, ULONG length);

#ifdef __cplusplus
}
#endif

#endif /* SRC_NX_CRYPTO_CLONE_CLEANUP_TEST_H_ */

