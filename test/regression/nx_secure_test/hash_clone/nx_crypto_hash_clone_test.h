

#ifndef SRC_NX_CRYPTO_HASH_CLONE_TEST_H_
#define SRC_NX_CRYPTO_HASH_CLONE_TEST_H_

/* Determine if a C++ compiler is being used.  If so, ensure that standard
   C is used to process the API information.  */
#ifdef __cplusplus

/* Yes, C++ compiler is present.  Use standard C.  */
extern   "C" {

#endif

#include "nx_secure_tls.h"
#include "nx_crypto.h"

typedef struct NX_CRYPTO_HASH_CLONE_TEST_STRUCT
{

    UINT nx_crypto_hash_operation;
    
} NX_CRYPTO_HASH_CLONE_TEST;


UINT _nx_crypto_method_hash_clone_test_init(struct  NX_CRYPTO_METHOD_STRUCT *method,
                                   UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                   VOID  **handle,
                                   VOID  *crypto_metadata,
                                   ULONG crypto_metadata_size);

UINT _nx_crypto_method_hash_clone_test_cleanup(VOID *crypto_metadata);

UINT _nx_crypto_method_hash_clone_test_operation(UINT op,      /* Encrypt, Decrypt, Authenticate */
                                        VOID *handle, /* Crypto handler */
                                        struct NX_CRYPTO_METHOD_STRUCT *method,
                                        UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                        UCHAR *input, ULONG input_length_in_byte,
                                        UCHAR *iv_ptr,
                                        UCHAR *output, ULONG output_length_in_byte,
                                        VOID *crypto_metadata, ULONG crypto_metadata_size,
                                        VOID *packet_ptr,
                                        VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status));

UINT nx_crypto_hash_clone_test_clone(VOID *dest_metadata, VOID *source_metadata, ULONG length);
UINT nx_crypto_clone_cleanup_test_clone(VOID *dest_metadata, VOID *source_metadata, ULONG length);


UINT _nx_crypto_method_clone_cleanup_test_init(struct  NX_CRYPTO_METHOD_STRUCT *method,
                                               UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                               VOID **handle,
                                               VOID *crypto_metadata,
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
                                                    VOID(*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status));


#ifdef __cplusplus
}
#endif

#endif /* SRC_NX_CRYPTO_HASH_CLONE_TEST_H_ */

