
#include <stdio.h>
#include "nx_secure_tls.h"

#include "nx_crypto_des.h"
#include "nx_crypto_3des.h"
#include "nx_crypto_aes.h"
#include "nx_crypto_hmac_sha1.h"
#include "nx_crypto_hmac_sha5.h"
#include "nx_crypto_hmac_md5.h"

#include "tls_test_utility.h"
#include "nx_secure_crypto_table_self_test.h"

/* Metadata buffer. */
static UCHAR metadata[10240];

static TX_THREAD thread_0;

static VOID thread_0_entry(ULONG thread_input);

extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

#ifdef NX_SECURE_POWER_ON_SELF_TEST_MODULE_INTEGRITY_CHECK
static NX_CRYPTO_METHOD crypto_method_des_cbc = 
{
    NX_CRYPTO_ENCRYPTION_DES_CBC,             /* DES crypto algorithm filled at runtime*/
    0,                                        /* Key size in bits                       */
    NX_CRYPTO_DES_IV_LEN_IN_BITS,             /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS,         /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_DES),                    /* Metadata size in bytes                 */
    _nx_crypto_method_des_init,               /* DES initialization routine.            */
    NX_NULL,                                  /* DES cleanup routine, not used.         */
    _nx_crypto_method_des_operation           /* DES operation                          */

};
static NX_CRYPTO_METHOD crypto_method_3des_cbc = 
{
    NX_CRYPTO_ENCRYPTION_3DES_CBC,            /* 3DES crypto algorithm filled at runtime*/
    0,                                        /* Key size in bits                       */
    NX_CRYPTO_3DES_IV_LEN_IN_BITS,            /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    NX_CRYPTO_3DES_BLOCK_SIZE_IN_BITS,        /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_3DES),                   /* Metadata size in bytes                 */
    _nx_crypto_method_3des_init,              /* 3DES initialization routine.            */
    NX_NULL,                                  /* 3DES cleanup routine, not used.         */
    _nx_crypto_method_3des_operation          /* 3DES operation                          */

};
static NX_CRYPTO_METHOD crypto_method_aes_cbc_192 =
{
    NX_CRYPTO_ENCRYPTION_AES_CBC,                /* AES crypto algorithm                   */
    NX_CRYPTO_AES_192_KEY_LEN_IN_BITS,           /* Key size in bits                       */
    NX_CRYPTO_AES_IV_LEN_IN_BITS,                /* IV size in bits                        */
    0,                                           /* ICV size in bits, not used.            */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),     /* Block size in bytes.                   */
    sizeof(NX_AES),                              /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,                  /* AES-CBC initialization routine.        */
    NX_NULL,                                     /* AES-CBC cleanup routine, not used.     */
    _nx_crypto_method_aes_cbc_operation          /* AES-CBC operation                      */
};
static NX_CRYPTO_METHOD crypto_method_aes_ctr_128 = 
{
    NX_CRYPTO_ENCRYPTION_AES_CTR,             /* AES crypto algorithm                   */
    NX_CRYPTO_AES_128_KEY_LEN_IN_BITS,        /* Key size in bits                       */
    64,                                       /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used             */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),  /* Block size in bytes.                   */
    sizeof(NX_AES),                           /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,               /* AES-CTR initialization routine.        */
    NX_NULL,                                  /* AES-CTR cleanup routine, not used.     */
    _nx_crypto_method_aes_ctr_operation       /* AES-CTR operation                      */
};
static NX_CRYPTO_METHOD crypto_method_aes_ctr_192 = 
{
    NX_CRYPTO_ENCRYPTION_AES_CTR,             /* AES crypto algorithm                   */
    NX_CRYPTO_AES_192_KEY_LEN_IN_BITS,        /* Key size in bits                       */
    64,                                       /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used             */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),  /* Block size in bytes.                   */
    sizeof(NX_AES),                           /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,               /* AES-CTR initialization routine.        */
    NX_NULL,                                  /* AES-CTR cleanup routine, not used.     */
    _nx_crypto_method_aes_ctr_operation       /* AES-CTR operation                      */
};
static NX_CRYPTO_METHOD crypto_method_aes_ctr_256 = 
{
    NX_CRYPTO_ENCRYPTION_AES_CTR,             /* AES crypto algorithm                   */
    NX_CRYPTO_AES_256_KEY_LEN_IN_BITS,        /* Key size in bits                       */
    64,                                       /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used             */
    (NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3),  /* Block size in bytes.                   */
    sizeof(NX_AES),                           /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,               /* AES-CTR initialization routine.        */
    NX_NULL,                                  /* AES-CTR cleanup routine, not used.     */
    _nx_crypto_method_aes_ctr_operation       /* AES-CTR operation                      */
};
static NX_CRYPTO_METHOD crypto_method_hmac_sha1_160 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_SHA1_160,            /* HMAC SHA1 algorithm                   */
    0,                                                 /* Key size in bits                      */
    0,                                                 /* IV size in bits, not used             */
    160,                                               /* Transmitted ICV size in bits          */
    0,                                                 /* Block size in bytes, not used         */
    sizeof(NX_SHA1_HMAC),                              /* Metadata size in bytes                */
    NX_NULL,                                           /* Initialization routine, not used      */
    NX_NULL,                                           /* Cleanup routine, not used             */
    _nx_crypto_method_hmac_sha1_operation              /* HMAC SHA1 operation                   */
};
static NX_CRYPTO_METHOD crypto_method_hmac_sha384 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_384,            /* HMAC SHA384 algorithm                 */
    0,                                                 /* Key size in bits                      */
    0,                                                 /* IV size in bits, not used             */
    384,                                               /* Transmitted ICV size in bits          */
    0,                                                 /* Block size in bytes, not used         */
    sizeof(NX_CRYPTO_SHA512_HMAC),                     /* Metadata size in bytes                */
    NX_NULL,                                           /* Initialization routine, not used      */
    NX_NULL,                                           /* Cleanup routine, not used             */
    _nx_crypto_method_hmac_sha512_operation            /* HMAC SHA384 operation                 */
};
static NX_CRYPTO_METHOD crypto_method_hmac_sha512 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_512,            /* HMAC SHA384 algorithm                 */
    0,                                                 /* Key size in bits                      */
    0,                                                 /* IV size in bits, not used             */
    512,                                               /* Transmitted ICV size in bits          */
    0,                                                 /* Block size in bytes, not used         */
    sizeof(NX_SHA512_HMAC),                            /* Metadata size in bytes                */
    NX_NULL,                                           /* Initialization routine, not used      */
    NX_NULL,                                           /* Cleanup routine, not used             */
    _nx_crypto_method_hmac_sha512_operation            /* HMAC SHA512 operation                 */
};
static NX_CRYPTO_METHOD crypto_method_hmac_md5_128 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_MD5_128,            /* HMAC MD5 algorithm                    */
    NX_CRYPTO_HMAC_MD5_KEY_LEN_IN_BITS,               /* Key size in bits                      */
    0,                                                /* IV size in bits, not used             */
    128,                                              /* Transmitted ICV size in bits          */
    0,                                                /* Block size in bytes, not used         */
    sizeof(NX_MD5_HMAC),                              /* Metadata size in bytes                */
    NX_NULL,                                          /* Initialization routine, not used      */
    NX_NULL,                                          /* Cleanup routine, not used             */
    _nx_crypto_method_hmac_md5_operation              /* HMAC MD5 operation                    */
};

extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_sha384;
extern NX_CRYPTO_METHOD crypto_method_sha512;
extern NX_CRYPTO_METHOD crypto_method_md5;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha1;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_hmac_md5;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;

/* For now we shall be able to test the following algorithms, based on the value in
   nx_crypto_algorithm:
   NX_CRYPTO_KEY_EXCHANGE_RSA (1024/2048/4096 bit key)
   NX_CRYPTO_ENCRYPTION_DES_CBC
   NX_CRYPTO_ENCRYPTION_3DES_CBC
   NX_CRYPTO_ENCRYPTION_AES_CBC (check key_size field)
   NX_CRYPTO_ENCRYPTION_AES_CTR
   NX_CRYPTO_HASH_SHA1
   NX_CRYPTO_HASH_SHA256
   NX_CRYPTO_HASH_SHA384
   NX_CRYPTO_HASH_SHA512
   NX_CRYPTO_HASH_MD5
   NX_CRYPTO_AUTHENTICATION_HMAC_SHA1_96
   NX_CRYPTO_AUTHENTICATION_HMAC_SHA1_160
   NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256
   NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_384
   NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_512
   NX_CRYPTO_AUTHENTICATION_HMAC_MD5_96
   NX_CRYPTO_AUTHENTICATION_HMAC_MD5_128
   NX_CRYPTO_PRF_HMAC_SHA1
   NX_CRYPTO_PRF_HMAC_SHA2_256
*/
static NX_CRYPTO_METHOD *test_crypto_method[] = {
&crypto_method_rsa,
&crypto_method_des_cbc,
&crypto_method_3des_cbc,
&crypto_method_aes_cbc_128,
&crypto_method_aes_cbc_192,
&crypto_method_aes_cbc_256,
&crypto_method_aes_ctr_128,
&crypto_method_aes_ctr_192,
&crypto_method_aes_ctr_256,
&crypto_method_sha1,
&crypto_method_sha256,
&crypto_method_sha384,
&crypto_method_sha512,
&crypto_method_md5,
&crypto_method_hmac_sha1,
&crypto_method_hmac_sha1_160,
&crypto_method_hmac_sha256,
&crypto_method_hmac_sha384,
&crypto_method_hmac_sha512,
&crypto_method_hmac_md5,
&crypto_method_hmac_md5_128,
&crypto_method_tls_prf_1,
&crypto_method_tls_prf_sha256,
};
static UINT test_crypto_method_size = sizeof(test_crypto_method) / sizeof(NX_CRYPTO_METHOD *);
#endif /* NX_SECURE_POWER_ON_SELF_TEST_MODULE_INTEGRITY_CHECK */

extern UINT _nx_secure_crypto_method_self_test(const NX_CRYPTO_METHOD *crypto_method,
                                               VOID *metadata, UINT metadata_size);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_crypto_self_test_application_define(void *first_unused_memory)
#endif
{
    tx_thread_create(&thread_0, "Thread 0", thread_0_entry, 0,
                     first_unused_memory, 4096,
                     16, 16, 4, TX_AUTO_START);
}

static VOID thread_0_entry(ULONG thread_input)
{
UINT i;
UINT status;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   Crypto Table Self Test.............................");

    status = nx_secure_crypto_table_self_test(&nx_crypto_tls_ciphers, metadata, sizeof(metadata));

    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#ifdef NX_SECURE_POWER_ON_SELF_TEST_MODULE_INTEGRITY_CHECK
    for (i = 0; i < test_crypto_method_size; i++)
    {
        status = _nx_secure_crypto_method_self_test(test_crypto_method[i], metadata, sizeof(metadata));

        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);
    }
#endif /* NX_SECURE_POWER_ON_SELF_TEST_MODULE_INTEGRITY_CHECK */

    status = nx_secure_crypto_rng_self_test();

    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    printf("SUCCESS!\n");

    test_control_return(0);
}
