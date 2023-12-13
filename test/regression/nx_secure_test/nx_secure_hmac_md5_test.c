
#include <stdio.h>
#include "nx_crypto_hmac_md5.h"

#include "tls_test_utility.h"

#define MAXIMUM_PLAIN_BYTES 256

#include "nx_secure_hmac_md5_test_data.c"

/* Define software MD5 method. */
static NX_CRYPTO_METHOD test_crypto_method_hmac_md5 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_MD5_128,    /* HMAC MD5 crypto algorithm              */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    128,                                      /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_MD5_HMAC),                      /* Metadata size in bytes                 */
    NX_CRYPTO_NULL,                           /* Initialization routine.                */
    NX_CRYPTO_NULL,                           /* Cleanup routine, not used.             */
    _nx_crypto_method_hmac_md5_operation,     /* HMAC MD5 operation                     */
};

/* HMAC MD5 context. */
static NX_MD5_HMAC hmac_md5_ctx;

/* Output. */
static ULONG output[4];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_hmac_md5_test_application_define(void *first_unused_memory)
#endif
{
#ifndef NX_CRYPTO_STANDALONE_ENABLE
    tx_thread_create(&thread_0, "Thread 0", thread_0_entry, 0,
                     first_unused_memory, 4096,
                     16, 16, 4, TX_AUTO_START);
#else
    thread_0_entry(0);
#endif
}

static VOID thread_0_entry(ULONG thread_input)
{
UINT i, status;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   HMAC MD5 Test......................................");

    for (i = 0; i < sizeof(hmac_md5_data) / sizeof(HMAC_MD5_DATA); i++)
    {

        /* Authentication. */
        memset(output, 0xFF, sizeof(output));

        test_crypto_method_hmac_md5.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                        NX_CRYPTO_NULL,
                                                        &test_crypto_method_hmac_md5,
                                                        hmac_md5_data[i].key,
                                                        (hmac_md5_data[i].key_len << 3),
                                                        hmac_md5_data[i].plain,
                                                        hmac_md5_data[i].plain_len,
                                                        NX_CRYPTO_NULL,
                                                        (UCHAR *)output,
                                                        sizeof(output),
                                                        &hmac_md5_ctx,
                                                        sizeof(hmac_md5_ctx),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, hmac_md5_data[i].secret, sizeof(output)));

        memset(output, 0xFF, sizeof(output));

        /* Test HMAC MD5 with Initialize, Update and Calculate operation.  */
        test_crypto_method_hmac_md5.nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                        NX_CRYPTO_NULL,
                                                        &test_crypto_method_hmac_md5,
                                                        hmac_md5_data[i].key,
                                                        (hmac_md5_data[i].key_len << 3),
                                                        NX_CRYPTO_NULL,
                                                        0,
                                                        NX_CRYPTO_NULL,
                                                        NX_CRYPTO_NULL,
                                                        0,
                                                        &hmac_md5_ctx,
                                                        sizeof(hmac_md5_ctx),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        test_crypto_method_hmac_md5.nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                        NX_CRYPTO_NULL,
                                                        &test_crypto_method_hmac_md5,
                                                        NX_CRYPTO_NULL,
                                                        0,
                                                        hmac_md5_data[i].plain,
                                                        hmac_md5_data[i].plain_len,
                                                        NX_CRYPTO_NULL,
                                                        NX_CRYPTO_NULL,
                                                        0,
                                                        &hmac_md5_ctx,
                                                        sizeof(hmac_md5_ctx),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        test_crypto_method_hmac_md5.nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                        NX_CRYPTO_NULL,
                                                        &test_crypto_method_hmac_md5,
                                                        NX_CRYPTO_NULL,
                                                        0,
                                                        NX_CRYPTO_NULL,
                                                        0,
                                                        NX_CRYPTO_NULL,
                                                        (UCHAR *)output,
                                                        sizeof(output),
                                                        &hmac_md5_ctx,
                                                        sizeof(hmac_md5_ctx),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, hmac_md5_data[i].secret, sizeof(output)));
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
