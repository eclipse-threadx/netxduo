
#include <stdio.h>
#include "nx_crypto_hmac_sha5.h"

#include "tls_test_utility.h"

#define MAXIMUM_PLAIN_BYTES 256

#include "nx_secure_hmac_sha384_test_data.c"

/* Define software SHA384 method. */
static NX_CRYPTO_METHOD test_crypto_method_hmac_sha384 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_384,   /* SHA crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    384,                                      /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_SHA512_HMAC),            /* Metadata size in bytes                 */
    NX_CRYPTO_NULL,                           /* SHA initialization routine.            */
    NX_CRYPTO_NULL,                           /* SHA cleanup routine, not used.         */
    _nx_crypto_method_hmac_sha512_operation,  /* SHA operation                          */
};

/* SHA context. */
static NX_CRYPTO_SHA512_HMAC hmac_sha384_ctx;

/* Output. */
static ULONG output[12];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_hmac_sha384_test_application_define(void *first_unused_memory)
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
UINT i;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   HMAC SHA384 Test...................................");

    for (i = 0; i < sizeof(hmac_sha384_data) / sizeof(HMAC_SHA384_DATA); i++)
    {

        /* Authentication. */
        memset(output, 0xFF, sizeof(output));

        test_crypto_method_hmac_sha384.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                           NX_CRYPTO_NULL,
                                                           &test_crypto_method_hmac_sha384,
                                                           hmac_sha384_data[i].key,
                                                           (hmac_sha384_data[i].key_len << 3),
                                                           hmac_sha384_data[i].plain,
                                                           hmac_sha384_data[i].plain_len,
                                                           NX_CRYPTO_NULL,
                                                           (UCHAR *)output,
                                                           sizeof(output),
                                                           &hmac_sha384_ctx,
                                                           sizeof(hmac_sha384_ctx),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, hmac_sha384_data[i].secret, sizeof(output)));
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
