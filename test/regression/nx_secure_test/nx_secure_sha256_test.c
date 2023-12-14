
#include <stdio.h>
#include "nx_crypto_sha2.h"

#include "tls_test_utility.h"

#define MAXIMUM_PLAIN_BYTES 256

#include "nx_secure_sha256_test_data.c"

/* Define software SHA256 method. */
extern NX_CRYPTO_METHOD crypto_method_sha256;
;

/* SHA context. */
static NX_SHA256 sha256_ctx;

/* Output. */
static ULONG output[8];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_sha256_test_application_define(void *first_unused_memory)
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
    printf("NetX Secure Test:   SHA256 Test........................................");

    for (i = 0; i < sizeof(sha256_data) / sizeof(SHA256_DATA); i++)
    {

        /* Authentication. */
        memset(output, 0xFF, sizeof(output));

        crypto_method_sha256.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                 NX_CRYPTO_NULL,
                                                 &crypto_method_sha256,
                                                 NX_CRYPTO_NULL,
                                                 0,
                                                 sha256_data[i].plain,
                                                 sha256_data[i].plain_len,
                                                 NX_CRYPTO_NULL,
                                                 (UCHAR *)output,
                                                 sizeof(output),
                                                 &sha256_ctx,
                                                 sizeof(sha256_ctx),
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, sha256_data[i].secret, sizeof(output)));
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
