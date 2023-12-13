
#include <stdio.h>
#include "nx_crypto_sha2.h"

#include "tls_test_utility.h"

#define MAXIMUM_PLAIN_BYTES 256

#include "nx_secure_sha224_test_data.c"

/* Define software SHA224 method. */
extern NX_CRYPTO_METHOD crypto_method_sha224;

/* SHA context. */
static NX_CRYPTO_SHA256 sha224_ctx;

/* Output. */
static ULONG output[7];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_sha224_test_application_define(void *first_unused_memory)
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
    printf("NetX Secure Test:   SHA224 Test........................................");

    for (i = 0; i < sizeof(sha224_data) / sizeof(SHA224_DATA); i++)
    {

        /* Authentication. */
        memset(output, 0xFF, sizeof(output));

        crypto_method_sha224.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                 NX_CRYPTO_NULL,
                                                 &crypto_method_sha224,
                                                 NX_CRYPTO_NULL,
                                                 0,
                                                 sha224_data[i].plain,
                                                 sha224_data[i].plain_len,
                                                 NX_CRYPTO_NULL,
                                                 (UCHAR *)output,
                                                 sizeof(output),
                                                 &sha224_ctx,
                                                 sizeof(sha224_ctx),
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, sha224_data[i].secret, sizeof(output)));
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
