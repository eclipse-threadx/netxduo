
#include <stdio.h>
#include "nx_crypto_sha5.h"

#include "tls_test_utility.h"

#define MAXIMUM_PLAIN_BYTES 256

#include "nx_secure_sha512_test_data.c"

extern NX_CRYPTO_METHOD crypto_method_sha512;

/* SHA context. */
static NX_SHA512 sha512_ctx;

/* Output. */
static ULONG output[16];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_sha512_test_application_define(void *first_unused_memory)
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
    printf("NetX Secure Test:   SHA512 Test........................................");

    for (i = 0; i < sizeof(sha512_data) / sizeof(SHA512_DATA); i++)
    {

        /* Authentication. */
        memset(output, 0xFF, sizeof(output));

        crypto_method_sha512.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                 NX_CRYPTO_NULL,
                                                 &crypto_method_sha512,
                                                 NX_CRYPTO_NULL,
                                                 0,
                                                 sha512_data[i].plain,
                                                 sha512_data[i].plain_len,
                                                 NX_CRYPTO_NULL,
                                                 (UCHAR *)output,
                                                 sizeof(output),
                                                 &sha512_ctx,
                                                 sizeof(sha512_ctx),
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, sha512_data[i].secret, sizeof(output)));
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
