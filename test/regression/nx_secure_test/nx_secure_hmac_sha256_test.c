
#include <stdio.h>
#include "nx_crypto_hmac_sha2.h"

#include "tls_test_utility.h"

#define MAXIMUM_PLAIN_BYTES 256

#include "nx_secure_hmac_sha256_test_data.c"

/* Define software SHA256 method. */
static NX_CRYPTO_METHOD test_crypto_method_hmac_sha256 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256,   /* SHA crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    256,                                      /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_SHA256_HMAC),                   /* Metadata size in bytes                 */
    NX_CRYPTO_NULL,                           /* SHA initialization routine.            */
    NX_CRYPTO_NULL,                           /* SHA cleanup routine, not used.         */
    _nx_crypto_method_hmac_sha256_operation,  /* SHA operation                          */
};

/* SHA context. */
static NX_SHA256_HMAC hmac_sha256_ctx;

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
void nx_secure_hmac_sha256_test_application_define(void *first_unused_memory)
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
UINT i, status, backup;
NX_CRYPTO_METHOD test_method;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   HMAC SHA256 Test...................................");

    for (i = 0; i < sizeof(hmac_sha256_data) / sizeof(HMAC_SHA256_DATA); i++)
    {

        /* Authentication. */
        memset(output, 0xFF, sizeof(output));

        test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                           NX_CRYPTO_NULL,
                                                           &test_crypto_method_hmac_sha256,
                                                           hmac_sha256_data[i].key,
                                                           (hmac_sha256_data[i].key_len << 3),
                                                           hmac_sha256_data[i].plain,
                                                           hmac_sha256_data[i].plain_len,
                                                           NX_CRYPTO_NULL,
                                                           (UCHAR *)output,
                                                           sizeof(output),
                                                           &hmac_sha256_ctx,
                                                           sizeof(hmac_sha256_ctx),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, hmac_sha256_data[i].secret, sizeof(output)));

        memset(output, 0xFF, sizeof(output));

        /* Test HMAC SHA256 with Initialize, Update and Calculate operation.  */
        test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                           NX_CRYPTO_NULL,
                                                           &test_crypto_method_hmac_sha256,
                                                           hmac_sha256_data[i].key,
                                                           (hmac_sha256_data[i].key_len << 3),
                                                           NX_CRYPTO_NULL,
                                                           0,
                                                           NX_CRYPTO_NULL,
                                                           NX_CRYPTO_NULL,
                                                           0,
                                                           &hmac_sha256_ctx,
                                                           sizeof(hmac_sha256_ctx),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                           NX_CRYPTO_NULL,
                                                           &test_crypto_method_hmac_sha256,
                                                           NX_CRYPTO_NULL,
                                                           0,
                                                           hmac_sha256_data[i].plain,
                                                           hmac_sha256_data[i].plain_len,
                                                           NX_CRYPTO_NULL,
                                                           NX_CRYPTO_NULL,
                                                           0,
                                                           &hmac_sha256_ctx,
                                                           sizeof(hmac_sha256_ctx),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                           NX_CRYPTO_NULL,
                                                           &test_crypto_method_hmac_sha256,
                                                           NX_CRYPTO_NULL,
                                                           0,
                                                           NX_CRYPTO_NULL,
                                                           0,
                                                           NX_CRYPTO_NULL,
                                                           (UCHAR *)output,
                                                           sizeof(output),
                                                           &hmac_sha256_ctx,
                                                           sizeof(hmac_sha256_ctx),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, hmac_sha256_data[i].secret, sizeof(output)));
    }

    /* NULL method pointer. */
    status = _nx_crypto_method_hmac_sha256_operation(0, NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, /* method */
                                                     NX_CRYPTO_NULL, 0, /* key */
                                                     NX_CRYPTO_NULL, 0, /* input */
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0, /* output */
                                                     NX_CRYPTO_NULL, 0, /* metadata */
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_hmac_sha256_operation(0, NX_CRYPTO_NULL,
                                                     &test_crypto_method_hmac_sha256, /* method */
                                                     NX_CRYPTO_NULL, 0, /* key */
                                                     NX_CRYPTO_NULL, 0, /* input */
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0, /* output */
                                                     NX_CRYPTO_NULL, 0, /* metadata */
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_hmac_sha256_operation(0, NX_CRYPTO_NULL,
                                                     &test_crypto_method_hmac_sha256, /* method */
                                                     NX_CRYPTO_NULL, 0, /* key */
                                                     NX_CRYPTO_NULL, 0, /* input */
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0, /* output */
                                                     (VOID *)0x03, 0, /* metadata */
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_hmac_sha256_operation(0, NX_CRYPTO_NULL,
                                                     &test_crypto_method_hmac_sha256, /* method */
                                                     NX_CRYPTO_NULL, 0, /* key */
                                                     NX_CRYPTO_NULL, 0, /* input */
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0, /* output */
                                                     &hmac_sha256_ctx, 0, /* metadata */
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_hmac_sha256_operation(NX_CRYPTO_HASH_INITIALIZE, NX_CRYPTO_NULL,
                                                     &test_crypto_method_hmac_sha256, /* method */
                                                     NX_CRYPTO_NULL, 0, /* key */
                                                     NX_CRYPTO_NULL, 0, /* input */
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0, /* output */
                                                     &hmac_sha256_ctx, sizeof(hmac_sha256_ctx), /* metadata */
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Output buffer size is not enough. */
    status = _nx_crypto_method_hmac_sha256_operation(NX_CRYPTO_HASH_CALCULATE, NX_CRYPTO_NULL,
                                                     &test_crypto_method_hmac_sha256, /* method */
                                                     NX_CRYPTO_NULL, 0, /* key */
                                                     NX_CRYPTO_NULL, 0, /* input */
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0, /* output */
                                                     &hmac_sha256_ctx, sizeof(hmac_sha256_ctx), /* metadata */
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_hmac_sha256_operation(0, NX_CRYPTO_NULL,
                                                     &test_crypto_method_hmac_sha256, /* method */
                                                     NX_CRYPTO_NULL, 0, /* key */
                                                     NX_CRYPTO_NULL, 0, /* input */
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0, /* output */
                                                     &hmac_sha256_ctx, sizeof(hmac_sha256_ctx), /* metadata */
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Output buffer size is not enough. */
    status = _nx_crypto_method_hmac_sha256_operation(0, NX_CRYPTO_NULL,
                                                     &test_crypto_method_hmac_sha256, /* method */
                                                     (VOID *)0x04, 0, /* key */
                                                     NX_CRYPTO_NULL, 0, /* input */
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0, /* output */
                                                     &hmac_sha256_ctx, sizeof(hmac_sha256_ctx), /* metadata */
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* Invalid algorithm id. */
    test_crypto_method_hmac_sha256.nx_crypto_algorithm = 0;
    status = _nx_crypto_method_hmac_sha256_operation(0, NX_CRYPTO_NULL,
                                                     &test_crypto_method_hmac_sha256, /* method */
                                                     (VOID *)0x04, 0, /* key */
                                                     NX_CRYPTO_NULL, 0, /* input */
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0, /* output */
                                                     &hmac_sha256_ctx, sizeof(hmac_sha256_ctx), /* metadata */
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_hmac_sha256_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_hmac_sha256_init(&test_crypto_method_hmac_sha256, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_hmac_sha256_init(&test_crypto_method_hmac_sha256, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_hmac_sha256_init(&test_crypto_method_hmac_sha256, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_hmac_sha256_init(&test_crypto_method_hmac_sha256, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_hmac_sha256_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

/* For NX_CRYPTO_STATE_CHECK. */
#ifdef NX_CRYPTO_SELF_TEST
    backup = _nx_crypto_library_state;
    _nx_crypto_library_state = 0;

    status = _nx_crypto_method_hmac_sha256_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_hmac_sha256_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_hmac_sha256_operation(0, NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, /* method */
                                                     NX_CRYPTO_NULL, 0, /* key */
                                                     NX_CRYPTO_NULL, 0, /* input */
                                                     NX_CRYPTO_NULL,
                                                     NX_CRYPTO_NULL, 0, /* output */
                                                     NX_CRYPTO_NULL, 0, /* metadata */
                                                     NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    _nx_crypto_library_state = backup;
#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
