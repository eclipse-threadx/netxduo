#include <stdio.h>
#include "nx_crypto_md5.h"
#include "nx_crypto_method_self_test.h"
#include "tls_test_utility.h"

extern NX_CRYPTO_METHOD crypto_method_md5;

/* Declare the MD5 hash method */
static NX_CRYPTO_METHOD test_crypto_method_md5 =
{
    NX_CRYPTO_HASH_MD5,                            /* MD5 algorithm                         */
    256,                                           /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    NX_CRYPTO_MD5_ICV_LEN_IN_BITS,                 /* Transmitted ICV size in bits          */
    NX_CRYPTO_MD5_BLOCK_SIZE_IN_BYTES,             /* Block size in bytes                   */
    sizeof(NX_CRYPTO_MD5),                         /* Metadata size in bytes                */
    _nx_crypto_method_md5_init,                    /* MD5 initialization routine            */
    NX_CRYPTO_NULL,                                       /* MD5 cleanup routine                   */
    _nx_crypto_method_md5_operation                /* MD5 operation                         */
};

/* HMAC MD5 context. */
static NX_CRYPTO_MD5 md5_ctx;

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static UINT test_nx_crypto_init_failed(NX_CRYPTO_METHOD *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    return 233;
}

static UINT test_nx_crypto_init_succeed(NX_CRYPTO_METHOD *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    return 0;
}

static UINT test_nx_crypto_operation_failed(UINT op,       /* Encrypt, Decrypt, Authenticate */
                                VOID *handler, /* Crypto handler */
                                struct NX_CRYPTO_METHOD_STRUCT *method,
                                UCHAR *key,
                                NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                UCHAR *input,
                                ULONG input_length_in_byte,
                                UCHAR *iv_ptr,
                                UCHAR *output,
                                ULONG output_length_in_byte,
                                VOID *crypto_metadata,
                                ULONG crypto_metadata_size,
                                VOID *packet_ptr,
                                VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 233;
}

static UINT test_nx_crypto_operation_succeed(UINT op,       /* Encrypt, Decrypt, Authenticate */
                                VOID *handler, /* Crypto handler */
                                struct NX_CRYPTO_METHOD_STRUCT *method,
                                UCHAR *key,
                                NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                UCHAR *input,
                                ULONG input_length_in_byte,
                                UCHAR *iv_ptr,
                                UCHAR *output,
                                ULONG output_length_in_byte,
                                VOID *crypto_metadata,
                                ULONG crypto_metadata_size,
                                VOID *packet_ptr,
                                VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 0;
}

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_md5_test_application_define(void *first_unused_memory)
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
UCHAR output[20], input[16];
NX_CRYPTO_METHOD test_method;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   MD5 Test...........................................");

    /* NULL method pointer. */
    status = _nx_crypto_method_md5_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_md5_init(&crypto_method_md5, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_md5_init(&crypto_method_md5, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_md5_init(&crypto_method_md5, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_md5_init(&crypto_method_md5, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_md5_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_md5_operation(0, NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, 0, /* output */
                                             NX_CRYPTO_NULL, 0, /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_md5_operation(0, NX_CRYPTO_NULL,
                                             &crypto_method_md5, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, 0, /* output */
                                             NX_CRYPTO_NULL, 0, /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_md5_operation(0, NX_CRYPTO_NULL,
                                             &crypto_method_md5, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, 0, /* output */
                                             (VOID *)0x03, 0, /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_md5_operation(0, NX_CRYPTO_NULL,
                                             &crypto_method_md5, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, 0, /* output */
                                             (VOID *)0x04, 0, /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL context pointer. */
    status = _nx_crypto_md5_initialize(NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL context pointer. */
    status = _nx_crypto_md5_update(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* input_length == 0. */
    status = _nx_crypto_md5_update(&md5_ctx, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NX_CRYPTO_HASH_CALCULATE output_length_in_byte < 16 */
    status = _nx_crypto_method_md5_operation(NX_CRYPTO_HASH_CALCULATE, NX_CRYPTO_NULL,
                                             &crypto_method_md5, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, 0, /* output */
                                             &md5_ctx, sizeof(md5_ctx), /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* op == 0 output_length_in_byte < 16 */
    status = _nx_crypto_method_md5_operation(0, NX_CRYPTO_NULL,
                                             &crypto_method_md5, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, 0, /* output */
                                             &md5_ctx, sizeof(md5_ctx), /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* Invoke _nx_crypto_md5_initialize by crypto_method_operation. */
    status = _nx_crypto_method_md5_operation(NX_CRYPTO_HASH_INITIALIZE, NX_CRYPTO_NULL,
                                             &crypto_method_md5, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, 0, /* output */
                                             &md5_ctx, sizeof(md5_ctx), /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Update 0 byte hash data. */
    status = _nx_crypto_method_md5_operation(NX_CRYPTO_HASH_UPDATE, NX_CRYPTO_NULL,
                                             &crypto_method_md5, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, 0, /* output */
                                             &md5_ctx, sizeof(md5_ctx), /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Invoke _nx_crypto_md5_digest_calculate by crypto_method_operation. */
    status = _nx_crypto_method_md5_operation(NX_CRYPTO_HASH_CALCULATE, NX_CRYPTO_NULL,
                                             &crypto_method_md5, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL,
                                             output, sizeof(output), /* output */
                                             &md5_ctx, sizeof(md5_ctx), /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* There is roll-over of the bit count into the MSW. */
    md5_ctx.nx_md5_bit_count[0] = -1;
    status = _nx_crypto_md5_update(&md5_ctx, input, 16);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#ifdef NX_CRYPTO_SELF_TEST
    /* Tests for md5 self test. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_md5(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_md5(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation is NULL. */
    test_method.nx_crypto_init = test_nx_crypto_init_succeed;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_md5(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_operation failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_succeed;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_md5(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* output != secret_1 */
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_md5(&test_method, output, sizeof(output));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_init is NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_md5(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_cleanup is NULL. */
    status = _nx_crypto_method_self_test_md5(&test_crypto_method_md5, &md5_ctx, sizeof(md5_ctx));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
};
