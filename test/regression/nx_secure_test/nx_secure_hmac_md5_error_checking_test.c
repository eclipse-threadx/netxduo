
#include <stdio.h>
#include "nx_crypto_hmac_md5.h"
#include "nx_crypto_method_self_test.h"

#include "tls_test_utility.h"

#define MAXIMUM_PLAIN_BYTES 256

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

extern NX_CRYPTO_METHOD crypto_method_hmac_md5;

/* HMAC MD5 context. */
static NX_MD5_HMAC hmac_md5_ctx;

/* Output. */
static ULONG output[4];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

static UINT test_nx_crypto_init_failed(NX_CRYPTO_METHOD *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    return 233;
}

static UINT test_nx_crypto_operation_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 233;
}

static UINT test_nx_crypto_operation_succeed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 0;
}

static UINT test_nx_crypto_operation_NX_CRYPTO_HASH_INITIALIZE_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_HASH_INITIALIZE)
        return 233;

    return _nx_crypto_method_hmac_md5_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_operation_NX_CRYPTO_HASH_UPDATE_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_HASH_UPDATE)
        return 233;

    return _nx_crypto_method_hmac_md5_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_operation_NX_CRYPTO_HASH_CALCULATE_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_HASH_CALCULATE)
        return 233;

    return _nx_crypto_method_hmac_md5_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_operation_NX_CRYPTO_HASH_CALCULATE_error(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_HASH_CALCULATE)
        return 0;

    return _nx_crypto_method_hmac_md5_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_hmac_md5_error_checking_test_application_define(void *first_unused_memory)
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
NX_CRYPTO_METHOD test_method;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   HMAC MD5 Error Test................................");

    /* NULL method pointer. */
    status = _nx_crypto_method_hmac_md5_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_hmac_md5_init(&test_crypto_method_hmac_md5, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_hmac_md5_init(&test_crypto_method_hmac_md5, (VOID *)0x04, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_hmac_md5_init(&test_crypto_method_hmac_md5, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_hmac_md5_init(&test_crypto_method_hmac_md5, (VOID *)0x04, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_hmac_md5_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_hmac_md5_operation(0, NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, /* method */
                                                  NX_CRYPTO_NULL, 0, /* key */
                                                  NX_CRYPTO_NULL, 0, /* input */
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0, /* output */
                                                  NX_CRYPTO_NULL, 0, /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_hmac_md5_operation(0, NX_CRYPTO_NULL,
                                                  &test_crypto_method_hmac_md5, /* method */
                                                  NX_CRYPTO_NULL, 0, /* key */
                                                  NX_CRYPTO_NULL, 0, /* input */
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0, /* output */
                                                  NX_CRYPTO_NULL, 0, /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_hmac_md5_operation(0, NX_CRYPTO_NULL,
                                                  &test_crypto_method_hmac_md5, /* method */
                                                  NX_CRYPTO_NULL, 0, /* key */
                                                  NX_CRYPTO_NULL, 0, /* input */
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0, /* output */
                                                  (VOID *)0x03, 0, /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_hmac_md5_operation(0, NX_CRYPTO_NULL,
                                                  &test_crypto_method_hmac_md5, /* method */
                                                  NX_CRYPTO_NULL, 0, /* key */
                                                  NX_CRYPTO_NULL, 0, /* input */
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0, /* output */
                                                  (VOID *)0x04, 0, /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_hmac_md5_operation(NX_CRYPTO_HASH_INITIALIZE, NX_CRYPTO_NULL,
                                                  &test_crypto_method_hmac_md5, /* method */
                                                  NX_CRYPTO_NULL, 0, /* key */
                                                  NX_CRYPTO_NULL, 0, /* input */
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0, /* output */
                                                  &hmac_md5_ctx, sizeof(hmac_md5_ctx), /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Output buffer size is not enough. */
    status = _nx_crypto_method_hmac_md5_operation(NX_CRYPTO_HASH_CALCULATE, NX_CRYPTO_NULL,
                                                  &test_crypto_method_hmac_md5, /* method */
                                                  NX_CRYPTO_NULL, 0, /* key */
                                                  NX_CRYPTO_NULL, 0, /* input */
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0, /* output */
                                                  &hmac_md5_ctx, sizeof(hmac_md5_ctx), /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_hmac_md5_operation(0, NX_CRYPTO_NULL,
                                                  &test_crypto_method_hmac_md5, /* method */
                                                  NX_CRYPTO_NULL, 0, /* key */
                                                  NX_CRYPTO_NULL, 0, /* input */
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0, /* output */
                                                  &hmac_md5_ctx, sizeof(hmac_md5_ctx), /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Output buffer size is not enough. */
    status = _nx_crypto_method_hmac_md5_operation(0, NX_CRYPTO_NULL,
                                                  &test_crypto_method_hmac_md5, /* method */
                                                  (VOID *)0x04, 0, /* key */
                                                  NX_CRYPTO_NULL, 0, /* input */
                                                  NX_CRYPTO_NULL,
                                                  NX_CRYPTO_NULL, 0, /* output */
                                                  &hmac_md5_ctx, sizeof(hmac_md5_ctx), /* metadata */
                                                  NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

#ifdef NX_CRYPTO_SELF_TEST
    /* Tests for _nx_crypto_method_self_test_hmac_md5. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_hmac_md5(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Invalid nx_crypto_algorithm. */
    test_method.nx_crypto_algorithm = 0;
    status = _nx_crypto_method_self_test_hmac_md5(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(1, status);

    /* nx_crypto_init and nx_crypto_operation are both NULL. */
    test_method.nx_crypto_algorithm = NX_CRYPTO_AUTHENTICATION_HMAC_MD5_96;
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_hmac_md5(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_hmac_md5(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_hmac_md5(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_hmac_md5(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_operation NX_CRYPTO_HASH_INITIALIZE failed. */
    test_method = crypto_method_hmac_md5;
    test_method.nx_crypto_operation = test_nx_crypto_operation_NX_CRYPTO_HASH_INITIALIZE_failed; 
    status = _nx_crypto_method_self_test_hmac_md5(&test_method, &hmac_md5_ctx, sizeof(hmac_md5_ctx));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_HASH_UPDATE failed. */
    test_method = crypto_method_hmac_md5;
    test_method.nx_crypto_operation = test_nx_crypto_operation_NX_CRYPTO_HASH_UPDATE_failed; 
    status = _nx_crypto_method_self_test_hmac_md5(&test_method, &hmac_md5_ctx, sizeof(hmac_md5_ctx));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_HASH_CALCULATE failed. */
    test_method = crypto_method_hmac_md5;
    test_method.nx_crypto_operation = test_nx_crypto_operation_NX_CRYPTO_HASH_CALCULATE_failed; 
    status = _nx_crypto_method_self_test_hmac_md5(&test_method, &hmac_md5_ctx, sizeof(hmac_md5_ctx));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_HASH_CALCULATE error. */
    test_method = crypto_method_hmac_md5;
    test_method.nx_crypto_operation = test_nx_crypto_operation_NX_CRYPTO_HASH_CALCULATE_error; 
    status = _nx_crypto_method_self_test_hmac_md5(&test_method, &hmac_md5_ctx, sizeof(hmac_md5_ctx));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_hmac_md5;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_hmac_md5(&test_method, &hmac_md5_ctx, sizeof(hmac_md5_ctx));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
