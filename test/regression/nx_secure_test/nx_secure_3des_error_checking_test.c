
#include <stdio.h>
#include "nx_crypto_3des.h"
#include "nx_crypto_method_self_test.h"

#include "tls_test_utility.h"
#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif

#define MAXIMUM_KEY_BITS 256

/* Define software 3DES method. */
static NX_CRYPTO_METHOD test_crypto_method_3des =
{
    NX_CRYPTO_ENCRYPTION_3DES_CBC,            /* 3DES crypto algorithm filled at runtime*/
    0,                                        /* Key size in bits                       */
    NX_CRYPTO_3DES_IV_LEN_IN_BITS,            /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    NX_CRYPTO_3DES_BLOCK_SIZE_IN_BITS,        /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_3DES),                   /* Metadata size in bytes                 */
    _nx_crypto_method_3des_init,              /* 3DES initialization routine.            */
    NX_CRYPTO_NULL,                           /* 3DES cleanup routine, not used.         */
    _nx_crypto_method_3des_operation          /* 3DES operation                          */

};

extern NX_CRYPTO_METHOD crypto_method_3des;

/* 3DES context. */
static NX_CRYPTO_3DES _3des_ctx;

/* Input to hold plain plus nonce. */
static UCHAR key[24];

/* IV. */
static UCHAR iv[8] = {0, 1, 2, 3, 4, 5, 6, 7};

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

static UINT count = 0;

static UINT test_nx_crypto_init_failed(NX_CRYPTO_METHOD *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    if (!count)
        return 233;

    count--;
    return _nx_crypto_method_3des_init(method, key, key_size_in_bits, handler, crypto_metadata, crypto_metadata_size);
}

static UINT test_nx_crypto_operation_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (!count)
        return 233;

    count--;
    return _nx_crypto_method_3des_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_operation_succeed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (!count)
        return 0;

    count--;
    return _nx_crypto_method_3des_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_cleanup_failed(VOID *crypto_metadata)
{
    return 233;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_3des_error_checking_test_application_define(void *first_unused_memory)
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
UCHAR input[24];
UCHAR output[24];
VOID *handle;
NX_CRYPTO_METHOD test_method;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   3DES Error Checking Test...........................");

    /* Unsupported operation. */
    status = test_crypto_method_3des.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_3des,
                                                       (UCHAR *)key,
                                                       (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),                                               
                                                       (UCHAR *)output,
                                                       sizeof(output),
                                                       (UCHAR *)iv,
                                                       (UCHAR *)output,
                                                       sizeof(output),
                                                       &_3des_ctx,
                                                       sizeof(_3des_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_NOT_SUCCESSFUL);

    /* Null method pointer. */
    status = test_crypto_method_3des.nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       (UCHAR *)key,
                                                       (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),                                               
                                                       (UCHAR *)output,
                                                       sizeof(output),
                                                       (UCHAR *)iv,
                                                       (UCHAR *)output,
                                                       sizeof(output),
                                                       &_3des_ctx,
                                                       sizeof(_3des_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Null metadata pointer. */
    status = test_crypto_method_3des.nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_3des,
                                                       (UCHAR *)key,
                                                       (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),                                               
                                                       (UCHAR *)output,
                                                       sizeof(output),
                                                       (UCHAR *)iv,
                                                       (UCHAR *)output,
                                                       sizeof(output),
                                                       NX_CRYPTO_NULL,
                                                       sizeof(_3des_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    test_crypto_method_3des.nx_crypto_algorithm = 0;
    status = test_crypto_method_3des.nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_3des,
                                                       (UCHAR *)key,
                                                       (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),                                               
                                                       (UCHAR *)output,
                                                       sizeof(output),
                                                       (UCHAR *)iv,
                                                       (UCHAR *)output,
                                                       sizeof(output),
                                                       &_3des_ctx,
                                                       sizeof(_3des_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_INVALID_ALGORITHM);
    test_crypto_method_3des.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_3DES_CBC;

    /* Invalid input size. */
    status = test_crypto_method_3des.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_3des,
                                                       (UCHAR *)key,
                                                       (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),
                                                       input,
                                                       1,
                                                       (UCHAR *)iv,
                                                       (UCHAR *)output,
                                                       sizeof(output),
                                                       &_3des_ctx,
                                                       sizeof(_3des_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid input size. */
    status = test_crypto_method_3des.nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_3des,
                                                       (UCHAR *)key,
                                                       (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),                                               
                                                       (UCHAR *)output,
                                                       1,
                                                       (UCHAR *)iv,
                                                       (UCHAR *)output,
                                                       sizeof(output),
                                                       &_3des_ctx,
                                                       sizeof(_3des_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Null method pointer. */
    status = test_crypto_method_3des.nx_crypto_init(NX_CRYPTO_NULL,
                                                  (UCHAR *)key,
                                                  (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),
                                                  &handle,
                                                  &_3des_ctx,
                                                  sizeof(_3des_ctx));
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Null key pointer. */
    status = test_crypto_method_3des.nx_crypto_init(&test_crypto_method_3des,
                                                  (UCHAR *)NX_CRYPTO_NULL,
                                                  (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),
                                                  &handle,
                                                  &_3des_ctx,
                                                  sizeof(_3des_ctx));
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Null metadata pointer. */
    status = test_crypto_method_3des.nx_crypto_init(&test_crypto_method_3des,
                                                  (UCHAR *)key,
                                                  (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),
                                                  &handle,
                                                  NX_CRYPTO_NULL,
                                                  sizeof(_3des_ctx));
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid key size. */
    status = test_crypto_method_3des.nx_crypto_init(&test_crypto_method_3des,
                                                  (UCHAR *)key,
                                                  0,
                                                  &handle,
                                                  &_3des_ctx,
                                                  sizeof(_3des_ctx));
    EXPECT_EQ(status, NX_CRYPTO_UNSUPPORTED_KEY_SIZE);

    /* Metadata address is not 4-byte aligned. */
    status = test_crypto_method_3des.nx_crypto_init(&test_crypto_method_3des,
                                                  (UCHAR *)key,
                                                  (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),
                                                  &handle,
                                                  (VOID *)0x03,
                                                  sizeof(_3des_ctx)-1);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Invalid metadata size. */
    status = test_crypto_method_3des.nx_crypto_init(&test_crypto_method_3des,
                                                  (UCHAR *)key,
                                                  (NX_CRYPTO_3DES_KEY_LEN_IN_BITS),
                                                  &handle,
                                                  &_3des_ctx,
                                                  sizeof(_3des_ctx)-1);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Null metadata pointer. */
    status = _nx_crypto_method_3des_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_3des_operation(0, NX_CRYPTO_NULL,
                                              &test_crypto_method_3des, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              (VOID *)0x03, 0, /* metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_3des_operation(0, NX_CRYPTO_NULL,
                                              &test_crypto_method_3des, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              (VOID *)0x04, 0, /* metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

/* For NX_CRYPTO_STATE_CHECK. */
#ifdef NX_CRYPTO_SELF_TEST
    backup = _nx_crypto_library_state;
    _nx_crypto_library_state = 0;

    status = _nx_crypto_method_3des_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_3des_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_3des_operation(0, NX_CRYPTO_NULL,
                                              NX_CRYPTO_NULL, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              NX_CRYPTO_NULL, 0, /* metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    _nx_crypto_library_state = backup;

    /* Tests for _nx_crypto_method_self_test_aes. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_3des(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init and nx_crypto_operation are both NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_3des(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_3des(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_3des(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_3des(&test_method, &_3des_ctx, sizeof(_3des_ctx));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_cleanup failed. */
    test_method = crypto_method_3des;
    test_method.nx_crypto_cleanup = test_nx_crypto_cleanup_failed;
    status = _nx_crypto_method_self_test_3des(&test_method, &_3des_ctx, sizeof(_3des_ctx));
    EXPECT_EQ(233, status);

    /* nx_crypto_init failed at the second time. */
    count = 1;
    test_method = crypto_method_3des;
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_3des(&test_method, &_3des_ctx, sizeof(_3des_ctx));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed at the second time. */
    count = 1;
    test_method = crypto_method_3des;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_3des(&test_method, &_3des_ctx, sizeof(_3des_ctx));
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed at the second time. */
    count = 1;
    test_method = crypto_method_3des;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_3des(&test_method, &_3des_ctx, sizeof(_3des_ctx));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_3des;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_3des(&test_method, &_3des_ctx, sizeof(_3des_ctx));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* nx_crypto_init is NULL. */
    UCHAR key_1[] = { 0x8f, 0x4f, 0x7a, 0xab, 0x25, 0x04, 0x37, 0x20, 0xf4, 0xfb, 0xae, 0x01, 0xae, 0xdf, 0x07, 0x1c, 0x68, 0xa2, 0x83, 0x68, 0x9b, 0x08, 0xad, 0x20, };
    test_method = crypto_method_3des;
    /* Initialized the method by the key used in the self test. */
    test_method.nx_crypto_init(&test_method, key_1, NX_CRYPTO_3DES_KEY_LEN_IN_BITS, NX_CRYPTO_NULL, &_3des_ctx, sizeof(_3des_ctx));
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_3des(&test_method, &_3des_ctx, sizeof(_3des_ctx));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
