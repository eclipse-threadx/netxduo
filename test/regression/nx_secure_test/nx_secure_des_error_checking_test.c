
#include <stdio.h>
#include "nx_crypto_des.h"
#include "nx_crypto_method_self_test.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif
#include "tls_test_utility.h"

#define MAXIMUM_KEY_BITS 256

/* Define software DES method. */
static NX_CRYPTO_METHOD test_crypto_method_des =
{
    NX_CRYPTO_ENCRYPTION_DES_CBC,             /* DES crypto algorithm filled at runtime*/
    0,                                        /* Key size in bits                       */
    NX_CRYPTO_DES_IV_LEN_IN_BITS,             /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS,         /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_DES),                    /* Metadata size in bytes                 */
    _nx_crypto_method_des_init,               /* DES initialization routine.            */
    NX_CRYPTO_NULL,                           /* DES cleanup routine, not used.         */
    _nx_crypto_method_des_operation           /* DES operation                          */

};

extern NX_CRYPTO_METHOD crypto_method_des;
/* DES context. */
static NX_CRYPTO_DES _des_ctx;

/* Input to hold plain plus nonce. */
static UCHAR key[8];

/* IV. */
static UCHAR iv[8] = {0, 1, 2, 3, 4, 5, 6, 7};

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

static UINT count = 0;

static UINT test_nx_crypto_init_failed(NX_CRYPTO_METHOD *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    return 233;
}

static UINT test_nx_crypto_operation_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (!count)
        return 233;

    count--;
    return _nx_crypto_method_des_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_operation_succeed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (!count)
        return 0;

    count--;
    return _nx_crypto_method_des_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_des_error_checking_test_application_define(void *first_unused_memory)
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
UCHAR input[8];
UCHAR output[8];
VOID *handle;
NX_CRYPTO_METHOD test_method;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DES Error Checking Test............................");

    /* Set key and IV. */
    for (i = 0; i < 8; i++)
    {
        key[i] = i;
        input[i] = i;
    }

    /* NULL method pointer. */
    status = _nx_crypto_method_des_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_des_init(&test_crypto_method_des, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_des_init(&test_crypto_method_des, (UCHAR *)key, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Invalid key size. */
    status = _nx_crypto_method_des_init(&test_crypto_method_des, (UCHAR *)key, 0, NX_CRYPTO_NULL, &_des_ctx, 0);
    EXPECT_EQ(NX_CRYPTO_SIZE_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_des_init(&test_crypto_method_des, (UCHAR *)key, NX_CRYPTO_DES_KEY_LEN_IN_BITS, NX_CRYPTO_NULL, &_des_ctx, 0);
    EXPECT_EQ(NX_CRYPTO_SIZE_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_des_init(&test_crypto_method_des, (UCHAR *)key, NX_CRYPTO_DES_KEY_LEN_IN_BITS, NX_CRYPTO_NULL, (VOID *)0x03, sizeof(NX_CRYPTO_DES));
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL crypto_metadata pointer. */
    status = _nx_crypto_method_des_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* Invalid operation id. */
    status = test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE, NX_CRYPTO_NULL,
                                               &test_crypto_method_des, /* method */
                                               (UCHAR *)key, NX_CRYPTO_DES_KEY_LEN_IN_BITS, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               (UCHAR *)iv, /* iv */
                                               (UCHAR *)output, sizeof(output), /* output */
                                               &_des_ctx, sizeof(_des_ctx), /* metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* NULL method pointer. */
    status = test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_ENCRYPT, NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL, /* method */
                                               (UCHAR *)key, NX_CRYPTO_DES_KEY_LEN_IN_BITS, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               (UCHAR *)iv, /* iv */
                                               (UCHAR *)output, sizeof(output), /* output */
                                               &_des_ctx, sizeof(_des_ctx), /* metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_ENCRYPT, NX_CRYPTO_NULL,
                                               &test_crypto_method_des, /* method */
                                               (UCHAR *)key, NX_CRYPTO_DES_KEY_LEN_IN_BITS, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               (UCHAR *)iv, /* iv */
                                               (UCHAR *)output, sizeof(output), /* output */
                                               NX_CRYPTO_NULL, sizeof(_des_ctx), /* metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_ENCRYPT, NX_CRYPTO_NULL,
                                               &test_crypto_method_des, /* method */
                                               (UCHAR *)key, NX_CRYPTO_DES_KEY_LEN_IN_BITS, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               (UCHAR *)iv, /* iv */
                                               (UCHAR *)output, sizeof(output), /* output */
                                               (VOID *)0x03, sizeof(_des_ctx), /* metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_ENCRYPT, NX_CRYPTO_NULL,
                                               &test_crypto_method_des, /* method */
                                               (UCHAR *)key, NX_CRYPTO_DES_KEY_LEN_IN_BITS, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               (UCHAR *)iv, /* iv */
                                               (UCHAR *)output, sizeof(output), /* output */
                                               &_des_ctx, 0, /* metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Invalid algorithm id. */
    backup = test_crypto_method_des.nx_crypto_algorithm;
    test_crypto_method_des.nx_crypto_algorithm = 0;
    status = test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_ENCRYPT, NX_CRYPTO_NULL,
                                               &test_crypto_method_des, /* method */
                                               (UCHAR *)key, NX_CRYPTO_DES_KEY_LEN_IN_BITS, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               (UCHAR *)iv, /* iv */
                                               (UCHAR *)output, sizeof(output), /* output */
                                               &_des_ctx, sizeof(_des_ctx), /* metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    test_crypto_method_des.nx_crypto_algorithm = backup;
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

#ifdef NX_CRYPTO_SELF_TEST
    /* Tests for _nx_crypto_method_self_test_des. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_des(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init and nx_crypto_operation are both NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_des(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_des(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_des(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_des(&test_method, &_des_ctx, sizeof(_des_ctx));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_operation NX_CRYPTO_DECRYPT failed. */
    count = 1;
    test_method = crypto_method_des;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_des(&test_method, &_des_ctx, sizeof(_des_ctx));
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed at the second time. */
    count = 1;
    test_method = crypto_method_des;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_des(&test_method, &_des_ctx, sizeof(_des_ctx));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_des;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_des(&test_method, &_des_ctx, sizeof(_des_ctx));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
