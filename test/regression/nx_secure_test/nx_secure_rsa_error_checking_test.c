
#include <stdio.h>
#include "nx_crypto_rsa.h"
#include "nx_crypto_method_self_test.h"

#include "tls_test_utility.h"
#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif

#define MAXIMUM_KEY_BITS 2048

#include "nx_secure_rsa_test_data.c"

/* Define software RSA method. */
static NX_CRYPTO_METHOD test_crypto_method_rsa =
{
    NX_CRYPTO_KEY_EXCHANGE_RSA,               /* RSA crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_RSA),                    /* Metadata size in bytes                 */
    _nx_crypto_method_rsa_init,               /* RSA initialization routine.            */
    NX_CRYPTO_NULL,                           /* RSA cleanup routine, not used.         */
    _nx_crypto_method_rsa_operation           /* RSA operation                          */

};

extern NX_CRYPTO_METHOD crypto_method_rsa;

/* RSA context. */
static NX_CRYPTO_RSA rsa_ctx;

/* Output. */
static ULONG output[MAXIMUM_KEY_BITS >> 5];

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
    return _nx_crypto_method_rsa_init(method, key, key_size_in_bits, handler, crypto_metadata, crypto_metadata_size);
}

static UINT test_nx_crypto_init_succeed(NX_CRYPTO_METHOD *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, VOID **handler, VOID *crypto_metadata, ULONG crypto_metadata_size)
{
    return 0;
}

static UINT test_nx_crypto_operation_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (!count)
        return 233;

    count--;
    return _nx_crypto_method_rsa_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_operation_succeed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (!count)
        return 0;

    count--;
    return _nx_crypto_method_rsa_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_rsa_error_checking_test_application_define(void *first_unused_memory)
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
    printf("NetX Secure Test:   RSA Error Checking Test............................");

    /* Illegal rsa input. */
    i = sizeof(rsa_data)/sizeof(RSA_DATA);
    rsa_ctx.nx_crypto_rsa_prime_p = (VOID *)4;
    rsa_ctx.nx_crypto_rsa_prime_q = NX_CRYPTO_NULL;
    test_crypto_method_rsa.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_rsa,
                                               rsa_data[i].pri_e,
                                               (rsa_data[i].pri_e_len << 3),
                                               rsa_data[i].secret,
                                               rsa_data[i].secret_len,
                                               NX_CRYPTO_NULL,
                                               (UCHAR *)output,
                                               sizeof(output),
                                               &rsa_ctx,
                                               sizeof(rsa_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    /* Test input length > modulus length  */
    test_crypto_method_rsa.nx_crypto_init(&test_crypto_method_rsa,
                                          rsa_data[0].m,
                                          (rsa_data[0].m_len << 3),
                                          NX_CRYPTO_NULL,
                                          &rsa_ctx,
                                          sizeof(rsa_ctx));

    rsa_ctx.nx_crypto_rsa_modulus_length = rsa_data[0].secret_len - 1;

    status = test_crypto_method_rsa.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                        NX_CRYPTO_NULL,
                                                        &test_crypto_method_rsa,
                                                        rsa_data[0].pub_e,
                                                        (rsa_data[0].pub_e_len << 3),
                                                        rsa_data[0].plain,
                                                        rsa_data[0].plain_len,
                                                        NX_CRYPTO_NULL,
                                                        (UCHAR *)output,
                                                        sizeof(output),
                                                        &rsa_ctx,
                                                        sizeof(rsa_ctx),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(status, NX_CRYPTO_PTR_ERROR);

    /* NULL method pointer. */
    status = _nx_crypto_method_rsa_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_rsa_init(&test_crypto_method_rsa, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_rsa_init(&test_crypto_method_rsa, rsa_data[0].m, (rsa_data[0].m_len << 3), NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_rsa_init(&test_crypto_method_rsa, rsa_data[0].m, (rsa_data[0].m_len << 3), NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_rsa_init(&test_crypto_method_rsa, rsa_data[0].m, (rsa_data[0].m_len << 3), NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_rsa_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_rsa_operation(0, NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL, /* iv */
                                             NX_CRYPTO_NULL, 0, /* output */
                                             NX_CRYPTO_NULL, 0, /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_rsa_operation(0, NX_CRYPTO_NULL,
                                             &test_crypto_method_rsa, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL, /* iv */
                                             NX_CRYPTO_NULL, 0, /* output */
                                             NX_CRYPTO_NULL, 0, /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_rsa_operation(0, NX_CRYPTO_NULL,
                                             &test_crypto_method_rsa, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL, /* iv */
                                             NX_CRYPTO_NULL, 0, /* output */
                                             (VOID *)0x03, 0, /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_rsa_operation(0, NX_CRYPTO_NULL,
                                             &test_crypto_method_rsa, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL, /* iv */
                                             NX_CRYPTO_NULL, 0, /* output */
                                             &rsa_ctx, 0, /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Output buffer size is not enough. */
    status = _nx_crypto_method_rsa_operation(0, NX_CRYPTO_NULL,
                                             &test_crypto_method_rsa, /* method */
                                             (VOID *)0x04, 1024, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL, /* iv */
                                             NX_CRYPTO_NULL, 0, /* output */
                                             &rsa_ctx, sizeof(rsa_ctx), /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_BUFFER_SIZE, status);

    /* q is NULL. */
    _nx_crypto_rsa_operation(pub_e_512_0, sizeof(pub_e_512_0),
                             m_512_0, sizeof(m_512_0),
                             p_512_0, sizeof(p_512_0),
                             NX_CRYPTO_NULL, 0,
                             plain_512_0, sizeof(plain_512_0),
                             (UCHAR *)output,
                             (USHORT *)&rsa_ctx, sizeof(rsa_ctx));

/* For NX_CRYPTO_STATE_CHECK. */
#ifdef NX_CRYPTO_SELF_TEST
    backup = _nx_crypto_library_state;
    _nx_crypto_library_state = 0;

    status = _nx_crypto_method_rsa_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_rsa_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_rsa_operation(0, NX_CRYPTO_NULL,
                                             NX_CRYPTO_NULL, /* method */
                                             NX_CRYPTO_NULL, 0, /* key */
                                             NX_CRYPTO_NULL, 0, /* input */
                                             NX_CRYPTO_NULL, /* iv */
                                             NX_CRYPTO_NULL, 0, /* output */
                                             NX_CRYPTO_NULL, 0, /* metadata */
                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    _nx_crypto_library_state = backup;

    /* Tests for _nx_crypto_method_self_test_rsa. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_rsa(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init is NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_rsa(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_operation is NULL. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_rsa(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_rsa(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_succeed;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_rsa(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_succeed;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_rsa(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_rsa;
    test_method.nx_crypto_cleanup  = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_rsa(&test_method, &rsa_ctx, sizeof(rsa_ctx));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* nx_crypto_init failed at the second time. */
    count = 1;
    test_method = crypto_method_rsa;
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_rsa(&test_method, &rsa_ctx, sizeof(rsa_ctx));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed at the second time. */
    count = 1;
    test_method = crypto_method_rsa;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_rsa(&test_method, &rsa_ctx, sizeof(rsa_ctx));
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed at the second time. */
    count = 1;
    test_method = crypto_method_rsa;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_rsa(&test_method, &rsa_ctx, sizeof(rsa_ctx));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_init failed at the second time. */
    count = 2;
    test_method = crypto_method_rsa;
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_rsa(&test_method, &rsa_ctx, sizeof(rsa_ctx));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed at the third time. */
    count = 2;
    test_method = crypto_method_rsa;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_rsa(&test_method, &rsa_ctx, sizeof(rsa_ctx));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed at the fourth time. */
    count = 3;
    test_method = crypto_method_rsa;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_rsa(&test_method, &rsa_ctx, sizeof(rsa_ctx));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed at the fifth time. */
    count = 4;
    test_method = crypto_method_rsa;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_rsa(&test_method, &rsa_ctx, sizeof(rsa_ctx));
    EXPECT_EQ(233, status);

    /* NX_CRYPTO_MEMCMP failed at the third time. */
    count = 4;
    test_method = crypto_method_rsa;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_rsa(&test_method, &rsa_ctx, sizeof(rsa_ctx));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

#endif /* NX_CRYPTO_SELF_TEST */

#ifndef NX_SECURE_KEY_CLEAR
    status = _nx_crypto_method_rsa_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(status, TX_SUCCESS);
#endif /* NX_SECURE_KEY_CLEAR */

    printf("SUCCESS!\n");
    test_control_return(0);
}
