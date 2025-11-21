#include <stdio.h>
#include "nx_crypto_drbg.h"
#include "nx_crypto_method_self_test.h"
#include "tls_test_utility.h"

extern NX_CRYPTO_METHOD crypto_method_drbg;

/* SHA context. */
static NX_CRYPTO_DRBG drbg_ctx;

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

static UINT test_nx_crypto_operation_failed_NX_CRYPTO_DRBG_INSTANTIATE(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_DRBG_INSTANTIATE)
        return 232;

    return 0;
}

static UINT test_nx_crypto_operation_failed_NX_CRYPTO_DRBG_GENERATE(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_DRBG_GENERATE)
        return 231;

    return 0;
}

static UINT count = 0;
static UINT test_nx_crypto_operation_failed_NX_CRYPTO_DRBG_GENERATE_0(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_DRBG_GENERATE)
    {
        count++;
        if (count == 2)
            return 231;
    }

    return 0;
}

static UINT test_nx_crypto_operation_succeed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 0;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_drbg_test_application_define(void *first_unused_memory)
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
    printf("NetX Secure Test:   DRBG Test..........................................");

    /* NULL method pointer. */
    status = _nx_crypto_method_drbg_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_drbg_init(&crypto_method_drbg, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_drbg_init(&crypto_method_drbg, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_drbg_init(&crypto_method_drbg, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, &drbg_ctx, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_drbg_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_drbg_operation(0, NX_CRYPTO_NULL,
                                              NX_CRYPTO_NULL, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              NX_CRYPTO_NULL, 0, /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_drbg_operation(0, NX_CRYPTO_NULL,
                                              &crypto_method_drbg, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              NX_CRYPTO_NULL, 0, /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_drbg_operation(0, NX_CRYPTO_NULL,
                                              &crypto_method_drbg, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              (VOID *)0x03, 0, /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_drbg_operation(0, NX_CRYPTO_NULL,
                                              &crypto_method_drbg, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              &drbg_ctx, 0, /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_drbg_operation(NX_CRYPTO_DRBG_INSTANTIATE, NX_CRYPTO_NULL,
                                              &crypto_method_drbg, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              &drbg_ctx, sizeof(drbg_ctx), /* crypto metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

/* For NX_CRYPTO_STATE_CHECK. */
#ifdef NX_CRYPTO_SELF_TEST
    backup = _nx_crypto_library_state;
    _nx_crypto_library_state = 0;

    status = _nx_crypto_method_drbg_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_drbg_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_drbg_operation(0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_module_state_get();

    _nx_crypto_library_state = backup;

    /* Tests for _nx_crypto_method_self_test_drbg. */
    
    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_drbg(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init and nx_crypto_operation are both NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_drbg(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_drbg(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_drbg(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_DRBG_INSTANTIATE failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed_NX_CRYPTO_DRBG_INSTANTIATE;
    status = _nx_crypto_method_self_test_drbg(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(232, status);

    /* nx_crypto_operation NX_CRYPTO_DRBG_GENERATE failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed_NX_CRYPTO_DRBG_GENERATE;
    status = _nx_crypto_method_self_test_drbg(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(231, status);

    /* nx_crypto_operation NX_CRYPTO_DRBG_GENERATE failed at the second time. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed_NX_CRYPTO_DRBG_GENERATE_0;
    status = _nx_crypto_method_self_test_drbg(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(231, status);

    /* NX_CRYPTO_MEMCMP failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    status = _nx_crypto_method_self_test_drbg(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_drbg;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_drbg(&test_method, &drbg_ctx, sizeof(drbg_ctx));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
