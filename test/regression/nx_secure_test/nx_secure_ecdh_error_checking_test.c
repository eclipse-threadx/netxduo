
#include <stdio.h>
#include "nx_crypto_ecdh.h"
#include "nx_crypto_method_self_test.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif
#include "tls_test_utility.h"

extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
extern NX_CRYPTO_METHOD crypto_method_ecdh;
extern NX_CRYPTO_CONST NX_CRYPTO_EC _nx_crypto_ec_secp192r1;

static UCHAR shared_secret[128];

static NX_CRYPTO_ECDH ecdh;
static NX_CRYPTO_ECDH ecdh_a, ecdh_b;

static UCHAR pubkey_a[256];
static UCHAR pubkey_b[256];

static UCHAR shared_secret_a[128];
static UCHAR shared_secret_b[128];

static NX_CRYPTO_METHOD *ecs[5] = {
    &crypto_method_ec_secp192,
    &crypto_method_ec_secp224,
    &crypto_method_ec_secp256,
    &crypto_method_ec_secp384,
    &crypto_method_ec_secp521
};

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
    return _nx_crypto_method_ecdh_init(method, key, key_size_in_bits, handler, crypto_metadata, crypto_metadata_size);
}

static UINT test_nx_crypto_operation_failed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (!count)
        return 233;

    count--;
    return _nx_crypto_method_ecdh_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_operation_succeed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (!count)
        return 0;

    count--;
    return _nx_crypto_method_ecdh_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_operation_succeed_0(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (!count)
    {
        ((NX_CRYPTO_EXTENDED_OUTPUT *)output) -> nx_crypto_extended_output_actual_size = 0;
        return 0;
    }

    count--;
    return _nx_crypto_method_ecdh_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_cleanup_failed(VOID *crypto_metadata)
{
    return 233;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_ecdh_error_checking_test_application_define(void *first_unused_memory)
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
UINT pubk_len;
UINT shared_secret_len;
NX_CRYPTO_METHOD *curve_method, test_method;
UINT clen;
NX_CRYPTO_EXTENDED_OUTPUT extended_output;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   ECDH Error Checking Test...........................");

    /* NULL method pointer. */
    status = _nx_crypto_method_ecdh_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_ecdh_init(&crypto_method_ecdh, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_ecdh_init(&crypto_method_ecdh, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_ecdh_init(&crypto_method_ecdh, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, &ecdh, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_ecdh_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_ecdh_operation(0, NX_CRYPTO_NULL,
                                              NX_CRYPTO_NULL, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              NX_CRYPTO_NULL, 0, /* crypto_metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_ecdh_operation(0, NX_CRYPTO_NULL,
                                              &crypto_method_ecdh, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              NX_CRYPTO_NULL, 0, /* crypto_metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_ecdh_operation(0, NX_CRYPTO_NULL,
                                              &crypto_method_ecdh, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              (VOID *)0x03, 0, /* crypto_metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_ecdh_operation(0, NX_CRYPTO_NULL,
                                              &crypto_method_ecdh, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              &ecdh, 0, /* crypto_metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Invalid operation. */
    status = crypto_method_ec_secp521.nx_crypto_operation(0, NX_CRYPTO_NULL,
                                                          &crypto_method_ecdh, /* method */
                                                          NX_CRYPTO_NULL, 0, /* key */
                                                          NX_CRYPTO_NULL, 0, /* input */
                                                          NX_CRYPTO_NULL, /* iv */
                                                          NX_CRYPTO_NULL, 0, /* output */
                                                          &ecdh, 0, /* crypto_metadata */
                                                          NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Invalid operation. */
    status = crypto_method_ec_secp384.nx_crypto_operation(0, NX_CRYPTO_NULL,
                                                          &crypto_method_ecdh, /* method */
                                                          NX_CRYPTO_NULL, 0, /* key */
                                                          NX_CRYPTO_NULL, 0, /* input */
                                                          NX_CRYPTO_NULL, /* iv */
                                                          NX_CRYPTO_NULL, 0, /* output */
                                                          &ecdh, 0, /* crypto_metadata */
                                                          NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Invalid operation. */
    status = crypto_method_ec_secp256.nx_crypto_operation(0, NX_CRYPTO_NULL,
                                                          &crypto_method_ecdh, /* method */
                                                          NX_CRYPTO_NULL, 0, /* key */
                                                          NX_CRYPTO_NULL, 0, /* input */
                                                          NX_CRYPTO_NULL, /* iv */
                                                          NX_CRYPTO_NULL, 0, /* output */
                                                          &ecdh, 0, /* crypto_metadata */
                                                          NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Invalid operation. */
    status = crypto_method_ec_secp224.nx_crypto_operation(0, NX_CRYPTO_NULL,
                                                          &crypto_method_ecdh, /* method */
                                                          NX_CRYPTO_NULL, 0, /* key */
                                                          NX_CRYPTO_NULL, 0, /* input */
                                                          NX_CRYPTO_NULL, /* iv */
                                                          NX_CRYPTO_NULL, 0, /* output */
                                                          &ecdh, 0, /* crypto_metadata */
                                                          NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Invalid operation. */
    status = crypto_method_ec_secp192.nx_crypto_operation(0, NX_CRYPTO_NULL,
                                                          &crypto_method_ecdh, /* method */
                                                          NX_CRYPTO_NULL, 0, /* key */
                                                          NX_CRYPTO_NULL, 0, /* input */
                                                          NX_CRYPTO_NULL, /* iv */
                                                          NX_CRYPTO_NULL, 0, /* output */
                                                          &ecdh, 0, /* crypto_metadata */
                                                          NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Output buffer size is not enough. */
    status = _nx_crypto_ec_key_pair_stream_generate((NX_CRYPTO_EC *)&_nx_crypto_ec_secp192r1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SIZE_ERROR, status);

    /* NX_CRYPTO_EC_KEY_PAIR_GENERATE NULL curve pointer. */
    ecdh.nx_crypto_ecdh_curve = NX_CRYPTO_NULL;
    status = _nx_crypto_method_ecdh_operation(NX_CRYPTO_EC_KEY_PAIR_GENERATE, NX_CRYPTO_NULL,
                                              &crypto_method_ecdh, /* method */
                                              NX_CRYPTO_NULL, 0, /* key */
                                              NX_CRYPTO_NULL, 0, /* input */
                                              NX_CRYPTO_NULL, /* iv */
                                              NX_CRYPTO_NULL, 0, /* output */
                                              &ecdh, sizeof(ecdh), /* crypto_metadata */
                                              NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);


#ifndef NX_CRYPTO_ECC_DISABLE_KEY_VALIDATION

    /* Invalid public key tests. */
    for (i = 0; i < (sizeof(ecs) / sizeof(NX_CRYPTO_METHOD *)); i++)
    {

        memset(pubkey_a, 0, sizeof(pubkey_a));
        memset(pubkey_b, 0, sizeof(pubkey_b));
        memset(shared_secret_a, 0, sizeof(shared_secret_a));
        memset(shared_secret_b, 0, sizeof(shared_secret_b));
        memset(&ecdh_a, 0, sizeof(ecdh_a));
        memset(&ecdh_b, 0, sizeof(ecdh_b));

        curve_method = ecs[i % 5];

        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_EC_CURVE_SET, NX_CRYPTO_NULL,
                                                        &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                        (UCHAR *)curve_method, sizeof(NX_CRYPTO_METHOD *), NX_CRYPTO_NULL,
                                                        NX_CRYPTO_NULL, 0,
                                                        &ecdh_a, sizeof(ecdh_a),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_EC_CURVE_SET, NX_CRYPTO_NULL,
                                                        &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                        (UCHAR *)curve_method, sizeof(NX_CRYPTO_METHOD *), NX_CRYPTO_NULL,
                                                        NX_CRYPTO_NULL, 0,
                                                        &ecdh_b, sizeof(ecdh_b),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        extended_output.nx_crypto_extended_output_data = pubkey_a;
        extended_output.nx_crypto_extended_output_length_in_byte = sizeof(pubkey_a);
        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_DH_SETUP, NX_CRYPTO_NULL,
                                                        &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                        NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL,
                                                        (UCHAR *)&extended_output, sizeof(extended_output),
                                                        &ecdh_a, sizeof(ecdh_a),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);
        pubk_len = extended_output.nx_crypto_extended_output_actual_size;

        extended_output.nx_crypto_extended_output_data = pubkey_b;
        extended_output.nx_crypto_extended_output_length_in_byte = sizeof(pubkey_b);
        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_DH_SETUP, NX_CRYPTO_NULL,
                                                        &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                        NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL,
                                                        (UCHAR *)&extended_output, sizeof(extended_output),
                                                        &ecdh_b, sizeof(ecdh_b),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);
        EXPECT_EQ(pubk_len, extended_output.nx_crypto_extended_output_actual_size);

        extended_output.nx_crypto_extended_output_data = shared_secret_b;
        extended_output.nx_crypto_extended_output_length_in_byte = sizeof(shared_secret_b);

        /* Test of point not on the curve */
        pubkey_a[1]--;
        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_DH_CALCULATE, NX_CRYPTO_NULL,
                                                        &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                        pubkey_a, pubk_len, NX_CRYPTO_NULL,
                                                        (UCHAR *)&extended_output, sizeof(extended_output),
                                                        &ecdh_b, sizeof(ecdh_b),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_INVALID_KEY, status);

        /* Test of yQ out of range */
        NX_CRYPTO_MEMSET(&pubkey_a[1 + (pubk_len - 1) / 2], 0xFF, (pubk_len - 1) / 2);
        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_DH_CALCULATE, NX_CRYPTO_NULL,
                                                        &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                        pubkey_a, pubk_len, NX_CRYPTO_NULL,
                                                        (UCHAR *)&extended_output, sizeof(extended_output),
                                                        &ecdh_b, sizeof(ecdh_b),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_INVALID_KEY, status);

        /* Test of xQ out of range */
        NX_CRYPTO_MEMSET(&pubkey_a[1], 0xFF, (pubk_len - 1) / 2);
        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_DH_CALCULATE, NX_CRYPTO_NULL,
                                                        &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                        pubkey_a, pubk_len, NX_CRYPTO_NULL,
                                                        (UCHAR *)&extended_output, sizeof(extended_output),
                                                        &ecdh_b, sizeof(ecdh_b),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_INVALID_KEY, status);

        /* Test of point at infinity */
        NX_CRYPTO_MEMSET(&pubkey_a[1], 0, pubk_len - 1);
        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_DH_CALCULATE, NX_CRYPTO_NULL,
                                                        &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                        pubkey_a, pubk_len, NX_CRYPTO_NULL,
                                                        (UCHAR *)&extended_output, sizeof(extended_output),
                                                        &ecdh_b, sizeof(ecdh_b),
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_INVALID_KEY, status);

    }
#endif

#ifdef NX_CRYPTO_SELF_TEST
    /* Tests for _nx_crypto_method_self_test_ecdh. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_ecdh(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init and nx_crypto_operation are both NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_ecdh(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_ecdh(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_ecdh(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_EC_CURVE_SET failed. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    count = 1;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_DH_CALCULATE failed. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    count = 2;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(233, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* nx_crypto_cleanup failed. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_cleanup = test_nx_crypto_cleanup_failed;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(233, status);

    /* nx_crypto_init failed at the second time. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    count = 1;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_EC_CURVE_SET failed. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    count = 3;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_DH_KEY_PAIR_IMPORT failed. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    count = 4;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_DH_CALCULATE failed. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    count = 5;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(233, status);

    /* Output validation failed. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed;
    count = 5;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Output size is invalid. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_operation = test_nx_crypto_operation_succeed_0;
    count = 5;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* nx_crypto_init is NULL. */
    test_method = crypto_method_ecdh;
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_ecdh(&test_method, &ecdh, sizeof(ecdh));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
