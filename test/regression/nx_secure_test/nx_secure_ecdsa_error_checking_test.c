
#include <stdio.h>
#include "nx_crypto_ecdsa.h"
#include "nx_crypto_ec.h"
#include "nx_crypto_method_self_test.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif
#include "tls_test_utility.h"

#define LOOP 100

extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
extern NX_CRYPTO_METHOD crypto_method_ecdsa;
extern NX_CRYPTO_CONST NX_CRYPTO_EC _nx_crypto_ec_secp521r1;

static UCHAR scratch_buffer[4000];
static NX_CRYPTO_ECDSA ecdsa;

static UCHAR hash_data[80];
static UCHAR signature[256];

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
    return _nx_crypto_method_ecdsa_operation(op, handler, method, key, key_size_in_bits, input, input_length_in_byte, iv_ptr, output, output_length_in_byte, crypto_metadata, crypto_metadata_size, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
}

static UINT test_nx_crypto_operation_succeed(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method, UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits, UCHAR *input, ULONG input_length_in_byte, UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte, VOID *crypto_metadata, ULONG crypto_metadata_size, VOID *packet_ptr, VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return 0;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_ecdsa_error_checking_test_application_define(void *first_unused_memory)
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
UINT i, j, status, backup;
NX_CRYPTO_HUGE_NUMBER private_key;
NX_CRYPTO_EC_POINT    public_key;
UCHAR                *privkey;
UCHAR                *pubkey;
UINT                  pubkey_length;
NX_CRYPTO_EC         *curve;
UINT                  buffer_size;
ULONG                 signature_length;
HN_UBASE             *scratch;
NX_CRYPTO_METHOD     *curve_method, test_method;
VOID                 *handler = NX_CRYPTO_NULL;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   ECDSA Error Checking Test..........................");

    /* NULL method pointer. */
    status = _nx_crypto_method_ecdsa_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_ecdsa_init(&crypto_method_ec_secp521, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_ecdsa_init(&crypto_method_ec_secp521, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_ecdsa_init(&crypto_method_ec_secp521, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_ecdsa_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_ecdsa_operation(0, NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL, /* method */
                                               NX_CRYPTO_NULL, 0, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               NX_CRYPTO_NULL, /* iv */
                                               NX_CRYPTO_NULL, 0, /* output */
                                               NX_CRYPTO_NULL, 0, /* crypto_metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_ecdsa_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_ecdsa, /* method */
                                               NX_CRYPTO_NULL, 0, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               NX_CRYPTO_NULL, /* iv */
                                               NX_CRYPTO_NULL, 0, /* output */
                                               NX_CRYPTO_NULL, 0, /* crypto_metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_ecdsa_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_ecdsa, /* method */
                                               NX_CRYPTO_NULL, 0, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               NX_CRYPTO_NULL, /* iv */
                                               NX_CRYPTO_NULL, 0, /* output */
                                               (VOID *)0x03, 0, /* crypto_metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_ecdsa_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_ecdsa, /* method */
                                               NX_CRYPTO_NULL, 0, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               NX_CRYPTO_NULL, /* iv */
                                               NX_CRYPTO_NULL, 0, /* output */
                                               (VOID *)0x04, 0, /* crypto_metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* op == NX_CRYPTO_EC_CURVE_SET && input -> nx_crypto_operation failed. */
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_ecdsa_operation(NX_CRYPTO_EC_CURVE_SET, NX_CRYPTO_NULL,
                                               &crypto_method_ecdsa, /* method */
                                               NX_CRYPTO_NULL, 0, /* key */
                                               (UCHAR *)&test_method, 0, /* input */
                                               NX_CRYPTO_NULL, /* iv */
                                               NX_CRYPTO_NULL, 0, /* output */
                                               &ecdsa, sizeof(ecdsa), /* crypto_metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(233, status);

    /* op == NX_CRYPTO_AUTHENTICATE && key == NULL. */
    status = _nx_crypto_method_ecdsa_operation(NX_CRYPTO_AUTHENTICATE, NX_CRYPTO_NULL,
                                               &crypto_method_ecdsa, /* method */
                                               NX_CRYPTO_NULL, 0, /* key */
                                               (UCHAR *)&test_method, 0, /* input */
                                               NX_CRYPTO_NULL, /* iv */
                                               NX_CRYPTO_NULL, 0, /* output */
                                               &ecdsa, sizeof(ecdsa), /* crypto_metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* op == NX_CRYPTO_VERIFY && key == NULL. */
    status = _nx_crypto_method_ecdsa_operation(NX_CRYPTO_VERIFY, NX_CRYPTO_NULL,
                                               &crypto_method_ecdsa, /* method */
                                               NX_CRYPTO_NULL, 0, /* key */
                                               (UCHAR *)&test_method, 0, /* input */
                                               NX_CRYPTO_NULL, /* iv */
                                               NX_CRYPTO_NULL, 0, /* output */
                                               &ecdsa, sizeof(ecdsa), /* crypto_metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* op == NX_CRYPTO_EC_KEY_PAIR_GENERATE && ecdsa -> nx_crypto_ecdsa_curve == NX_CRYPTO_NULL. */
    ecdsa.nx_crypto_ecdsa_curve = NX_CRYPTO_NULL;
    status = _nx_crypto_method_ecdsa_operation(NX_CRYPTO_EC_KEY_PAIR_GENERATE, NX_CRYPTO_NULL,
                                               &crypto_method_ecdsa, /* method */
                                               NX_CRYPTO_NULL, 0, /* key */
                                               (UCHAR *)&test_method, 0, /* input */
                                               NX_CRYPTO_NULL, /* iv */
                                               NX_CRYPTO_NULL, 0, /* output */
                                               &ecdsa, sizeof(ecdsa), /* crypto_metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Invalid op. */
    status = _nx_crypto_method_ecdsa_operation(0, NX_CRYPTO_NULL,
                                               &crypto_method_ecdsa, /* method */
                                               NX_CRYPTO_NULL, 0, /* key */
                                               (UCHAR *)&test_method, 0, /* input */
                                               NX_CRYPTO_NULL, /* iv */
                                               NX_CRYPTO_NULL, 0, /* output */
                                               &ecdsa, sizeof(ecdsa), /* crypto_metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* signature_length < curve_size. */
    status = _nx_crypto_ecdsa_sign((NX_CRYPTO_EC *)&_nx_crypto_ec_secp521r1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SIZE_ERROR, status);

    /* private_key_length < buffer_size. */
    status = _nx_crypto_ecdsa_sign((NX_CRYPTO_EC *)&_nx_crypto_ec_secp521r1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (UINT)-1, NX_CRYPTO_NULL, (UINT)-1, NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SIZE_ERROR, status);

    /* public_key_length > 1 + buffer_size << 1. */
    status = _nx_crypto_ecdsa_verify((NX_CRYPTO_EC *)&_nx_crypto_ec_secp521r1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, (UINT)-1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SIZE_ERROR, status);

    /* signature[0] != 0x30. */
    signature[0] = 0;
    status = _nx_crypto_ecdsa_verify((NX_CRYPTO_EC *)&_nx_crypto_ec_secp521r1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, signature, 0, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_AUTHENTICATION_FAILED, status);

    /* signature[1] == 0x80 && signature_length < signature[2] + 3. */
    signature[0] = 0x30;
    signature[1] = 0x80;
    signature[2] = 0;
    status = _nx_crypto_ecdsa_verify((NX_CRYPTO_EC *)&_nx_crypto_ec_secp521r1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, signature, 0, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SIZE_ERROR, status);

    /* signature[1] != 0x80 && signature_length < signature[1] + 2. */
    signature[0] = 0x30;
    signature[1] = 0;
    status = _nx_crypto_ecdsa_verify((NX_CRYPTO_EC *)&_nx_crypto_ec_secp521r1, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, 0, signature, 0, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SIZE_ERROR, status);

/* For NX_CRYPTO_STATE_CHECK. */
#ifdef NX_CRYPTO_SELF_TEST
    backup = _nx_crypto_library_state;
    _nx_crypto_library_state = 0;

    status = _nx_crypto_method_ecdsa_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_ecdsa_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    status = _nx_crypto_method_ecdsa_operation(0, NX_CRYPTO_NULL,
                                               NX_CRYPTO_NULL, /* method */
                                               NX_CRYPTO_NULL, 0, /* key */
                                               NX_CRYPTO_NULL, 0, /* input */
                                               NX_CRYPTO_NULL, /* iv */
                                               NX_CRYPTO_NULL, 0, /* output */
                                               NX_CRYPTO_NULL, 0, /* crypto_metadata */
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_INVALID_LIBRARY, status);

    _nx_crypto_library_state = backup;

    /* Tests for _nx_crypto_method_self_test_ecdsa. */

    /* NULL method pointer. */
    status = _nx_crypto_method_self_test_ecdsa(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init and nx_crypto_operation are both NULL. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    test_method.nx_crypto_operation = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_ecdsa(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* nx_crypto_init failed. */
    test_method.nx_crypto_init = test_nx_crypto_init_failed;
    status = _nx_crypto_method_self_test_ecdsa(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_AUTHENTICATE failed. */
    test_method = crypto_method_ecdsa;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    status = _nx_crypto_method_self_test_ecdsa(&test_method, &ecdsa, sizeof(ecdsa));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_EC_CURVE_GET failed. */
    test_method = crypto_method_ecdsa;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    count = 1;
    status = _nx_crypto_method_self_test_ecdsa(&test_method, &ecdsa, sizeof(ecdsa));
    EXPECT_EQ(233, status);

    /* nx_crypto_operation NX_CRYPTO_VERIFY failed. */
    test_method = crypto_method_ecdsa;
    test_method.nx_crypto_operation = test_nx_crypto_operation_failed;
    count = 2;
    status = _nx_crypto_method_self_test_ecdsa(&test_method, &ecdsa, sizeof(ecdsa));
    EXPECT_EQ(233, status);

    /* nx_crypto_cleanup is NULL. */
    test_method = crypto_method_ecdsa;
    test_method.nx_crypto_cleanup = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_ecdsa(&test_method, &ecdsa, sizeof(ecdsa));
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* curve_method -> nx_crypto_operation failed. */
    test_method.nx_crypto_init = NX_CRYPTO_NULL;
    status = _nx_crypto_method_self_test_ecdsa(&test_method, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

#endif /* NX_CRYPTO_SELF_TEST */

    printf("SUCCESS!\n");
    test_control_return(0);
}
