
#include <stdio.h>
#include <time.h>
#include "nx_crypto_ecdh.h"

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
extern NX_CRYPTO_METHOD crypto_method_ec_x25519;
extern NX_CRYPTO_METHOD crypto_method_ec_x448;
extern NX_CRYPTO_METHOD crypto_method_ecdh;


static UCHAR pubkey_a[256];
static UCHAR pubkey_b[256];

static UCHAR shared_secret_a[128];
static UCHAR shared_secret_b[128];

static NX_CRYPTO_ECDH ecdh_a, ecdh_b;

static NX_CRYPTO_METHOD *ecs[] = {
    &crypto_method_ec_secp192,
    &crypto_method_ec_secp224,
    &crypto_method_ec_secp256,
    &crypto_method_ec_secp384,
    &crypto_method_ec_secp521,
#ifdef NX_CRYPTO_ENABLE_CURVE25519_448
    &crypto_method_ec_x25519,
    &crypto_method_ec_x448,
#endif /* NX_CRYPTO_ENABLE_CURVE25519_448 */
};


#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_ecdh_self_test_application_define(void *first_unused_memory)
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
UINT pubk_len;
UINT shared_secret_len;
NX_CRYPTO_METHOD *curve_method;
UINT clen;
UINT status;
NX_CRYPTO_EXTENDED_OUTPUT extended_output;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   ECDH Self Test.....................................");

    srand(time(0));

    for (i = 0; i < LOOP; i++)
    {

        memset(pubkey_a, 0, sizeof(pubkey_a));
        memset(pubkey_b, 0, sizeof(pubkey_b));
        memset(shared_secret_a, 0, sizeof(shared_secret_a));
        memset(shared_secret_b, 0, sizeof(shared_secret_b));
        memset(&ecdh_a, 0, sizeof(ecdh_a));
        memset(&ecdh_b, 0, sizeof(ecdh_b));

        curve_method = ecs[i % (sizeof(ecs) / sizeof(NX_CRYPTO_METHOD *))];

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
        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_DH_CALCULATE, NX_CRYPTO_NULL,
                                                           &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                           pubkey_a, pubk_len, NX_CRYPTO_NULL,
                                                           (UCHAR *)&extended_output, sizeof(extended_output),
                                                           &ecdh_b, sizeof(ecdh_b),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);
        shared_secret_len = extended_output.nx_crypto_extended_output_actual_size;

        extended_output.nx_crypto_extended_output_data = shared_secret_a;
        extended_output.nx_crypto_extended_output_length_in_byte = sizeof(shared_secret_a);
        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_DH_CALCULATE, NX_CRYPTO_NULL,
                                                           &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                           pubkey_b, pubk_len, NX_CRYPTO_NULL,
                                                           (UCHAR *)&extended_output, sizeof(extended_output),
                                                           &ecdh_a, sizeof(ecdh_a),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        EXPECT_EQ(shared_secret_len, extended_output.nx_crypto_extended_output_actual_size);
        EXPECT_EQ(0, memcmp(shared_secret_a, shared_secret_b, shared_secret_len));

    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
