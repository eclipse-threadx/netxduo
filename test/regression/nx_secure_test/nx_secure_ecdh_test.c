
#include <stdio.h>
#include "nx_crypto_ecdh.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif
#include "tls_test_utility.h"

#define LOOP 100

#include "nx_secure_ecdh_test_data.c"

extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
extern NX_CRYPTO_METHOD crypto_method_ec_x25519;
extern NX_CRYPTO_METHOD crypto_method_ec_x448;
extern NX_CRYPTO_METHOD crypto_method_ecdh;
extern NX_CRYPTO_CONST NX_CRYPTO_EC _nx_crypto_ec_secp192r1;

static UCHAR shared_secret[128];

static NX_CRYPTO_ECDH ecdh;

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_ecdh_test_application_define(void *first_unused_memory)
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
NX_CRYPTO_METHOD *curve_method;
UINT clen;
NX_CRYPTO_EXTENDED_OUTPUT extended_output;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   ECDH Test..........................................");


    for (i = 0; i < sizeof(ecdh_data) / sizeof(ECDH_DATA); i++)
    {
        memset(shared_secret, 0, sizeof(shared_secret));

        if (!strcmp(ecdh_data[i].curve, "secp192r1"))
        {
            curve_method = &crypto_method_ec_secp192;
        }
        else if (!strcmp(ecdh_data[i].curve, "secp224r1"))
        {
            curve_method = &crypto_method_ec_secp224;
        }
        else if (!strcmp(ecdh_data[i].curve, "secp256r1"))
        {
            curve_method = &crypto_method_ec_secp256;
        }
        else if (!strcmp(ecdh_data[i].curve, "secp384r1"))
        {
            curve_method = &crypto_method_ec_secp384;
        }
        else if (!strcmp(ecdh_data[i].curve, "secp521r1"))
        {
            curve_method = &crypto_method_ec_secp521;
        }
        #ifdef NX_CRYPTO_ENABLE_CURVE25519_448
        else if (!strcmp(ecdh_data[i].curve, "x25519"))
        {
            curve_method = &crypto_method_ec_x25519;
        }
        else if (!strcmp(ecdh_data[i].curve, "x448"))
        {
            curve_method = &crypto_method_ec_x448;
        }
        #endif /* NX_CRYPTO_ENABLE_CURVE25519_448 */

        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_EC_CURVE_SET, NX_CRYPTO_NULL,
                                                           &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                           (UCHAR *)curve_method, sizeof(NX_CRYPTO_METHOD *), NX_CRYPTO_NULL,
                                                           NX_CRYPTO_NULL, 0,
                                                           &ecdh, sizeof(ecdh),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_DH_KEY_PAIR_IMPORT, NX_CRYPTO_NULL,
                                                           &crypto_method_ecdh,
                                                           ecdh_data[i].local_private_key,
                                                           ecdh_data[i].local_private_key_len << 3,
                                                           ecdh_data[i].local_public_key,
                                                           ecdh_data[i].local_public_key_len,
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0,
                                                           &ecdh, sizeof(ecdh),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        extended_output.nx_crypto_extended_output_data = shared_secret;
        extended_output.nx_crypto_extended_output_length_in_byte = sizeof(shared_secret);
        status = crypto_method_ecdh.nx_crypto_operation(NX_CRYPTO_DH_CALCULATE, NX_CRYPTO_NULL,
                                                           &crypto_method_ecdh, NX_CRYPTO_NULL, 0,
                                                           ecdh_data[i].remote_public_key,
                                                           ecdh_data[i].remote_public_key_len,
                                                           NX_CRYPTO_NULL,
                                                           (UCHAR *)&extended_output, sizeof(extended_output),
                                                           &ecdh, sizeof(ecdh),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        EXPECT_EQ(ecdh_data[i].shared_secret_len, extended_output.nx_crypto_extended_output_actual_size);
        EXPECT_EQ(0, memcmp(shared_secret, ecdh_data[i].shared_secret,
                            ecdh_data[i].shared_secret_len));
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
