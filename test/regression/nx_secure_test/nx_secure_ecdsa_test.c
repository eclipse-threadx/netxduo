
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "nx_crypto_ecdsa.h"
#include "nx_crypto_ec.h"
#include "tls_test_utility.h"
#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif

#define LOOP 100

#include "nx_secure_ecdsa_test_data.c"

extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
extern NX_CRYPTO_METHOD crypto_method_ecdsa;
extern NX_CRYPTO_CONST NX_CRYPTO_EC _nx_crypto_ec_secp256r1;
extern NX_CRYPTO_CONST NX_CRYPTO_EC _nx_crypto_ec_secp521r1;

static UCHAR scratch_buffer[4000];
static NX_CRYPTO_ECDSA ecdsa;

static UCHAR hash_data[80];
static UCHAR signature[256];

static UCHAR hash[32] = { 0 }; /* arbitrary */

static UCHAR testpubkey[65] = { /* arbitrary */
         0x04, 0xc5, 0xd7, 0xd0, 0x22, 0xbc, 0x2b, 0xa3, 0x7a, 0x58,
         0x17, 0xe7, 0x52, 0x0a, 0xf8, 0x7c, 0x66, 0xa4, 0xa0, 0xd0,
         0x25, 0x1b, 0x1c, 0xf7, 0x99, 0xd5, 0x6c, 0x06, 0xe0, 0x58,
         0x29, 0x6b, 0x04, 0x16, 0x19, 0x01, 0x94, 0xf6, 0x8c, 0x36,
         0xec, 0xe6, 0x2b, 0x07, 0x63, 0x76, 0xfb, 0xa3, 0x06, 0x4a,
         0x35, 0x60, 0x4d, 0x83, 0xa3, 0x67, 0xf8, 0x25, 0x53, 0x99,
         0xd0, 0x17, 0x11, 0x64, 0x85  
};

static UCHAR zerosignature[] = {
        0x30, 0x80, 0x44, /* 0x44 byte asn1 sequence */
        0x02, 0x20, /* r tag, size, r */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x02, 0x20, /* s tag, size, s */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
};

static UCHAR maxsignature[] = {
        0x30, 0x80, 0x46, /* 0x46 byte asn1 sequence */
        0x02, 0x21, /* r tag, size, r */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF,
        0x02, 0x21, /* s tag, size, s */
        0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF,
};

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_ecdsa_test_application_define(void *first_unused_memory)
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
NX_CRYPTO_METHOD     *curve_method;
VOID                 *handler = NX_CRYPTO_NULL;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   ECDSA Test.........................................");

    srand(time(0));

    curve = (NX_CRYPTO_EC *)&_nx_crypto_ec_secp256r1;

    /* Test the input validation of ECDSA verify. */
    status = _nx_crypto_ecdsa_verify(curve, hash, sizeof(hash), 
                                     testpubkey, sizeof(testpubkey),
                                     zerosignature, sizeof(zerosignature),
                                     (HN_UBASE*)scratch_buffer);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    status = _nx_crypto_ecdsa_verify(curve, hash, sizeof(hash), 
                                     testpubkey, sizeof(testpubkey),
                                     maxsignature, sizeof(maxsignature),
                                     (HN_UBASE*)scratch_buffer);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);


    for (i = 0; i < LOOP; i++)
    {
        if (i == 0)
        {

            /* Add a special test of hash data is zero. */
            memset(hash_data, 0, sizeof(hash_data));
        }
        else
        {
            for (j = 0; j < sizeof(hash_data); j++)
            {
                hash_data[j] = rand();
            }
        }

        curve = (NX_CRYPTO_EC *)&_nx_crypto_ec_secp521r1;
        buffer_size = curve->nx_crypto_ec_n.nx_crypto_huge_buffer_size;
        scratch = (HN_UBASE*)(&scratch_buffer[3 * buffer_size + 4]);
        privkey = scratch_buffer;
        pubkey = &scratch_buffer[buffer_size];
        NX_CRYPTO_EC_POINT_INITIALIZE(&public_key, NX_CRYPTO_EC_POINT_AFFINE, scratch, buffer_size);
        NX_CRYPTO_HUGE_NUMBER_INITIALIZE(&private_key, scratch, buffer_size + 8);

        /* Generate the key pair. */
        do
        {
            _nx_crypto_ec_key_pair_generation_extra(curve, &curve -> nx_crypto_ec_g, &private_key,
                                                    &public_key, scratch);
        } while (_nx_crypto_huge_number_is_zero(&private_key));

        status = _nx_crypto_huge_number_extract_fixed_size(&private_key, privkey, buffer_size);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        pubkey_length = 0;
        _nx_crypto_ec_point_extract_uncompressed(curve, &public_key, pubkey, 4 + 2 * buffer_size, &pubkey_length);
        EXPECT_TRUE(pubkey_length != 0);

        signature_length = sizeof(signature);

        /* Sign the hash data using ECDSA. */
        _nx_crypto_ecdsa_sign(curve, hash_data, sizeof(hash_data), privkey, buffer_size, signature, signature_length, &signature_length, scratch);

        /* Verify the signature. */
        EXPECT_EQ(NX_CRYPTO_SUCCESS, _nx_crypto_ecdsa_verify(curve, hash_data, sizeof(hash_data), pubkey, pubkey_length, signature, signature_length, scratch));
        
    }

    for (i = 0; i < sizeof(ecdsa_data) / sizeof(ECDSA_DATA); i++)
    {
        if (!strcmp(ecdsa_data[i].curve, "secp192r1"))
        {
            curve_method = &crypto_method_ec_secp192;
        }
        else if (!strcmp(ecdsa_data[i].curve, "secp224r1"))
        {
            curve_method = &crypto_method_ec_secp224;
        }
        else if (!strcmp(ecdsa_data[i].curve, "secp256r1"))
        {
            curve_method = &crypto_method_ec_secp256;
        }
        else if (!strcmp(ecdsa_data[i].curve, "secp384r1"))
        {
            curve_method = &crypto_method_ec_secp384;
        }
        else if (!strcmp(ecdsa_data[i].curve, "secp521r1"))
        {
            curve_method = &crypto_method_ec_secp521;
        }

        status = crypto_method_ecdsa.nx_crypto_init(&crypto_method_ecdsa,
                                                    ecdsa_data[i].public_key,
                                                    (NX_CRYPTO_KEY_SIZE)(ecdsa_data[i].public_key_len << 3),
                                                    &handler,
                                                    &ecdsa,
                                                    sizeof(ecdsa));
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecdsa.nx_crypto_operation(NX_CRYPTO_EC_CURVE_SET, handler,
                                                         &crypto_method_ecdsa, NX_CRYPTO_NULL, 0,
                                                         (UCHAR *)curve_method, sizeof(NX_CRYPTO_METHOD *), NX_CRYPTO_NULL,
                                                         NX_CRYPTO_NULL, 0,
                                                         &ecdsa,
                                                         sizeof(ecdsa),
                                                         NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecdsa.nx_crypto_operation(NX_CRYPTO_VERIFY, handler,
                                                         &crypto_method_ecdsa,
                                                         ecdsa_data[i].public_key,
                                                         (NX_CRYPTO_KEY_SIZE)(ecdsa_data[i].public_key_len << 3),
                                                         ecdsa_data[i].hash,
                                                         ecdsa_data[i].hash_len,
                                                         NX_CRYPTO_NULL,
                                                         ecdsa_data[i].signature,
                                                         ecdsa_data[i].signature_len,
                                                         &ecdsa,
                                                         sizeof(ecdsa),
                                                         NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
