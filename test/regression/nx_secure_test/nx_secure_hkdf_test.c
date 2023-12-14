
#include <stdio.h>
#include "nx_crypto_sha1.h"
#include "nx_crypto_sha2.h"
#include "nx_crypto_hmac.h"
#include "nx_crypto_hkdf.h"

#include "tls_test_utility.h"

#include "nx_secure_hkdf_test_data.c"

/* Crypto methods for HKDF, SHA-1 and SHA-256. */
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_hmac;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_sha256;

/* HKDF context. */
static UCHAR hkdf_metadata[sizeof(NX_CRYPTO_HKDF) + sizeof(NX_CRYPTO_HMAC)];

/* Output - must be large enough to hold the largest desired HKDF expand data. */
static UINT output[256];

static TX_THREAD thread_0;

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_hkdf_test_application_define(void *first_unused_memory)
#endif
{
    tx_thread_create(&thread_0, "Thread 0", thread_0_entry, 0,
                     first_unused_memory, 4096,
                     16, 16, 4, TX_AUTO_START);
}

static VOID thread_0_entry(ULONG thread_input)
{
UINT i;
NX_CRYPTO_METHOD *method_hkdf;
NX_CRYPTO_METHOD *method_hash;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   HKDF Test..........................................");

    method_hkdf = &crypto_method_hkdf;

    for (i = 0; i < sizeof(hkdf_test_data) / sizeof(HKDF_DATA); i++)
    {

        /* First, extract the HKDF key using the IKM and salt. */
        memset(output, 0xFF, sizeof(output));

        /* Get the right hash method version. */
        switch(hkdf_test_data[i].hash_routine_id)
        {
        case NX_CRYPTO_HASH_SHA256:
            method_hash = &crypto_method_sha256;
            break;
        case NX_CRYPTO_HASH_SHA1:
            method_hash = &crypto_method_sha1;
            break;
        default:
            printf("Error: missing HKDF hash routine.\n");
            test_control_return(1);
        }

        /* Initialize the IKM. */
        method_hkdf->nx_crypto_init(method_hkdf, (UCHAR*)(hkdf_test_data[i].ikm), hkdf_test_data[i].ikm_len << 3,
                                    NX_NULL, hkdf_metadata, sizeof(hkdf_metadata));

        method_hkdf->nx_crypto_operation(NX_CRYPTO_HKDF_SET_HMAC, NX_NULL, &crypto_method_hmac,
                					     NX_NULL, 0,NX_NULL, 0, NX_NULL, NX_NULL, 0, &hkdf_metadata,
										 sizeof(hkdf_metadata),
									     NX_NULL, NX_NULL);

        method_hkdf->nx_crypto_operation(NX_CRYPTO_HKDF_SET_HASH, NX_NULL, method_hash,
                        					     NX_NULL, 0,NX_NULL, 0, NX_NULL, NX_NULL, 0, &hkdf_metadata,
        										 sizeof(hkdf_metadata),
        									     NX_NULL, NX_NULL);

        /* Now perform the expand operation using the IKM we just initialized and the "salt" data. */
        method_hkdf->nx_crypto_operation(NX_CRYPTO_HKDF_EXTRACT,
                                                NX_NULL,
                                                &crypto_method_hkdf,
                                                (UCHAR*)(hkdf_test_data[i].salt),
                                                hkdf_test_data[i].salt_len << 3,
                                                (UCHAR*)(hkdf_test_data[i].ikm),
                                                hkdf_test_data[i].ikm_len,
												NX_NULL,
                                                (UCHAR *)output,
                                                sizeof(output),
                                                &hkdf_metadata,
                                                sizeof(hkdf_metadata),
                                                NX_NULL, NX_NULL);

        /* Initialize the IKM. */
        method_hkdf->nx_crypto_init(method_hkdf, (UCHAR*)(hkdf_test_data[i].ikm), hkdf_test_data[i].ikm_len << 3,
                                    NX_NULL, hkdf_metadata, sizeof(hkdf_metadata));

        method_hkdf->nx_crypto_operation(NX_CRYPTO_HKDF_SET_HMAC, NX_NULL, &crypto_method_hmac,
                					     NX_NULL, 0,NX_NULL, 0, NX_NULL, NX_NULL, 0, &hkdf_metadata,
										 sizeof(hkdf_metadata),
									     NX_NULL, NX_NULL);

        method_hkdf->nx_crypto_operation(NX_CRYPTO_HKDF_SET_HASH, NX_NULL, method_hash,
                        					     NX_NULL, 0,NX_NULL, 0, NX_NULL, NX_NULL, 0, &hkdf_metadata,
        										 sizeof(hkdf_metadata),
        									     NX_NULL, NX_NULL);

        /* Compare to the expected output. */
        EXPECT_EQ(0, memcmp(output, hkdf_test_data[i].prk, hkdf_test_data[i].prk_length));

        /* Now perform the key expansion using the PRK we just generated which is stored in the HKDF context. */
        method_hkdf->nx_crypto_operation(NX_CRYPTO_HKDF_EXPAND,
                                                NX_NULL,
                                                &crypto_method_hkdf,
                                                (UCHAR*)(hkdf_test_data[i].info),
                                                hkdf_test_data[i].info_len << 3,
                                                NX_NULL,
                                                0,
                                                NX_NULL,
                                                (UCHAR *)output,
                                                hkdf_test_data[i].desired_length,
                                                &hkdf_metadata,
                                                sizeof(hkdf_metadata),
                                                NX_NULL, NX_NULL);

        /* Compare to the expected output. */
        EXPECT_EQ(0, memcmp(output, hkdf_test_data[i].okm, hkdf_test_data[i].okm_len));
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
