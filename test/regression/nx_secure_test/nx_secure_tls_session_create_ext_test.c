/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

extern VOID    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
#define THREAD_STACK_SIZE           1024
#define METADATA_SIZE               16000

#define TEST_CASE_REMOVE_CRYPTO_PRF_HMAC_SHA2_256 0
#define TEST_CASE_REMOVE_ECC 1
#define TEST_CASE_KEEP_2_ECC 2
#define TEST_CASE_UNALIGNED_METADATA_SIZE 3
#define TEST_CASE_INVALID_CIPHER_ID 4

#define TEST_CIPHERSUITEMAP_SIZE 1

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static NX_SECURE_TLS_SESSION    tls_session_ptr;
static UCHAR                    tls_session_metadata[METADATA_SIZE];

extern const NX_CRYPTO_METHOD *supported_crypto[];
extern const UINT supported_crypto_size;
extern const NX_CRYPTO_CIPHERSUITE *ciphersuite_map[];
extern const UINT ciphersuite_map_size;

static NX_CRYPTO_METHOD **test_supported_crypto;
static UINT test_supported_crypto_size;

static const NX_CRYPTO_CIPHERSUITE nx_crypto_tls_ecdhe_ecdsa_with_aes_128_gcm_sha256_test_1 =
/* TLS ciphersuite entry. */
{   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, /* Ciphersuite ID. */
    NX_SECURE_APPLICATION_TLS,               /* Internal application label. */
    16,                                      /* Symmetric key size. */
    {   /* Cipher role array. */
        {0, 0},
        {0, 0},
        {0, 0},
        {0, 0},
        {0, 0},
        {0, 0},
        {0, 0},
        {0, 0}
    },
    /* TLS/DTLS Versions supported. */
    (NX_SECURE_TLS_BITFIELD_VERSIONS_PRE_1_3 | NX_SECURE_DTLS_BITFIELD_VERSIONS_PRE_1_3)
};

const NX_CRYPTO_CIPHERSUITE nx_crypto_tls_ecdhe_ecdsa_with_aes_128_gcm_sha256_test_2 =
/* TLS ciphersuite entry. */
{   TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, /* Ciphersuite ID. */
    NX_SECURE_APPLICATION_TLS,               /* Internal application label. */
    16,                                      /* Symmetric key size. */
    {   /* Cipher role array. */
        {NX_CRYPTO_KEY_EXCHANGE_ECDHE, NX_CRYPTO_KEY_EXCHANGE_ECDHE},
        {NX_CRYPTO_KEY_EXCHANGE_ECDHE, NX_CRYPTO_KEY_EXCHANGE_ECDHE},
        {NX_CRYPTO_KEY_EXCHANGE_ECDHE, NX_CRYPTO_KEY_EXCHANGE_ECDHE},
        {NX_CRYPTO_KEY_EXCHANGE_ECDHE, NX_CRYPTO_KEY_EXCHANGE_ECDHE},
        {NX_CRYPTO_KEY_EXCHANGE_ECDHE, NX_CRYPTO_KEY_EXCHANGE_ECDHE},
        {NX_CRYPTO_KEY_EXCHANGE_ECDHE, NX_CRYPTO_KEY_EXCHANGE_ECDHE},
        {NX_CRYPTO_KEY_EXCHANGE_ECDHE, NX_CRYPTO_KEY_EXCHANGE_ECDHE},
        {NX_CRYPTO_KEY_EXCHANGE_ECDHE, NX_CRYPTO_KEY_EXCHANGE_ECDHE}
    },
    /* TLS/DTLS Versions supported. */
    (NX_SECURE_TLS_BITFIELD_VERSIONS_PRE_1_3 | NX_SECURE_DTLS_BITFIELD_VERSIONS_PRE_1_3)
};

static const NX_CRYPTO_CIPHERSUITE nx_crypto_x509_ecdsa_sha_256_test_1 =
/* X.509 ciphersuite entry. */
{
    NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256,
    NX_SECURE_APPLICATION_X509,
    0,                                 /* Symmetric key size. */
    {
        {0, 0},
        {0, 0},
        {0, 0},
        {0, 0},
        {0, 0},
        {0, 0},
        {0, 0},
        {0, 0}
    },
    /* Versions supported. */
    NX_SECURE_X509_BITFIELD_VERSION_3
};

static const NX_CRYPTO_CIPHERSUITE nx_crypto_x509_ecdsa_sha_256_test_2 =
/* X.509 ciphersuite entry. */
{
    NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256,
    NX_SECURE_APPLICATION_X509,
    0,                                 /* Symmetric key size. */
    {
        {NX_CRYPTO_ROLE_SIGNATURE_CRYPTO, NX_CRYPTO_ROLE_SIGNATURE_CRYPTO},
        {NX_CRYPTO_ROLE_SIGNATURE_CRYPTO, NX_CRYPTO_ROLE_SIGNATURE_CRYPTO},
        {NX_CRYPTO_ROLE_SIGNATURE_CRYPTO, NX_CRYPTO_ROLE_SIGNATURE_CRYPTO},
        {NX_CRYPTO_ROLE_SIGNATURE_CRYPTO, NX_CRYPTO_ROLE_SIGNATURE_CRYPTO},
        {NX_CRYPTO_ROLE_SIGNATURE_CRYPTO, NX_CRYPTO_ROLE_SIGNATURE_CRYPTO},
        {NX_CRYPTO_ROLE_SIGNATURE_CRYPTO, NX_CRYPTO_ROLE_SIGNATURE_CRYPTO},
        {NX_CRYPTO_ROLE_SIGNATURE_CRYPTO, NX_CRYPTO_ROLE_SIGNATURE_CRYPTO},
        {NX_CRYPTO_ROLE_SIGNATURE_CRYPTO, NX_CRYPTO_ROLE_SIGNATURE_CRYPTO}
    },
    /* Versions supported. */
    NX_SECURE_X509_BITFIELD_VERSION_3
};

static const NX_CRYPTO_CIPHERSUITE nx_crypto_x509_rsa_sha_256_test_3 =
/* X.509 ciphersuite entry. */
{
    NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,
    NX_SECURE_APPLICATION_X509,
    0,                                 /* Symmetric key size. */
    {
        {NX_CRYPTO_KEY_EXCHANGE_RSA,         NX_CRYPTO_ROLE_SYMMETRIC},
        {NX_CRYPTO_HASH_SHA256,              NX_CRYPTO_ROLE_SYMMETRIC},
        {NX_CRYPTO_NONE,                     NX_CRYPTO_ROLE_SYMMETRIC},
        {NX_CRYPTO_KEY_EXCHANGE_RSA,         NX_CRYPTO_ROLE_SYMMETRIC},
        {NX_CRYPTO_HASH_SHA256,              NX_CRYPTO_ROLE_SYMMETRIC},
        {NX_CRYPTO_NONE,                     NX_CRYPTO_ROLE_SYMMETRIC},
        {NX_CRYPTO_KEY_EXCHANGE_RSA,         NX_CRYPTO_ROLE_SYMMETRIC},
        {NX_CRYPTO_HASH_SHA256,              NX_CRYPTO_ROLE_SYMMETRIC}
    },
    /* Versions supported. */
    NX_SECURE_X509_BITFIELD_VERSION_3
};

static const NX_CRYPTO_CIPHERSUITE *test_invalid_tls_ciphersuite_map_1[] = 
{
    &nx_crypto_tls_ecdhe_ecdsa_with_aes_128_gcm_sha256_test_1
};

static const NX_CRYPTO_CIPHERSUITE *test_invalid_tls_ciphersuite_map_2[] = 
{
    &nx_crypto_tls_ecdhe_ecdsa_with_aes_128_gcm_sha256_test_2
};

static const NX_CRYPTO_CIPHERSUITE *test_invalid_x509_ciphersuite_map_1[] = 
{
    &nx_crypto_x509_ecdsa_sha_256_test_1
};

static const NX_CRYPTO_CIPHERSUITE *test_invalid_x509_ciphersuite_map_2[] = 
{
    &nx_crypto_x509_ecdsa_sha_256_test_2
};

static const NX_CRYPTO_CIPHERSUITE *test_invalid_x509_ciphersuite_map_3[] = 
{
    &nx_crypto_x509_rsa_sha_256_test_3
};

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_session_create_ext_test_application_define(void *first_unused_memory)
#endif
{
    /* Create the client thread.  */
    tx_thread_create(&thread_0, "thread 0", ntest_0_entry, 0,
                     thread_0_stack, sizeof(thread_0_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);
}

static void make_test_crypto_table(int test_case)
{
    int ecc_count = 0;
    NX_CRYPTO_METHOD *crypto_method;
    test_supported_crypto_size = 0;
    test_supported_crypto = (NX_CRYPTO_METHOD **)malloc(sizeof(NX_CRYPTO_METHOD *) * supported_crypto_size);

    for(int index = 0; index < supported_crypto_size; index++)
    {
        if(test_case == TEST_CASE_REMOVE_CRYPTO_PRF_HMAC_SHA2_256 &&
           supported_crypto[index]->nx_crypto_algorithm == NX_CRYPTO_PRF_HMAC_SHA2_256)
        {
            continue;
        }

        if((supported_crypto[index] -> nx_crypto_algorithm & 0xFFFF0000) == NX_CRYPTO_EC_MASK)
        {
            ecc_count++;
        }

        if(test_case == TEST_CASE_REMOVE_ECC)
        {
            continue;
        }

        if((test_case == TEST_CASE_KEEP_2_ECC) && (ecc_count > 2))
        {
            continue;
        }

        crypto_method = (NX_CRYPTO_METHOD *)malloc(sizeof(NX_CRYPTO_METHOD));
        test_supported_crypto[test_supported_crypto_size++] = crypto_method;

        memcpy(crypto_method, supported_crypto[index], sizeof(NX_CRYPTO_METHOD));

        switch(test_case)
        {
            case TEST_CASE_UNALIGNED_METADATA_SIZE:
                if(!(crypto_method->nx_crypto_metadata_area_size & 0x3))
                {
                    crypto_method->nx_crypto_metadata_area_size ++;
                }
                break;

            case TEST_CASE_INVALID_CIPHER_ID:
                crypto_method->nx_crypto_algorithm = 0;
                break;
        }
        
    }
}

static void cleanup_test_crypto_table()
{
    if(test_supported_crypto)
    {
        for(int index = 0; index < test_supported_crypto_size; index++)
        {
            free(test_supported_crypto[index]);
        }
        free(test_supported_crypto);
        test_supported_crypto = NX_NULL;
    }
    test_supported_crypto_size = 0;
}

static int calculate_tls_ciphersuite_info_size()
{
    INT size = 0;

    /* Loop through cipher map, check each ciphersuite. */
    for(int index = 0; index < ciphersuite_map_size; index++)
    {
        if(ciphersuite_map[index]->nx_crypto_internal_id == NX_SECURE_APPLICATION_TLS)
        {
            size += sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO);
        }
    }

    return size;
}

static int calculate_x509_ciphersuite_info_size()
{
    INT size = 0;

    /* Loop through cipher map, check each ciphersuite. */
    for(int index = 0; index < ciphersuite_map_size; index++)
    {
        if(ciphersuite_map[index]->nx_crypto_internal_id == NX_SECURE_APPLICATION_X509)
        {
            size += sizeof(NX_SECURE_X509_CRYPTO);
        }
    }

    return size;
}

static int calculate_ecc_curves_size()
{
    INT size = 0;

    /* Find ECC curves in the crypto array. */
    for (int index = 0; index < supported_crypto_size; index++)
    {
        if ((supported_crypto[index] -> nx_crypto_algorithm & 0xFFFF0000) == NX_CRYPTO_EC_MASK)
        {
            size  += sizeof(NX_CRYPTO_METHOD *);
        }
    }

    return size;
}

static void ntest_0_entry(ULONG thread_input)
{
UINT   status;
UCHAR *metadata_buffer;
INT    metadata_size;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Session Create Ext Test....................");

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           0, 0,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    make_test_crypto_table(TEST_CASE_REMOVE_CRYPTO_PRF_HMAC_SHA2_256);
    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           (const NX_CRYPTO_METHOD **)test_supported_crypto, test_supported_crypto_size,
                                           ciphersuite_map, 0,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);
    cleanup_test_crypto_table();

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    metadata_buffer = tls_session_metadata;
    metadata_size = sizeof(tls_session_metadata);
    if(!(((ULONG)tls_session_metadata) & 0x3))
    {
        metadata_buffer++;
        metadata_size--;
    }

    /* Test metadata buffer alignment check. */
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           metadata_buffer,
                                           metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    metadata_size = 0;

    /* Test insufficient metadata buffer size. */
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           metadata_buffer,
                                           metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_INSUFFICIENT_METADATA_SPACE, status);

    metadata_buffer = tls_session_metadata;
    metadata_size = 1;
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           metadata_buffer,
                                           metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_INSUFFICIENT_METADATA_SPACE, status);

    metadata_size = sizeof(NX_SECURE_TLS_CRYPTO) + 1;
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           metadata_buffer,
                                           metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_INSUFFICIENT_METADATA_SPACE, status);

    metadata_size = sizeof(NX_SECURE_TLS_CRYPTO) + calculate_tls_ciphersuite_info_size() + 1;
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           metadata_buffer,
                                           metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_INSUFFICIENT_METADATA_SPACE, status);

#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    metadata_size = sizeof(NX_SECURE_TLS_CRYPTO) + calculate_tls_ciphersuite_info_size() + calculate_x509_ciphersuite_info_size() + 1;
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           metadata_buffer,
                                           metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_INSUFFICIENT_METADATA_SPACE, status);

    metadata_size = sizeof(NX_SECURE_TLS_CRYPTO) + calculate_tls_ciphersuite_info_size() + calculate_x509_ciphersuite_info_size() + calculate_ecc_curves_size() + 1;
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           supported_crypto, supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           metadata_buffer,
                                           metadata_size);
    EXPECT_EQ(NX_SECURE_TLS_INSUFFICIENT_METADATA_SPACE, status);
#endif

    make_test_crypto_table(TEST_CASE_REMOVE_ECC);
    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           (const NX_CRYPTO_METHOD **)test_supported_crypto, test_supported_crypto_size,
                                           ciphersuite_map, 0,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);
    cleanup_test_crypto_table();

    make_test_crypto_table(TEST_CASE_KEEP_2_ECC);
    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           (const NX_CRYPTO_METHOD **)test_supported_crypto, test_supported_crypto_size,
                                           ciphersuite_map, 0,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);
    cleanup_test_crypto_table();

    make_test_crypto_table(TEST_CASE_UNALIGNED_METADATA_SIZE);
    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           (const NX_CRYPTO_METHOD **)test_supported_crypto, test_supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);
    cleanup_test_crypto_table();

    make_test_crypto_table(TEST_CASE_INVALID_CIPHER_ID);
    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           (const NX_CRYPTO_METHOD **)test_supported_crypto, test_supported_crypto_size,
                                           ciphersuite_map, ciphersuite_map_size,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);
    cleanup_test_crypto_table();

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           (const NX_CRYPTO_METHOD **)supported_crypto, supported_crypto_size,
                                           test_invalid_tls_ciphersuite_map_1, 1,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           (const NX_CRYPTO_METHOD **)supported_crypto, supported_crypto_size,
                                           test_invalid_tls_ciphersuite_map_2, 1,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           (const NX_CRYPTO_METHOD **)supported_crypto, supported_crypto_size,
                                           test_invalid_x509_ciphersuite_map_1, 1,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           (const NX_CRYPTO_METHOD **)supported_crypto, supported_crypto_size,
                                           test_invalid_x509_ciphersuite_map_2, 1,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status = _nx_secure_tls_session_create_ext(&tls_session_ptr,
                                           (const NX_CRYPTO_METHOD **)supported_crypto, supported_crypto_size,
                                           test_invalid_x509_ciphersuite_map_3, 1,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    status = nx_secure_tls_session_delete(&tls_session_ptr);
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_session_create_ext_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Session Create Ext Test....................N/A\n");
    test_control_return(3);
}
#endif
