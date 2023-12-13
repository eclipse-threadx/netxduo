#include <stdio.h>
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

#if defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && !defined(NX_SECURE_DISABLE_X509)

/* Test basic X509 parsing with an example certificates. */
#include "test_ca_cert.c"

#include "device.cert.c"
#include "ica.cert.c"

extern void    test_control_return(UINT status);

#define METADATA_SIZE 16000

static UCHAR tls_session_metadata[METADATA_SIZE];
static NX_SECURE_TLS_SESSION tls_session;
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

/* ecc initialization */
extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;

static NX_CRYPTO_METHOD test_x509_hash_method = {0};

static NX_CRYPTO_METHOD test_public_cipher_method =
{
    TLS_PUBLIC_AUTH_PSK,                      /* PSK placeholder                        */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    0,                                        /* Metadata size in bytes                 */
    NX_NULL,                                  /* Initialization routine.                */
    NX_NULL,                                  /* Cleanup routine, not used.             */
    NX_NULL                                   /* Operation                              */
};

static UINT test_crypto_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                           UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                           VOID **handler,
                           VOID *crypto_metadata,
                           ULONG crypto_metadata_size)
{
    return NX_CRYPTO_NOT_SUCCESSFUL;
}

static UINT test_crypto_cleanup(VOID *crypto_metadata)
{
    return NX_CRYPTO_NOT_SUCCESSFUL;
}

static UINT test_crypto_operation(UINT op,       /* Encrypt, Decrypt, Authenticate */
                                VOID *handler, /* Crypto handler */
                                struct NX_CRYPTO_METHOD_STRUCT *method,
                                UCHAR *key,
                                NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                UCHAR *input,
                                ULONG input_length_in_byte,
                                UCHAR *iv_ptr,
                                UCHAR *output,
                                ULONG output_length_in_byte,
                                VOID *crypto_metadata,
                                ULONG crypto_metadata_size,
                                VOID *packet_ptr,
                                VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    return NX_CRYPTO_NOT_SUCCESSFUL;
}

static NX_SECURE_X509_CRYPTO test_x509_cipher_table[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &test_public_cipher_method,    &test_x509_hash_method},
};

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_x509_certificate_verify_test_application_define(void *first_unused_memory)
#endif
{
UINT status;
NX_SECURE_X509_CERT certificate, certificate_1, certificate_2;
NX_SECURE_X509_CERTIFICATE_STORE store;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS X509 Certificate Verify Test.......................");

    nx_system_initialize();

    status =  nx_secure_tls_session_create(&tls_session,
                                           &nx_crypto_tls_ciphers,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    memset(&store, 0, sizeof(NX_SECURE_X509_CERTIFICATE_STORE));
    status = nx_secure_x509_certificate_initialize(&certificate, test_ca_cert_der, test_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add our certificates to the store. */
    status = _nx_secure_x509_store_certificate_add(&certificate, &store, NX_SECURE_X509_CERT_LOCATION_TRUSTED);
    EXPECT_EQ(NX_SUCCESS, status);

    certificate.nx_secure_x509_cipher_table = test_x509_cipher_table;
    certificate.nx_secure_x509_cipher_table_size = 1;
    test_x509_hash_method.nx_crypto_init = test_crypto_init;

    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    test_x509_hash_method.nx_crypto_init = NX_NULL;

    test_x509_hash_method.nx_crypto_cleanup = test_crypto_cleanup;
    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    test_x509_hash_method.nx_crypto_cleanup = NX_NULL;

    test_x509_hash_method.nx_crypto_operation = test_crypto_operation;
    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    test_x509_hash_method.nx_crypto_operation = NX_NULL;

    test_public_cipher_method.nx_crypto_algorithm = NX_CRYPTO_DIGITAL_SIGNATURE_RSA;
    certificate.nx_secure_x509_public_algorithm = 0;
    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_SECURE_X509_WRONG_SIGNATURE_METHOD, status);
    certificate.nx_secure_x509_public_algorithm = NX_SECURE_TLS_X509_TYPE_RSA;

    test_public_cipher_method.nx_crypto_init = test_crypto_init;
    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    test_public_cipher_method.nx_crypto_init = NX_NULL;

    test_public_cipher_method.nx_crypto_operation = test_crypto_operation;
    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    test_public_cipher_method.nx_crypto_operation = NX_NULL;

    test_public_cipher_method.nx_crypto_cleanup = test_crypto_cleanup;
    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    test_public_cipher_method.nx_crypto_cleanup = NX_NULL;

    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_SECURE_X509_PKCS7_PARSING_FAILED, status);

    test_public_cipher_method.nx_crypto_algorithm = NX_CRYPTO_DIGITAL_SIGNATURE_ECDSA;
    certificate.nx_secure_x509_public_algorithm = 0;
    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_SECURE_X509_WRONG_SIGNATURE_METHOD, status);
    certificate.nx_secure_x509_public_algorithm = NX_SECURE_TLS_X509_TYPE_EC;

    status = _nx_secure_tls_ecc_initialize(&tls_session, nx_crypto_ecc_supported_groups, nx_crypto_ecc_supported_groups_size, nx_crypto_ecc_curves);
    EXPECT_EQ(NX_SUCCESS, status);

    certificate.nx_secure_x509_public_key.ec_public_key.nx_secure_ec_named_curve = nx_crypto_ecc_supported_groups[0];

    test_public_cipher_method.nx_crypto_init = test_crypto_init;
    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    test_public_cipher_method.nx_crypto_init = NX_NULL;

    test_public_cipher_method.nx_crypto_operation = test_crypto_operation;
    status = _nx_secure_x509_certificate_verify(&store, &certificate, &certificate);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Cover nx_secure_x509_certificate_chain_verify.c  */
    memset(&store, 0, sizeof(NX_SECURE_X509_CERTIFICATE_STORE));
    status = nx_secure_x509_certificate_initialize(&certificate, test_ca_cert_der, test_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_secure_x509_certificate_initialize(&certificate_1, device_cert_der, device_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_secure_x509_certificate_initialize(&certificate_2, ica_cert_der, ica_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_secure_tls_local_certificate_add(&tls_session, &certificate);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_secure_tls_local_certificate_add(&tls_session, &certificate_1);
    EXPECT_EQ(NX_SUCCESS, status);
    status = nx_secure_tls_local_certificate_add(&tls_session, &certificate_2);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_x509_store_certificate_add(&certificate_2, &store, NX_SECURE_X509_CERT_LOCATION_REMOTE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_x509_certificate_chain_verify(&store, &certificate_1, 0);
    EXPECT_EQ(NX_SECURE_X509_ISSUER_CERTIFICATE_NOT_FOUND, status);

    status = _nx_secure_x509_certificate_chain_verify(&store, &certificate, 0);
    EXPECT_EQ(NX_SECURE_X509_CHAIN_VERIFY_FAILURE, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_x509_certificate_verify_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS X509 Certificate Verify Test.......................N/A\n");
    test_control_return(3);
}
#endif
