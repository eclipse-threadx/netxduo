/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"
#include "ecc_certs.c"

/* Test basic X509 parsing with an example certificates. */
#include "test_ca_cert.c"

extern VOID    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && !defined(NX_SECURE_DISABLE_X509)
#define THREAD_STACK_SIZE           1024
#define METADATA_SIZE               16000

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static UCHAR                    tls_session_metadata[METADATA_SIZE];

extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
static NX_SECURE_TLS_CRYPTO test_crypto_tls_ciphers;
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

static NX_SECURE_X509_CRYPTO test_x509_cipher_table[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &test_public_cipher_method,    &test_x509_hash_method},
};

static NX_CRYPTO_METHOD fake_ecc_curve_method;
static NX_CRYPTO_METHOD fake_ecc_curve_method2;
static const NX_CRYPTO_METHOD *fake_ecc_curves[2] = {&fake_ecc_curve_method, &fake_ecc_curve_method2};
static USHORT fake_groups[2] = {19, 1};

static UINT test_crypto_operation_fail(UINT op,       /* Encrypt, Decrypt, Authenticate */
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

static UINT test_crypto_operation_fail_on_crypto_verify(UINT op,       /* Encrypt, Decrypt, Authenticate */
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
    if(op == NX_CRYPTO_VERIFY)
    {
        return NX_CRYPTO_NOT_SUCCESSFUL;
    }
    return NX_CRYPTO_SUCCESS;
}

static UINT test_crypto_operation_success(UINT op,       /* Encrypt, Decrypt, Authenticate */
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
    if(output)
    {
        output[0] = 1;
        output[1] = 1;
        memset(&output[2], 0xff, output_length_in_byte - 2);
    }
    return NX_CRYPTO_SUCCESS;
}

static UINT test_crypto_cleanup(VOID *crypto_metadata)
{
    return NX_CRYPTO_NOT_SUCCESSFUL;
}

static UINT test_crypto_init(struct NX_CRYPTO_METHOD_STRUCT *method,
                           UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                           VOID **handler,
                           VOID *crypto_metadata,
                           ULONG crypto_metadata_size)
{
    return NX_CRYPTO_NOT_SUCCESSFUL;
}

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_process_certificate_verify_test_application_define(void *first_unused_memory)
#endif
{
    /* Create the client thread.  */
    tx_thread_create(&thread_0, "thread 0", ntest_0_entry, 0,
                     thread_0_stack, sizeof(thread_0_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);
}

static void ntest_0_entry(ULONG thread_input)
{
UINT   status;
NX_SECURE_TLS_SESSION tls_session;
UCHAR buffer[256];
NX_SECURE_X509_CERTIFICATE_STORE store;
NX_SECURE_X509_CERT certificate;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Process Certificate Verify Test....................");

    memcpy(&test_crypto_tls_ciphers, &nx_crypto_tls_ciphers, sizeof(NX_SECURE_TLS_CRYPTO));
    status =  nx_secure_tls_session_create(&tls_session,
                                           &test_crypto_tls_ciphers,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    memset(&store, 0, sizeof(NX_SECURE_X509_CERTIFICATE_STORE));
    status = nx_secure_x509_certificate_initialize(&certificate, test_ca_cert_der, test_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add our certificates to the store. */
    status = _nx_secure_x509_store_certificate_add(&certificate, &store, NX_SECURE_X509_CERT_LOCATION_REMOTE);
    EXPECT_EQ(NX_SUCCESS, status);

    tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store = store;

    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CERT_SIG_ALGORITHM, status);

    /* Set cipher table. */
    certificate.nx_secure_x509_cipher_table = test_x509_cipher_table;
    certificate.nx_secure_x509_cipher_table_size = 1;
    tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store = store;

    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_TLS_VERSION, status);

    /* Set protocol version. */
    tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    buffer[0] = 0;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CERT_SIG_ALGORITHM, status);

    buffer[0] = NX_SECURE_TLS_HASH_ALGORITHM_SHA256;
    buffer[1] = 0;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CERT_SIG_ALGORITHM, status);

    buffer[0] = NX_SECURE_TLS_HASH_ALGORITHM_SHA256;
    buffer[1] = NX_SECURE_TLS_SIGNATURE_ALGORITHM_RSA;
    buffer[2] = 0;
    buffer[3] = 0;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_SIG_CHECK_FAILED, status);

    buffer[2] = 1;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, 100);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_PADDING_CHECK_FAILED, status);

    test_public_cipher_method.nx_crypto_operation = test_crypto_operation_fail;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    test_public_cipher_method.nx_crypto_operation = NX_NULL;
    test_public_cipher_method.nx_crypto_cleanup = test_crypto_cleanup;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    test_public_cipher_method.nx_crypto_operation = test_crypto_operation_success;
    test_public_cipher_method.nx_crypto_cleanup = NX_NULL;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_VERIFY_FAILURE, status);

    status = nx_secure_x509_certificate_initialize(&certificate, ECTestServer9_192_der, sizeof(ECTestServer9_192_der), NX_NULL, 0, ECTestServer9_192_key_der, sizeof(ECTestServer9_192_key_der), NX_SECURE_X509_KEY_TYPE_EC_DER);
    EXPECT_EQ(NX_SUCCESS, status);

    certificate.nx_secure_x509_cipher_table = test_x509_cipher_table;
    certificate.nx_secure_x509_cipher_table_size = 1;

    test_x509_cipher_table->nx_secure_x509_crypto_identifier = NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256;
    buffer[0] = 0;
    buffer[1] = NX_SECURE_TLS_SIGNATURE_ALGORITHM_ECDSA;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CERT_SIG_ALGORITHM, status);

    buffer[0] = NX_SECURE_TLS_HASH_ALGORITHM_SHA256;
    buffer[1] = 0;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CERT_SIG_ALGORITHM, status);

    buffer[1] = NX_SECURE_TLS_SIGNATURE_ALGORITHM_ECDSA;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_ECC_CURVE, status);

    /* set up the curves */
    tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 1;
    tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups = fake_groups;
    tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_curves = &fake_ecc_curves[0];

    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_X509_ASN1_LENGTH_TOO_LONG, status);

    test_public_cipher_method.nx_crypto_operation = test_crypto_operation_fail;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    test_public_cipher_method.nx_crypto_init = test_crypto_init;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    test_public_cipher_method.nx_crypto_init = NX_NULL;
    test_public_cipher_method.nx_crypto_operation = NX_NULL;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);

    test_public_cipher_method.nx_crypto_operation = test_crypto_operation_success;
    test_public_cipher_method.nx_crypto_cleanup = test_crypto_cleanup;
    buffer[2] = 0;
    buffer[3] = 10;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    test_public_cipher_method.nx_crypto_operation = test_crypto_operation_fail_on_crypto_verify;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    test_public_cipher_method.nx_crypto_operation = test_crypto_operation_success;

    test_public_cipher_method.nx_crypto_cleanup = NX_NULL;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SUCCESS, status);

    certificate.nx_secure_x509_public_algorithm = NX_SECURE_TLS_X509_TYPE_UNKNOWN;
    test_x509_cipher_table->nx_secure_x509_crypto_identifier = NX_SECURE_TLS_X509_TYPE_RSA_SHA_256;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_PUBLIC_CIPHER, status);

    /* Set invalid hash method. */
    test_crypto_tls_ciphers.nx_secure_tls_handshake_hash_sha256_method = &test_x509_hash_method;
    test_x509_hash_method.nx_crypto_operation = test_crypto_operation_fail;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    test_x509_hash_method.nx_crypto_operation = NX_NULL;
    status = _nx_secure_tls_process_certificate_verify(&tls_session, buffer, sizeof(buffer));
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_PUBLIC_CIPHER, status);

    /* Revert hash method. */
    test_crypto_tls_ciphers.nx_secure_tls_handshake_hash_sha256_method = nx_crypto_tls_ciphers.nx_secure_tls_handshake_hash_sha256_method;

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_process_certificate_verify_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Process Certificate Verify Test....................N/A\n");
    test_control_return(3);
}
#endif
