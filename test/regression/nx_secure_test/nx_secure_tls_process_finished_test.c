/* This test concentrates on process Finished message.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

/* Test basic X509 parsing with an example certificates. */
#include "test_ca_cert.c"

extern VOID    test_control_return(UINT status);

#ifndef NX_SECURE_DISABLE_X509
#define METADATA_SIZE               16000

extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table[];

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_process_finished_test_application_define(void *first_unused_memory)
#endif
{
UINT status;
NX_SECURE_TLS_SESSION tls_session;
UCHAR tls_session_metadata[METADATA_SIZE];
UCHAR packet_buffer[NX_SECURE_TLS_FINISHED_HASH_SIZE] = {0x14, 0xf4, 0xc9, 0x5a, 0xd9, 0x10, 0xc4, 0x22, 0x33, 0x20, 0xb8, 0x1};
NX_SECURE_X509_CERTIFICATE_STORE store;
NX_SECURE_X509_CERT certificate;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Process Finished Test....................");

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status =  nx_secure_tls_session_create(&tls_session,
                                           &nx_crypto_tls_ciphers,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    memset(&store, 0, sizeof(NX_SECURE_X509_CERTIFICATE_STORE));
    status = nx_secure_x509_certificate_initialize(&certificate, test_ca_cert_der, test_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add our certificates to the store. */
    status = _nx_secure_x509_store_certificate_add(&certificate, &store, NX_SECURE_X509_CERT_LOCATION_REMOTE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_x509_store_certificate_add(&certificate, &store, NX_SECURE_X509_CERT_LOCATION_FREE);
    certificate.nx_secure_x509_user_allocated_cert = NX_TRUE;

    tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store = store;
    tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    tls_session.nx_secure_tls_remote_session_active = NX_TRUE;
    tls_session.nx_secure_tls_received_remote_credentials = NX_TRUE;
    tls_session.nx_secure_tls_session_ciphersuite = _nx_crypto_ciphersuite_lookup_table;
    status = _nx_secure_tls_process_finished(&tls_session, packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_process_finished_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Process Finished Test....................N/A\n");
    test_control_return(3);
}

#endif
