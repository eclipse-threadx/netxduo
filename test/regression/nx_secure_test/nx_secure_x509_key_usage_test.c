#include <stdio.h>

#include "nx_secure_tls_api.h"

#include "tls_test_utility.h"

static TX_THREAD thread_0;

void NX_SECURE_X509_KeyUsageTest();

static void    thread_0_entry(ULONG thread_input);

#define DEMO_STACK_SIZE 2048
static CHAR thread_stack[DEMO_STACK_SIZE];

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_x509_key_usage_test_application_define(void *first_unused_memory)
#endif
{

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     thread_stack, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
}

static void    thread_0_entry(ULONG thread_input)
{
    /* Print out test information banner.  */
    printf("NetX Secure Test:   X509 Key Usage Test...............................");

#ifndef NX_SECURE_DISABLE_X509
    NX_SECURE_X509_KeyUsageTest();

    printf("SUCCESS!\n");
#else
    printf("N/A\n");
#endif

    test_control_return(0);
}

#ifndef NX_SECURE_DISABLE_X509

static UCHAR server_packet_buffer[2000];

static NX_PACKET_POOL    pool_0;

#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 32)


static ULONG             packet_pool_area[NX_PACKET_POOL_SIZE/sizeof(ULONG) + 64 / sizeof(ULONG)];

#include "key_usage_certs.c"

static NX_SECURE_X509_CERT root_ca;
static NX_SECURE_X509_CERT ica_cert;
static NX_SECURE_X509_CERT revoked_cert;
static NX_SECURE_X509_CERT device_cert;

/*  Cryptographic routines. */
static CHAR crypto_metadata[16000];
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

/* Buffer space for certificate tests. */
static CHAR ica_buf1[8000];
static CHAR ica_buf2[3000];
static CHAR device_buf1[8000];
static CHAR device_buf2[3000];
static CHAR revoked_buf1[8000];
static CHAR revoked_buf2[3000];

TEST(NX_SECURE_X509, KeyUsageTest)
{

UINT status;
NX_PACKET *packet;
NX_SECURE_TLS_SESSION session;
UCHAR header_buffer[6];
UCHAR header_data[6];
USHORT header_size;
UINT message_length;
USHORT message_type;
const NX_SECURE_TLS_CIPHERSUITE_INFO *ciphersuite;
NX_SECURE_X509_CERTIFICATE_STORE *store;
NX_SECURE_X509_CERT **remote_certs;

    memset(&session, 0, sizeof(NX_SECURE_TLS_SESSION));

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_tls_session_reset(&session);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Initialize the server session. */
    /* Create a TLS session.  */
    status =  nx_secure_tls_session_create(&session,
                                           &nx_crypto_tls_ciphers,
                                           crypto_metadata,
                                           sizeof(crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup our packet reassembly buffer. */
    status = _nx_secure_tls_session_packet_buffer_set(&session, server_packet_buffer, sizeof(server_packet_buffer));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup TLS session as if we were in the middle of a handshake. */
    session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;

    /* Initialize our certificates - NOTE: We don't need private keys because we aren't doing anything but chain verification. */
    status = _nx_secure_x509_certificate_initialize(&ica_cert, ica_cert_der, ica_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = _nx_secure_x509_certificate_initialize(&root_ca, root_ca_cert_der, root_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = _nx_secure_x509_certificate_initialize(&device_cert, device_cert_der, device_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = _nx_secure_x509_certificate_initialize(&revoked_cert, revoked_cert_der, revoked_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add certificates to session. */
    status = _nx_secure_tls_trusted_certificate_add(&session, &root_ca);
    EXPECT_EQ(NX_SUCCESS, status);

    store = &session.nx_secure_tls_credentials.nx_secure_tls_certificate_store;
    remote_certs = &session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates;

    /* Add remote certificates as if we received a chain. */
    status = _nx_secure_x509_certificate_list_add(remote_certs, &ica_cert, NX_TRUE);
    EXPECT_EQ(NX_SUCCESS, status);
    ica_cert.nx_secure_x509_public_cipher_metadata_area = ica_buf1;
    ica_cert.nx_secure_x509_public_cipher_metadata_size = sizeof(ica_buf1);
    ica_cert.nx_secure_x509_hash_metadata_area = ica_buf2;
    ica_cert.nx_secure_x509_hash_metadata_size = sizeof(ica_buf2);
    ica_cert.nx_secure_x509_cipher_table = session.nx_secure_tls_crypto_table -> nx_secure_tls_x509_cipher_table;
    ica_cert.nx_secure_x509_cipher_table_size = session.nx_secure_tls_crypto_table -> nx_secure_tls_x509_cipher_table_size;

    status = _nx_secure_x509_certificate_list_add(remote_certs, &device_cert, NX_TRUE);
    EXPECT_EQ(NX_SUCCESS, status);
    device_cert.nx_secure_x509_public_cipher_metadata_area = device_buf1;
    device_cert.nx_secure_x509_public_cipher_metadata_size = sizeof(device_buf1);
    device_cert.nx_secure_x509_hash_metadata_area = device_buf2;
    device_cert.nx_secure_x509_hash_metadata_size = sizeof(device_buf2);
    device_cert.nx_secure_x509_cipher_table = session.nx_secure_tls_crypto_table -> nx_secure_tls_x509_cipher_table;
    device_cert.nx_secure_x509_cipher_table_size = session.nx_secure_tls_crypto_table -> nx_secure_tls_x509_cipher_table_size;


    status = _nx_secure_x509_certificate_list_add(remote_certs, &revoked_cert, NX_TRUE);
    EXPECT_EQ(NX_SUCCESS, status);
    revoked_cert.nx_secure_x509_public_cipher_metadata_area = revoked_buf1;
    revoked_cert.nx_secure_x509_public_cipher_metadata_size = sizeof(revoked_buf1);
    revoked_cert.nx_secure_x509_hash_metadata_area = revoked_buf2;
    revoked_cert.nx_secure_x509_hash_metadata_size = sizeof(revoked_buf2);
    revoked_cert.nx_secure_x509_cipher_table = session.nx_secure_tls_crypto_table -> nx_secure_tls_x509_cipher_table;
    revoked_cert.nx_secure_x509_cipher_table_size = session.nx_secure_tls_crypto_table -> nx_secure_tls_x509_cipher_table_size;


    /* Now do some chain verifications. */

    /* Check "device cert" - should FAIL because ICA does not have proper KeyUsage. */
    status = _nx_secure_x509_certificate_chain_verify(store, &device_cert, 0);
    EXPECT_EQ(NX_SECURE_X509_KEY_USAGE_ERROR, status);

    /* Check "revoked cert" - should PASS because root CA DOES have proper KeyUsage. */
    status = _nx_secure_x509_certificate_chain_verify(store, &revoked_cert, 0);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Check CRLs. */

#ifndef NX_SECURE_X509_DISABLE_CRL
    /* Root CRL is good because root CA has proper KeyUsage, but revoked_cert is revoked. */
    status = _nx_secure_x509_crl_revocation_check(root_crl_der, root_crl_der_len, store, &revoked_cert);
    EXPECT_EQ(NX_SECURE_X509_CRL_CERTIFICATE_REVOKED, status);

    /* The ICA CRL is no good because ICA has improper KeyUsage. device_cert is OK, but CRL should fail. */
    status = nx_secure_x509_crl_revocation_check(ica_crl_der, ica_crl_der_len, store, &device_cert);
    EXPECT_EQ(NX_SECURE_X509_KEY_USAGE_ERROR, status);
#endif

    nx_secure_tls_session_delete(&session);

}
#endif
