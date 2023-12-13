/* This tests nx_secure_tls_send_certificate. */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

#include "nx_tcp.h"
#include "nx_secure_tls.h"
#include "tls_test_utility.h"

extern VOID    test_control_return(UINT status);
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

UCHAR packet_buffer[100];

NX_SECURE_X509_DNS_NAME name;


extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_md5;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_hmac;
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_rsa;

NX_CRYPTO_METHOD crypto_method_test_1 =
{
    NX_CRYPTO_DIGITAL_SIGNATURE_DSA,          /* crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    256,                                      /* Metadata size in bytes                 */
    NX_NULL,                                  /* Initialization routine.            */
    NX_NULL,                                  /* Cleanup routine                    */
    NX_NULL                                   /* Operation                          */
};

NX_CRYPTO_METHOD crypto_method_test_2 =
{
    NX_CRYPTO_DIGITAL_SIGNATURE_ANONYMOUS,    /* crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    256,                                      /* Metadata size in bytes                 */
    NX_NULL,                                  /* Initialization routine.            */
    NX_NULL,                                  /* Cleanup routine                    */
    NX_NULL                                   /* Operation                          */
};

NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
};

/* tls_session -> nx_secure_tls_crypto_table -> nx_secure_tls_x509_cipher_table */
NX_SECURE_X509_CRYPTO _nx_crypto_x509_cipher_lookup_table_test[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &crypto_method_test_1, &crypto_method_hmac},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &crypto_method_test_2, &crypto_method_sha256},


};

/* tls_session -> nx_secure_tls_crypto_table */
NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_test_dsa =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table,
    sizeof(_nx_crypto_ciphersuite_lookup_table) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _nx_crypto_x509_cipher_lookup_table_test,
    sizeof(_nx_crypto_x509_cipher_lookup_table_test) / sizeof(NX_SECURE_X509_CRYPTO),
#endif

    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    &crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    &crypto_method_sha256,
    &crypto_method_tls_prf_sha256,
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif
};


#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_send_client_hello_test_application_define(void *first_unused_memory)
#endif
{
UINT   status;
NX_SECURE_TLS_SESSION tls_session;
NX_SECURE_X509_CERT certificate;
NX_PACKET send_packet;


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_DISABLE_X509)

    printf("NetX Secure Test:   TLS Send ClientHello Test....................");

    memset(&tls_session, 0, sizeof(tls_session));
    tls_session.nx_secure_tls_credentials.nx_secure_tls_active_certificate = &certificate;
    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    tls_session.nx_secure_tls_protocol_version_override = 2;
    tls_session.nx_secure_tls_crypto_table = &nx_crypto_tls_ciphers;
    tls_session.nx_secure_tls_session_id_length = 2;
    tls_session.nx_secure_tls_renegotation_enabled = NX_TRUE;
    
    memset(&send_packet, 0, sizeof(send_packet));
    send_packet.nx_packet_append_ptr = packet_buffer;
    send_packet.nx_packet_data_end = send_packet.nx_packet_append_ptr + 90;
#ifndef NX_SECURE_TLS_SNI_EXTENSION_DISABLED
    name.nx_secure_x509_dns_name_length = 100;
    tls_session.nx_secure_tls_sni_extension_server_name = &name;

    status = _nx_secure_tls_send_clienthello(&tls_session, &send_packet);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

    tls_session.nx_secure_tls_session_id_length = 0;
    status = _nx_secure_tls_send_clienthello(&tls_session, &send_packet);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
#endif

    /* Cover nx_secure_tls_send_clienthello_extensions.c: 163, 1546 */
    ULONG packet_offset = 0;
    ULONG extensions_length = 0;
    ULONG available_size = 0;
    status = _nx_secure_tls_send_clienthello_extensions(&tls_session, send_packet.nx_packet_append_ptr,
                                &packet_offset, &extensions_length, available_size);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

    /* Cover nx_secure_tls_send_clienthello_extensions.c: 1566 */
    tls_session.nx_secure_tls_local_session_active = 0;
    available_size = packet_offset + 2;
    status = _nx_secure_tls_send_clienthello_extensions(&tls_session, send_packet.nx_packet_append_ptr,
                                &packet_offset, &extensions_length, available_size);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

    /* Cover nx_secure_tls_send_clienthello_extensions.c: 1585 */
    tls_session.nx_secure_tls_local_session_active = 1;
    available_size = packet_offset + 2;
    status = _nx_secure_tls_send_clienthello_extensions(&tls_session, send_packet.nx_packet_append_ptr,
                                &packet_offset, &extensions_length, available_size);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);


    /* Cover nx_secure_tls_send_clienthello_extensions.c: 231, 336 */
    tls_session.nx_secure_tls_renegotation_enabled = NX_FALSE;
    tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    status = _nx_secure_tls_send_clienthello_extensions(&tls_session, send_packet.nx_packet_append_ptr,
                                &packet_offset, &extensions_length, available_size);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);


#ifndef NX_SECURE_TLS_SNI_EXTENSION_DISABLED
    /* Cover nx_secure_tls_send_clienthello_extensions.c: 357 */
    tls_session.nx_secure_tls_renegotation_enabled = NX_FALSE;
    tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    available_size = packet_offset + 6 + 20;
    tls_session.nx_secure_tls_crypto_table = &nx_crypto_tls_ciphers_test_dsa;
    status = _nx_secure_tls_send_clienthello_extensions(&tls_session, send_packet.nx_packet_append_ptr,
                                &packet_offset, &extensions_length, available_size);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
#endif

    /* Cover nx_secure_tls_send_clienthello_extensions.c: 1684 */
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    tls_session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 1;
    available_size = packet_offset + 2;
    status = _nx_secure_tls_send_clienthello_extensions(&tls_session, send_packet.nx_packet_append_ptr,
                                &packet_offset, &extensions_length, available_size);
#endif

    printf("SUCCESS!\n");

#endif

    printf("NetX Secure Test:   TLS Send ChangeCipherSpec Test....................");

    send_packet.nx_packet_data_end = send_packet.nx_packet_append_ptr;
    status = _nx_secure_tls_send_changecipherspec(&tls_session, &send_packet);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

    printf("SUCCESS!\n");

    test_control_return(0);
}
