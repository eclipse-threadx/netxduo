/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

#include "nx_crypto_ciphersuites_regression.c"

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED)
extern VOID    test_control_return(UINT status);

#define METADATA_SIZE               16000
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))

static NX_PACKET_POOL pool_0;
static ULONG pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];

extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

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
    return NX_CRYPTO_SUCCESS;
}

static NX_CRYPTO_METHOD test_crypto_method_aes_cbc_256;

NX_SECURE_TLS_CIPHERSUITE_INFO test_crypto_ciphersuite_lookup_table[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &test_crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     0,        &crypto_method_tls_prf_sha256}
};

NX_SECURE_TLS_CIPHERSUITE_INFO test_crypto_ciphersuite_lookup_table_2[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &test_crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     1983,        &crypto_method_tls_prf_sha256}
};

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_packet_trim_test_application_define(void *first_unused_memory)
#endif
{
UINT status;
NX_SECURE_TLS_SESSION tls_session;
UCHAR tls_session_metadata[METADATA_SIZE];
UCHAR header_buffer[5];
UCHAR data_buffer[2000] = "hello";
ULONG data_length;
ULONG bytes_processed;
NX_PACKET *packet;
UCHAR test_iv[128];
UCHAR packet_buffer[100];

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Packet Trim Test....................");

    memset(tls_session_metadata, 0, sizeof(tls_session_metadata));
    status =  nx_secure_tls_session_create(&tls_session,
                                           &nx_crypto_tls_ciphers,
                                           tls_session_metadata,
                                           sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
    tls_session.nx_secure_tls_remote_session_active = NX_TRUE;
    tls_session.nx_secure_tls_key_material.nx_secure_tls_client_iv = test_iv;
    tls_session.nx_secure_tls_session_ciphersuite = test_crypto_ciphersuite_lookup_table;
    tls_session.nx_secure_tls_packet_pool = &pool_0;

    memcpy(&test_crypto_method_aes_cbc_256, &crypto_method_aes_cbc_256, sizeof(NX_CRYPTO_METHOD));
    test_crypto_method_aes_cbc_256.nx_crypto_operation = NX_NULL;

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE,
                                    pool_0_memory, PACKET_POOL_SIZE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Test message length overflow. */
    status = nx_packet_allocate(&pool_0, &packet, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    data_length = 17;
    header_buffer[0] = NX_SECURE_TLS_APPLICATION_DATA;
    header_buffer[1] = (NX_SECURE_TLS_VERSION_TLS_1_2 >> 8);
    header_buffer[2] = (NX_SECURE_TLS_VERSION_TLS_1_2 & 0xff);
    header_buffer[3] = (data_length >> 8);
    header_buffer[4] = (data_length & 0xff);

    status = nx_packet_data_append(packet, header_buffer, sizeof(header_buffer), &pool_0, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_packet_data_append(packet, data_buffer, data_length, &pool_0, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_tls_process_record(&tls_session, packet, &bytes_processed, 0);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_packet_release(packet);
    EXPECT_EQ(NX_SUCCESS, status);

    test_crypto_method_aes_cbc_256.nx_crypto_operation = test_crypto_operation_success;
    data_length = 2000;
    header_buffer[3] = (data_length >> 8);
    header_buffer[4] = (data_length & 0xff);

    status = nx_packet_allocate(&pool_0, &packet, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_packet_data_append(packet, header_buffer, sizeof(header_buffer), &pool_0, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_packet_data_append(packet, data_buffer, data_length, &pool_0, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    tls_session.nx_secure_record_queue_header = NX_NULL;
    tls_session.nx_secure_tls_session_ciphersuite = test_crypto_ciphersuite_lookup_table_2;

    status = _nx_secure_tls_process_record(&tls_session, packet, &bytes_processed, 0);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_process_record_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Packet Trim Test....................N/A\n");
    test_control_return(3);
}
#endif
