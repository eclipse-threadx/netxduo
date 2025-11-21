/* This test concentrates on TLS ECC ciphersuites negotiation.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

extern VOID    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION)
#define THREAD_STACK_SIZE           1024
#define METADATA_SIZE               16000

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
#if 0
static NX_SECURE_TLS_SESSION    tls_session_ptr;
static UCHAR                    tls_session_metadata[METADATA_SIZE];

extern const NX_CRYPTO_METHOD *supported_crypto[];
extern const UINT supported_crypto_size;
extern const NX_CRYPTO_CIPHERSUITE *ciphersuite_map[];
extern const UINT ciphersuite_map_size;
#endif
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

extern volatile ULONG      _tx_thread_system_state;
extern volatile TX_THREAD *_tx_thread_current_ptr;
extern TX_THREAD           _tx_timer_thread;

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_error_checking_2_test_application_define(void *first_unused_memory)
#endif
{
    /* Create the client thread.  */
    tx_thread_create(&thread_0, "thread 0", ntest_0_entry, 0,
                     thread_0_stack, sizeof(thread_0_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);
}

static ULONG test_client_callback(NX_SECURE_TLS_SESSION *tls_session,
                                  NX_SECURE_TLS_HELLO_EXTENSION *extensions,
                                  UINT num_extensions)
{
    return 0;
}

static ULONG test_renegotiate_callback(NX_SECURE_TLS_SESSION *session)
{
    return 0;
}

static ULONG test_server_callback(NX_SECURE_TLS_SESSION *tls_session,
                                  NX_SECURE_TLS_HELLO_EXTENSION *extensions,
                                  UINT num_extensions)
{
    return 0;
}

static ULONG test_timer_function(void)
{
    return 0;
}

static ULONG test_certificate_callback(NX_SECURE_TLS_SESSION *session,
                                      NX_SECURE_X509_CERT *certificate)
{
    return 0;
}

static void ntest_0_entry(ULONG thread_input)
{
UINT status;
NX_SECURE_TLS_SESSION tls_session;
NX_SECURE_TLS_SESSION tls_session_2;
NX_SECURE_X509_CERT certificate;
NX_SECURE_X509_CERTIFICATE_STORE certificate_store;
NX_SECURE_X509_EXTENSION extension;
CHAR crypto_metadata[16000];
UCHAR packet_buffer[NX_SECURE_TLS_MINIMUM_MESSAGE_BUFFER_SIZE];
ULONG correct_thread_system_state;
volatile TX_THREAD *correct_thread_current_ptr;
NX_TCP_SOCKET tcp_socket;
NX_SECURE_TLS_HELLO_EXTENSION extensions;
NX_SECURE_X509_DNS_NAME dns_name;
NX_PACKET packet;
INT ip_version;
ULONG metadata_size;
TX_INTERRUPT_SAVE_AREA

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Error Checking 2 Test....................");

    TX_DISABLE
    status = nx_secure_tls_session_delete(&tls_session);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_session_create(&tls_session, &nx_crypto_tls_ciphers, NX_NULL, sizeof(crypto_metadata));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_session_create(&tls_session, &nx_crypto_tls_ciphers, crypto_metadata, sizeof(crypto_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);

    /* Test create duplicate tls session.  */
    status = nx_secure_tls_session_create(&tls_session, &nx_crypto_tls_ciphers, crypto_metadata, sizeof(crypto_metadata));
    EXPECT_EQ(NX_PTR_ERROR, status);

    correct_thread_system_state = _tx_thread_system_state;
    correct_thread_current_ptr = _tx_thread_current_ptr;

    /* Set thread system state to invalid value.  */
    _tx_thread_system_state = 1;
    status = nx_secure_tls_active_certificate_set(&tls_session, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_local_certificate_add(&tls_session, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_local_certificate_find(&tls_session, (NX_SECURE_X509_CERT **)&certificate, "name", 4);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_local_certificate_remove(&tls_session, "name", 4);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_metadata_size_calculate(&nx_crypto_tls_ciphers, &metadata_size);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    tls_session.nx_secure_tls_tcp_socket = &tcp_socket;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = 0;
    status = nx_secure_tls_packet_allocate(&tls_session, 0, 0, 0);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    status = nx_secure_tls_packet_allocate(&tls_session, 0, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_remote_certificate_allocate(&tls_session, &certificate, (UCHAR *)packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_remote_certificate_buffer_allocate(&tls_session, 1, (VOID *)packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);
    
    status = nx_secure_tls_remote_certificate_free_all(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_server_certificate_add(&tls_session, &certificate, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_server_certificate_find(&tls_session,(NX_SECURE_X509_CERT **) &certificate, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_server_certificate_remove(&tls_session, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_client_callback_set(&tls_session, test_client_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_client_verify_disable(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_client_verify_enable(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_create(&tls_session_2, &nx_crypto_tls_ciphers, crypto_metadata, sizeof(crypto_metadata));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_end(&tls_session, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_packet_buffer_set(&tls_session, packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_protocol_version_override(&tls_session,NX_SECURE_TLS_VERSION_TLS_1_0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    tls_session.nx_secure_tls_tcp_socket = &tcp_socket;
    status = nx_secure_tls_session_receive(&tls_session, (NX_PACKET **)packet_buffer, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_renegotiate(&tls_session, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_renegotiate_callback_set(&tls_session, test_renegotiate_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    tls_session.nx_secure_tls_id = 0;
    status = nx_secure_tls_session_reset(&tls_session);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);
    tls_session.nx_secure_tls_id = NX_SECURE_TLS_ID;

    status = nx_secure_tls_session_reset(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    tls_session.nx_secure_tls_id = 0;
    status = nx_secure_tls_session_send(&tls_session, &packet, 0);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);
    tls_session.nx_secure_tls_id = NX_SECURE_TLS_ID;

    status = nx_secure_tls_session_send(&tls_session, &packet, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_server_callback_set(&tls_session, test_server_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_sni_extension_parse(&tls_session, &extensions, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_sni_extension_set(&tls_session, &dns_name);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_start(&tls_session, &tcp_socket, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_time_function_set(&tls_session, test_timer_function);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_x509_client_verify_configure(&tls_session, 0, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_certificate_callback_set(&tls_session, test_certificate_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_trusted_certificate_add(&tls_session, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_certificate_initialize(&certificate, (UCHAR *)&packet_buffer, sizeof(packet_buffer), 0, 0, 0, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_common_name_dns_check(&certificate, (const UCHAR *)&packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_crl_revocation_check((const UCHAR *)&packet_buffer, 1024, &certificate_store, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_dns_name_initialize(&dns_name, NX_NULL, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_extended_key_usage_extension_parse(&certificate, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_extension_find(&certificate, &extension, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_key_usage_extension_parse(&certificate, (USHORT *)packet_buffer);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_delete(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_trusted_certificate_remove(&tls_session, "name", 4);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    /* Restore thread system state.  */
    _tx_thread_system_state = correct_thread_system_state;

    /* Set current ptr to invalid value.  */
    _tx_thread_current_ptr = TX_NULL;
    status = nx_secure_tls_active_certificate_set(&tls_session, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_local_certificate_add(&tls_session, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_local_certificate_find(&tls_session, (NX_SECURE_X509_CERT **)&certificate, "name", 4);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_local_certificate_remove(&tls_session, "name", 4);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_metadata_size_calculate(&nx_crypto_tls_ciphers, &metadata_size);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_packet_allocate(&tls_session, 0, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_remote_certificate_allocate(&tls_session, &certificate, (UCHAR *)packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_remote_certificate_buffer_allocate(&tls_session, 1, (VOID *)packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_remote_certificate_free_all(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_server_certificate_add(&tls_session, &certificate, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_server_certificate_find(&tls_session,(NX_SECURE_X509_CERT **) &certificate, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_server_certificate_remove(&tls_session, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_client_callback_set(&tls_session, test_client_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_client_verify_disable(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_client_verify_enable(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_create(&tls_session_2, &nx_crypto_tls_ciphers, crypto_metadata, sizeof(crypto_metadata));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_end(&tls_session, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_packet_buffer_set(NX_NULL, packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_session_packet_buffer_set(&tls_session, packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_protocol_version_override(&tls_session,NX_SECURE_TLS_VERSION_TLS_1_0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_receive(&tls_session, (NX_PACKET **)packet_buffer, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_renegotiate(&tls_session, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_renegotiate_callback_set(&tls_session, test_renegotiate_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_reset(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_send(&tls_session, &packet, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_server_callback_set(&tls_session, test_server_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_sni_extension_parse(&tls_session, &extensions, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_sni_extension_set(&tls_session, &dns_name);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_start(&tls_session, &tcp_socket, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_time_function_set(&tls_session, test_timer_function);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_x509_client_verify_configure(&tls_session, 0, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_certificate_callback_set(&tls_session, test_certificate_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_trusted_certificate_add(&tls_session, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_certificate_initialize(&certificate, (UCHAR *)&packet_buffer, sizeof(packet_buffer), 0, 0, 0, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_common_name_dns_check(&certificate, (const UCHAR *)&packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_crl_revocation_check((const UCHAR *)&packet_buffer, 1024, &certificate_store, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_dns_name_initialize(&dns_name, NX_NULL, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_extended_key_usage_extension_parse(&certificate, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_extension_find(&certificate, &extension, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_key_usage_extension_parse(&certificate, (USHORT *)packet_buffer);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_delete(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_trusted_certificate_remove(&tls_session, "name", 4);
    EXPECT_EQ(NX_CALLER_ERROR, status);
    
    _tx_thread_current_ptr = &_tx_timer_thread;
    status = nx_secure_tls_active_certificate_set(&tls_session, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_local_certificate_add(&tls_session, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_local_certificate_find(&tls_session, (NX_SECURE_X509_CERT **)&certificate, "name", 4);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_local_certificate_remove(&tls_session, "name", 4);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_metadata_size_calculate(&nx_crypto_tls_ciphers, &metadata_size);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_packet_allocate(&tls_session, 0, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_remote_certificate_allocate(&tls_session, &certificate, (UCHAR *)packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_remote_certificate_buffer_allocate(&tls_session, 1, (VOID *)packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_remote_certificate_free_all(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_server_certificate_add(&tls_session, &certificate, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_server_certificate_find(&tls_session,(NX_SECURE_X509_CERT **) &certificate, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_server_certificate_remove(&tls_session, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_client_callback_set(&tls_session, test_client_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_client_verify_disable(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_client_verify_enable(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_create(&tls_session_2, &nx_crypto_tls_ciphers, crypto_metadata, sizeof(crypto_metadata));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_end(&tls_session, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_packet_buffer_set(&tls_session, packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_protocol_version_override(&tls_session,NX_SECURE_TLS_VERSION_TLS_1_0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_receive(&tls_session, (NX_PACKET **)packet_buffer, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_renegotiate(&tls_session, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_renegotiate_callback_set(&tls_session, test_renegotiate_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_reset(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_send(&tls_session, &packet, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_server_callback_set(&tls_session, test_server_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_sni_extension_parse(&tls_session, &extensions, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_sni_extension_set(&tls_session, &dns_name);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_start(&tls_session, &tcp_socket, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_time_function_set(&tls_session, test_timer_function);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_x509_client_verify_configure(&tls_session, 0, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);
    
    status = nx_secure_tls_session_certificate_callback_set(&tls_session, test_certificate_callback);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_trusted_certificate_add(&tls_session, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_certificate_initialize(&certificate, (UCHAR *)&packet_buffer, sizeof(packet_buffer), 0, 0, 0, 0, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_common_name_dns_check(&certificate, (const UCHAR *)&packet_buffer, sizeof(packet_buffer));
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_crl_revocation_check((const UCHAR *)&packet_buffer, 1024, &certificate_store, &certificate);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_dns_name_initialize(&dns_name, NX_NULL, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_extended_key_usage_extension_parse(&certificate, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_extension_find(&certificate, &extension, 0);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_x509_key_usage_extension_parse(&certificate, (USHORT *)packet_buffer);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_session_delete(&tls_session);
    EXPECT_EQ(NX_CALLER_ERROR, status);

    status = nx_secure_tls_trusted_certificate_remove(&tls_session, "name", 4);
    EXPECT_EQ(NX_CALLER_ERROR, status);
    
    /* Restore thread system state.  */
    _tx_thread_current_ptr = correct_thread_current_ptr;

    TX_RESTORE

    status = nx_secure_tls_session_delete(&tls_session_2);
    EXPECT_EQ(NX_PTR_ERROR, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_error_checking_2_test_application_define(void *first_unused_memory)
#endif
{
    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Error Checking 2 Test....................N/A\n");
    test_control_return(3);
}
#endif
