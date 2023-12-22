#include "tls_test_frame.h"

/* Global demo emaphore. */
extern TLS_TEST_SEMAPHORE* semaphore_server_prepared;

/* Define the ThreadX and NetX object control blocks...  */
NX_PACKET_POOL    pool_0;
NX_IP             ip_0;

NX_SECURE_DTLS_SERVER dtls_server;
NX_SECURE_X509_CERT certificate;

UCHAR tls_packet_buffer[4000];

/* Session buffer for DTLS server. Must be equal to the size of NX_SECURE_DTLS_SESSION times the
   number of desired DTLS sessions. */
static UCHAR      session_buffer[sizeof(NX_SECURE_DTLS_SESSION)];

/* Define the IP thread's stack area.  */
ULONG             ip_thread_stack[3 * 1024 / sizeof(ULONG)];

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 32)
ULONG             packet_pool_area[NX_PACKET_POOL_SIZE/sizeof(ULONG) + 64 / sizeof(ULONG)];

/* Define the ARP cache area.  */
ULONG             arp_space_area[512 / sizeof(ULONG)];

/* Define the demo thread.  */
ULONG             demo_thread_stack[6 * 1024 / sizeof(ULONG)];
TX_THREAD         demo_thread;
void              server_thread_entry(ULONG thread_input);
CHAR crypto_metadata[30000];

#if (NX_SECURE_TLS_TLS_1_0_ENABLED) || (NX_SECURE_TLS_TLS_1_1_ENABLED)
extern NX_CRYPTO_METHOD crypto_method_null;
extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_auth_psk;
extern NX_CRYPTO_METHOD crypto_method_md5;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_aes_ccm_8; 
extern NX_CRYPTO_METHOD crypto_method_aes_128_gcm_16;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha1;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_hkdf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_hmac;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;

NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_1_0_1_1[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_RSA_WITH_AES_128_GCM_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_256_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    {TLS_PSK_WITH_AES_128_CBC_SHA256,         &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_PSK_WITH_AES_128_CCM_8,              &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_ccm_8,       16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif
#endif /* NX_SECURE_ENABLE_PSK_CIPHERSUITES */
};

/* Lookup table for X.509 digital certificates - they need a public-key algorithm and a hash routine for verification. */
NX_SECURE_X509_CRYPTO _nx_crypto_x509_cipher_lookup_table_1_0_1_1[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &crypto_method_rsa,       &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_1,      &crypto_method_rsa,       &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_RSA_MD5,        &crypto_method_rsa,       &crypto_method_md5},
};

/* Define the object we can pass into TLS. */
NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table_1_0_1_1,
    sizeof(_nx_crypto_ciphersuite_lookup_table_1_0_1_1) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _nx_crypto_x509_cipher_lookup_table_1_0_1_1,
    sizeof(_nx_crypto_x509_cipher_lookup_table_1_0_1_1) / sizeof(NX_SECURE_X509_CRYPTO),
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
#else
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
#endif

#include "ica_test_device_cert.c"
#include "ica_test_ica_cert.c"

/* Define the pointer of current instance control block. */
static TLS_TEST_INSTANCE* demo_instance_ptr;

/* Define external references.  */
VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);

/*  Instance one test entry. */
INT dtls_server_entry(TLS_TEST_INSTANCE* instance_ptr)
{

#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_DTLS)

    /* Get instance pointer. */
    demo_instance_ptr = instance_ptr;

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();

#else /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

    exit(TLS_TEST_NOT_AVAILABLE);

#endif /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

}

/* Define what the initial system looks like.  */
void    tx_application_define(void *first_unused_memory)
{
    ULONG gateway_ipv4_address;
    UINT  status;

    /* Initialize the NetX system.  */
    nx_system_initialize();
    
    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", TLS_TEST_IP_ADDRESS_NUMBER, 0xFFFFFF00UL, &pool_0, _nx_pcap_network_driver, (UCHAR*)ip_thread_stack, sizeof(ip_thread_stack), 1);
print_error_message( "ip address number: %lu\n", TLS_TEST_IP_ADDRESS_NUMBER);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *)arp_space_area, sizeof(arp_space_area));
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    nx_secure_tls_initialize();
    nx_secure_dtls_initialize();

    tx_thread_create(&demo_thread, "demo thread", server_thread_entry, 0, demo_thread_stack, sizeof(demo_thread_stack), 16, 16, 4, TX_AUTO_START);
}

/* Notification flags for DTLS server connect/receive. */
UINT server_connect_count = 0;
UINT server_receive_count = 0;
NX_SECURE_DTLS_SESSION *connect_session;
NX_SECURE_DTLS_SESSION *receive_session;

/* Connect notify callback for DTLS server - notifies the application thread that
   a DTLS connection is ready to kickoff a handshake. */
UINT server_connect_notify(NX_SECURE_DTLS_SESSION *dtls_session, NXD_ADDRESS *ip_address, UINT port)
{
    connect_session = dtls_session;
    server_connect_count++;
    return(NX_SUCCESS);
}

/* Receive notify callback for DTLS server - notifies the application thread that
   we have received a DTLS record over an established DTLS session. */
UINT server_receive_notify(NX_SECURE_DTLS_SESSION *dtls_session)
{
    receive_session = dtls_session;
    server_receive_count++;
    return(NX_SUCCESS);
}

/* TLS Server example application thread. */
void server_thread_entry(ULONG thread_input)
{
    INT status = 0;
    ULONG actual_status;
    NX_PACKET *receive_packet;
    NX_PACKET *send_packet;
    UCHAR receive_buffer[100];
    ULONG bytes;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    show_error_message_if_fail( NX_SUCCESS == status);

    /* Create a socket.  */
    status = nx_secure_dtls_server_create(&dtls_server, &ip_0, DEVICE_SERVER_PORT, NX_IP_PERIODIC_RATE,
                                          session_buffer, sizeof(session_buffer),
                                          &nx_crypto_tls_ciphers, crypto_metadata, sizeof(crypto_metadata),
                                          tls_packet_buffer, sizeof(tls_packet_buffer),
                                          server_connect_notify, server_receive_notify);
    show_error_message_if_fail( NX_SUCCESS == status);

    memset(&certificate, 0, sizeof(certificate));
    status = nx_secure_x509_certificate_initialize(&certificate,
                                                   test_device_cert_der, test_device_cert_der_len,
                                                   NX_NULL, 0, test_device_cert_key_der,
                                                   test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    show_error_message_if_fail( NX_SUCCESS == status);

    status = nx_secure_dtls_server_local_certificate_add(&dtls_server, &certificate, 1);
    show_error_message_if_fail( NX_SUCCESS == status);

    status = nx_secure_dtls_server_start(&dtls_server);
    show_error_message_if_fail( NX_SUCCESS == status);

    /* Post semaphore before accept sockets. */
    print_error_message("Server is prepared. Post the semaphore.\n");
    tls_test_semaphore_post(semaphore_server_prepared);

    /* Accept a client socket connection.  */
    print_error_message("Server wait for connections.\n");

    while (!server_connect_count)
    {
        tx_thread_sleep(1);
    }
    server_connect_count = 0;
    print_error_message("Server accept.\n");

    /* Start the DTLS Session now that we have a connected socket. */
    status = nx_secure_dtls_server_session_start(connect_session, 20 * NX_IP_PERIODIC_RATE);
    exit_if_fail(NX_SUCCESS == status, 1);

    /* Wait for records to be received. */
    print_error_message("Server wait for records.\n");
    while (!server_receive_count)
    {
        tx_thread_sleep(1);
    }
    server_receive_count = 0;

    /* Receive the data, and print it out. */
    status = nx_secure_dtls_session_receive(receive_session, &receive_packet, 5 * NX_IP_PERIODIC_RATE);
    exit_if_fail(NX_SUCCESS == status, 2);

    /* Show received data. */
    nx_packet_data_extract_offset(receive_packet, 0, receive_buffer, 100, &bytes);
    receive_buffer[bytes] = 0;
    print_error_message("Server received data: %s\n", receive_buffer);

    /* Allocate a return packet and send received data back to the client. */
    status = nx_secure_dtls_packet_allocate(connect_session, &pool_0, &send_packet, NX_NO_WAIT);
    exit_if_fail(NX_SUCCESS == status, 3);

    /* Append the data. */
    status = nx_packet_data_append(send_packet, receive_buffer, bytes, &pool_0, NX_NO_WAIT);
    exit_if_fail(NX_SUCCESS == status, 4);

    /* DTLS send the received data back to the client. */
    status = nx_secure_dtls_server_session_send(connect_session, send_packet);
    exit_if_fail(NX_SUCCESS == status, 5);

    /* End the DTLS session. */
    status = nx_secure_dtls_session_end(connect_session, 5 * NX_IP_PERIODIC_RATE);
    print_error_message("Server session end status %d.\n", status);

    /* Shutdown DTLS server. */
    nx_secure_dtls_server_stop(&dtls_server);
    print_error_message("Server stop.\n");

    /* Delete server. */
    nx_secure_dtls_server_delete(&dtls_server);

    exit(0);
}
