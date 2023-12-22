#include "tls_test_frame.h"

/* Define the ThreadX and NetX object control blocks...  */

NX_PACKET_POOL    pool_0;
NX_IP             ip_0;  

NX_TCP_SOCKET tcp_socket;
NX_SECURE_TLS_SESSION tls_session;
NX_SECURE_X509_CERT remote_certificate, remote_issuer;
UCHAR remote_cert_buffer[2000];
UCHAR remote_issuer_buffer[2000];
NX_SECURE_X509_CERT trusted_certificate;

UCHAR tls_packet_buffer[4000];
#include "cert.c"

/* Define the IP thread's stack area.  */
ULONG             ip_thread_stack[3 * 1024 / sizeof(ULONG)];

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 32)

ULONG             packet_pool_area[NX_PACKET_POOL_SIZE/sizeof(ULONG) + 64 / sizeof(ULONG)];

/* Define an error counter.  */

ULONG             error_counter;


/* Define the ARP cache area.  */
ULONG             arp_space_area[512 / sizeof(ULONG)];

/* Define the demo thread.  */
ULONG             demo_thread_stack[6 * 1024 / sizeof(ULONG)];
TX_THREAD         demo_thread;

TLS_TEST_INSTANCE* client_instance_ptr;
extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;
VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);
void client_thread_entry(ULONG thread_input);
CHAR crypto_metadata[30000]; // 2*sizeof(NX_AES) + sizeof(NX_SHA1_HMAC) + 2*sizeof(NX_CRYPTO_RSA) + (2 * (sizeof(NX_MD5) + sizeof(NX_SHA1) + sizeof(NX_SHA256)))];


extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_md5;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha1;
extern NX_CRYPTO_METHOD crypto_method_hkdf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_hmac;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;

NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_1_0_1_1[] =
{
    /* Ciphersuite,                        public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                  hash size, TLS PRF */
    {TLS_RSA_WITH_AES_256_CBC_SHA,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,     20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,     20,        &crypto_method_tls_prf_sha256},
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
NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_1_0_1_1 =
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
    & crypto_method_md5,
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

INT nx_secure_echo_client_entry(TLS_TEST_INSTANCE* instance_ptr)
{

#ifndef NX_SECURE_TLS_CLIENT_DISABLED

    client_instance_ptr = instance_ptr;
    tx_kernel_enter();

#else /* ifndef NX_SECURE_TLS_CLIENT_DISABLED */

    exit(TLS_TEST_NOT_AVAILABLE);

#endif /* ifndef NX_SECURE_TLS_CLIENT_DISABLED */

}

void    tx_application_define(void *first_unused_memory)
{
ULONG gateway_ipv4_address;
UINT  status;
    

    /* Initialize the NetX system.  */
    nx_system_initialize();
    
    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, 
                          "NetX IP Instance 0", 
                          TLS_TEST_IP_ADDRESS_NUMBER,                           
                          0xFFFFFF00UL, 
                          &pool_0,
                          _nx_pcap_network_driver,
                          (UCHAR*)ip_thread_stack,
                          sizeof(ip_thread_stack),
                          1);
    show_error_message_if_fail(NX_SUCCESS == status);
    
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *)arp_space_area, sizeof(arp_space_area));
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    status =  nx_ip_fragment_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    nx_secure_tls_initialize();
    
    tx_thread_create(&demo_thread, "demo thread", client_thread_entry, 0,
            demo_thread_stack, sizeof(demo_thread_stack),
            16, 16, 4, TX_AUTO_START);
}

void client_thread_entry(ULONG thread_input)
{
UINT        status;
ULONG       actual_status;
NX_PACKET   *send_packet;
NX_PACKET   *receive_packet;
UCHAR       receive_buffer[100];
ULONG       bytes;
NX_PARAMETER_NOT_USED(thread_input);
    
    /* Address of remote server. */
    print_error_message( "remote ip address number %lu, remote ip address string %s.\n", REMOTE_IP_ADDRESS_NUMBER, REMOTE_IP_ADDRESS_STRING);
    
    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    /* Create a socket. */
    status =  nx_tcp_socket_create(&ip_0, &tcp_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192,
                                   NX_NULL, NX_NULL);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Create a tls session. */
    status =  nx_secure_tls_session_create(&tls_session,
                                       &nx_crypto_tls_ciphers_1_0_1_1,
                                       crypto_metadata,
                                       sizeof(crypto_metadata));
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    nx_secure_tls_session_protocol_version_override(&tls_session, NX_SECURE_TLS_VERSION_TLS_1_1);

    /* Allocate space for packet reassembly. */
    status = nx_secure_tls_session_packet_buffer_set(&tls_session, tls_packet_buffer, sizeof(tls_packet_buffer));
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    /* Setup this thread to bind to a port.  */
    status =  nx_tcp_client_socket_bind(&tcp_socket, 0, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    /* Need to allocate space for the certificate coming in from the remote host. */
    nx_secure_tls_remote_certificate_allocate(&tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));

    /* Added trusted certificates. */
    status = nx_secure_x509_certificate_initialize(&trusted_certificate, cert_der, cert_der_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nx_secure_tls_trusted_certificate_add(&tls_session,
                                                   &trusted_certificate);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Wait for the semaphore. */
    tls_test_semaphore_wait(semaphore_echo_server_prepared);
    tx_thread_sleep(100);

    /* Attempt to connect the echo server. */
    status = nx_tcp_client_socket_connect(&tcp_socket, REMOTE_IP_ADDRESS_NUMBER, DEVICE_SERVER_PORT, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nx_secure_tls_session_start(&tls_session, &tcp_socket, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    /* Send some data to be echoed by the OpenSSL s_server echo instance. */
    status = nx_secure_tls_packet_allocate(&tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Append application to the allocated packet. */
    status = nx_packet_data_append(send_packet, "hello\n", 6, &pool_0, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Send "hello" message. */
    status = nx_secure_tls_session_send(&tls_session, send_packet, NX_IP_PERIODIC_RATE);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Receive the echoed and reversed data, and print it out. */
    status = nx_secure_tls_session_receive(&tls_session, &receive_packet, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Extract data received from server. */
    status = nx_packet_data_extract_offset(receive_packet, 0, receive_buffer, 100, &bytes);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Check the reverse text received from openssl server. */
    exit_if_fail('o' == ((CHAR*)receive_buffer)[0], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail('l' == ((CHAR*)receive_buffer)[1], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail('l' == ((CHAR*)receive_buffer)[2], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail('e' == ((CHAR*)receive_buffer)[3], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail('h' == ((CHAR*)receive_buffer)[4], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail('\n' == ((CHAR*)receive_buffer)[5], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail(6 == bytes, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* End the TLS session. This is required to properly shut down the TLS connection. */
    status = nx_secure_tls_session_end(&tls_session, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Close the TCP connection. */
    status =  nx_tcp_socket_disconnect(&tcp_socket, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Unbind the TCP socket from our port. */
    status = nx_tcp_client_socket_unbind(&tcp_socket);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    /* Delete the TCP socket instance to clean up. */
    status = nx_tcp_socket_delete(&tcp_socket);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    exit(0);
}
