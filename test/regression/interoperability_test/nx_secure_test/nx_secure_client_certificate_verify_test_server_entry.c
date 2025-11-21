#include "tls_test_frame.h"
#include "test_server.der.c"
#include "test_server.key.der.c"
#include "test.der.c"

/* Global demo emaphore. */
extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;

/* Define the ThreadX and NetX object control blocks...  */
NX_PACKET_POOL    pool_0;
NX_IP             ip_0;  

NX_TCP_SOCKET tcp_socket;
NX_SECURE_TLS_SESSION tls_session;

UCHAR tls_packet_buffer[4000];

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
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
UCHAR remote_cert_buffer[2000];
UCHAR remote_issuer_buffer[2000];
NX_SECURE_X509_CERT certificate, device_issuer_certificate;
NX_SECURE_X509_CERT remote_certificate, remote_issuer;
CHAR crypto_metadata[30000]; // 2*sizeof(NX_AES) + sizeof(NX_SHA1_HMAC) + 2*sizeof(NX_CRYPTO_RSA) + (2 * (sizeof(NX_MD5) + sizeof(NX_SHA1) + sizeof(NX_SHA256)))];

/* Define the pointer of current instance control block. */
static TLS_TEST_INSTANCE* demo_instance_ptr;

/* Define external references.  */
VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);

/*  Instance one test entry. */
INT nx_secure_echo_server_entry(TLS_TEST_INSTANCE* instance_ptr)
{  

#ifdef NX_SECURE_ENABLE_CLIENT_CERTIFICATE_VERIFY

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
print_error_message( "ip address number: %lu", TLS_TEST_IP_ADDRESS_NUMBER);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *)arp_space_area, sizeof(arp_space_area));
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    status =  nx_ip_fragment_enable(&ip_0);
    show_error_message_if_fail( status == NX_SUCCESS);

    tx_thread_create(&demo_thread, "demo thread", server_thread_entry, 0, demo_thread_stack, sizeof(demo_thread_stack), 16, 16, 4, TX_AUTO_START);
}

/* TLS Server example application thread. */
void server_thread_entry(ULONG thread_input)
{
    INT i = 0, status = 0;
    ULONG actual_status;
    NX_PACKET *receive_packet;
    NX_PACKET *send_packet;
    UCHAR receive_buffer[100];
    ULONG bytes;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    show_error_message_if_fail( NX_SUCCESS == status);

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &tcp_socket, "Server Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY /*NX_DONT_FRAGMENT*/, NX_IP_TIME_TO_LIVE, 8192,
                                   NX_NULL, NX_NULL);
    show_error_message_if_fail( NX_SUCCESS == status);

    status =  nx_secure_tls_session_create(&tls_session,
                                       &nx_crypto_tls_ciphers,
                                       crypto_metadata,
                                       sizeof(crypto_metadata));
    show_error_message_if_fail( NX_SUCCESS == status);

    /* Allocate space for packet reassembly. */
    status = nx_secure_tls_session_packet_buffer_set(&tls_session, tls_packet_buffer, sizeof(tls_packet_buffer));
    show_error_message_if_fail( NX_SUCCESS == status);
    
    /* Enable Client Certificate Verification. */
    nx_secure_tls_session_client_verify_enable(&tls_session);

    // Initialize our certificates        
    nx_secure_tls_remote_certificate_allocate(&tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));
    
    /* Added a certificate. */
    memset(&certificate, 0, sizeof(certificate));
    status = nx_secure_x509_certificate_initialize(&certificate, test_server_der, test_server_der_len, NX_NULL, 0, test_server_key_der, test_server_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    show_error_message_if_fail( NX_SUCCESS == status);
    status = nx_secure_tls_local_certificate_add(&tls_session, &certificate);
    show_error_message_if_fail( NX_SUCCESS == status);

    // Initialize the Intermediate CA certificate - it does not have a private RSA key
    status = nx_secure_x509_certificate_initialize(&device_issuer_certificate, test_der, test_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    show_error_message_if_fail( NX_SUCCESS == status);
    status = nx_secure_tls_trusted_certificate_add(&tls_session, &device_issuer_certificate);
    show_error_message_if_fail( NX_SUCCESS == status);
        
    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_0, DEVICE_SERVER_PORT, &tcp_socket, 5, NX_NULL);
    show_error_message_if_fail( NX_SUCCESS == status);

    /* Post semaphore before accept sockets. */
    print_error_message("Connection %d: server is prepared. Post the semaphore.\n", i);
    tls_test_semaphore_post(semaphore_echo_server_prepared);

    /* Accept a client socket connection.  */
    print_error_message("Connection %d: wait for connections.\n", i);
    status = nx_tcp_server_socket_accept(&tcp_socket, NX_WAIT_FOREVER);
    print_error_message("Connection %d: server accept.\n", i);
    exit_if_fail( NX_SUCCESS == status, 1);

    /* Start the TLS Session now that we have a connected socket. */
    status = nx_secure_tls_session_start(&tls_session, &tcp_socket, NX_WAIT_FOREVER);
    exit_if_fail( NX_SUCCESS == status, 2);

    /* Receive the HTTP request, and print it out. */
    status = nx_secure_tls_session_receive(&tls_session, &receive_packet, NX_WAIT_FOREVER);
    exit_if_fail( NX_SUCCESS == status, 3);

    /* Show received data. */
    nx_packet_data_extract_offset(receive_packet, 0, receive_buffer, 100, &bytes);
    exit_if_fail( bytes == 6, 4);
    exit_if_fail( receive_buffer[0] == 'h', 5);
    exit_if_fail( receive_buffer[1] == 'e', 5);
    exit_if_fail( receive_buffer[2] == 'l', 5);
    exit_if_fail( receive_buffer[3] == 'l', 5);
    exit_if_fail( receive_buffer[4] == 'o', 5);

    /* End the TLS session. This is required to properly shut down the TLS connection. */
    status = nx_secure_tls_session_end(&tls_session, NX_WAIT_FOREVER);
    exit_if_fail( NX_SUCCESS == status, 7);

    /* Disconnect the TCP socket, closing the connection. */
    status =  nx_tcp_socket_disconnect(&tcp_socket, NX_WAIT_FOREVER);
    exit_if_fail( NX_SUCCESS == status, 8);

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&tcp_socket);
    exit_if_fail( NX_SUCCESS == status, 9);

    exit(0);
}
