#include "tls_test_frame.h"

#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)
#include   "nx_crypto_ecdh.h"

/* Global demo emaphore. */
extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;

/* Define the ThreadX and NetX object control blocks...  */
NX_PACKET_POOL    pool_0;
NX_IP             ip_0;

NX_TCP_SOCKET tcp_socket;
NX_SECURE_TLS_SESSION tls_session;
NX_SECURE_X509_CERT certificate;

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
CHAR crypto_metadata[30000]; // 2*sizeof(NX_AES) + sizeof(NX_SHA1_HMAC) + 2*sizeof(NX_CRYPTO_RSA) + (2 * (sizeof(NX_MD5) + sizeof(NX_SHA1) + sizeof(NX_SHA256)))];

#include "../../nx_secure_test/ecc_certs.c"

extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;


/* Define the pointer of current instance control block. */
static TLS_TEST_INSTANCE* demo_instance_ptr;

/* Define external references.  */
VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);

/*  Instance one test entry. */
INT nx_secure_ecc_echo_server_entry(TLS_TEST_INSTANCE* instance_ptr)
{


    /* Get instance pointer. */
    demo_instance_ptr = instance_ptr;

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
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
                                       &nx_crypto_tls_ciphers_ecc,
                                       crypto_metadata,
                                       sizeof(crypto_metadata));
    show_error_message_if_fail( NX_SUCCESS == status);

    /* Initialize ECC tables. */
    status = nx_secure_tls_ecc_initialize(&tls_session, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    show_error_message_if_fail( NX_SUCCESS == status);

    /* Allocate space for packet reassembly. */
    status = nx_secure_tls_session_packet_buffer_set(&tls_session, tls_packet_buffer, sizeof(tls_packet_buffer));
    show_error_message_if_fail( NX_SUCCESS == status);

    memset(&certificate, 0, sizeof(certificate));
    nx_secure_x509_certificate_initialize(&certificate,
                                          ECTestServer2_der, ECTestServer2_der_len,
                                          NX_NULL, 0, ECTestServer2_key_der,
                                          ECTestServer2_key_der_len,
                                          NX_SECURE_X509_KEY_TYPE_EC_DER);
    nx_secure_tls_local_certificate_add(&tls_session, &certificate);

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
    receive_buffer[bytes] = 0;
    print_error_message("Received data: %s\n", receive_buffer);

    /* Allocate a return packet and send our HTML data back to the client. */
    status = nx_secure_tls_packet_allocate(&tls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
    exit_if_fail( NX_SUCCESS == status, 4);

    /* Echo the message received. */
    status = nx_packet_data_append(send_packet, receive_buffer, bytes, &pool_0, NX_WAIT_FOREVER);
    exit_if_fail( NX_SUCCESS == status, 5);

    /* TLS send the HTML/HTTPS data back to the client. */
    status = nx_secure_tls_session_send(&tls_session, send_packet, NX_IP_PERIODIC_RATE);
    /* Exit the test process directly without release packet. */
    exit_if_fail( NX_SUCCESS == status, 6);

    /* End the TLS session. This is required to properly shut down the TLS connection. */
    status = nx_secure_tls_session_end(&tls_session, NX_WAIT_FOREVER);
    exit_if_fail( NX_SUCCESS == status, 7);

    /* Disconnect the TCP socket, closing the connection. */
    status =  nx_tcp_socket_disconnect(&tcp_socket, NX_WAIT_FOREVER);
    exit_if_fail( NX_SUCCESS == status, 8);

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&tcp_socket);
    exit_if_fail( NX_SUCCESS == status, 9);

    print_error_message("Connection %d: server unaccept, sleeping...\n", i);
    tx_thread_sleep( 500);

    /* Setup server socket for listening again.  */
    status =  nx_tcp_server_socket_relisten(&ip_0, DEVICE_SERVER_PORT, &tcp_socket);
    exit_if_fail( NX_SUCCESS == status, 10);

    exit(0);
}
#else

/*  Instance one test entry. */
INT nx_secure_ecc_echo_server_entry(TLS_TEST_INSTANCE* instance_ptr)
{
    exit(TLS_TEST_NOT_AVAILABLE);
}
#endif
