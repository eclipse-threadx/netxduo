#include "tls_test_frame.h"

/* Define the ThreadX and NetX object control blocks...  */

NX_PACKET_POOL    pool_0;
NX_IP             ip_0;  

NX_UDP_SOCKET udp_socket;
NX_SECURE_DTLS_SESSION dtls_session;
UCHAR cert_buffer[2000];
NX_SECURE_X509_CERT trusted_certificate;

UCHAR tls_packet_buffer[4000];

#include "cert.c"

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

TLS_TEST_INSTANCE* client_instance_ptr;
extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;
VOID    _nx_pcap_network_driver(NX_IP_DRIVER *driver_req_ptr);
void client_thread_entry(ULONG thread_input);
CHAR crypto_metadata[30000]; // 2*sizeof(NX_AES) + sizeof(NX_SHA1_HMAC) + 2*sizeof(NX_CRYPTO_RSA) + (2 * (sizeof(NX_MD5) + sizeof(NX_SHA1) + sizeof(NX_SHA256)))];
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

INT nx_secure_echo_client_entry(TLS_TEST_INSTANCE* instance_ptr)
{

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && defined(NX_SECURE_ENABLE_DTLS)

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

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&ip_0);
    show_error_message_if_fail(NX_SUCCESS == status);

    nx_secure_tls_initialize();
    nx_secure_dtls_initialize();
    
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
NXD_ADDRESS server_address;
NX_PARAMETER_NOT_USED(thread_input);


    /* Address of remote server. */
    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = REMOTE_IP_ADDRESS_NUMBER;
    print_error_message( "remote ip address number %lu, remote ip address string %s.\n", REMOTE_IP_ADDRESS_NUMBER, REMOTE_IP_ADDRESS_STRING);
    
    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    /* Create a socket. */
    status =  nx_udp_socket_create(&ip_0, &udp_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 5);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);
    
    /* Setup this thread to bind to a port.  */
    status =  nx_udp_socket_bind(&udp_socket, 0, NX_NO_WAIT);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Create a DTLS session. */
    status =  nx_secure_dtls_session_create(&dtls_session,
                                            &nx_crypto_tls_ciphers,
                                            crypto_metadata,
                                            sizeof(crypto_metadata),
                                            tls_packet_buffer,
                                            sizeof(tls_packet_buffer),
                                            1,
                                            cert_buffer,
                                            sizeof(cert_buffer));
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nx_secure_x509_certificate_initialize(&trusted_certificate, cert_der, cert_der_len,
                                                   NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    status = nx_secure_dtls_session_trusted_certificate_add(&dtls_session, &trusted_certificate, 1);
    exit_if_fail(NX_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Wait for the semaphore. */
    tls_test_semaphore_wait(semaphore_echo_server_prepared);
    tx_thread_sleep(100);

    status = nx_icmp_ping(&ip_0, REMOTE_IP_ADDRESS_NUMBER, "abcdefg", 7, &send_packet, 10 * NX_IP_PERIODIC_RATE);
    exit_if_fail(NX_SUCCESS == status, status);
    nx_packet_release(send_packet);

    /* Attempt to connect the echo server. */
    print_error_message("DTLS client session starting...\n");
    status = nx_secure_dtls_client_session_start(&dtls_session, &udp_socket, &server_address, DEVICE_SERVER_PORT, 20 * NX_IP_PERIODIC_RATE);
    exit_if_fail(NX_SUCCESS == status, status);
    
    /* Send some data to be echoed by the OpenSSL s_server echo instance. */
    status = nx_secure_dtls_packet_allocate(&dtls_session, &pool_0, &send_packet, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, 2);

    /* Append application to the allocated packet. */
    status = nx_packet_data_append(send_packet, "hello\n", 6, &pool_0, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, 3);

    /* Send "hello" message. */
    print_error_message("DTLS client session sending...\n");
    status = nx_secure_dtls_client_session_send(&dtls_session, send_packet);
    exit_if_fail(NX_SUCCESS == status, 4);

#if 0
    /* Receive the echoed and reversed data, and print it out. */
    print_error_message("DTLS client session receving...\n");
    status = nx_secure_dtls_session_receive(&dtls_session, &receive_packet, NX_WAIT_FOREVER);
    exit_if_fail(NX_SUCCESS == status, 5);

    /* Extract data received from server. */
    status = nx_packet_data_extract_offset(receive_packet, 0, receive_buffer, 100, &bytes);
    exit_if_fail(NX_SUCCESS == status, 6);

    /* Check the reverse text received from openssl server. */
    exit_if_fail('o' == ((CHAR*)receive_buffer)[0], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail('l' == ((CHAR*)receive_buffer)[1], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail('l' == ((CHAR*)receive_buffer)[2], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail('e' == ((CHAR*)receive_buffer)[3], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail('h' == ((CHAR*)receive_buffer)[4], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail('\n' == ((CHAR*)receive_buffer)[5], TLS_TEST_UNKNOWN_TYPE_ERROR);
    exit_if_fail(6 == bytes, 7);
#endif

    /* End the DTLS session. This is required to properly shut down the DTLS connection. */
    print_error_message("DTLS client session end.\n");
    nx_secure_dtls_session_end(&dtls_session, NX_NO_WAIT);

    /* Delete the DTLS session. */
    status = nx_secure_dtls_session_delete(&dtls_session);
    exit_if_fail(NX_SUCCESS == status, 8);

    /* Unbind the UDP socket from our port. */
    status = nx_udp_socket_unbind(&udp_socket);
    exit_if_fail(NX_SUCCESS == status, 9);

    /* Delete the UDP socket instance to clean up. */
    status = nx_udp_socket_delete(&udp_socket);
    exit_if_fail(NX_SUCCESS == status, 10);

    exit(0);
}
