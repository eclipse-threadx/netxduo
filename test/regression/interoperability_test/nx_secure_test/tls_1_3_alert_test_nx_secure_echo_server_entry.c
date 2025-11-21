/* This test concentrates on TLS ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA. The client certificate is require. */
#include "tls_test_frame.h"

#if !defined (NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && (NX_SECURE_TLS_TLS_1_3_ENABLED)
#include   "nx_crypto_ecdh.h"
#include   "../../nx_secure_test/ecc_certs.c"

/* Global demo emaphore. */
extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;

/* Define the ThreadX and NetX object control blocks...  */
NX_PACKET_POOL    pool_0;
NX_IP             ip_0;  

NX_TCP_SOCKET tcp_socket;
NX_SECURE_TLS_SESSION tls_session;
NX_SECURE_X509_CERT server_local_certificate;

UCHAR tls_packet_buffer[4000];
UCHAR server_cert_buffer[2048];

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
CHAR crypto_metadata[30000]; // 2*sizeof(NX_AES) + sizeof(NX_SHA1_HMAC) + 2*sizeof(NX_CRYPTO_RSA) + (2 * (sizeof(NX_MD5) + sizeof(NX_SHA1) + sizeof(NX_SHA256)))];

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

static ULONG server_callback_plain_alert(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION *extensions, UINT num_extensions)
{

    tls_session -> nx_secure_tls_local_sequence_number[0]++;

    return(NX_SUCCESS);
}

static UCHAR client_hello[] = {
0x16, 0x03, 0x03, 0x00, 0xe3, 0x01, 0x00, 0x00, 0xdf, 0x03,
0x03, 0x00, 0x00, 0x00, 0x00, 0x25, 0x3b, 0x00, 0x00, 0x1f, 0x1e, 0x00, 0x00, 0x5d, 0x6e, 0x00,
0x00, 0xd4, 0x1a, 0x00, 0x00, 0xcb, 0x63, 0x00, 0x00, 0xfc, 0x6b, 0x00, 0x00, 0x96, 0x7f, 0x00,
0x00, 0x00, 0x00, 0x34, 0x13, 0x01, 0x13, 0x04, 0x13, 0x05, 0xc0, 0x23, 0xc0, 0x09, 0xc0, 0x0a,
0xc0, 0x27, 0xc0, 0x13, 0xc0, 0x14, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x3d, 0x00, 0x35, 0x00, 0x3c,
0x00, 0x2f, 0x00, 0x9c, 0xc0, 0x25, 0xc0, 0x04, 0xc0, 0x05, 0xc0, 0x29, 0xc0, 0x0e, 0xc0, 0x0f,
0xc0, 0x2d, 0xc0, 0x31, 0x00, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00, 0x82, 0x00, 0x0a, 0x00, 0x08,
0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x2b,
0x00, 0x07, 0x06, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x00, 0x33, 0x00, 0x47, 0x00, 0x45, 0x00,
0x17, 0x00, 0x41, 0x04, 0x35, 0x1d, 0x63, 0xce, 0x8d, 0x7a, 0xee, 0xf7, 0x39, 0xb4, 0x37, 0x0c,
0x20, 0xe2, 0xe6, 0x26, 0xe9, 0xdb, 0xc8, 0xf3, 0x58, 0x39, 0xb1, 0xa7, 0x2a, 0x06, 0xfe, 0x46,
0x85, 0xca, 0x35, 0xd8, 0xad, 0xc1, 0xc1, 0xb7, 0x7c, 0xdd, 0x8c, 0x2a, 0xe2, 0x8e, 0xf3, 0x4e,
0x61, 0x4a, 0x0e, 0xf6, 0x96, 0xbf, 0xa3, 0x9d, 0x89, 0xf5, 0xf1, 0x6f, 0x65, 0x90, 0xc3, 0xf5,
0x4e, 0x7b, 0xe6, 0xd2, 0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x01, 0x01, 0x02, 0x01, 0x04, 0x01,
0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x03, 0x03, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
};

static ULONG server_callback_second_clienthello(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION *extensions, UINT num_extensions)
{
NX_PACKET *packet_ptr;

    if (tls_session -> nx_secure_tls_server_state == 0)
    {

        /* Create ClientHello. */
        nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        nx_packet_data_append(packet_ptr, client_hello, sizeof(client_hello), &pool_0, NX_NO_WAIT);

        /* Chain the packet. */
        if (tls_session -> nx_secure_record_queue_header == NX_NULL)
        {
            tls_session -> nx_secure_record_queue_header = packet_ptr;
        }
        else
        {

            /* Link current packet. */
            tls_session -> nx_secure_record_queue_header -> nx_packet_last -> nx_packet_next = packet_ptr;
            tls_session -> nx_secure_record_queue_header -> nx_packet_last = packet_ptr -> nx_packet_last;
            tls_session -> nx_secure_record_queue_header -> nx_packet_length += packet_ptr -> nx_packet_length;
        }
    }

    return(NX_SUCCESS);
}

/* TLS Server example application thread. */
void server_thread_entry(ULONG thread_input)
{
    INT status = 0, i = 0;
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

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   ECTestServer2_der, ECTestServer2_der_len,
                                                   NX_NULL, 0, ECTestServer2_key_der,
                                                   ECTestServer2_key_der_len,
                                                   NX_SECURE_X509_KEY_TYPE_EC_DER);
    show_error_message_if_fail( NX_SUCCESS == status);

    status = nx_secure_tls_local_certificate_add(&tls_session,
                                                 &server_local_certificate);
    show_error_message_if_fail( NX_SUCCESS == status);
        
    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_0, DEVICE_SERVER_PORT, &tcp_socket, 5, NX_NULL);
    show_error_message_if_fail( NX_SUCCESS == status);

    for (i = 0; i < 2; i++)
    {

        if (i == 0)
        {
            nx_secure_tls_session_server_callback_set(&tls_session, server_callback_plain_alert);
        }
        else
        {
            nx_secure_tls_session_server_callback_set(&tls_session, server_callback_second_clienthello);
        }

        /* Post semaphore before accept sockets. */
        tls_test_semaphore_post(semaphore_echo_server_prepared);

        /* Accept a client socket connection.  */
        status = nx_tcp_server_socket_accept(&tcp_socket, NX_WAIT_FOREVER);
        exit_if_fail(NX_SUCCESS == status, 1);

        /* Start the TLS Session now that we have a connected socket. */
        status = nx_secure_tls_session_start(&tls_session, &tcp_socket, NX_WAIT_FOREVER);

        if (i == 0)
        {
            exit_if_fail(NX_SECURE_TLS_ALERT_RECEIVED == status, 2);
        }
        else
        {
            exit_if_fail(NX_SECURE_TLS_UNEXPECTED_CLIENTHELLO == status, 2);
        }

        /* End the TLS session. This is required to properly shut down the TLS connection. */
        status = nx_secure_tls_session_end(&tls_session, NX_WAIT_FOREVER);
        exit_if_fail(NX_SUCCESS == status, 3);

        /* Disconnect the TCP socket, closing the connection. */
        status = nx_tcp_socket_disconnect(&tcp_socket, NX_WAIT_FOREVER);
        exit_if_fail(NX_SUCCESS == status, 4);

        /* Unaccept the server socket.  */
        status = nx_tcp_server_socket_unaccept(&tcp_socket);
        exit_if_fail(NX_SUCCESS == status, 5);

        print_error_message("Connection %d: server unaccept, sleeping...\n", i);
        tx_thread_sleep(100);

        /* Setup server socket for listening again.  */
        status =  nx_tcp_server_socket_relisten(&ip_0, DEVICE_SERVER_PORT, &tcp_socket);
        exit_if_fail( NX_SUCCESS == status, 6);
    }

    exit(0);
}
#else

/*  Instance one test entry. */
INT nx_secure_ecc_echo_server_entry(TLS_TEST_INSTANCE* instance_ptr)
{  
    exit(TLS_TEST_NOT_AVAILABLE);
}
#endif
