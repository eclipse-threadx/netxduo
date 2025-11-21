/* This test concentrates on DTLS connections.  */

#include   "nx_api.h"
#include   "nx_secure_dtls_api.h"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"
#include   "nx_udp.h"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_DTLS)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            (2048 + sizeof(NX_SECURE_X509_CERT))
#define PSK                         "simple_psk"
#define PSK_IDENTITY                "psk_indentity"
#define PSK_HINT                    "psk_hint"
#define SERVER_PORT                 4433
#define WRONG_SERVER_PORT           4434
#define CLIENT_PORT                 5002


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static TX_THREAD                thread_1;
static NX_PACKET_POOL           pool_0;
static NX_PACKET_POOL           pool_1;
static NX_IP                    ip_0;
static NX_IP                    ip_1;
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
#endif /* FEATURE_NX_IPV6 */
static UINT                     error_counter;

static NX_UDP_SOCKET            client_socket_0;
static NX_SECURE_DTLS_SESSION   dtls_client_session_0;
static NX_SECURE_DTLS_SERVER    dtls_server_0;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_SECURE_X509_CERT      server_local_certificate;
extern const NX_SECURE_TLS_CRYPTO
                                nx_crypto_tls_ciphers;

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    pool_1_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_1_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_1_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache0[ARP_CACHE_SIZE];
static ULONG                    arp_cache1[ARP_CACHE_SIZE];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];

static UCHAR                    tls_packet_buffer[2][4000];

static UINT                     server_running;

/* Session buffer for DTLS server. Must be equal to the size of NX_SECURE_DTLS_SESSION times the
   number of desired DTLS sessions. */
static UCHAR                    server_session_buffer[sizeof(NX_SECURE_DTLS_SESSION)];

/* Define thread prototypes.  */
static VOID udp_packet_filter_bad_helloverify(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static VOID udp_packet_filter_bad_serverhello_length(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static VOID udp_packet_filter_bad_serverhello_version(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static VOID udp_packet_filter_bad_serverhello_ciphersuite(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static VOID udp_packet_filter_bad_serverhello_compression(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static VOID udp_packet_filter_bad_certificate_total_length(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static VOID udp_packet_filter_bad_certificate_1_length(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static VOID test_dtls_helloverify_after_handshake_server();
static VOID test_dtls_helloverify_after_handshake_client();
static VOID test_dtls_no_renegotiate_server();
static VOID test_dtls_no_renegotiate_client();
static VOID test_dtls_handshake_header_server();
static VOID test_dtls_handshake_header_client();
static VOID test_dtls_handshake_fragment_len_server();
static VOID test_dtls_handshake_fragment_len_client();
static VOID test_dtls_handshake_buffer_pointer_server();
static VOID test_dtls_handshake_buffer_pointer_client();
static VOID test_dtls_handshake_fragment_len2_server();
static VOID test_dtls_handshake_fragment_len2_client();

static VOID (*packet_filters[])(NX_IP *ip_ptr, NX_PACKET *packet_ptr) = 
{
    udp_packet_filter_bad_helloverify,
    udp_packet_filter_bad_serverhello_length,
    udp_packet_filter_bad_serverhello_version,
    udp_packet_filter_bad_serverhello_ciphersuite,
    udp_packet_filter_bad_serverhello_compression,
    udp_packet_filter_bad_certificate_1_length,
};
static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern VOID    _nx_udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

static TX_SEMAPHORE            semaphore_receive;
static TX_SEMAPHORE            semaphore_connect;

typedef struct
{
    VOID(*test_server)();
    VOID(*test_client)();

} DTLS_HANDSHAKE_TEST_DATA;

static DTLS_HANDSHAKE_TEST_DATA test_data[] =
{
    {test_dtls_handshake_fragment_len2_server, test_dtls_handshake_fragment_len2_client},
    {test_dtls_helloverify_after_handshake_server, test_dtls_helloverify_after_handshake_client},
    {test_dtls_no_renegotiate_server, test_dtls_no_renegotiate_client},
    {test_dtls_handshake_header_server, test_dtls_handshake_header_client},
    {test_dtls_handshake_fragment_len_server, test_dtls_handshake_fragment_len_client},
    {test_dtls_handshake_buffer_pointer_server, test_dtls_handshake_buffer_pointer_client},

};

/* Define what the initial system looks like.  */


static VOID _error_print(char *file, unsigned int line)
{
    printf("Error at %s:%d\n", file, line);
    error_counter++;
}
#define ERROR_COUNTER() _error_print(__FILE__, __LINE__);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_handshake_fail_test_application_define(void *first_unused_memory)
#endif
{
UINT     status;
CHAR    *pointer;


    error_counter = 0;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&thread_0, "thread 0", ntest_0_entry, 0,
                     thread_0_stack, sizeof(thread_0_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Create the client thread.  */
    tx_thread_create(&thread_1, "thread 1", ntest_1_entry, 0,
                     thread_1_stack, sizeof(thread_1_stack),
                     8, 8, TX_NO_TIME_SLICE, TX_AUTO_START);

    tx_semaphore_create(&semaphore_receive, "semaphore receive", 0);
    tx_semaphore_create(&semaphore_connect, "semaphore connect", 0);

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE,
                                    pool_0_memory, PACKET_POOL_SIZE);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", PACKET_SIZE,
        pool_1_memory, PACKET_POOL_SIZE);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL,
                          &pool_0, _nx_ram_network_driver_1500,
                          ip_0_stack, sizeof(ip_0_stack), 1);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Create another IP instance.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL,
                          &pool_1, _nx_ram_network_driver_1500,
                          ip_1_stack, sizeof(ip_1_stack), 1);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (VOID *)arp_cache0, sizeof(arp_cache0));
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_1, (VOID *)arp_cache1, sizeof(arp_cache1));
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    if (status)
    {
        ERROR_COUNTER();
    }
    status = nx_udp_enable(&ip_1);
    if (status)
    {
        ERROR_COUNTER();
    }


    nx_secure_tls_initialize();
    nx_secure_dtls_initialize();

}

/* Test client handshake with bad hello verify request. */
static VOID udp_packet_filter_bad_helloverify(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
UCHAR *data;
UINT checksum;

    data = packet_ptr -> nx_packet_prepend_ptr;

    if (data[8] == NX_SECURE_TLS_HANDSHAKE && data[21] == NX_SECURE_TLS_HELLO_VERIFY_REQUEST)
    {
        checksum = (data[6] << 8) + data[7];
        checksum = checksum + data[35];
        /* Modify cookie length to invalid value.  */
        data[35] = 255;
        /* Fix udp checksum. */
        checksum = checksum - data[35];
        data[6] = (UCHAR)((checksum & 0xFF00) >> 8);
        data[7] = (UCHAR)(checksum & 0xFF);

    }
    _nx_udp_packet_receive(ip_ptr, packet_ptr);
}

/* Test client handshake with wrong server hello message length. */
static VOID udp_packet_filter_bad_serverhello_length(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
    UCHAR *data;
    UINT checksum;

    data = packet_ptr->nx_packet_prepend_ptr;

    if (data[8] == NX_SECURE_TLS_HANDSHAKE && data[21] == NX_SECURE_TLS_SERVER_HELLO)
    {
        checksum = (data[6] << 8) + data[7];

        /* Modify record length. */
        checksum += data[20] << 8;
        data[20] -= 1;
        checksum -= data[20] << 8;

        /* Modify message length. */
        checksum += data[24] << 8;
        data[24] -= 1;
        checksum -= data[24] << 8;

        /* Modify fragment length. */
        checksum += data[32] << 8;
        data[32] -= 1;
        checksum -= data[32] << 8;

        /* Modify udp length. */
        checksum += 2;
        data[5] -= 1;
        packet_ptr->nx_packet_length--;
        packet_ptr->nx_packet_append_ptr--;

        data[6] = (UCHAR)((checksum & 0xFF00) >> 8);
        data[7] = (UCHAR)(checksum & 0xFF);
    }
    _nx_udp_packet_receive(ip_ptr, packet_ptr);
}

/* Test client handshake with wrong version. */
static VOID udp_packet_filter_bad_serverhello_version(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
    UCHAR *data;
    UINT checksum;

    data = packet_ptr->nx_packet_prepend_ptr;

    if (data[8] == NX_SECURE_TLS_HANDSHAKE && data[21] == NX_SECURE_TLS_SERVER_HELLO)
    {
        checksum = (data[6] << 8) + data[7];

        /* Modify version. */
        checksum += data[33];
        data[33] = 1;
        checksum -= data[33];

        data[6] = (UCHAR)((checksum & 0xFF00) >> 8);
        data[7] = (UCHAR)(checksum & 0xFF);
    }
    _nx_udp_packet_receive(ip_ptr, packet_ptr);
}

/* Test client handshake with bad cipher suite. */
static VOID udp_packet_filter_bad_serverhello_ciphersuite(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
    UCHAR *data;
    UINT checksum;

    data = packet_ptr->nx_packet_prepend_ptr;

    if (data[8] == NX_SECURE_TLS_HANDSHAKE && data[21] == NX_SECURE_TLS_SERVER_HELLO)
    {
        checksum = (data[6] << 8) + data[7];

        /* Modify cipher suite. */
        checksum += data[69];
        data[69] = 0;
        checksum -= data[69];

        data[6] = (UCHAR)((checksum & 0xFF00) >> 8);
        data[7] = (UCHAR)(checksum & 0xFF);
    }
    _nx_udp_packet_receive(ip_ptr, packet_ptr);
}

/* Test client handshake with bad compression method. */
static VOID udp_packet_filter_bad_serverhello_compression(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
    UCHAR *data;
    UINT checksum;

    data = packet_ptr->nx_packet_prepend_ptr;

    if (data[8] == NX_SECURE_TLS_HANDSHAKE && data[21] == NX_SECURE_TLS_SERVER_HELLO)
    {
        checksum = (data[6] << 8) + data[7];

        /* Modify compression method. */
        checksum += data[70] << 8;
        data[70] = 10;
        checksum -= data[70] << 8;

        data[6] = (UCHAR)((checksum & 0xFF00) >> 8);
        data[7] = (UCHAR)(checksum & 0xFF);
    }
    _nx_udp_packet_receive(ip_ptr, packet_ptr);
}

/* Test client handshake with wrong certificate total length. */
static VOID udp_packet_filter_bad_certificate_total_length(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
    UCHAR *data;
    UINT checksum;

    data = packet_ptr->nx_packet_prepend_ptr;

    if (data[8] == NX_SECURE_TLS_HANDSHAKE && data[21] == NX_SECURE_TLS_CERTIFICATE_MSG)
    {
        checksum = (data[6] << 8) + data[7];

        /* Modify certificate length. */
        checksum += data[35];
        data[35] += 5;
        checksum -= data[35];

        data[6] = (UCHAR)((checksum & 0xFF00) >> 8);
        data[7] = (UCHAR)(checksum & 0xFF);
    }
    _nx_udp_packet_receive(ip_ptr, packet_ptr);
}

/* Test client handshake with wrong certificate length. */
static VOID udp_packet_filter_bad_certificate_1_length(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
    UCHAR *data;
    UINT checksum;

    data = packet_ptr->nx_packet_prepend_ptr;

    if (data[8] == NX_SECURE_TLS_HANDSHAKE && data[21] == NX_SECURE_TLS_CERTIFICATE_MSG)
    {
        checksum = (data[6] << 8) + data[7];

        /* Modify individual certificate length. */
        checksum += data[37];
        data[37] += 2;
        checksum -= data[37];

        data[6] = (UCHAR)((checksum & 0xFF00) >> 8);
        data[7] = (UCHAR)(checksum & 0xFF);
    }
    _nx_udp_packet_receive(ip_ptr, packet_ptr);
}

static VOID client_dtls_setup(NX_SECURE_DTLS_SESSION *dtls_session_ptr)
{
UINT status;

    status = nx_secure_dtls_session_create(dtls_session_ptr,
                                           &nx_crypto_tls_ciphers,
                                           client_metadata,
                                           sizeof(client_metadata), tls_packet_buffer[0],
                                           sizeof(tls_packet_buffer[0]), 1, client_cert_buffer,
                                           sizeof(client_cert_buffer));
    if (status)
    {
        ERROR_COUNTER();
    }



    status = nx_secure_x509_certificate_initialize(&client_trusted_ca,
                                                   test_ca_cert_der,
                                                   test_ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_dtls_session_trusted_certificate_add(dtls_session_ptr, &client_trusted_ca, 1);
    if (status)
    {
        ERROR_COUNTER();
    }



#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) || defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
    /* For PSK ciphersuites, add a PSK and identity hint.  */
    nx_secure_dtls_psk_add(dtls_session_ptr, PSK, strlen(PSK),
                         PSK_IDENTITY, strlen(PSK_IDENTITY), PSK_HINT, strlen(PSK_HINT));
#endif
}

/* Notification flags for DTLS server connect/receive. */
static UINT server_connect_notify_flag = NX_FALSE;
static UINT server_receive_notify_flag = NX_FALSE;

NX_SECURE_DTLS_SESSION *connect_session;
NX_SECURE_DTLS_SESSION *receive_session;

/* Connect notify callback for DTLS server - notifies the application thread that
   a DTLS connection is ready to kickoff a handshake. */
static UINT server_connect_notify(NX_SECURE_DTLS_SESSION *dtls_session, NXD_ADDRESS *ip_address, UINT port)
{
    /* Drop connections if one is in progress. Better way would be to have
     * an array of pointers to DTLS sessions and check the port/IP address
     * to see if it's an existing connection. Application thread then loops
     * through array servicing each session.
     */
    if (server_connect_notify_flag == NX_FALSE)
    {
        server_connect_notify_flag = NX_TRUE;
        connect_session = dtls_session;
        tx_semaphore_put(&semaphore_connect);
    }

    return(NX_SUCCESS);
}

/* Receive notify callback for DTLS server - notifies the application thread that
   we have received a DTLS record over an established DTLS session. */
static UINT server_receive_notify(NX_SECURE_DTLS_SESSION *dtls_session)
{

    /* Drop records if more come in while processing one. Better would be to
       service each session in a queue. */
    if (server_receive_notify_flag == NX_FALSE)
    {
        server_receive_notify_flag = NX_TRUE;
        receive_session = dtls_session;
        tx_semaphore_put(&semaphore_receive);
    }

    return(NX_SUCCESS);
}

static VOID server_dtls_setup(NX_SECURE_DTLS_SERVER *dtls_server_ptr)
{
UINT status;

    status = nx_secure_dtls_server_create(dtls_server_ptr, &ip_0, SERVER_PORT, NX_IP_PERIODIC_RATE,
                                          server_session_buffer, sizeof(server_session_buffer),
                                          &nx_crypto_tls_ciphers, server_metadata, sizeof(server_metadata),
                                          tls_packet_buffer[1], sizeof(tls_packet_buffer[1]),
                                          server_connect_notify, server_receive_notify);
    if (status)
    {
        ERROR_COUNTER();
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   test_device_cert_der, test_device_cert_der_len,
                                                   NX_NULL, 0, test_device_cert_key_der,
                                                   test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_dtls_server_local_certificate_add(dtls_server_ptr, &server_local_certificate, 1);
    if (status)
    {
        ERROR_COUNTER();
    }
}

static void ntest_0_entry(ULONG thread_input)
{
UINT status;
UINT i;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Handshake Fail Test...........................");

    for (i = 0; i < sizeof(test_data) / sizeof(DTLS_HANDSHAKE_TEST_DATA); i++)
    {
        test_data[i].test_server();
    }

    while (1)
    {

        server_dtls_setup(&dtls_server_0);

        /* Start DTLS session. */
        status = nx_secure_dtls_server_start(&dtls_server_0);
        if (status)
        {
            ERROR_COUNTER();
        }

        server_running = 1;

        /* Wait for connection attempt. */
        tx_semaphore_get(&semaphore_connect, NX_IP_PERIODIC_RATE);
        server_connect_notify_flag = NX_FALSE;

        status = nx_secure_dtls_server_session_start(connect_session, 1 * NX_IP_PERIODIC_RATE);
        if (!status)
        {
            ERROR_COUNTER();
        }

        /* Shutdown DTLS server. */
        nx_secure_dtls_server_stop(&dtls_server_0);

        /* Delete server. */
        nx_secure_dtls_server_delete(&dtls_server_0);

        server_running = 0;
        tx_thread_suspend(&thread_0);
    }

}

static void ntest_1_entry(ULONG thread_input)
{
UINT i;
UINT status;
NXD_ADDRESS server_address;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 4);

    /* Create UDP socket. */
    status = nx_udp_socket_create(&ip_1, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, 0x80, 5);
    if (status)
    {
        ERROR_COUNTER();
    }

    for (i = 0; i < sizeof(test_data) / sizeof(DTLS_HANDSHAKE_TEST_DATA); i++)
    {
        test_data[i].test_client();
    }

    for (i = 0; i < sizeof(packet_filters) / sizeof(packet_filters[0]); i++)
    {
        ip_1.nx_ip_udp_packet_receive = packet_filters[i];

        status = nx_udp_socket_bind(&client_socket_0, CLIENT_PORT + i, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        client_dtls_setup(&dtls_client_session_0);

        /* Start DTLS session. */
        status = nx_secure_dtls_client_session_start(&dtls_client_session_0, &client_socket_0, &server_address, SERVER_PORT, 1 * NX_IP_PERIODIC_RATE);
        if (!status)
        {
            ERROR_COUNTER();
        }


        _nx_secure_dtls_session_end(&dtls_client_session_0, NX_NO_WAIT);

        _nx_secure_dtls_session_delete(&dtls_client_session_0);

        status = nx_udp_socket_unbind(&client_socket_0);
        if (status)
        {
            ERROR_COUNTER();
        }

        while (server_running)
        {
            tx_thread_sleep(1);
        }
        tx_thread_resume(&thread_0);
    }

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}

static UCHAR dtls_helloverifyreq[] = {
    0xfe, 0xff, 0x14, 0x6b, 0x8b, 0x45, 0x67, 0x32, 0x7b, 0x23, 0xc6,
    0x64, 0x3c, 0x98, 0x69, 0x66, 0x33, 0x48, 0x73, 0x74, 0xb0, 0xdc, 0x51
};

static VOID test_dtls_helloverify_after_handshake_server()
{
UINT status;
NX_PACKET *send_packet;

    server_dtls_setup(&dtls_server_0);

    /* Start DTLS session. */
    status = nx_secure_dtls_server_start(&dtls_server_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    server_running = 1;

    /* Wait for connection attempt. */
    tx_semaphore_get(&semaphore_connect, NX_IP_PERIODIC_RATE);
    server_connect_notify_flag = NX_FALSE;


    status = nx_secure_dtls_server_session_start(connect_session, 1 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Prepare packet to send HelloVerifyRequest. */
    status = _nx_secure_dtls_allocate_handshake_packet(connect_session, connect_session -> nx_secure_dtls_tls_session.nx_secure_tls_packet_pool, &send_packet, NX_IP_PERIODIC_RATE);

    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_data_append(send_packet, dtls_helloverifyreq, sizeof(dtls_helloverifyreq),
                                   &pool_0, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Send HelloVerifyRequest. */
    status = _nx_secure_dtls_send_handshake_record(connect_session, send_packet, NX_SECURE_TLS_HELLO_VERIFY_REQUEST, NX_IP_PERIODIC_RATE, 0);
    if (status)
    {
        ERROR_COUNTER();
    }

    tx_mutex_put(&_nx_secure_tls_protection);

    server_receive_notify_flag = NX_FALSE;

    /* Shutdown DTLS server. */
    nx_secure_dtls_server_stop(&dtls_server_0);

    /* Delete server. */
    nx_secure_dtls_server_delete(&dtls_server_0);

    server_running = 0;
    tx_thread_suspend(&thread_0);

}


static VOID test_dtls_helloverify_after_handshake_client()
{
UINT status;
NXD_ADDRESS server_address;
NX_PACKET *packet_ptr;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 4);

    status = nx_udp_socket_bind(&client_socket_0, CLIENT_PORT - 5, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    client_dtls_setup(&dtls_client_session_0);

    /* Start DTLS session. */
    status = nx_secure_dtls_client_session_start(&dtls_client_session_0, &client_socket_0, &server_address, SERVER_PORT, 2 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_dtls_session_receive(&dtls_client_session_0,
                                            &packet_ptr, NX_WAIT_FOREVER);
    if (status != NX_INVALID_PACKET)
    {
        ERROR_COUNTER();
    }

    _nx_secure_dtls_session_end(&dtls_client_session_0, NX_NO_WAIT);

    _nx_secure_dtls_session_delete(&dtls_client_session_0);

    status = nx_udp_socket_unbind(&client_socket_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    while (server_running)
    {
        tx_thread_sleep(1);
    }
    tx_thread_resume(&thread_0);

}


static VOID test_dtls_no_renegotiate_server()
{
UINT status;
NX_PACKET *packet_ptr;

    server_dtls_setup(&dtls_server_0);

    /* Start DTLS session. */
    status = nx_secure_dtls_server_start(&dtls_server_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    server_running = 1;

    /* Wait for connection attempt. */
    tx_semaphore_get(&semaphore_connect, NX_IP_PERIODIC_RATE);
    server_connect_notify_flag = NX_FALSE;

    status = nx_secure_dtls_server_session_start(connect_session, 1 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Wait for records to be received. */
    tx_semaphore_get(&semaphore_receive, NX_IP_PERIODIC_RATE);

    status = nx_secure_dtls_session_receive(receive_session,
                                            &packet_ptr, NX_WAIT_FOREVER);
    if (status != NX_SECURE_TLS_NO_RENEGOTIATION_ERROR)
    {
        ERROR_COUNTER();
    }

    server_receive_notify_flag = NX_FALSE;

    /* Shutdown DTLS server. */
    nx_secure_dtls_server_stop(&dtls_server_0);

    /* Delete server. */
    nx_secure_dtls_server_delete(&dtls_server_0);

    server_running = 0;
    tx_thread_suspend(&thread_0);

}
static UCHAR dtls_clienthello[] = {
  0xfe, 0xfd, 0xbf, 0x98, 0x8b, 0x26, 0x5c, 0x31, 0x7a, 0xb9, 0xd4, 0x15,
  0xcc, 0x9f, 0xd9, 0xe2, 0xe2, 0x06, 0x51, 0x4c, 0x10, 0xbb, 0xcc, 0xfc,
  0x1e, 0xb5, 0xab, 0xf9, 0x80, 0x2e, 0x2e, 0xa1, 0x34, 0x57, 0x00, 0x00,
  0x00, 0x38, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8,
  0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28,
  0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14,
  0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c,
  0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff, 0x01, 0x00,
  0x00, 0x6e, 0x00, 0x00, 0x00, 0x12, 0x00, 0x10, 0x00, 0x00, 0x0d, 0x31,
  0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x32, 0x30, 0x30, 0x2e, 0x31,
  0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c,
  0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18,
  0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
  0x00, 0x0d, 0x00, 0x30, 0x00, 0x2e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
  0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04,
  0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03,
  0x02, 0x03, 0x03, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02, 0x02, 0x04, 0x02,
  0x05, 0x02, 0x06, 0x02
};

static VOID test_dtls_no_renegotiate_client()
{
UINT status;
NXD_ADDRESS server_address;
NX_PACKET *send_packet;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 4);

    status = nx_udp_socket_bind(&client_socket_0, CLIENT_PORT - 1, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    client_dtls_setup(&dtls_client_session_0);

    /* Start DTLS session. */
    status = nx_secure_dtls_client_session_start(&dtls_client_session_0, &client_socket_0, &server_address, SERVER_PORT, 1 * NX_IP_PERIODIC_RATE);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Prepare packet to send ClientHello. */
    status = _nx_secure_dtls_allocate_handshake_packet(&dtls_client_session_0, dtls_client_session_0.nx_secure_dtls_tls_session.nx_secure_tls_packet_pool, &send_packet, NX_IP_PERIODIC_RATE);

    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_data_append(send_packet, dtls_clienthello, sizeof(dtls_clienthello),
                               &pool_0, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Test renegotiate by sending ClientHello. */
    status = _nx_secure_dtls_send_handshake_record(&dtls_client_session_0, send_packet, NX_SECURE_TLS_CLIENT_HELLO, NX_IP_PERIODIC_RATE, 0);
    if (status)
    {
        ERROR_COUNTER();
    }

    _nx_secure_dtls_session_end(&dtls_client_session_0, NX_NO_WAIT);

    _nx_secure_dtls_session_delete(&dtls_client_session_0);

    status = nx_udp_socket_unbind(&client_socket_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    while (server_running)
    {
        tx_thread_sleep(1);
    }
    tx_thread_resume(&thread_0);

}
static UCHAR dtls_bad_handshake_header[] = {
  0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06,
  0x02, 0x00, 0x0b, 0x4d, 0x00, 0x01,
};

static VOID test_dtls_handshake_header_server()
{
UINT status;
NX_UDP_SOCKET server_udp_socket;
NXD_ADDRESS client_address;
NX_PACKET *send_packet;
NX_PACKET *receive_packet;

    server_running = 1;

    client_address.nxd_ip_version = NX_IP_VERSION_V4;
    client_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);

    status = nx_udp_socket_create(&ip_0, &server_udp_socket, "DTLS Server",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_PERIODIC_RATE, 8192);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_bind(&server_udp_socket, SERVER_PORT,
                                NX_IP_PERIODIC_RATE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_allocate(&pool_0, &send_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_data_append(send_packet, dtls_bad_handshake_header, sizeof(dtls_bad_handshake_header),
                                   &pool_0, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_receive(&server_udp_socket, &receive_packet, 2 * NX_IP_PERIODIC_RATE);
    if (!status)
    {
        nx_packet_release(receive_packet);
    }

    status = _nxd_udp_socket_send(&server_udp_socket, send_packet,
                                  &client_address,
                                  CLIENT_PORT - 2);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_unbind(&server_udp_socket);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_delete(&server_udp_socket);
    if (status)
    {
        ERROR_COUNTER();
    }

    server_running = 0;
    tx_thread_suspend(&thread_0);

}

static VOID test_dtls_handshake_header_client()
{
UINT status;
NXD_ADDRESS server_address;
NX_PACKET *send_packet;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 4);

    status = nx_udp_socket_bind(&client_socket_0, CLIENT_PORT - 2, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    client_dtls_setup(&dtls_client_session_0);

    /* Start DTLS session. */
    status = nx_secure_dtls_client_session_start(&dtls_client_session_0, &client_socket_0, &server_address, SERVER_PORT, 2 * NX_IP_PERIODIC_RATE);
    if (status != NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH)
    {
        ERROR_COUNTER();
    }

    _nx_secure_dtls_session_end(&dtls_client_session_0, NX_NO_WAIT);

    _nx_secure_dtls_session_delete(&dtls_client_session_0);

    status = nx_udp_socket_unbind(&client_socket_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    while (server_running)
    {
        tx_thread_sleep(1);
    }
    tx_thread_resume(&thread_0);

}

static UCHAR dtls_bad_handshake_fragment_len[] = {
  0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0e,
  0x02, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0xfe, 0xfd
};

static VOID test_dtls_handshake_fragment_len_server()
{
UINT status;
NX_UDP_SOCKET server_udp_socket;
NXD_ADDRESS client_address;
NX_PACKET *send_packet;

    server_running = 1;

    client_address.nxd_ip_version = NX_IP_VERSION_V4;
    client_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);

    status = nx_udp_socket_create(&ip_0, &server_udp_socket, "DTLS Server",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_PERIODIC_RATE, 8192);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_bind(&server_udp_socket, SERVER_PORT,
                                NX_IP_PERIODIC_RATE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_allocate(&pool_0, &send_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_data_append(send_packet, dtls_bad_handshake_fragment_len, sizeof(dtls_bad_handshake_fragment_len),
                                   &pool_0, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    status = _nxd_udp_socket_send(&server_udp_socket, send_packet,
                                  &client_address,
                                  CLIENT_PORT - 3);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_unbind(&server_udp_socket);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_delete(&server_udp_socket);
    if (status)
    {
        ERROR_COUNTER();
    }

    server_running = 0;
    tx_thread_suspend(&thread_0);

}

static VOID test_dtls_handshake_fragment_len_client()
{
    UINT status;
    NXD_ADDRESS server_address;
    NX_PACKET *send_packet;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 4);

    status = nx_udp_socket_bind(&client_socket_0, CLIENT_PORT - 3, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    client_dtls_setup(&dtls_client_session_0);

    /* Start DTLS session. */
    status = nx_secure_dtls_client_session_start(&dtls_client_session_0, &client_socket_0, &server_address, SERVER_PORT, NX_WAIT_FOREVER);
    if (status != NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH)
    {
        ERROR_COUNTER();
    }

    _nx_secure_dtls_session_end(&dtls_client_session_0, NX_NO_WAIT);

    _nx_secure_dtls_session_delete(&dtls_client_session_0);

    status = nx_udp_socket_unbind(&client_socket_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    while (server_running)
    {
        tx_thread_sleep(1);
    }
    tx_thread_resume(&thread_0);

}

static UCHAR dtls_handshake_buffer_pointer[] = {
  0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c,

  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00,
  0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x10, 0x00

};

static VOID test_dtls_handshake_buffer_pointer_server()
{
    UINT status;
    NX_UDP_SOCKET server_udp_socket;
    NXD_ADDRESS client_address;
    NX_PACKET *send_packet;
    NX_PACKET *receive_packet;

    server_running = 1;

    client_address.nxd_ip_version = NX_IP_VERSION_V4;
    client_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);

    status = nx_udp_socket_create(&ip_0, &server_udp_socket, "DTLS Server",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_PERIODIC_RATE, 8192);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_bind(&server_udp_socket, SERVER_PORT,
                                NX_IP_PERIODIC_RATE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_allocate(&pool_0, &send_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_data_append(send_packet, dtls_handshake_buffer_pointer, sizeof(dtls_handshake_buffer_pointer),
                                   &pool_0, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_receive(&server_udp_socket, &receive_packet, 2 * NX_IP_PERIODIC_RATE);
    if (!status)
    {
        nx_packet_release(receive_packet);
    }

    status = _nxd_udp_socket_send(&server_udp_socket, send_packet,
                                  &client_address,
                                  CLIENT_PORT - 4);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_unbind(&server_udp_socket);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_delete(&server_udp_socket);
    if (status)
    {
        ERROR_COUNTER();
    }

    server_running = 0;
    tx_thread_suspend(&thread_0);

}

static VOID test_dtls_handshake_buffer_pointer_client()
{
    UINT status;
    NXD_ADDRESS server_address;
    NX_PACKET *send_packet;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 4);

    status = nx_udp_socket_bind(&client_socket_0, CLIENT_PORT - 4, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    client_dtls_setup(&dtls_client_session_0);

    /* Start DTLS session. */
    status = nx_secure_dtls_client_session_start(&dtls_client_session_0, &client_socket_0, &server_address, SERVER_PORT, 2 * NX_IP_PERIODIC_RATE);
    if (status != NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL)
    {
        ERROR_COUNTER();
    }

    _nx_secure_dtls_session_end(&dtls_client_session_0, NX_NO_WAIT);

    _nx_secure_dtls_session_delete(&dtls_client_session_0);

    status = nx_udp_socket_unbind(&client_socket_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    while (server_running)
    {
        tx_thread_sleep(1);
    }
    tx_thread_resume(&thread_0);

}


static VOID test_dtls_handshake_fragment_len2_server()
{
UINT status;
NX_PACKET *packet_ptr;

    server_dtls_setup(&dtls_server_0);

    /* Start DTLS session. */
    status = nx_secure_dtls_server_start(&dtls_server_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    server_running = 1;

    /* Wait for connection attempt. */
    tx_semaphore_get(&semaphore_connect, NX_IP_PERIODIC_RATE);
    server_connect_notify_flag = NX_FALSE;

    status = nx_secure_dtls_server_session_start(connect_session, 1 * NX_IP_PERIODIC_RATE);
    if (status != NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH)
    {
        ERROR_COUNTER();
    }

    /* Shutdown DTLS server. */
    nx_secure_dtls_server_stop(&dtls_server_0);

    /* Delete server. */
    nx_secure_dtls_server_delete(&dtls_server_0);

    server_running = 0;
    tx_thread_suspend(&thread_0);

}
static UCHAR dtls_bad_handshake_fragment_len2[] = {
  0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e,
  0x01, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0xfe, 0xfd
};
static VOID test_dtls_handshake_fragment_len2_client()
{
UINT status;
NXD_ADDRESS server_address;
NX_PACKET *send_packet;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 4);

    status = nx_udp_socket_bind(&client_socket_0, CLIENT_PORT - 6, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_allocate(&pool_0, &send_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_data_append(send_packet, dtls_bad_handshake_fragment_len2, sizeof(dtls_bad_handshake_fragment_len2),
                                   &pool_0, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }


    status = _nxd_udp_socket_send(&client_socket_0, send_packet,
                                  &server_address,
                                  SERVER_PORT);
    if (status)
    {
        ERROR_COUNTER();
    }


    status = nx_udp_socket_unbind(&client_socket_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    while (server_running)
    {
        tx_thread_sleep(1);
    }
    tx_thread_resume(&thread_0);

}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_handshake_fail_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Handshake Fail Test...........................N/A\n");
    test_control_return(3);
}
#endif
