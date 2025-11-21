/* This test concentrates on DTLS connections.  */

#include   "nx_api.h"
#include   "nx_secure_dtls_api.h"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"
#include   "tls_test_utility.h"

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

/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD                thread_0;
static TX_THREAD                thread_1;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
#endif /* FEATURE_NX_IPV6 */
static UINT                     error_counter;

static NX_UDP_SOCKET            client_socket_0;
static NX_UDP_SOCKET            server_socket_0;
static NX_SECURE_DTLS_SESSION   dtls_client_session_0;
static NX_SECURE_DTLS_SESSION   dtls_server_session_0;
static NX_SECURE_DTLS_SERVER    dtls_server_0;
static NX_SECURE_DTLS_SERVER    dtls_server_test;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_SECURE_X509_CERT      server_local_certificate;
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_1_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];

static UCHAR                    request_buffer[BUFFER_SIZE];
static UCHAR                    response_buffer[BUFFER_SIZE];
static UCHAR                    tls_packet_buffer[2][4000];


/* Session buffer for DTLS server. Must be equal to the size of NX_SECURE_DTLS_SESSION times the
   number of desired DTLS sessions. */
static UCHAR                    server_session_buffer[sizeof(NX_SECURE_DTLS_SESSION)];

/* Define thread prototypes.  */
static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

static TX_SEMAPHORE            semaphore_receive;
static TX_SEMAPHORE            semaphore_connect;

/* Define what the initial system looks like.  */
static VOID    ERROR_COUNTER()
{
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_error_checking_test_application_define(void *first_unused_memory)
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

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL,
                          &pool_0, _nx_ram_network_driver_1500,
                          ip_0_stack, sizeof(ip_0_stack), 1);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (VOID *)arp_cache, sizeof(arp_cache));
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

    nx_secure_tls_initialize();
    nx_secure_dtls_initialize();
}

static VOID client_dtls_setup(NX_SECURE_DTLS_SESSION *dtls_session_ptr)
{
UINT status;

    status = nx_secure_dtls_session_create(dtls_session_ptr,
                                           &nx_crypto_tls_ciphers,
                                           client_metadata,
                                           sizeof(client_metadata),
                                           tls_packet_buffer[0], sizeof(tls_packet_buffer[0]),
                                           1, client_cert_buffer, sizeof(client_cert_buffer));
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

extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

static UCHAR dtls_clienthello_bad_compression[] = {
  0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x32, 0x7b, 0x23, 0xc6, 0x64, 0x3c,
  0x98, 0x69, 0x66, 0x33, 0x48, 0x73, 0x74, 0xb0, 0xdc, 0x51, 0x19, 0x49,
  0x5c, 0xff, 0x2a, 0xe8, 0x94, 0x4a, 0x62, 0x55, 0x58, 0xec, 0x00, 0x00,
  0x00, 0x10, 0x00, 0x3d, 0x00, 0x35, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0x9c,
  0x00, 0x02, 0x00, 0x01, 0x00, 0xff, 0xff, 0x00
};

static void ntest_0_entry(ULONG thread_input)
{
UINT status;
ULONG response_length;
NX_PACKET *packet_ptr = NX_NULL, *pp1, *pp2, unused_packet;
NX_SECURE_TLS_SESSION *tls_session_ptr;
USHORT header_length;
NXD_ADDRESS server_address;
NX_PACKET_POOL unused_pool;
UINT active_value;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Error Checking Test...........................");

    /* Call APIs with invalid pointers. */
    status = nx_secure_dtls_session_create(NX_NULL, &nx_crypto_tls_ciphers, client_metadata, sizeof(client_metadata),
                                           tls_packet_buffer[1], sizeof(tls_packet_buffer[1]), 0, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);
    status = nx_secure_dtls_session_create(&dtls_server_session_0, NX_NULL, client_metadata, sizeof(client_metadata),
                                           tls_packet_buffer[1], sizeof(tls_packet_buffer[1]), 0, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);
    status = nx_secure_dtls_session_create(&dtls_server_session_0, &nx_crypto_tls_ciphers, NX_NULL, sizeof(client_metadata),
                                           tls_packet_buffer[1], sizeof(tls_packet_buffer[1]), 0, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_dtls_session_create(&dtls_server_session_0, &nx_crypto_tls_ciphers, client_metadata, sizeof(client_metadata),
                                           NX_NULL, sizeof(tls_packet_buffer[1]), 0, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);


    status = nx_secure_dtls_session_start(NX_NULL, &server_socket_0, NX_FALSE, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);
    status = nx_secure_dtls_session_start(&dtls_server_session_0, NX_NULL, NX_FALSE, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    status = nx_secure_dtls_session_send(NX_NULL, packet_ptr, &server_address, WRONG_SERVER_PORT);
    EXPECT_EQ(NX_PTR_ERROR, status);
    status = nx_secure_dtls_session_send(&dtls_client_session_0, NX_NULL, &server_address, WRONG_SERVER_PORT);
    EXPECT_EQ(NX_PTR_ERROR, status);
    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr, NX_NULL, WRONG_SERVER_PORT);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_dtls_session_receive(NX_NULL, &packet_ptr, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);
    status = nx_secure_dtls_session_receive(&dtls_server_session_0, NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_dtls_session_end(NX_NULL, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_PTR_ERROR, status);
    status = nx_secure_dtls_session_delete(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Fail to allocate dtls packets. */
    tx_mutex_get(&_nx_secure_tls_protection, TX_WAIT_FOREVER);
    unused_pool.nx_packet_pool_available = 0;
    status = _nx_secure_dtls_allocate_handshake_packet(&dtls_server_session_0, &unused_pool, &packet_ptr, NX_NO_WAIT);
    tx_mutex_put(&_nx_secure_tls_protection);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);

    /* Invalid packet pointer. */
    status = _nx_secure_dtls_process_header(&dtls_server_session_0, NX_NULL, 0, NX_NULL, NX_NULL, NX_NULL, &header_length);
    EXPECT_EQ(NX_SECURE_TLS_INVALID_PACKET, status);

    /* Process ClientHello message with invalid length. */
    status = _nx_secure_dtls_process_clienthello(NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    status = _nx_secure_dtls_process_clienthello(&dtls_server_session_0, dtls_clienthello_bad_compression, sizeof(dtls_clienthello_bad_compression));
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);

    /* Error checkings for invalid ciphersuites. */
    tls_session_ptr = &(dtls_server_session_0.nx_secure_dtls_tls_session);
    tls_session_ptr -> nx_secure_tls_session_ciphersuite = 0;
    tls_session_ptr -> nx_secure_tls_crypto_table = &nx_crypto_tls_ciphers;
    status = _nx_secure_dtls_hash_record(&dtls_server_session_0, NX_NULL, NX_NULL, 0, NX_NULL, 0, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);
    status = _nx_secure_dtls_verify_mac(&dtls_server_session_0, NX_NULL, 0, NX_NULL, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);
    dtls_server_session_0.nx_secure_dtls_tls_session.nx_secure_tls_local_session_active = 1;
    status = _nx_secure_dtls_send_record(&dtls_server_session_0, &unused_packet, 0, NX_WAIT_FOREVER);
    dtls_server_session_0.nx_secure_dtls_tls_session.nx_secure_tls_local_session_active = 0;
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

    /* Delete session before session created.  */
    status = nx_secure_dtls_session_delete(&dtls_server_session_0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Delete server before server created.  */
    status = nx_secure_dtls_server_delete(&dtls_server_0);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /* Setup DTLS server. */
    server_dtls_setup(&dtls_server_0);

    /* Check duplicate creation.  */
    status = nx_secure_dtls_server_create(&dtls_server_0, &ip_0, SERVER_PORT, NX_IP_PERIODIC_RATE,
                                          server_session_buffer, sizeof(server_session_buffer),
                                          &nx_crypto_tls_ciphers, server_metadata, sizeof(server_metadata),
                                          tls_packet_buffer[1], sizeof(tls_packet_buffer[1]),
                                          server_connect_notify, server_receive_notify);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Check duplicate creation.  */
    status = nx_secure_dtls_server_create(&dtls_server_test, &ip_0, SERVER_PORT, NX_IP_PERIODIC_RATE,
                                          server_session_buffer, sizeof(server_session_buffer),
                                          &nx_crypto_tls_ciphers, server_metadata, sizeof(server_metadata),
                                          tls_packet_buffer[1], sizeof(tls_packet_buffer[1]),
                                          server_connect_notify, server_receive_notify);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /* Start DTLS session. */
    status = nx_secure_dtls_server_start(&dtls_server_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Wait for connection attempt. */
    tx_semaphore_get(&semaphore_connect, NX_IP_PERIODIC_RATE);
    server_connect_notify_flag = NX_FALSE;

    status = nx_secure_dtls_server_session_start(connect_session, NX_WAIT_FOREVER);

    if(status)
    {
        printf("Error in establishing DTLS server session: 0x%02X\n", status);
        ERROR_COUNTER();
    }

    /* Wait for records to be received. */
    tx_semaphore_get(&semaphore_receive, NX_IP_PERIODIC_RATE);

    status = nx_secure_dtls_session_receive(receive_session,
                                             &packet_ptr, NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }
    server_receive_notify_flag = NX_FALSE;

    nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
    nx_packet_release(packet_ptr);

    if ((response_length != sizeof(request_buffer)) ||
        memcmp(request_buffer, response_buffer, response_length))
    {
        ERROR_COUNTER();
    }

    /* End dtls session with packets to be released. */
    nx_packet_allocate(&pool_0, &pp1, NX_UDP_PACKET, NX_NO_WAIT);
    nx_packet_allocate(&pool_0, &pp2, NX_UDP_PACKET, NX_NO_WAIT);
    connect_session -> nx_secure_dtls_tls_session.nx_secure_record_queue_header = pp1;
    connect_session -> nx_secure_dtls_tls_session.nx_secure_record_decrypted_packet = pp2;

    status = nx_secure_dtls_session_end(connect_session, 100);
    EXPECT_EQ(NX_SUCCESS, status);

    /* End dtls session with an ivalid packet pool. Make sure the session is "active" to hit the proper code path. */
    active_value = connect_session -> nx_secure_dtls_tls_session.nx_secure_tls_remote_session_active;
    connect_session -> nx_secure_dtls_tls_session.nx_secure_tls_remote_session_active = NX_TRUE;
    connect_session -> nx_secure_dtls_tls_session.nx_secure_tls_packet_pool = NX_NULL;
    status = _nx_secure_dtls_session_end(connect_session, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);
    connect_session -> nx_secure_dtls_tls_session.nx_secure_tls_remote_session_active = active_value;

    /* End dtls session with a detached packet pool. */
    active_value = connect_session -> nx_secure_dtls_tls_session.nx_secure_tls_remote_session_active;
    connect_session -> nx_secure_dtls_tls_session.nx_secure_tls_remote_session_active = NX_TRUE;
    connect_session -> nx_secure_dtls_tls_session.nx_secure_tls_packet_pool = &pool_0;
    connect_session -> nx_secure_dtls_remote_ip_address.nxd_ip_version = 4;
    for (UINT i = 0; i < NX_MAX_IP_INTERFACES; i++)
    {
        ip_0.nx_ip_interface[i].nx_interface_link_up = NX_FALSE;
    }
    status = _nx_secure_dtls_session_end(connect_session, NX_NO_WAIT);
    EXPECT_EQ(NX_SECURE_TLS_TCP_SEND_FAILED, status);
    for (UINT i = 0; i < NX_MAX_IP_INTERFACES; i++)
    {
        ip_0.nx_ip_interface[i].nx_interface_link_up = NX_TRUE;
    }
    connect_session -> nx_secure_dtls_tls_session.nx_secure_tls_remote_session_active = active_value;

    /* Send another packet after session end. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    packet_ptr -> nx_packet_prepend_ptr += NX_SECURE_DTLS_RECORD_HEADER_SIZE;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;

    status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
                                   &pool_0, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_dtls_session_send(connect_session, packet_ptr,
        &server_address, WRONG_SERVER_PORT);
    if (status)
    {
        nx_packet_release(packet_ptr);
    }

    /* Check invalid packet release count.  */
    if (pool_0.nx_packet_pool_invalid_releases != 0)
    {
        ERROR_COUNTER();
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

static void ntest_1_entry(ULONG thread_input)
{
UINT i;
UINT status;
NX_PACKET *packet_ptr;
NXD_ADDRESS server_address;

    for (i = 0; i < sizeof(request_buffer); i++)
    {
        request_buffer[i] = i;
        response_buffer[i] = 0;
    }

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    /* Create UDP socket. */
    status = nx_udp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, 0x80, 5);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    client_dtls_setup(&dtls_client_session_0);

    /* Check duplicate creation.  */
    status = nx_secure_dtls_session_create(&dtls_client_session_0,
                                           &nx_crypto_tls_ciphers,
                                           client_metadata,
                                           sizeof(client_metadata),
                                           tls_packet_buffer[0], sizeof(tls_packet_buffer[0]),
                                           1, client_cert_buffer, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Start DTLS session. */
    status = nx_secure_dtls_client_session_start(&dtls_client_session_0, &client_socket_0, &server_address, SERVER_PORT, NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Prepare packet to send. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    packet_ptr -> nx_packet_prepend_ptr += NX_SECURE_DTLS_RECORD_HEADER_SIZE;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr;

    status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
                                   &pool_0, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Test send with wrong port. */
    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
        &server_address, WRONG_SERVER_PORT);
    if (!status)
    {
        ERROR_COUNTER();
    }

    /* Test send with wrong IP. */
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 0, 0, 1);
    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
        &server_address, SERVER_PORT);
    if (!status)
    {
        ERROR_COUNTER();
    }

    /* Test send with wrong IP version. */
    server_address.nxd_ip_version = NX_IP_VERSION_V6;
    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
        &server_address, SERVER_PORT);
    if (!status)
    {
        ERROR_COUNTER();
    }
    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    /* Send the packet. */
    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
                                          &server_address, SERVER_PORT);
    if (status)
    {
        ERROR_COUNTER();
    }

    nx_secure_dtls_session_end(&dtls_client_session_0, NX_NO_WAIT);

#if 0
    nx_secure_dtls_session_delete(&dtls_client_session_0);

    server_address.nxd_ip_version = NX_IP_VERSION_V6;
    server_address.nxd_ip_address.v6[0] = 0;
    server_address.nxd_ip_address.v6[1] = 0;
    server_address.nxd_ip_address.v6[2] = 0;
    server_address.nxd_ip_address.v6[3] = 1;

    client_dtls_setup(&dtls_client_session_0);

    /* Start DTLS session. */
    status = nx_secure_dtls_session_start(&dtls_client_session_0, &client_socket_0, NX_TRUE, NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Prepare packet to send. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    packet_ptr->nx_packet_prepend_ptr += NX_SECURE_DTLS_RECORD_HEADER_SIZE;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;

    status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
        &pool_0, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }


    /* Test send with wrong IP. */
    server_address.nxd_ip_address.v6[3] = 2;
    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
        &server_address, SERVER_PORT);
    if (!status)
    {
        ERROR_COUNTER();
    }

    server_address.nxd_ip_address.v6[2] = 2;
    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
        &server_address, SERVER_PORT);
    if (!status)
    {
        ERROR_COUNTER();
    }

    server_address.nxd_ip_address.v6[1] = 2;
    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
        &server_address, SERVER_PORT);
    if (!status)
    {
        ERROR_COUNTER();
    }

    server_address.nxd_ip_address.v6[0] = 2;
    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
        &server_address, SERVER_PORT);
    if (!status)
    {
        ERROR_COUNTER();
    }
    server_address.nxd_ip_version = NX_IP_VERSION_V6;
    server_address.nxd_ip_address.v6[0] = 0;
    server_address.nxd_ip_address.v6[1] = 0;
    server_address.nxd_ip_address.v6[2] = 0;
    server_address.nxd_ip_address.v6[3] = 1;

    /* Send the packet. */
    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
        &server_address, SERVER_PORT);
    if (status)
    {
        ERROR_COUNTER();
    }

    nx_secure_dtls_session_end(&dtls_client_session_0, NX_NO_WAIT);
#endif
    nx_secure_dtls_session_delete(&dtls_client_session_0);

    nx_udp_socket_unbind(&client_socket_0);

    nx_udp_socket_delete(&client_socket_0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_error_checking_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Error Checking Test...........................N/A\n");
    test_control_return(3);
}
#endif
