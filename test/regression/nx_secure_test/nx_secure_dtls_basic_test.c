/* This test concentrates on DTLS connections.  */

#include   "nx_api.h"
#include   "nx_secure_dtls_api.h"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"

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

/* Number of DTLS sessions to apply to DTLS server. */
#define NUM_SERVER_SESSIONS         2


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
static NX_SECURE_DTLS_SESSION   dtls_client_session_0;
static NX_SECURE_DTLS_SERVER    dtls_server_0;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_X509_CERT      server_local_certificate;
extern const NX_SECURE_TLS_CRYPTO
                                nx_crypto_tls_ciphers;

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_1_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE * NUM_SERVER_SESSIONS];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];

static UCHAR                    request_buffer[BUFFER_SIZE];
static UCHAR                    response_buffer[BUFFER_SIZE];
static UCHAR                    tls_packet_buffer[2][4000 * NUM_SERVER_SESSIONS];

/* Session buffer for DTLS server. Must be equal to the size of NX_SECURE_DTLS_SESSION times the
   number of desired DTLS sessions. */
static UCHAR                    server_session_buffer[sizeof(NX_SECURE_DTLS_SESSION) * NUM_SERVER_SESSIONS];

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

static TX_SEMAPHORE            semaphore_receive;
static TX_SEMAPHORE            semaphore_connect;


/* Define what the initial system looks like.  */

#define ERROR_COUNTER() __ERROR_COUNTER(__FILE__, __LINE__)

static VOID    __ERROR_COUNTER(UCHAR *file, UINT line)
{
    printf("\nError on line %d in %s\n", line, file);
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_basic_test_application_define(void *first_unused_memory)
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

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 traffic.  */
    status = nxd_ipv6_enable(&ip_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable ICMP processing.  */
    status = nxd_icmp_enable(&ip_0);
    if (status)
    {
        ERROR_COUNTER();
    }


    /* Set address with global address. */
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010000;
    address_0.nxd_ip_address.v6[1] = 0x00000000;
    address_0.nxd_ip_address.v6[2] = 0x00000000;
    address_0.nxd_ip_address.v6[3] = 0x00000002;

    status = nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL);
    if (status)
    {
        ERROR_COUNTER();
    }
#endif /* FEATURE_NX_IPV6 */
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

static NX_SECURE_DTLS_SESSION *connect_session;
static NX_SECURE_DTLS_SESSION *receive_session;

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
UINT i;

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

#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) || defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)

    for (i = 0; i < dtls_server_ptr -> nx_dtls_server_sessions_count; i++)
    {

        /* For PSK ciphersuites, add a PSK and identity hint.  */
        nx_secure_dtls_psk_add(&dtls_server_ptr -> nx_dtls_server_sessions[i], PSK, strlen(PSK),
                               PSK_IDENTITY, strlen(PSK_IDENTITY), PSK_HINT, strlen(PSK_HINT));
    }

#endif
}

static void ntest_0_entry(ULONG thread_input)
{
UINT status;
UINT i;
ULONG response_length;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Basic Test....................................");

    server_dtls_setup(&dtls_server_0);

    /* Start DTLS session. */
    status = nx_secure_dtls_server_start(&dtls_server_0);
    if (status)
    {
        printf("Error in starting DTLS server: 0x%02X\n", status);
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
        printf("Error in DTLS server session receive: 0x%02X\n", status);
        ERROR_COUNTER();
    }

    server_receive_notify_flag = NX_FALSE;

    nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
    nx_packet_release(packet_ptr);

    if ((response_length != sizeof(request_buffer)) ||
        memcmp(request_buffer, response_buffer, response_length))
    {
        printf("Received data did not match expected in DTLS Server: %s\n", __FILE__);
        ERROR_COUNTER();
    }

    for(i = 0; i < NUM_SERVER_SESSIONS; ++i)
    {
        if(dtls_server_0.nx_dtls_server_sessions[i].nx_secure_dtls_session_in_use)
        {
            status = nx_secure_dtls_session_end(&dtls_server_0.nx_dtls_server_sessions[i], NX_IP_PERIODIC_RATE);
            if(status)
            {                
                ERROR_COUNTER();
            }
        }
    }

#ifdef FEATURE_NX_IPV6

    /* Wait for connection attempt. */
    tx_semaphore_get(&semaphore_connect, NX_IP_PERIODIC_RATE);
    server_connect_notify_flag = NX_FALSE;

    /* Start DTLS session. */
    status = nx_secure_dtls_server_session_start(connect_session, NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Wait for records to be received. */
    tx_semaphore_get(&semaphore_receive, NX_IP_PERIODIC_RATE);

    status = nx_secure_dtls_session_receive(receive_session, &packet_ptr, NX_WAIT_FOREVER);
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

    for(i = 0; i < NUM_SERVER_SESSIONS; ++i)
    {
        if(dtls_server_0.nx_dtls_server_sessions[i].nx_secure_dtls_session_in_use)
        {
            status = nx_secure_dtls_session_end(&dtls_server_0.nx_dtls_server_sessions[i], NX_IP_PERIODIC_RATE);
            if(status)
            {                
                ERROR_COUNTER();
            }
        }

    }

#endif

    tx_thread_suspend(&thread_0);

    /* Shutdown DTLS server. */
    nx_secure_dtls_server_stop(&dtls_server_0);

    /* Check packet leak.  */
    if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total)
    {
        ERROR_COUNTER();
    }

    /* Delete server. */
    nx_secure_dtls_server_delete(&dtls_server_0);

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

    /* Test 64-bit sequence number overflow. */
    dtls_client_session_0.nx_secure_dtls_tls_session.nx_secure_tls_local_sequence_number[0] = 0xFFFFFFFF;
    dtls_client_session_0.nx_secure_dtls_tls_session.nx_secure_tls_local_sequence_number[1] = 0xFFFFFFFF;

    status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
                                         &server_address, SERVER_PORT);
    if (status != NX_NOT_SUCCESSFUL)
    {
        ERROR_COUNTER();
    }

    nx_packet_release(packet_ptr);


    status = nx_secure_dtls_session_end(&dtls_client_session_0, NX_IP_PERIODIC_RATE);
    if(status)
    {
        ERROR_COUNTER();
    }

    nx_secure_dtls_session_delete(&dtls_client_session_0);

#ifdef FEATURE_NX_IPV6

    server_address.nxd_ip_version = NX_IP_VERSION_V6;
    server_address.nxd_ip_address.v6[0] = 0;
    server_address.nxd_ip_address.v6[1] = 0;
    server_address.nxd_ip_address.v6[2] = 0;
    server_address.nxd_ip_address.v6[3] = 1;

    client_dtls_setup(&dtls_client_session_0);

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

    packet_ptr->nx_packet_prepend_ptr += NX_SECURE_DTLS_RECORD_HEADER_SIZE;
    packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;

    status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer), &pool_0, NX_NO_WAIT);
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

    nx_secure_dtls_session_delete(&dtls_client_session_0);
#endif

    nx_udp_socket_unbind(&client_socket_0);

    nx_udp_socket_delete(&client_socket_0);

    tx_thread_resume(&thread_0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_basic_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Basic Test....................................N/A\n");
    test_control_return(3);
}
#endif
