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

/* Number of DTLS sessions to apply to DTLS server. */
#define NUM_SERVER_SESSIONS         2


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                server_thread;
static NX_PACKET_POOL           server_pool;
static NX_IP                    server_ip;
static TX_THREAD                client_thread;
static NX_PACKET_POOL           client_pool;
static NX_IP                    client_ip;
static UINT                     error_counter;

static NX_UDP_SOCKET            client_socket;
static NX_SECURE_DTLS_SESSION   dtls_client_session;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_DTLS_SERVER    dtls_server;
static NX_SECURE_X509_CERT      server_local_certificate;
extern const NX_SECURE_TLS_CRYPTO
                                nx_crypto_tls_ciphers;

static ULONG                    server_pool_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    client_pool_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    server_thread_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    client_thread_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    server_ip_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    client_ip_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    server_arp_cache[ARP_CACHE_SIZE];
static ULONG                    client_arp_cache[ARP_CACHE_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE * NUM_SERVER_SESSIONS];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];

static UCHAR                    request_buffer[BUFFER_SIZE];
static UCHAR                    response_buffer[BUFFER_SIZE];
static UCHAR                    server_tls_packet_buffer[4000 * NUM_SERVER_SESSIONS];
static UCHAR                    client_tls_packet_buffer[4000];

/* Session buffer for DTLS server. Must be equal to the size of NX_SECURE_DTLS_SESSION times the
   number of desired DTLS sessions. */
static UCHAR                    server_session_buffer[sizeof(NX_SECURE_DTLS_SESSION) * NUM_SERVER_SESSIONS];

/* Define thread prototypes.  */

static VOID    server_thread_entry(ULONG thread_input);
static VOID    client_thread_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

static TX_SEMAPHORE            semaphore_connect;
static TX_SEMAPHORE            semaphore_receive;
static TX_SEMAPHORE            semaphore_server;


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
VOID    nx_secure_dtls_out_of_order_test_application_define(void *first_unused_memory)
#endif
{
UINT     status;
CHAR    *pointer;


    error_counter = 0;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&server_thread, "server thread", server_thread_entry, 0,
                     server_thread_stack, sizeof(server_thread_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Create the client thread.  */
    tx_thread_create(&client_thread, "client thread 0", client_thread_0_entry, 0,
                     client_thread_stack, sizeof(client_thread_stack),
                     8, 8, TX_NO_TIME_SLICE, TX_AUTO_START);

    tx_semaphore_create(&semaphore_connect, "semaphore connect", 0);
    tx_semaphore_create(&semaphore_receive, "semaphore receive", 0);
    tx_semaphore_create(&semaphore_server, "semaphore server", 0);

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "Server Packet Pool", PACKET_SIZE,
                                    server_pool_memory, PACKET_POOL_SIZE);
    if (status)
    {
        ERROR_COUNTER();
    }
    status =  nx_packet_pool_create(&client_pool, "Client 0 Packet Pool", PACKET_SIZE,
                                    client_pool_memory, PACKET_POOL_SIZE);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, "Server IP Instance", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL,
                          &server_pool, _nx_ram_network_driver_1500,
                          server_ip_stack, sizeof(server_ip_stack), 1);
    if (status)
    {
        ERROR_COUNTER();
    }
    status = nx_ip_create(&client_ip, "Client 0 IP Instance", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL,
                          &client_pool, _nx_ram_network_driver_1500,
                          client_ip_stack, sizeof(client_ip_stack), 1);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&server_ip, (VOID *)server_arp_cache, sizeof(server_arp_cache));
    if (status)
    {
        ERROR_COUNTER();
    }
    status =  nx_arp_enable(&client_ip, (VOID *)client_arp_cache, sizeof(client_arp_cache));
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&server_ip);
    if (status)
    {
        ERROR_COUNTER();
    }
    status =  nx_udp_enable(&client_ip);
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
                                           client_tls_packet_buffer, sizeof(client_tls_packet_buffer),
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
static UINT server_connect_count = 0;
static UINT server_receive_count = 0;
static NX_SECURE_DTLS_SESSION *connect_session;
static NX_SECURE_DTLS_SESSION *receive_session;
#define TEST_SEND_COUNT 5

/* Connect notify callback for DTLS server - notifies the application thread that
   a DTLS connection is ready to kickoff a handshake. */
static UINT server_connect_notify(NX_SECURE_DTLS_SESSION *dtls_session, NXD_ADDRESS *ip_address, UINT port)
{
    connect_session = dtls_session;
    server_connect_count++;
    tx_semaphore_put(&semaphore_connect);
    return(NX_SUCCESS);
}

/* Receive notify callback for DTLS server - notifies the application thread that
   we have received a DTLS record over an established DTLS session. */
static UINT server_receive_notify(NX_SECURE_DTLS_SESSION *dtls_session)
{
    receive_session = dtls_session;
    server_receive_count++;
    tx_semaphore_put(&semaphore_receive);
    return(NX_SUCCESS);
}


static VOID server_dtls_setup(NX_SECURE_DTLS_SERVER *dtls_server_ptr)
{
UINT status;

    status = nx_secure_dtls_server_create(dtls_server_ptr, &server_ip, SERVER_PORT, NX_IP_PERIODIC_RATE,
                                          server_session_buffer, sizeof(server_session_buffer),
                                          &nx_crypto_tls_ciphers, server_metadata, sizeof(server_metadata),
                                          server_tls_packet_buffer, sizeof(server_tls_packet_buffer),
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

extern VOID _nx_udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static VOID test_udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
UCHAR *data;

    data = packet_ptr -> nx_packet_prepend_ptr;

    if ((data[8] == NX_SECURE_TLS_HANDSHAKE))
    {

        /* Second Client Hello (after Hello Verify Request): message sequence = 1.  */
        if ((data[25] == 0) && (data[26] == 1))
        {

            /* Change message sequence.  */
            dtls_client_session.nx_secure_dtls_tls_session.nx_secure_tls_local_sequence_number[0]++;
        }
    }

    _nx_udp_packet_receive(ip_ptr, packet_ptr);
}

static void server_thread_entry(ULONG thread_input)
{
UINT i;
UINT status;
ULONG response_length;
NX_PACKET *packet_ptr;


    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Out of Order Test.............................");

    server_dtls_setup(&dtls_server);

    server_ip.nx_ip_udp_packet_receive = test_udp_packet_receive;

    /* Start DTLS session. */
    status = nx_secure_dtls_server_start(&dtls_server);
    if (status)
    {
        printf("Error in starting DTLS server: 0x%02X\n", status);
        ERROR_COUNTER();
    }

    /* Wait for connection attempt. */
    tx_semaphore_get(&semaphore_connect, NX_IP_PERIODIC_RATE);

    status = nx_secure_dtls_server_session_start(connect_session, NX_IP_PERIODIC_RATE*10);

    /* The handshake message is out of order - we should be able to recover.  */
    if (status)
    {
        ERROR_COUNTER();
    }

    nx_secure_dtls_session_end(connect_session, NX_NO_WAIT);

    server_ip.nx_ip_udp_packet_receive = _nx_udp_packet_receive;

    /* Wait for connection attempt. */
    tx_semaphore_get(&semaphore_connect, NX_IP_PERIODIC_RATE);

    status = nx_secure_dtls_server_session_start(connect_session, NX_IP_PERIODIC_RATE);

    if (status)
    {
        printf("Error in establishing DTLS server session: 0x%02X\n", status);
        ERROR_COUNTER();
    }

    for (i = 0; i < TEST_SEND_COUNT; i++)
    {

        tx_semaphore_put(&semaphore_server);

        /* Wait for connection attempt. */
        tx_semaphore_get(&semaphore_receive, NX_IP_PERIODIC_RATE);

        status = nx_secure_dtls_session_receive(receive_session, &packet_ptr, NX_IP_PERIODIC_RATE);

        if (i == 1)
        {
            /* Client sent duplicate message. This message should be dropped.  */
            if (!status)
            {
                ERROR_COUNTER();
            }
        }
        else
        {
            if(status == NX_NO_PACKET)
            {
                /* No packet recevied. This is OK */
                continue; 
            }

            if(status == NX_SECURE_TLS_CLOSE_NOTIFY_RECEIVED)
            {
                /* Session was closed by the other side. */
                break;
            }

            if (status)
            {
                ERROR_COUNTER();
            }
            else
            {

                memset(response_buffer, 0, sizeof(response_buffer));
                nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
                nx_packet_release(packet_ptr);

                if ((response_length != sizeof(request_buffer)) ||
                    memcmp(request_buffer, response_buffer, response_length))
                {
                    ERROR_COUNTER();
                }
            }
        }
    }

    for (i = 0; i < NUM_SERVER_SESSIONS; ++i)
    {
        if(dtls_server.nx_dtls_server_sessions[i].nx_secure_dtls_tls_session.nx_secure_tls_local_session_active)
        {
			/* All server instances should shut down without error. */
            status = nx_secure_dtls_session_end(&dtls_server.nx_dtls_server_sessions[i], NX_IP_PERIODIC_RATE);
            if(status)
            {
                ERROR_COUNTER();
            }
        }
    }

    /* Shutdown DTLS server. */
    nx_secure_dtls_server_stop(&dtls_server);

    /* Check packet leak.  */
    if (server_pool.nx_packet_pool_available != server_pool.nx_packet_pool_total)
    {
        ERROR_COUNTER();
    }

    /* Make sure client is done before checking its pool. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    if (client_pool.nx_packet_pool_available != client_pool.nx_packet_pool_total)
    {
        printf("client pool available: %ld, total: %ld\n", client_pool.nx_packet_pool_available, client_pool.nx_packet_pool_total);
        ERROR_COUNTER();
    }

    /* Delete server. */
    nx_secure_dtls_server_delete(&dtls_server);

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

static void client_thread_0_entry(ULONG thread_input)
{
UINT i;
UINT status;
NX_PACKET *packet_ptr;
NXD_ADDRESS server_address;

    for (i = 0; i < sizeof(request_buffer); i++)
    {
        request_buffer[i] = i;
    }

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 4);

    /* Create UDP socket. */
    status = nx_udp_socket_create(&client_ip, &client_socket, "Client socket 0", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, 0x80, 5);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_udp_socket_bind(&client_socket, NX_ANY_PORT, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    client_dtls_setup(&dtls_client_session);

    /* Start DTLS session. */
    status = nx_secure_dtls_client_session_start(&dtls_client_session, &client_socket, &server_address, SERVER_PORT, NX_IP_PERIODIC_RATE);

    /* Out of order handshake message, we should handle it. */
    if (status != NX_SUCCESS)
    {
        ERROR_COUNTER();
    }

    nx_secure_dtls_session_end(&dtls_client_session,NX_NO_WAIT);

    /* Start DTLS session. */
    status = nx_secure_dtls_client_session_start(&dtls_client_session, &client_socket, &server_address, SERVER_PORT, NX_IP_PERIODIC_RATE);
    if (status)
    {
        ERROR_COUNTER();
    }

    for (i = 0; i < TEST_SEND_COUNT; i++)
    {

        /* Send out of order message.  */
        if (i == 1)
        {

            /* Decreas the sequence number.  */
            dtls_client_session.nx_secure_dtls_tls_session.nx_secure_tls_local_sequence_number[0]--;
        }

        if (i == 2)
        {

            /* Increase the sequence number.  */
            dtls_client_session.nx_secure_dtls_tls_session.nx_secure_tls_local_sequence_number[0]++;
        }

        /* Prepare packet to send. */
        status = nx_secure_dtls_packet_allocate(&dtls_client_session, &client_pool, &packet_ptr, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
            &client_pool, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        tx_semaphore_get(&semaphore_server, NX_IP_PERIODIC_RATE);

        /* Send the packet. */
        status = nx_secure_dtls_client_session_send(&dtls_client_session, packet_ptr);
        if (status)
        {
            ERROR_COUNTER();
        }
    }

    if(dtls_client_session.nx_secure_dtls_tls_session.nx_secure_tls_remote_session_active)
    {
        status = nx_secure_dtls_session_end(&dtls_client_session, NX_IP_PERIODIC_RATE * 2);

        if(status)
        {
            ERROR_COUNTER();
        }
    }

    nx_secure_dtls_session_delete(&dtls_client_session);

    nx_udp_socket_unbind(&client_socket);

    nx_udp_socket_delete(&client_socket);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_out_of_order_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Out of Order Test.............................N/A\n");
    test_control_return(3);
}
#endif
