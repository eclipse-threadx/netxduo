/* This test Client can select the corresponding CA from the lists.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "ecc_certs.c"
#include   "nx_crypto_ecdh.h"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
#define SERVER_PORT                 4433

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static TX_THREAD                thread_1;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static UINT                     error_counter;

static NX_TCP_SOCKET            client_socket_0;
static NX_TCP_SOCKET            server_socket_0;
static NX_SECURE_TLS_SESSION    tls_client_session_0;
static NX_SECURE_TLS_SESSION    tls_server_session_0;
static NX_SECURE_X509_CERT      client_trusted_ca[3];
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_SECURE_X509_CERT      server_local_certificate;

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

extern const                    USHORT nx_crypto_ecc_supported_groups[];
extern const                    NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const                    UINT nx_crypto_ecc_supported_groups_size;
extern const                    NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

typedef struct TEST_CERT_STRUCT
{
    UCHAR *cert;
    UINT cert_len;
    UCHAR *key;
    UINT key_len;
}TEST_CERT;

static TEST_CERT test_certs[] =
{
    {ECTestServer2_der, sizeof(ECTestServer2_der), ECTestServer2_key_der, sizeof(ECTestServer2_key_der)},
    {ECTestServer3_der, sizeof(ECTestServer3_der), ECTestServer3_key_der, sizeof(ECTestServer3_key_der)},
    {ECTestServer4_der, sizeof(ECTestServer4_der), ECTestServer4_key_der, sizeof(ECTestServer4_key_der)},
};

/* Define what the initial system looks like.  */


static VOID    ERROR_COUNTER()
{
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_client_ca_select_test_application_define(void *first_unused_memory)
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

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    nx_secure_tls_initialize();
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;
UINT i;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                          &nx_crypto_tls_ciphers_ecc,
                                          client_metadata,
                                          sizeof(client_metadata));
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    if (status)
    {
        ERROR_COUNTER();
    }

    memset(&client_remote_cert, 0, sizeof(client_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &client_remote_cert,
                                                       client_cert_buffer,
                                                       sizeof(client_cert_buffer));
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca[0], ECCA3_der, ECCA3_der_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca[1], ECCA2_der, ECCA2_der_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca[2], ECCA4_der, ECCA4_der_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Add multiple CAs.  */
    for (i = 0; i < 3; i++)
    {
        status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                       &client_trusted_ca[i]);
        if (status)
        {
            ERROR_COUNTER();
        }
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[0],
                                                     sizeof(tls_packet_buffer[0]));
    if (status)
    {
        ERROR_COUNTER();
    }
}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr, TEST_CERT *test_cert)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session_ptr,
                                           &nx_crypto_tls_ciphers_ecc,
                                           server_metadata,
                                           sizeof(server_metadata));
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    if (status)
    {
        ERROR_COUNTER();
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   test_cert -> cert, test_cert -> cert_len,
                                                   NX_NULL, 0, test_cert -> key,
                                                   test_cert -> key_len,
                                                   NX_SECURE_X509_KEY_TYPE_EC_DER);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_local_certificate_add(tls_session_ptr,
                                                 &server_local_certificate);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[1],
                                                     sizeof(tls_packet_buffer[1]));
    if (status)
    {
        ERROR_COUNTER();
    }
}

static void ntest_0_entry(ULONG thread_input)
{
UINT status, i;
ULONG response_length;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Client CA Select Test..........................");

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &server_socket_0, "Server socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_tcp_server_socket_listen(&ip_0, SERVER_PORT, &server_socket_0, 5, NX_NULL);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Test 3 times for different certificate.  */
    for (i = 0; i < 3; i++)
    {
        server_tls_setup(&tls_server_session_0, &test_certs[i]);

        status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        status = nx_secure_tls_session_receive(&tls_server_session_0, &packet_ptr, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
        nx_packet_release(packet_ptr);
        if ((response_length != sizeof(request_buffer)) ||
            memcmp(request_buffer, response_buffer, response_length))
        {
            ERROR_COUNTER();
        }

        /* Prepare packet to send. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        packet_ptr -> nx_packet_prepend_ptr += NX_SECURE_TLS_RECORD_HEADER_SIZE;
        packet_ptr -> nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;

        status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
                                       &pool_0, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Send the packet. */
        status = nx_secure_tls_session_send(&tls_server_session_0, packet_ptr, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        tx_thread_sleep(10);

        nx_secure_tls_session_end(&tls_server_session_0, NX_NO_WAIT);
        nx_secure_tls_session_delete(&tls_server_session_0);

        nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
        nx_tcp_server_socket_unaccept(&server_socket_0);
        nx_tcp_server_socket_relisten(&ip_0, SERVER_PORT, &server_socket_0);
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
ULONG response_length;
NXD_ADDRESS server_address;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    /* Create TCP socket. */
    status = nx_tcp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_tcp_client_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    if (status)
    {
        ERROR_COUNTER();
    }

    for (i = 0; i < sizeof(request_buffer); i++)
    {
        request_buffer[i] = i;
        response_buffer[i] = 0;
    }

    client_tls_setup(&tls_client_session_0);

    for (i = 0; i < 3; i++)
    {
        status = nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Start TLS session. */
        status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Prepare packet to send. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        packet_ptr->nx_packet_prepend_ptr += NX_SECURE_TLS_RECORD_HEADER_SIZE;
        packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr;

        status = nx_packet_data_append(packet_ptr, request_buffer, sizeof(request_buffer),
                                       &pool_0, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Send the packet. */
        status = nx_secure_tls_session_send(&tls_client_session_0, packet_ptr, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        status = nx_secure_tls_session_receive(&tls_client_session_0, &packet_ptr, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
        nx_packet_release(packet_ptr);
        if ((response_length != sizeof(request_buffer)) ||
            memcmp(request_buffer, response_buffer, response_length))
        {
            ERROR_COUNTER();
        }

        nx_secure_tls_session_end(&tls_client_session_0, NX_NO_WAIT);
        nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    }

    nx_secure_tls_session_delete(&tls_client_session_0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_client_ca_select_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Client CA Select Test..........................N/A\n");
    test_control_return(3);
}
#endif
