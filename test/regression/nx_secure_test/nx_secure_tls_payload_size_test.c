/* This test concentrates on different payload size for TLS record.  */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "ecc_certs.c"
#include   "nx_crypto_ecdh.h"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)
#define NUM_PACKETS                 128
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 0x2000
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
#define SERVER_PORT                 4433

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static TX_THREAD                thread_1;
static NX_PACKET_POOL           pool_0;
static NX_PACKET_POOL           pool_small_payload;
static NX_IP                    ip_0;
static UINT                     error_counter;

static NX_TCP_SOCKET            client_socket_0;
static NX_TCP_SOCKET            server_socket_0;
static NX_SECURE_TLS_SESSION    tls_client_session_0;
static NX_SECURE_TLS_SESSION    tls_server_session_0;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_SECURE_X509_CERT      server_local_certificate;

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    pool_small_payload_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
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


/* Define what the initial system looks like.  */


static VOID    ERROR_COUNTER()
{
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_payload_size_test_application_define(void *first_unused_memory)
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

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca, ECCA2_der, ECCA2_der_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr,
                                                   &client_trusted_ca);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[0],
                                                     sizeof(tls_packet_buffer[0]));
    if (status)
    {
        ERROR_COUNTER();
    }
}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
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
                                                   ECTestServer2_der, ECTestServer2_der_len,
                                                   NX_NULL, 0, ECTestServer2_key_der,
                                                   ECTestServer2_key_der_len,
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
UINT status;
ULONG pool_available;
ULONG response_length;
NX_PACKET *packet_ptr;
UINT i;

    pool_available = pool_0.nx_packet_pool_available;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Payload Size Test..............................");

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

    server_tls_setup(&tls_server_session_0);

    status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Start TLS session. */
    status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0,
                                          NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    for (i = 1; i < BUFFER_SIZE; i++)
    {        
        status = nx_secure_tls_session_receive(&tls_server_session_0, &packet_ptr, NX_WAIT_FOREVER);
        if (status)
        {
            ERROR_COUNTER();
        }

        memset(response_buffer, 0, i);
        nx_packet_data_retrieve(packet_ptr, response_buffer, &response_length);
        nx_packet_release(packet_ptr);
        if ((response_length != i) ||
            memcmp(request_buffer, response_buffer, i))
        {
            ERROR_COUNTER();
        }
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    nx_secure_tls_session_end(&tls_server_session_0, NX_NO_WAIT);
    nx_secure_tls_session_delete(&tls_server_session_0);

    nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
    nx_tcp_server_socket_unaccept(&server_socket_0);
    nx_tcp_server_socket_relisten(&ip_0, SERVER_PORT, &server_socket_0);

    /* Check packet leak. */
    if (pool_available != pool_0.nx_packet_pool_available)
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
ULONG response_length;
NXD_ADDRESS server_address;
const NX_SECURE_TLS_CIPHERSUITE_INFO *ciphersuite_ptr;

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

    srand(time(0));
    for (i = 0; i < sizeof(request_buffer); i++)
    {
        request_buffer[i] = rand();
    }

    client_tls_setup(&tls_client_session_0);

    status =  nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT,
                                            NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Start TLS session. */
    status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0,
                                          NX_WAIT_FOREVER);
    if (status)
    {
        ERROR_COUNTER();
    }

    /* Test: Fail to allocate packet since the packet can not fill in the TLS record header NX_SECURE_TLS_RECORD_HEADER_SIZE.
             Cover the code between line106 and line108 in _nx_secure_tls_packet_allocate().
    */
    status =  nx_packet_pool_create(&pool_small_payload, "NetX Small Packet Pool", NX_IPv4_TCP_PACKET,
                                    pool_small_payload_memory, PACKET_POOL_SIZE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_packet_allocate(&tls_client_session_0, &pool_small_payload, &packet_ptr, NX_NO_WAIT);
    if (status != NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_pool_delete(&pool_small_payload);
    if (status)
    {
        ERROR_COUNTER();
    }

#if (!NX_SECURE_TLS_TLS_1_3_ENABLED) && !defined NX_SECURE_ENABLE_AEAD_CIPHER 
    /* Test: Fail to allocate packet since the packet can not fill in the TLS record header iv_size .
             Cover the code between line129 and line132 in _nx_secure_tls_packet_allocate().
    */
    status =  nx_packet_pool_create(&pool_small_payload, "NetX Small Packet Pool", NX_IPv4_TCP_PACKET + NX_SECURE_TLS_RECORD_HEADER_SIZE + 2,
                                    pool_small_payload_memory, PACKET_POOL_SIZE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_tls_packet_allocate(&tls_client_session_0, &pool_small_payload, &packet_ptr, NX_NO_WAIT);
    if (status != NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL)
    {
        ERROR_COUNTER();
    }

    status = nx_packet_pool_delete(&pool_small_payload);
    if (status)
    {
        ERROR_COUNTER();
    }
#endif

    /* Test: Fail to allocate packet since get the iv size failure in _nx_secure_tls_session_iv_size_get().
             Cover the code at line123 in _nx_secure_tls_packet_allocate().
    */
    ciphersuite_ptr = tls_client_session_0.nx_secure_tls_session_ciphersuite;
    tls_client_session_0.nx_secure_tls_session_ciphersuite = NX_NULL;
    status = nx_secure_tls_packet_allocate(&tls_client_session_0, &pool_0, &packet_ptr, NX_NO_WAIT);
    if (status != NX_SECURE_TLS_UNKNOWN_CIPHERSUITE)
    {
        ERROR_COUNTER();
    }
    tls_client_session_0.nx_secure_tls_session_ciphersuite = ciphersuite_ptr;

    for (i = 1; i < BUFFER_SIZE; i++)
    {
        
        /* Prepare packet to send. */
        status = nx_secure_tls_packet_allocate(&tls_client_session_0, &pool_0, &packet_ptr, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        status = nx_packet_data_append(packet_ptr, request_buffer, i,
                                       &pool_0, NX_NO_WAIT);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Send the packet. */
        status = nx_secure_tls_session_send(&tls_client_session_0, packet_ptr, NX_IP_PERIODIC_RATE * 5);
        if (status)
        {
            ERROR_COUNTER();
        }
    }

    nx_secure_tls_session_end(&tls_client_session_0, NX_NO_WAIT);
    nx_secure_tls_session_delete(&tls_client_session_0);

    nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&client_socket_0);
    nx_tcp_socket_delete(&client_socket_0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_payload_size_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Payload Size Test..............................N/A\n");
    test_control_return(3);
}
#endif