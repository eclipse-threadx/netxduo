/* This test concentrates on DTLS ciphersuites negotiation.  */

#include   "nx_api.h"
#include   "nx_secure_dtls_api.h"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_DTLS) && defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
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
#define CIPHERSUITE_INIT(p)         {p, sizeof(p) / sizeof(UINT)}

typedef struct
{
    UINT *list;
    UINT count;
} CIPHERSUITE;

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                thread_0;
static TX_THREAD                thread_1;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static UINT                     error_counter;

static NX_UDP_SOCKET            client_socket_0;
static NX_SECURE_DTLS_SESSION   dtls_client_session_0;
static NX_SECURE_DTLS_SERVER    dtls_server_0;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_SECURE_X509_CERT      server_local_certificate;
static NX_SECURE_TLS_CRYPTO     tls_ciphers;
static NX_SECURE_TLS_CIPHERSUITE_INFO
                                ciphersuite_table[20];
extern const NX_SECURE_TLS_CRYPTO
                                nx_crypto_tls_ciphers;
extern NX_SECURE_TLS_CIPHERSUITE_INFO
                                _nx_crypto_ciphersuite_lookup_table[];

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

static UINT                     server_running;

/* Session buffer for DTLS server. Must be equal to the size of NX_SECURE_DTLS_SESSION times the
   number of desired DTLS sessions. */
static UCHAR                    server_session_buffer[sizeof(NX_SECURE_DTLS_SESSION)];

static UINT ciphersuite_list_0[] = {};
static UINT ciphersuite_list_1[] = {TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_2[] = {TLS_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_3[] = {TLS_RSA_WITH_AES_256_CBC_SHA256};
//static UINT ciphersuite_list_4[] = {TLS_RSA_WITH_NULL_MD5};
//static UINT ciphersuite_list_5[] = {TLS_RSA_WITH_NULL_SHA};
//static UINT ciphersuite_list_6[] = {TLS_PSK_WITH_AES_128_CBC_SHA};
//static UINT ciphersuite_list_7[] = {TLS_PSK_WITH_AES_256_CBC_SHA};
static UINT ciphersuite_list_8[] = {TLS_PSK_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_9[] = {TLS_ECJPAKE_WITH_AES_128_CCM_8};
static CIPHERSUITE ciphersuites[] =
{
    CIPHERSUITE_INIT(ciphersuite_list_0),
    CIPHERSUITE_INIT(ciphersuite_list_1),
    CIPHERSUITE_INIT(ciphersuite_list_2),
    CIPHERSUITE_INIT(ciphersuite_list_3),
//    CIPHERSUITE_INIT(ciphersuite_list_4),
//    CIPHERSUITE_INIT(ciphersuite_list_5),
#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
//    CIPHERSUITE_INIT(ciphersuite_list_6),
//    CIPHERSUITE_INIT(ciphersuite_list_7),
    CIPHERSUITE_INIT(ciphersuite_list_8),
#endif /* NX_SECURE_ENABLE_PSK_CIPHERSUITES */
#ifdef NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE
    CIPHERSUITE_INIT(ciphersuite_list_9)
#endif /* NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE */
};

extern NX_CRYPTO_METHOD crypto_method_null;
extern NX_CRYPTO_METHOD crypto_method_auth_ecjpake;
extern NX_CRYPTO_METHOD crypto_method_aes_ccm_8;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
static NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_ecjpake =
{TLS_ECJPAKE_WITH_AES_128_CCM_8,    &crypto_method_null, &crypto_method_auth_ecjpake, &crypto_method_aes_ccm_8,  16,      16,        &crypto_method_null,      0,         &crypto_method_tls_prf_sha256};

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#define ERROR_COUNTER() _ERROR_COUNTER(__FILE__, __LINE__)

static VOID    _ERROR_COUNTER(const char *file, int line)
{
	printf("Error at %s:%d", file, line);
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_ciphersuites_test_application_define(void *first_unused_memory)
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

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    if (status)
    {
        ERROR_COUNTER();
    }

    nx_secure_tls_initialize();
    nx_secure_dtls_initialize();
}

static VOID ciphersuites_setup(CIPHERSUITE *ciphersuite)
{
UINT i;
UINT count;

    /* Initialize ciphersuites. */
    memcpy(&tls_ciphers, &nx_crypto_tls_ciphers, sizeof(NX_SECURE_TLS_CRYPTO));
    if (ciphersuite -> count > 0)
    {
        for (count = 0; count < ciphersuite -> count; count++)
        {
            if (ciphersuite -> list[count] == TLS_ECJPAKE_WITH_AES_128_CCM_8)
            {
                memcpy(&ciphersuite_table[count],
                       &_nx_crypto_ciphersuite_ecjpake,
                       sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
                continue;
            }

            i = 0;
            while (ciphersuite -> list[count] !=
                   (UINT)_nx_crypto_ciphersuite_lookup_table[i].nx_secure_tls_ciphersuite)
            {
                i++;
            }
            memcpy(&ciphersuite_table[count],
                   &_nx_crypto_ciphersuite_lookup_table[i],
                   sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
        }
        tls_ciphers.nx_secure_tls_ciphersuite_lookup_table = ciphersuite_table;
        tls_ciphers.nx_secure_tls_ciphersuite_lookup_table_size = count;
    }
}

static VOID client_dtls_setup(NX_SECURE_DTLS_SESSION *dtls_session_ptr)
{
UINT status;

    status = nx_secure_dtls_session_create(dtls_session_ptr,
                                           &tls_ciphers,
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
    }

    return(NX_SUCCESS);
}

static VOID server_dtls_setup(NX_SECURE_DTLS_SERVER *dtls_server_ptr)
{
UINT status;

    status = nx_secure_dtls_server_create(dtls_server_ptr, &ip_0, SERVER_PORT, NX_IP_PERIODIC_RATE,
                                          server_session_buffer, sizeof(server_session_buffer),
                                          &tls_ciphers, server_metadata, sizeof(server_metadata),
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
    /* For PSK ciphersuites, add a PSK and identity hint.  */
    nx_secure_dtls_psk_add(dtls_server_ptr -> nx_dtls_server_sessions, PSK, strlen(PSK),
                             PSK_IDENTITY, strlen(PSK_IDENTITY), PSK_HINT, strlen(PSK_HINT));
#endif
}

static void ntest_0_entry(ULONG thread_input)
{
UINT i;
UINT status;
ULONG response_length;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Ciphersuites Test.............................");

    for (i = 0; i < sizeof(ciphersuites) / sizeof(CIPHERSUITE); i++)
    {

        ciphersuites_setup(&ciphersuites[i]);

        server_dtls_setup(&dtls_server_0);

        /* Start DTLS server. */
        status = nx_secure_dtls_server_start(&dtls_server_0);
        if (status)
        {
            ERROR_COUNTER();
        }

        server_running = 1;

        /* Wait for connection attempt. */
        while (server_connect_notify_flag != NX_TRUE)
        {
            tx_thread_sleep(1);
        }
        server_connect_notify_flag = NX_FALSE;

        status = nx_secure_dtls_server_session_start(connect_session, 20 * NX_IP_PERIODIC_RATE);
        if (status)
        {
            ERROR_COUNTER();
        }

        /* Wait for records to be received. */
        while (server_receive_notify_flag != NX_TRUE)
        {
            tx_thread_sleep(1);
        }

        status = nx_secure_dtls_session_receive(receive_session, &packet_ptr, 20 * NX_IP_PERIODIC_RATE);
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

        /* Clear the receive flag. */
        server_receive_notify_flag = NX_FALSE;

        /* Shutdown DTLS server. */
        nx_secure_dtls_server_stop(&dtls_server_0);

        /* Delete server. */
        nx_secure_dtls_server_delete(&dtls_server_0);

        server_running = 0;
        tx_thread_suspend(&thread_0);
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
UINT i, j;
UINT status;
NX_PACKET *packet_ptr;
NXD_ADDRESS server_address;

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

    for (i = 0; i < sizeof(ciphersuites) / sizeof(CIPHERSUITE); i++)
    {

        for (j = 0; j < sizeof(request_buffer); j++)
        {
            request_buffer[j] = j;
            response_buffer[j] = 0;
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

        /* Send the packet. */
        status = nx_secure_dtls_session_send(&dtls_client_session_0, packet_ptr,
                                              &server_address, SERVER_PORT);
        if (status)
        {
            ERROR_COUNTER();
        }

        nx_secure_dtls_session_end(&dtls_client_session_0, NX_NO_WAIT);
        nx_secure_dtls_session_delete(&dtls_client_session_0);

         while (server_running)
        {
            tx_thread_sleep(1);
        }
        tx_thread_resume(&thread_0);
    }
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_ciphersuites_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS Ciphersuites Test.............................N/A\n");
    test_control_return(3);
}
#endif
