/* This test concentrates on DTLS ECC ciphersuites negotiation.  */

#include   "nx_api.h"
#include   "nx_secure_dtls_api.h"
#include   "ecc_certs.c"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_DTLS) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define BUFFER_SIZE                 64
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            (2048 + sizeof(NX_SECURE_X509_CERT))
#define SERVER_PORT                 4433
#define CIPHERSUITE_INIT(p, s, c)   {p, sizeof(p) / sizeof(UINT), s, c}
#define CERTIFICATE_INIT(s, k, c, t) {s, sizeof(s), k, sizeof(k), c, sizeof(c), t}

typedef struct
{
    UCHAR *server_cert;
    UINT   server_cert_len;
    UCHAR *server_key;
    UINT   server_key_len;
    UCHAR *ca_cert;
    UINT   ca_cert_len;
    UINT   key_type;
} CERTIFICATE;

typedef struct
{
    UINT *list;
    UINT count;
    UINT session_succ;
    CERTIFICATE *cert;
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
static NX_SECURE_TLS_CRYPTO     tls_ciphers_client;
static NX_SECURE_TLS_CRYPTO     tls_ciphers_server;
static NX_SECURE_TLS_CIPHERSUITE_INFO
                                ciphersuite_table_client[20];
static NX_SECURE_TLS_CIPHERSUITE_INFO
                                ciphersuite_table_server[20];

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

extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc[];
extern const USHORT nx_crypto_ecc_supported_groups[];
extern const NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const UINT nx_crypto_ecc_supported_groups_size;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

static CERTIFICATE test_certs[] =
{
    CERTIFICATE_INIT(ECTest_der, ECTest_key_der, ECCA_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(ECTestServer2_der, ECTestServer2_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
    CERTIFICATE_INIT(test_device_cert_der, test_device_cert_key_der, test_ca_cert_der, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER),
    CERTIFICATE_INIT(ECTestServer10_der, ECTestServer10_key_der, ECCA2_der, NX_SECURE_X509_KEY_TYPE_EC_DER),
};

static UINT ciphersuite_list_0[] = {};
static UINT ciphersuite_list_1[] = {TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_2[] = {TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_3[] = {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_4[] = {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256};
static UINT ciphersuite_list_5[] =
{
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
};
static UINT ciphersuite_list_6[] = {TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256};
static UINT ciphersuite_list_7[] = {TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256};
static UINT ciphersuite_list_8[] = {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
static UINT ciphersuite_list_9[] = {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256};

static CIPHERSUITE ciphersuites_client[] =
{

    /* Select ciphersuite according to certificate. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[3]),

    /* Select ciphersuite according to certificate.
     * The order of client ciphersuites are reversed of server. */
    CIPHERSUITE_INIT(ciphersuite_list_5, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_5, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_5, NX_TRUE, &test_certs[2]),

    /* Specified ciphersuites. */
    CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[2]),

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    CIPHERSUITE_INIT(ciphersuite_list_6, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_7, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_8, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[2]),
#endif

    /* The Server cert supports ECDH_ECDSA and ECDHE_ECDSA. */
    CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_2, NX_FALSE, &test_certs[1]),     /* ECDH_RSA ciphersuite - expect failure. */
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1]),      
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_FALSE, &test_certs[1]),     /* ECDHE_RSA ciphersuite only. */

    /* Let the server pickup supported ciphersuite. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2]),
};

static CIPHERSUITE ciphersuites_server[] =
{

    /* Select ciphersuite according to certificate. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[3]),

    /* Select ciphersuite according to certificate.
     * The order of client ciphersuites are reversed of server. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[2]),

    /* Specified ciphersuites. */
    CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[2]),

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    CIPHERSUITE_INIT(ciphersuite_list_6, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_7, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_8, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_9, NX_TRUE, &test_certs[2]),
#endif

    /* The Server cert supports ECDH_ECDSA and ECDHE_ECDSA. Full default table. */
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_FALSE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_TRUE, &test_certs[1]),  // <========
    CIPHERSUITE_INIT(ciphersuite_list_0, NX_FALSE, &test_certs[1]),

    /* Let the server pickup supported ciphersuite. */
    CIPHERSUITE_INIT(ciphersuite_list_1, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_2, NX_TRUE, &test_certs[0]),
    CIPHERSUITE_INIT(ciphersuite_list_3, NX_TRUE, &test_certs[1]),
    CIPHERSUITE_INIT(ciphersuite_list_4, NX_TRUE, &test_certs[2]),
};

/* Define thread prototypes.  */

static VOID    ntest_0_entry(ULONG thread_input);
static VOID    ntest_1_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#define ERROR_COUNTER() _ERROR_COUNTER(__FILE__, __LINE__)

static VOID    _ERROR_COUNTER(const char *file, int line)
{
	printf("\nError at %s:%d\n", file, line);
    error_counter++;
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_dtls_ecc_ciphersuites_test_application_define(void *first_unused_memory)
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

static VOID ciphersuites_setup(CIPHERSUITE *ciphersuite, NX_SECURE_TLS_CRYPTO *tls_ciphers,
                               NX_SECURE_TLS_CIPHERSUITE_INFO *ciphersuite_table)
{
UINT i;
UINT count;

    /* Initialize ciphersuites to the default table. */
    memcpy(tls_ciphers, &nx_crypto_tls_ciphers_ecc, sizeof(NX_SECURE_TLS_CRYPTO));
    /* If ciphersuite test table has entries, replace the default lookup table
       with one we create here. */
    if (ciphersuite -> count > 0)
    {
        /* Find the entry in the main table. */
        for (count = 0; count < ciphersuite -> count; count++)
        {
            i = 0;
            while (ciphersuite -> list[count] !=
                   (UINT)_nx_crypto_ciphersuite_lookup_table_ecc[i].nx_secure_tls_ciphersuite)
            {
                i++;
            }

            /* Add the entry to the end of the cipbersuite table. */
            memcpy(&ciphersuite_table[count],
                   &_nx_crypto_ciphersuite_lookup_table_ecc[i],
                   sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO));
        }

        /* Set the TLS cipher structure ciphersuite table to the updated ciphersuite table which should now
           only contain the ciphersuites in the "ciphersuite" passed-in parameter. */
        tls_ciphers -> nx_secure_tls_ciphersuite_lookup_table = ciphersuite_table;
        tls_ciphers -> nx_secure_tls_ciphersuite_lookup_table_size = count;
    }
}

static VOID client_dtls_setup(NX_SECURE_DTLS_SESSION *dtls_session_ptr, CERTIFICATE *cert)
{
UINT status;

    status = nx_secure_dtls_session_create(dtls_session_ptr,
                                           &tls_ciphers_client,
                                           client_metadata,
                                           sizeof(client_metadata),
                                           tls_packet_buffer[0], sizeof(tls_packet_buffer[0]),
                                           1, client_cert_buffer, sizeof(client_cert_buffer));

    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_dtls_ecc_initialize(dtls_session_ptr, nx_crypto_ecc_supported_groups,
                                           nx_crypto_ecc_supported_groups_size,
                                           nx_crypto_ecc_curves);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca,
                                                   cert -> ca_cert,
                                                   cert -> ca_cert_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_dtls_session_trusted_certificate_add(dtls_session_ptr, &client_trusted_ca, 1);
    if (status)
    {
        ERROR_COUNTER();
    }


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

static VOID server_dtls_setup(NX_SECURE_DTLS_SERVER *dtls_server_ptr, CERTIFICATE *cert, int i)
{
UINT status;

    /* Use a different port for each client to avoid overlap!! */
    status = nx_secure_dtls_server_create(dtls_server_ptr, &ip_0, SERVER_PORT + i, NX_IP_PERIODIC_RATE,
                                          server_session_buffer, sizeof(server_session_buffer),
                                          &tls_ciphers_server, server_metadata, sizeof(server_metadata),
                                          tls_packet_buffer[1], sizeof(tls_packet_buffer[1]),
                                          server_connect_notify, server_receive_notify);
    if (status)
    {
        ERROR_COUNTER();
    }

    status = nx_secure_dtls_server_ecc_initialize(dtls_server_ptr, nx_crypto_ecc_supported_groups,
                                                  nx_crypto_ecc_supported_groups_size,
                                                  nx_crypto_ecc_curves);
    if (status)
    {
        ERROR_COUNTER();
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   cert -> server_cert, cert -> server_cert_len,
                                                   NX_NULL, 0, cert -> server_key,
                                                   cert -> server_key_len,
                                                   cert -> key_type);
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
UINT i;
UINT status;
ULONG response_length;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS ECC Ciphersuites Test.........................");

    for (i = 0; i < sizeof(ciphersuites_server) / sizeof(CIPHERSUITE); i++)
    {

        ciphersuites_setup(&ciphersuites_server[i], &tls_ciphers_server, ciphersuite_table_server);

        server_dtls_setup(&dtls_server_0, ciphersuites_server[i].cert, i);


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

        status = nx_secure_dtls_server_session_start(connect_session, NX_WAIT_FOREVER);
        if ((status && ciphersuites_server[i].session_succ) ||
            (!status && !ciphersuites_server[i].session_succ))
        {
            printf("Server failure with i=%d, status=%x\n", i, status);
            ERROR_COUNTER();
        }

        if (!status)
        {
        
            /* Wait for records to be received. */
            while (server_receive_notify_flag != NX_TRUE)
            {
                tx_thread_sleep(1);
            }

            status = nx_secure_dtls_session_receive(receive_session, &packet_ptr, NX_WAIT_FOREVER);
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
        }


        status = nx_secure_dtls_session_end(receive_session, NX_WAIT_FOREVER);
        if(status)
        {
            ERROR_COUNTER();
        }

        tx_thread_sleep(NX_IP_PERIODIC_RATE * 5);

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

    for (i = 0; i < sizeof(ciphersuites_client) / sizeof(CIPHERSUITE); i++)
    {

        for (j = 0; j < sizeof(request_buffer); j++)
        {
            request_buffer[j] = j;
            response_buffer[j] = 0;
        }
        request_buffer[0] = i;

        ciphersuites_setup(&ciphersuites_client[i], &tls_ciphers_client, ciphersuite_table_client);

        client_dtls_setup(&dtls_client_session_0, ciphersuites_client[i].cert);

        /* Start DTLS session. */
        status = nx_secure_dtls_client_session_start(&dtls_client_session_0, &client_socket_0, &server_address, SERVER_PORT + i, NX_WAIT_FOREVER);
        if ((status != NX_SUCCESS && ciphersuites_client[i].session_succ) ||
            (status == NX_SUCCESS && !ciphersuites_client[i].session_succ))
        {
            printf("Client failure with i=%d, status=%x\n", i, status);
            ERROR_COUNTER();
        }

        if (!status)
        {

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
                                                  &server_address, SERVER_PORT + i);
            if (status)
            {
                ERROR_COUNTER();
            }
        }

        status = nx_secure_dtls_session_end(&dtls_client_session_0, NX_WAIT_FOREVER);
        if(status)
        {
            ERROR_COUNTER();
        }
        nx_secure_dtls_session_delete(&dtls_client_session_0);

        tx_thread_sleep(NX_IP_PERIODIC_RATE * 5);

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
VOID    nx_secure_dtls_ecc_ciphersuites_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS ECC Ciphersuites Test.........................N/A\n");
    test_control_return(3);
}
#endif
