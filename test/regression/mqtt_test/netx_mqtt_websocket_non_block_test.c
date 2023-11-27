/* MQTT over websocket connect test.  This test case validates MQTT client connect over websocket in non-blocking mode. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_mqtt_client.h"
#include   "nx_websocket_client.h"
#include   "nx_sha1.h"

extern void    test_control_return(UINT status);
#if defined(NX_ENABLE_EXTENDED_NOTIFY_SUPPORT) && defined(NXD_MQTT_OVER_WEBSOCKET)

/* Define the ThreadX and NetX object control blocks...  */
#define DEMO_STACK_SIZE         2048
#define CLIENT_ID               "1234"
#define NUM_PACKETS             24
#define PACKET_SIZE             1536
#define PACKET_POOL_SIZE        (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))

#define HOST_NAME                 "test.host.org"
#define TEST_CONNECT_GUID         "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define TEST_CONNECT_GUID_SIZE    (sizeof(TEST_CONNECT_GUID) - 1)
#define TEST_CONNECT_DIGEST_SIZE  21 /* The length of SHA-1 hash is 20 bytes, with 1 extra byte for base64 encode calculation */
#define TEST_CONNECT_KEY_SIZE     32 /* Make it larger than the minimum length (28 bytes )for the encoded key */

static TX_THREAD                ntest_0;
static TX_THREAD                ntest_1;

static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static NX_IP                    ip_1;
static NX_TCP_SOCKET            server_socket;


static UCHAR                    connect_key[TEST_CONNECT_KEY_SIZE];
static UINT                     connect_key_size;

static NXD_MQTT_CLIENT          *client_ptr;
static UCHAR                    *stack_ptr;

static TX_SEMAPHORE             semaphore_server_start;
static TX_SEMAPHORE             semaphore_client_stop;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   connected = NX_FALSE;

#ifdef NX_SECURE_ENABLE

#include "../web_test/test_device_cert.c"
#include "../web_test/test_ca_cert.c"

/* Declare external cryptosuites. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

static NX_SECURE_TLS_SESSION tls_server_session;
static NX_SECURE_X509_CERT server_local_certificate;

/* Define crypto metadata buffer. */
static UCHAR client_metadata[5*4096];
static UCHAR server_metadata[5*4096];

/* For remote certificate. */
static NX_SECURE_X509_CERT remote_certificate, remote_issuer, ca_certificate;
static UCHAR remote_cert_buffer[2000];
static UCHAR remote_issuer_buffer[2000];
static UCHAR tls_packet_buffer[2][4096];

#define TEST_LOOP 4
#else
#define TEST_LOOP 2
#endif

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1024(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    SET_ERROR_COUNTER(ULONG *error_counter, CHAR *filename, int line_number);
static void    mqtt_connect_notify(struct NXD_MQTT_CLIENT_STRUCT *client_ptr, UINT status, VOID *context);

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void       netx_mqtt_websocket_non_block_test_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_DONT_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    tx_semaphore_create(&semaphore_server_start, "semaphore server start", 0);
    tx_semaphore_create(&semaphore_client_stop, "semaphore client stop", 0);

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pointer, PACKET_POOL_SIZE);
    pointer = pointer + PACKET_POOL_SIZE;

    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1024,
                           pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    stack_ptr = pointer;
    pointer += DEMO_STACK_SIZE;
    client_ptr = (NXD_MQTT_CLIENT*)pointer;

}

#ifdef NX_SECURE_ENABLE

/* Define the callback function for tls connection. */
static UINT client_tls_setup(NXD_MQTT_CLIENT* client_ptr, NX_SECURE_TLS_SESSION* tls_session,
                             NX_SECURE_X509_CERT* certificate, NX_SECURE_X509_CERT* trusted_certificate)
{
UINT status;

    /* Create a tls session. */
    status = nx_secure_tls_session_create(tls_session,
                                          &nx_crypto_tls_ciphers,
                                          client_metadata,
                                          sizeof(client_metadata));

    if (status)
    {
        return status;
    }
    
    nx_secure_tls_session_packet_buffer_set(tls_session, tls_packet_buffer[0], sizeof(tls_packet_buffer[0]));
    nx_secure_tls_remote_certificate_allocate(tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));

    nx_secure_x509_certificate_initialize(&ca_certificate, test_ca_cert_der, test_ca_cert_der_len,
                                          NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(tls_session, &ca_certificate);

    return(NX_SUCCESS);
}

static UINT server_tls_setup(NX_SECURE_TLS_SESSION *tls_session)
{
UINT status;

    status = nx_secure_tls_session_create(tls_session,
                                          &nx_crypto_tls_ciphers,
                                          server_metadata,
                                          sizeof(server_metadata));
    if (status)
    {
        return status;
    }

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    nx_secure_x509_certificate_initialize(&server_local_certificate,
                                          test_device_cert_der, test_device_cert_der_len,
                                          NX_NULL, 0, test_device_cert_key_der,
                                          test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);

    nx_secure_tls_local_certificate_add(tls_session, &server_local_certificate);

    nx_secure_tls_session_packet_buffer_set(tls_session, tls_packet_buffer[1], sizeof(tls_packet_buffer[1]));

    return(NX_SUCCESS);
}
#endif

#define MQTT_CLIENT_THREAD_PRIORITY  2
static UINT keepalive_value;
static UINT cleansession_value;
/* Define the test threads.  */
/* This thread sets up MQTT client and makes a connect request without username/password. */
static void    ntest_0_entry(ULONG thread_input)
{
UINT status;
NXD_ADDRESS server_address;
UINT i;

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT Websocket Non Block Test.............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_mqtt_client_create(client_ptr, "my client", CLIENT_ID, strlen(CLIENT_ID), &ip_0, &pool_0,
                                    stack_ptr, DEMO_STACK_SIZE, MQTT_CLIENT_THREAD_PRIORITY, NX_NULL, 0);
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    if ((status = nxd_mqtt_client_websocket_set(client_ptr, (UCHAR *)HOST_NAME, sizeof(HOST_NAME) - 1, (UCHAR *)"/mqtt", sizeof("/mqtt") - 1)))
    {
        printf("Error setting MQTT websocket: 0x%02x\r\n", status);
        return;
    }

    tx_thread_sleep(1);

    server_address.nxd_ip_version = 4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    keepalive_value = 0;
    cleansession_value = 0;

    client_ptr-> nxd_mqtt_connect_notify = mqtt_connect_notify;

    for (i = 0; i < TEST_LOOP; i++)
    {

        tx_semaphore_get(&semaphore_server_start, NX_WAIT_FOREVER);

        if (i < 2)
        {
            status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT,
                                             keepalive_value, cleansession_value, 0);

#ifndef NXD_MQTT_REQUIRE_TLS
            if (status != NX_IN_PROGRESS)
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
#else
            if (status != NXD_MQTT_CONNECT_FAILURE)
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
#endif
        }
#ifdef NX_SECURE_ENABLE
        else
        {
            status = nxd_mqtt_client_secure_connect(client_ptr, &server_address, NXD_MQTT_PORT,
                                                    client_tls_setup,
                                                    keepalive_value, cleansession_value, 0);

            if (status != NX_IN_PROGRESS)
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        }
#endif

#ifdef NXD_MQTT_REQUIRE_TLS
        if (i >= 2)
#endif
        {

            /* Wait for connecting.  */
            tx_thread_sleep(NX_IP_PERIODIC_RATE);

            /* Check connected flag.  */
            if (connected == NX_FALSE)
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

            nxd_mqtt_client_disconnect(client_ptr);
        }

        tx_semaphore_put(&semaphore_client_stop);
    }
    nxd_mqtt_client_delete(client_ptr);

    if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total)
    {
        error_counter++;
    }

    /* Determine if the test was successful.  */
    if(error_counter)
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


static UCHAR content[100];
static UCHAR fixed_header[] = {0x10, 0x00, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x4, 0x0, 0x0, 0x0};
static UCHAR server_switch_101[] = 
{
0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x31, 0x30, 0x31, 0x20, 0x53, 0x77, 0x69, /* HTTP/1.1 101 Swi */
0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x73, /* tching Protocols */
0x0d, 0x0a, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x3a, 0x20, 0x57, 0x65, 0x62, 0x53, 0x6f, /* ..Upgrade: WebSo */
0x63, 0x6b, 0x65, 0x74, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, /* cket..Connection */
0x3a, 0x20, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x0d, 0x0a, 0x53, 0x65, 0x63, 0x2d, 0x57, /* : Upgrade..Sec-W */
0x65, 0x62, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2d, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, /* ebSocket-Accept: */
0x20, 0x64, 0x4f, 0x32, 0x68, 0x36, 0x5a, 0x4c, 0x46, 0x33, 0x71, 0x54, 0x74, 0x4d, 0x48, 0x7a, /*  dO2h6ZLF3qTtMHz */
0x47, 0x4b, 0x69, 0x59, 0x76, 0x53, 0x52, 0x45, 0x57, 0x6a, 0x76, 0x55, 0x3d, 0x0d, 0x0a, 0x53, /* GKiYvSREWjvU=..S */
0x65, 0x63, 0x2d, 0x57, 0x65, 0x62, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2d, 0x50, 0x72, 0x6f, /* ec-WebSocket-Pro */
0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x3a, 0x20, 0x6d, 0x71, 0x74, 0x74, 0x0d, 0x0a, 0x0d, 0x0a,       /* tocol: mqtt.... */
};


static UINT  _server_connect_response_process(NX_PACKET *packet_ptr)
{
UCHAR  *buffer_ptr;
UINT    offset = 0;
UCHAR  *field_name;
UINT    field_name_length;
UCHAR  *field_value;
UINT    field_value_length;
NX_SHA1 SH;
UCHAR   digest[TEST_CONNECT_DIGEST_SIZE];

    buffer_ptr = packet_ptr -> nx_packet_prepend_ptr;

    /* Skip over the first Command line (GET /xxx HTTP/1.1\r\n).  */
    while(((buffer_ptr + 1) < packet_ptr -> nx_packet_append_ptr) &&
          (*buffer_ptr != '\r') && (*(buffer_ptr + 1) != '\n'))
    {
        buffer_ptr++;
        offset++;
    }

    /* Skip over the CR,LF. */
    buffer_ptr += 2;
    offset += 2;

    /* Skip over the first Host line (Host: xxx\r\n).  */
    while(((buffer_ptr + 1) < packet_ptr -> nx_packet_append_ptr) &&
          (*buffer_ptr != '\r') && (*(buffer_ptr + 1) != '\n'))
    {
        buffer_ptr++;
        offset++;
    }

    /* Skip over the CR,LF. */
    buffer_ptr += 2;
    offset += 2;

    /* Loop until we find the "cr,lf,cr,lf" token.  */
    while (((buffer_ptr + 1) < packet_ptr -> nx_packet_append_ptr) && (*buffer_ptr != 0))
    {

        /* Check for the <cr,lf,cr,lf> token.  This signals a blank line, which also 
           specifies the start of the content.  */
        if ((*buffer_ptr == '\r') &&
            (*(buffer_ptr + 1) ==  '\n'))
        {

            /* Adjust the offset.  */
            offset = offset + 2;
            break;
        }

        /* We haven't seen the <cr,lf,cr,lf> so we are still processing header data.
           Extract the field name and it's value.  */
        field_name = buffer_ptr;
        field_name_length = 0;

        /* Look for the ':' that separates the field name from its value. */
        while(*buffer_ptr != ':')
        {
            buffer_ptr++;
            field_name_length++;
        }
        offset += field_name_length;

        /* Skip ':'.  */
        buffer_ptr++;
        offset++;

        /* Now skip over white space. */
        while ((buffer_ptr < packet_ptr -> nx_packet_append_ptr) && (*buffer_ptr == ' '))
        {
            buffer_ptr++;
            offset++;
        }

        /* Now get the field value. */
        field_value = buffer_ptr;
        field_value_length = 0;

        /* Loop until we see a <CR, LF>. */
        while(((buffer_ptr + 1) < packet_ptr -> nx_packet_append_ptr) && (*buffer_ptr != '\r') && (*(buffer_ptr+1) != '\n'))
        {
            buffer_ptr++;
            field_value_length++;
        }
        offset += field_value_length;

        /* Skip over the CR,LF. */
        buffer_ptr += 2;
        offset += 2;

        /* Check the upgrade.  */
        if (_nx_websocket_client_name_compare((UCHAR *)field_name, field_name_length, (UCHAR *)"Upgrade", sizeof("Upgrade") - 1) == NX_SUCCESS)
        {
            if (_nx_websocket_client_name_compare((UCHAR *)field_value, field_value_length, (UCHAR *)"websocket", sizeof("websocket") - 1))
            {
                return(NX_WEBSOCKET_INVALID_PACKET);
            }
        }
        else if (_nx_websocket_client_name_compare((UCHAR *)field_name, field_name_length, (UCHAR *)"Connection", sizeof("Connection") - 1) == NX_SUCCESS)
        {
            if (_nx_websocket_client_name_compare((UCHAR *)field_value, field_value_length, (UCHAR *)"Upgrade", sizeof("Upgrade") - 1))
            {
                return(NX_WEBSOCKET_INVALID_PACKET);
            }
        }
        else if (_nx_websocket_client_name_compare((UCHAR *)field_name, field_name_length, (UCHAR *)"Sec-WebSocket-Key", sizeof("Sec-WebSocket-Key") - 1) == NX_SUCCESS)
        {

            /* Calculate the SHA-1 hash of the concatenation of the client key and the Globally Unique Identifier (GUID)
               Referenced in RFC 6455, Section 1.3, Page 6 */
            _nx_sha1_initialize(&SH);
            _nx_sha1_update(&SH, field_value, field_value_length);
            _nx_sha1_update(&SH, (UCHAR*)TEST_CONNECT_GUID, TEST_CONNECT_GUID_SIZE);
            _nx_sha1_digest_calculate(&SH, digest);

            /* Set the last extra byte of the digest to be zero, since the function _nx_utility_base64_encode will use this byte for calculation */
            digest[20] = 0;

            /* Encode the hash and compare it with the field value from the server.  */
            _nx_utility_base64_encode(digest, (TEST_CONNECT_DIGEST_SIZE - 1), connect_key, TEST_CONNECT_KEY_SIZE, &connect_key_size);
        }
    }

    /* Check if the all fields are processed.  */
    if (offset != packet_ptr -> nx_packet_length)
    {
        return(NX_WEBSOCKET_INVALID_PACKET);
    }

    return(NX_SUCCESS);
}

/* This thread acts as MQTT server, accepting the connection. */
static void    ntest_1_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
NX_PACKET  *packet_ptr;
UCHAR      *buffer_ptr;
UINT       i, j;
UINT       length;
UINT       packet_count;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1000,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, NXD_MQTT_PORT, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

#ifdef NX_SECURE_ENABLE
    /* Session setup.  */
    server_tls_setup(&tls_server_session);
#endif

    tx_thread_resume(&ntest_0);

    for (i = 0; i < TEST_LOOP; i++)
    {

        tx_semaphore_put(&semaphore_server_start);

        /* Accept a connection from client socket.  */
        status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
#ifdef NXD_MQTT_REQUIRE_TLS
            if (i >= 2)
#endif
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        }

#ifdef NX_SECURE_ENABLE
        if (i >= 2)
        {
            status = nx_secure_tls_session_start(&tls_server_session, &server_socket, NX_WAIT_FOREVER);
            if (status)
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        }
#endif

        tx_thread_sleep(1);

        /* Receive websocket connect.  */
        if (i < 2)
        {
            status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        }
#ifdef NX_SECURE_ENABLE
        else
        {
            status = nx_secure_tls_session_receive(&tls_server_session, &packet_ptr, NX_WAIT_FOREVER);
        }
#endif
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        /* Get connect_key.  */
        _server_connect_response_process(packet_ptr);
        memcpy(&server_switch_101[97], connect_key, 28);
        nx_packet_release(packet_ptr);

        if (i % 2 == 0)
        {
            packet_count = 1;
        }
        else
        {
            packet_count = 3;
        }

        buffer_ptr = server_switch_101;
        for (j = 0; j < packet_count; j++)
        {

            if ((packet_count == 3) && (j < 2))
            {
                length = 50;
            }
            else
            {
                length = sizeof(server_switch_101) - 50 * j;
            }

            if (i < 2)
            {
                status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
                if (status)
                    SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
            }
#ifdef NX_SECURE_ENABLE
            else
            {

                status = nx_secure_tls_packet_allocate(&tls_server_session, &pool_0, &packet_ptr, NX_NO_WAIT);
                if (status)
                    SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
            }
#endif

            /* Append response 101.  */
            status = nx_packet_data_append(packet_ptr, buffer_ptr, length, &pool_0, NX_NO_WAIT);
            if (status)
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

            /* Send websocket connect response.  */
            if (i < 2)
            {
                status = nx_tcp_socket_send(&server_socket, packet_ptr, NX_IP_PERIODIC_RATE);
            }
#ifdef NX_SECURE_ENABLE
            else
            {
                status = nx_secure_tls_session_send(&tls_server_session, packet_ptr, NX_WAIT_FOREVER);
            }
#endif
            if (status)
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

            buffer_ptr += length;
        }

        /* Receive MQTT connect.  */
        if (i < 2)
        {
            status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
        }
#ifdef NX_SECURE_ENABLE
        else
        {
            status = nx_secure_tls_session_receive(&tls_server_session, &packet_ptr, NX_WAIT_FOREVER);
        }
#endif

        if (status)
        {
#ifdef NXD_MQTT_REQUIRE_TLS
            if (i >= 2)
#endif
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        }
        else
        {

#ifdef NX_SECURE_ENABLE
            if (i >= 2)
            {
                nx_packet_release(packet_ptr);
                status = nx_secure_tls_packet_allocate(&tls_server_session, &pool_0, &packet_ptr, NX_NO_WAIT);
                if (status)
                    SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
            }
#endif

            /* Response with SUCCESS */
            buffer_ptr = packet_ptr->nx_packet_prepend_ptr;
            buffer_ptr[0] = 0x82;
            buffer_ptr[1] = 0x04;
            buffer_ptr[2] = 0x20;
            buffer_ptr[3] = 0x02;
            buffer_ptr[4] = 0;
            buffer_ptr[5] = 0;

            packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr + 6;
            packet_ptr->nx_packet_length = 6;

            if (i < 2)
            {
                status = nx_tcp_socket_send(&server_socket, packet_ptr, NX_IP_PERIODIC_RATE);
            }
#ifdef NX_SECURE_ENABLE
            else
            {
                status = nx_secure_tls_session_send(&tls_server_session, packet_ptr, NX_WAIT_FOREVER);
            }
#endif
            if (status)
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

#ifdef NX_SECURE_ENABLE
            if (i >= 2)
            {
                /* End session.  */
                nx_secure_tls_session_end(&tls_server_session, NX_NO_WAIT);
            }
#endif

            /* Disconnect.  */
            status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

            /* Check for error.  */
            if (status)
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        }

        tx_semaphore_get(&semaphore_client_stop, NX_WAIT_FOREVER);

        /* Unaccept the server socket.  */
        status = nx_tcp_server_socket_unaccept(&server_socket);

        /* Check for error.  */
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        /* Prepare to accept another connection. */
        status = nx_tcp_server_socket_relisten(&ip_1, NXD_MQTT_PORT, &server_socket);

        /* Check for error.  */
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    }

#ifdef NX_SECURE_ENABLE
    /* Delete the session.  */
    nx_secure_tls_session_delete(&tls_server_session);
#endif

    /* Unlisten on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, NXD_MQTT_PORT);

    /* Check for error.  */
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
}


static void    mqtt_connect_notify(struct NXD_MQTT_CLIENT_STRUCT *client_ptr, UINT status, VOID *context)
{

    /* Check status. */
    if (status == NXD_MQTT_SUCCESS)
    {
        connected = NX_TRUE;
    }
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void       netx_mqtt_websocket_non_block_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT Websocket Non Block Test.............................N/A\n");

    test_control_return(3);
}
#endif

