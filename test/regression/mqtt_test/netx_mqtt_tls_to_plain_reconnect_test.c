/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* MQTT TLS to plain reconnect test.  This test case validates that a plain connection can be
   established on a client instance that was previously used for a secure connection, through
   both teardown routes: a secure connection ended by nxd_mqtt_client_disconnect(), and a secure
   connection that never completed because the TCP connect itself failed.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_mqtt_client.h"

extern void    test_control_return(UINT status);

#if defined(NX_SECURE_ENABLE) && !defined(NXD_MQTT_REQUIRE_TLS)

#include "../web_test/test_device_cert.c"
#include "../web_test/test_ca_cert.c"

#define     DEMO_STACK_SIZE    2048

#define CLIENT_ID "1234"

/* The port the failed secure connect is directed to.  Nothing listens on it.  */
#define UNREACHABLE_PORT   (NXD_MQTT_PORT + 1)

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           server_socket;

#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))

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

static TX_SEMAPHORE semaphore_server_start;
static TX_SEMAPHORE semaphore_client_stop;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
#ifdef CTEST
static
#else /* CTEST */
extern
#endif /* CTEST */
UCHAR mqtt_memory[8192];
extern void SET_ERROR_COUNTER(ULONG *error_counter, CHAR *filename, int line_number);

/* Define what the initial system looks like.  */
static NXD_MQTT_CLIENT *client_ptr;
static UCHAR *stack_ptr;
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void       netx_mqtt_tls_to_plain_reconnect_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
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

#define MQTT_CLIENT_THREAD_PRIORITY  2
static UINT keepalive_value;
static UINT cleansession_value;

/* Define the test threads.  */
/* This thread sets up MQTT client and makes a plain connect request on a client instance that
   was previously used for a secure connection. */
static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NXD_ADDRESS server_address;

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT TLS To Plain Reconnect Test .........................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_mqtt_client_create(client_ptr, "my client", CLIENT_ID, strlen(CLIENT_ID), &ip_0, &pool_0,
                                    stack_ptr, DEMO_STACK_SIZE, MQTT_CLIENT_THREAD_PRIORITY,
                                    mqtt_memory, sizeof(mqtt_memory));
    if(status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    tx_thread_sleep(1);

    server_address.nxd_ip_version = 4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    keepalive_value = 0;
    cleansession_value = 0;

    /* Case 1: the secure connect fails at the TCP level, so the connection is torn down by the
       error path of _nxd_mqtt_client_connect() rather than by _nxd_mqtt_client_connection_end().  */
    status = nxd_mqtt_client_secure_connect(client_ptr, &server_address, UNREACHABLE_PORT,
                                            client_tls_setup,
                                            keepalive_value, cleansession_value, NX_IP_PERIODIC_RATE);

    if (status != NXD_MQTT_CONNECT_FAILURE)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    /* A plain connect on the same client instance must now succeed.  */
    tx_semaphore_get(&semaphore_server_start, NX_WAIT_FOREVER);

    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT,
                                     keepalive_value, cleansession_value, NX_IP_PERIODIC_RATE);

    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    nxd_mqtt_client_disconnect(client_ptr);

    tx_semaphore_put(&semaphore_client_stop);

    /* Case 2: the secure connection is established, then ended by nxd_mqtt_client_disconnect(),
       which goes through _nxd_mqtt_client_connection_end().  */
    tx_semaphore_get(&semaphore_server_start, NX_WAIT_FOREVER);

    status = nxd_mqtt_client_secure_connect(client_ptr, &server_address, NXD_MQTT_PORT,
                                            client_tls_setup,
                                            keepalive_value, cleansession_value, NX_IP_PERIODIC_RATE);

    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    nxd_mqtt_client_disconnect(client_ptr);

    tx_semaphore_put(&semaphore_client_stop);

    /* A plain connect on the same client instance must now succeed.  */
    tx_semaphore_get(&semaphore_server_start, NX_WAIT_FOREVER);

    status = nxd_mqtt_client_connect(client_ptr, &server_address, NXD_MQTT_PORT,
                                     keepalive_value, cleansession_value, NX_IP_PERIODIC_RATE);

    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    nxd_mqtt_client_disconnect(client_ptr);

    tx_semaphore_put(&semaphore_client_stop);

    nxd_mqtt_client_delete(client_ptr);

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

/* Accept one connection, validate the MQTT connect request and respond with a CONNACK. */
static void    server_serve_connection(UINT use_tls)
{
UINT       status;
NX_PACKET  *packet_ptr;
UCHAR      *byte;

    tx_semaphore_put(&semaphore_server_start);

    /* Accept a connection from client socket.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

    if (use_tls)
    {

        /* Session setup.  */
        status = server_tls_setup(&tls_server_session);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        status = nx_secure_tls_session_start(&tls_server_session, &server_socket, NX_WAIT_FOREVER);
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    }

    tx_thread_sleep(1);

    if (use_tls)
    {
        status = nx_secure_tls_session_receive(&tls_server_session, &packet_ptr, NX_WAIT_FOREVER);
    }
    else
    {
        status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    }

    if (status)
    {
        SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    }
    else
    {

        /* construct the connect message. */
        memcpy(content, fixed_header, sizeof(fixed_header));
        /* Append client ID */
        content[sizeof(fixed_header)] = (strlen(CLIENT_ID) >> 8) & 0xf;
        content[sizeof(fixed_header) + 1] = (strlen(CLIENT_ID) & 0xf);
        memcpy(content + sizeof(fixed_header) + 2, CLIENT_ID, strlen(CLIENT_ID));

        content[1] = (UCHAR)(sizeof(fixed_header) + strlen(CLIENT_ID));

        /* Fill in the connection_flag, keepalive, and cleansession flags. */
        content[10] = keepalive_value >> 8;
        content[11] = keepalive_value & 0xFF;
        if (cleansession_value)
            content[9] = content[9] | 2;

        /* Validate the MQTT connect request. */
        if (memcmp(packet_ptr->nx_packet_prepend_ptr, content, sizeof(fixed_header) + strlen(CLIENT_ID)))
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        if (use_tls)
        {
            nx_packet_release(packet_ptr);
            status = nx_secure_tls_packet_allocate(&tls_server_session, &pool_0, &packet_ptr, NX_NO_WAIT);
            if (status)
                SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
        }

        /* Response with SUCCESS */
        byte = packet_ptr->nx_packet_prepend_ptr;
        byte[0] = 0x20;
        byte[1] = 0x02;
        byte[2] = 0;
        byte[3] = 0;

        packet_ptr->nx_packet_append_ptr = packet_ptr->nx_packet_prepend_ptr + 4;
        packet_ptr->nx_packet_length = 4;

        if (use_tls)
        {
            status = nx_secure_tls_session_send(&tls_server_session, packet_ptr, NX_WAIT_FOREVER);
        }
        else
        {
            status = nx_tcp_socket_send(&server_socket, packet_ptr, 1);
        }

        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);

        tx_thread_sleep(1);

        if (use_tls)
        {

            /* End session.  */
            nx_secure_tls_session_end(&tls_server_session, NX_NO_WAIT);
        }

        /* Disconnect.  */
        status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
            SET_ERROR_COUNTER(&error_counter, __FILE__, __LINE__);
    }

    if (use_tls)
    {

        /* Delete the session.  */
        nx_secure_tls_session_delete(&tls_server_session);
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

/* This thread acts as MQTT server, accepting the connection. */
static void    ntest_1_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;

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

    tx_thread_resume(&ntest_0);

    /* Case 1: the failed secure connect is directed to UNREACHABLE_PORT, so only the plain
       connect that follows it reaches this thread.  */
    server_serve_connection(NX_FALSE);

    /* Case 2: a secure connection, then a plain one on the same client instance.  */
    server_serve_connection(NX_TRUE);
    server_serve_connection(NX_FALSE);

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

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void       netx_mqtt_tls_to_plain_reconnect_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   MQTT TLS To Plain Reconnect Test .........................N/A\n");

    test_control_return(3);
}
#endif
