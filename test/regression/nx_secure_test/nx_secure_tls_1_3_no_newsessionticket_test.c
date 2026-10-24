/***************************************************************************/
/* Copyright (c) 2024 Microsoft Corporation                                */
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* This test completes a TLS 1.3 handshake between a NetX client and a    */
/* NetX server and asserts that the server sends no additional record     */
/* after its Finished. The server previously emitted a stub               */
/* NewSessionTicket here; see PR #403 for the reason it was removed.      */

#include   "nx_api.h"
#include   "nx_secure_tls_api.h"
#include   "ecc_certs.c"

extern VOID    test_control_return(UINT status);


#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && (NX_SECURE_TLS_TLS_1_3_ENABLED)
#define NUM_PACKETS                 24
#define PACKET_SIZE                 1536
#define PACKET_POOL_SIZE            (NUM_PACKETS * (PACKET_SIZE + sizeof(NX_PACKET)))
#define THREAD_STACK_SIZE           1024
#define ARP_CACHE_SIZE              1024
#define METADATA_SIZE               16000
#define CERT_BUFFER_SIZE            2048
#define SERVER_PORT                 4433

/* Define the ThreadX and NetX object control blocks. */

static TX_THREAD                thread_server;
static TX_THREAD                thread_client;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static UINT                     error_counter;

static NX_TCP_SOCKET            client_socket_0;
static NX_SECURE_TLS_SESSION    tls_client_session_0;
static NX_SECURE_X509_CERT      client_trusted_ca;
static NX_SECURE_X509_CERT      client_remote_cert;
static NX_TCP_SOCKET            server_socket_0;
static NX_SECURE_TLS_SESSION    tls_server_session_0;
static NX_SECURE_X509_CERT      server_local_certificate;

static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                    thread_server_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    thread_client_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static ULONG                    arp_cache[ARP_CACHE_SIZE];
static UCHAR                    client_metadata[METADATA_SIZE];
static UCHAR                    server_metadata[METADATA_SIZE];
static UCHAR                    client_cert_buffer[CERT_BUFFER_SIZE];

static UCHAR                    tls_packet_buffer[2][4000];

extern const                    USHORT nx_crypto_ecc_supported_groups[];
extern const                    NX_CRYPTO_METHOD *nx_crypto_ecc_curves[];
extern const                    UINT nx_crypto_ecc_supported_groups_size;
extern const                    NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

/* Signal from client to server: handshake done and the raw TCP receive
   check has finished, so the server may tear down its session. */
static TX_SEMAPHORE             semaphore_check_done;

/* Define thread prototypes. */

static VOID    test_client_entry(ULONG thread_input);
static VOID    test_server_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

static VOID    ERROR_COUNTER(void)
{
    error_counter++;
}

#define do_something_if_fail(p)   if (!(p)) { ERROR_COUNTER(); }

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_no_newsessionticket_test_application_define(void *first_unused_memory)
#endif
{
UINT     status;
CHAR    *pointer;

    error_counter = 0;

    pointer = (CHAR *)first_unused_memory;

    tx_thread_create(&thread_server, "thread server", test_server_entry, 0,
                     thread_server_stack, sizeof(thread_server_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);

    tx_thread_create(&thread_client, "thread client", test_client_entry, 0,
                     thread_client_stack, sizeof(thread_client_stack),
                     8, 8, TX_NO_TIME_SLICE, TX_AUTO_START);

    tx_semaphore_create(&semaphore_check_done, "semaphore check done", 0);

    nx_system_initialize();

    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE,
                                   pool_0_memory, PACKET_POOL_SIZE);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL,
                          &pool_0, _nx_ram_network_driver_1500,
                          ip_0_stack, sizeof(ip_0_stack), 1);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_arp_enable(&ip_0, (VOID *)arp_cache, sizeof(arp_cache));
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_tcp_enable(&ip_0);
    do_something_if_fail(status == NX_SUCCESS);

    nx_secure_tls_initialize();
}

static VOID client_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    memset(client_metadata, 0xFF, sizeof(client_metadata));
    status = nx_secure_tls_session_create(tls_session_ptr,
                                          &nx_crypto_tls_ciphers_ecc,
                                          client_metadata,
                                          sizeof(client_metadata));
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    do_something_if_fail(status == NX_SUCCESS);

    memset(&client_remote_cert, 0, sizeof(client_remote_cert));
    status = nx_secure_tls_remote_certificate_allocate(tls_session_ptr,
                                                       &client_remote_cert,
                                                       client_cert_buffer,
                                                       sizeof(client_cert_buffer));
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_x509_certificate_initialize(&client_trusted_ca, ECCA4_der, ECCA4_der_len,
                                                   NX_NULL, 0, NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_trusted_certificate_add(tls_session_ptr, &client_trusted_ca);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[0],
                                                     sizeof(tls_packet_buffer[0]));
    do_something_if_fail(status == NX_SUCCESS);
}

static VOID server_tls_setup(NX_SECURE_TLS_SESSION *tls_session_ptr)
{
UINT status;

    memset(server_metadata, 0xFF, sizeof(server_metadata));
    status = nx_secure_tls_session_create(tls_session_ptr,
                                          &nx_crypto_tls_ciphers_ecc,
                                          server_metadata,
                                          sizeof(server_metadata));
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_ecc_initialize(tls_session_ptr, nx_crypto_ecc_supported_groups,
                                          nx_crypto_ecc_supported_groups_size,
                                          nx_crypto_ecc_curves);
    do_something_if_fail(status == NX_SUCCESS);

    memset(&server_local_certificate, 0, sizeof(server_local_certificate));
    status = nx_secure_x509_certificate_initialize(&server_local_certificate,
                                                   ECTestServer4_der, ECTestServer4_der_len,
                                                   NX_NULL, 0, ECTestServer4_key_der,
                                                   ECTestServer4_key_der_len,
                                                   NX_SECURE_X509_KEY_TYPE_EC_DER);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_local_certificate_add(tls_session_ptr,
                                                 &server_local_certificate);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_session_packet_buffer_set(tls_session_ptr, tls_packet_buffer[1],
                                                     sizeof(tls_packet_buffer[1]));
    do_something_if_fail(status == NX_SUCCESS);
}

static void test_server_entry(ULONG thread_input)
{
UINT status;

    printf("NetX Secure Test:   TLS 1.3 No NewSessionTicket Test..................");

    status = nx_tcp_socket_create(&ip_0, &server_socket_0, "Server socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_tcp_server_socket_listen(&ip_0, SERVER_PORT, &server_socket_0, 5, NX_NULL);
    do_something_if_fail(status == NX_SUCCESS);

    server_tls_setup(&tls_server_session_0);

    status = nx_tcp_server_socket_accept(&server_socket_0, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_session_start(&tls_server_session_0, &server_socket_0, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);

    /* Wait for the client to finish its post-handshake check before we
       tear down. Tearing down early would send a close_notify alert that
       the client's raw TCP peek could observe. */
    tx_semaphore_get(&semaphore_check_done, NX_WAIT_FOREVER);

    nx_secure_tls_session_end(&tls_server_session_0, NX_IP_PERIODIC_RATE);
    nx_secure_tls_session_delete(&tls_server_session_0);

    nx_tcp_socket_disconnect(&server_socket_0, NX_NO_WAIT);
    nx_tcp_server_socket_unaccept(&server_socket_0);
    nx_tcp_server_socket_unlisten(&ip_0, SERVER_PORT);
    nx_tcp_socket_delete(&server_socket_0);
}

static void test_client_entry(ULONG thread_input)
{
UINT       status;
NX_PACKET *packet_ptr = NX_NULL;
NXD_ADDRESS server_address;

    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(127, 0, 0, 1);

    status = nx_tcp_socket_create(&ip_0, &client_socket_0, "Client socket", NX_IP_NORMAL,
                                  NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_tcp_client_socket_bind(&client_socket_0, NX_ANY_PORT, NX_NO_WAIT);
    do_something_if_fail(status == NX_SUCCESS);

    client_tls_setup(&tls_client_session_0);

    status = nxd_tcp_client_socket_connect(&client_socket_0, &server_address, SERVER_PORT, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);

    status = nx_secure_tls_session_start(&tls_client_session_0, &client_socket_0, NX_WAIT_FOREVER);
    do_something_if_fail(status == NX_SUCCESS);

    /* Give the server thread time to run and, in the buggy case, send its
       stub NewSessionTicket after processing our Finished. One periodic
       tick is far more than the server needs. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Peek the raw TCP receive queue. The TLS layer has not been asked to
       receive anything since the handshake, so any bytes here must have
       been sent by the server after its Finished. In the fixed server
       there are none. In the buggy server there is a NewSessionTicket. */
    status = nx_tcp_socket_receive(&client_socket_0, &packet_ptr, NX_NO_WAIT);
    if (status != NX_NO_PACKET)
    {
        ERROR_COUNTER();
        if (packet_ptr != NX_NULL)
        {
            nx_packet_release(packet_ptr);
        }
    }

    tx_semaphore_put(&semaphore_check_done);

    nx_secure_tls_session_end(&tls_client_session_0, NX_IP_PERIODIC_RATE);
    nx_secure_tls_session_delete(&tls_client_session_0);

    nx_tcp_socket_disconnect(&client_socket_0, NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&client_socket_0);
    nx_tcp_socket_delete(&client_socket_0);

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

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_no_newsessionticket_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Secure Test:   TLS 1.3 No NewSessionTicket Test..................N/A\n");
    test_control_return(3);
}
#endif
