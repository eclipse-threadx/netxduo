/* 14.19 TCP MUST include an SWS avoidance algorithm in the receiver when effective send MSS < (1/ 2)*RCV_BUFF.  */

/*  Procedure
    1.Connection successfully
    2.First Client sends 40 data to Server, then check if the last_sent changed
    3.Then Client sends more 20 data to Server, also check if the last_sent changed
    4.If the last_sent changed, the SWS avoidance algorithm has not been used.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"
/* Include CRL associated with Verisign root CA (for AWS) for demo purposes. */
#include "test_ca.crl.der.c"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED)
#define __LINUX__

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static NX_SECURE_TLS_SESSION   client_tls_session;
static NX_SECURE_TLS_SESSION   server_tls_session;

static NX_SECURE_X509_CERT certificate;
static NX_SECURE_X509_CERT server_certificate;
static NX_SECURE_X509_CERT ica_certificate;
static NX_SECURE_X509_CERT client_certificate;
static NX_SECURE_X509_CERT remote_certificate, remote_issuer;
static NX_SECURE_X509_CERT client_remote_certificate, client_remote_issuer;
static NX_SECURE_X509_CERT trusted_certificate;

UCHAR remote_cert_buffer[2000];
UCHAR remote_issuer_buffer[2000];
UCHAR client_remote_cert_buffer[2000];
UCHAR client_remote_issuer_buffer[2000];

UCHAR server_packet_buffer[4000];
UCHAR client_packet_buffer[4000];

CHAR server_crypto_metadata[16000];
CHAR client_crypto_metadata[16000];

/* Test PKI (3-level). */
#include "test_ca_cert.c"
#include "tls_two_test_certs.c"
#define ca_cert_der test_ca_cert_der
#define ca_cert_der_len test_ca_cert_der_len

/*  Cryptographic routines. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
static UCHAR tls_psk[] = { 0x1a, 0x2b, 0x3c, 0x4d };
#endif

#define     DEMO_STACK_SIZE  4096 //  (3 * 1024 / sizeof(ULONG))

/* Define the IP thread's stack area.  */
#define IP_STACK_SIZE 4096 //(2 * 1024 / sizeof(ULONG))

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_BYTES  ((1536 + sizeof(NX_PACKET)) * 20)
#define NX_PACKET_POOL_SIZE (NX_PACKET_POOL_BYTES/sizeof(ULONG) + 64 / sizeof(ULONG))

/* Define the ARP cache area.  */
#define ARP_AREA_SIZE 1024 // (512 / sizeof(ULONG))

#define TOTAL_STACK_SPACE (2 * (DEMO_STACK_SIZE + IP_STACK_SIZE + NX_PACKET_POOL_SIZE + ARP_AREA_SIZE))

#ifndef __LINUX__
ULONG test_stack_area[TOTAL_STACK_SPACE + 2000];
#endif

static ULONG pool_area[2][NX_PACKET_POOL_SIZE];

/* Define the counters used in the demo application...  */
ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */
#ifndef __LINUX__
void    tx_application_define(void *first_unused_memory)
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void           nx_secure_tls_receive_alert_test_application_define(void *first_unused_memory)
#endif
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
#ifndef __LINUX__
    pointer = (CHAR*)test_stack_area;
#else
    pointer = (CHAR *) first_unused_memory;
#endif

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pool_area[0], sizeof(pool_area[0]));

    if(status)
    {
        printf("Error in function nx_packet_pool_create: 0x%x\n", status);
        error_counter++;
    }

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 1536, pool_area[1], sizeof(pool_area[1]));

    if(status)
    {
        printf("Error in function nx_packet_pool_create: 0x%x\n", status);
        error_counter++;
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, IP_STACK_SIZE, 1);
    pointer = pointer + IP_STACK_SIZE;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_1, _nx_ram_network_driver_1500,
                           pointer, IP_STACK_SIZE, 1);
    pointer = pointer + IP_STACK_SIZE;

    if(status)
    {
        printf("Error in function nx_ip_create: 0x%x\n", status);
        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, ARP_AREA_SIZE);
    pointer = pointer + ARP_AREA_SIZE;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, ARP_AREA_SIZE);
    pointer = pointer + ARP_AREA_SIZE;

    /* Check ARP enable status.  */
    if(status)
    {
        printf("Error in function nx_arp_enable: 0x%x\n", status);
        error_counter++;
    }

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
    {
        printf("Error in function tcp_enable: 0x%x\n", status);
        error_counter++;
    }

    nx_secure_tls_initialize();
}

/*  Define callbacks used by TLS.  */

/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Receive Alert Test.............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_ip_status_check: 0x%x\n", status);
        error_counter++;
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 16*1024,
                                  NX_NULL, ntest_0_disconnect_received);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_socket_create: 0x%x\n", status);
        error_counter++;
    }

    /* Create a TLS session for our socket.  */
    status =  nx_secure_tls_session_create(&server_tls_session,
                                           &nx_crypto_tls_ciphers,
                                           server_crypto_metadata,
                                           sizeof(server_crypto_metadata));

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_secure_tls_session_create: 0x%x\n", status);
        error_counter++;
    }

    /* Setup our packet reassembly buffer. */
    nx_secure_tls_session_packet_buffer_set(&server_tls_session, server_packet_buffer, sizeof(server_packet_buffer));


    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Initialize our certificate
    nx_secure_x509_certificate_initialize(&certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    nx_secure_tls_server_certificate_add(&server_tls_session, &certificate, 1);

    nx_secure_x509_certificate_initialize(&server_certificate, test_server_cert_der, test_server_cert_der_len, NX_NULL, 0, test_server_cert_key_der, test_server_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    nx_secure_tls_server_certificate_add(&server_tls_session, &server_certificate, 2);

    nx_secure_x509_certificate_initialize(&ica_certificate, ica_cert_der, ica_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_local_certificate_add(&server_tls_session, &ica_certificate);

    // If we are testing client certificate verify, allocate remote certificate space.
    nx_secure_tls_remote_certificate_allocate(&server_tls_session, &client_remote_certificate, client_remote_cert_buffer, sizeof(client_remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&server_tls_session, &client_remote_issuer, client_remote_issuer_buffer, sizeof(client_remote_issuer_buffer));

    /* Add a CA Certificate to our trusted store for verifying incoming client certificates. */
    nx_secure_x509_certificate_initialize(&trusted_certificate, ca_cert_der, ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(&server_tls_session, &trusted_certificate);

    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, ntest_0_connect_received);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_server_socket_listen: 0x%x\n", status);
        error_counter++;
    }

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    /* For PSK ciphersuites, add a PSK and identity hint.  */
    nx_secure_tls_psk_add(&server_tls_session, tls_psk, sizeof(tls_psk), "Client_identity", 15, "12345678", 8);
#endif

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    tx_thread_suspend(&ntest_0);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_server_socket_accept: 0x%x\n", status);
        error_counter++;
    }

    /* Start the TLS Session now that we have a connected socket. */
    status = nx_secure_tls_session_start(&server_tls_session, &server_socket, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
    {
        printf("TLS Server Session start failed, error: %x\n", status);
        error_counter++;
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* End the TLS session. This is required to properly shut down the TLS connection. */
    status = nx_secure_tls_session_end(&server_tls_session, NX_WAIT_FOREVER);

    /* If the session did not shut down cleanly, this is a possible security issue. */
    if (status)
    {
          printf("Error in TLS Server session end: %x\n", status);
          error_counter++;
    }

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_WAIT_FOREVER); // NX_IP_PERIODIC_RATE * 10);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_socket_disconnect: 0x%x\n", status);
        error_counter++;
    }

    /* Unaccept the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_server_socket_unaccept: 0x%x\n", status);
        error_counter++;
    }

    /* Unlisten on the server port.  */
    status = nx_tcp_server_socket_unlisten(&ip_0, 12);

    /* Check for error.  */
    if (status)
    {
        printf("Error in function nx_tcp_server_socket_unlisten: 0x%x\n", status);
        error_counter++;
    }

    /* Delete TLS session. */
    status = nx_secure_tls_session_delete(&server_tls_session);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_secure_tls_session_delete: 0x%x\n", status);
        error_counter++;
    }

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_socket_delete: 0x%x\n", status);
        error_counter++;
    }
}



/* -----===== CLIENT =====----- */
static void    ntest_1_entry(ULONG thread_input)
{
UINT         status;
NX_PACKET *receive_packet;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE * 100, 1024*16,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_socket_create: 0x%x\n", status);
        error_counter++;
    }


    /* Create a TLS session for our socket.  */
    status =  nx_secure_tls_session_create(&client_tls_session,
                                           &nx_crypto_tls_ciphers,
                                           client_crypto_metadata,
                                           sizeof(client_crypto_metadata));

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_secure_tls_session_create: 0x%x\n", status);
        error_counter++;
    }


    /* Setup our packet reassembly buffer. */
    nx_secure_tls_session_packet_buffer_set(&client_tls_session, client_packet_buffer, sizeof(client_packet_buffer));

    /* Need to allocate space for the certificate coming in from the remote host. */
    nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));

    //nx_secure_x509_certificate_initialize(&certificate, cert_der, cert_der_len, NX_NULL, 0, private_key_der, private_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    nx_secure_x509_certificate_initialize(&client_certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    nx_secure_tls_local_certificate_add(&client_tls_session, &client_certificate);

    /* Add a CA Certificate to our trusted store for verifying incoming server certificates. */
    nx_secure_x509_certificate_initialize(&trusted_certificate, ca_cert_der, ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(&client_tls_session, &trusted_certificate);

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    /* For PSK ciphersuites, add a PSK and identity hint.  For the client, we need to add the identity
       and set it for the particular server with which we want to communicate.
       "Client_identity" is the identity hint used by default in the OpenSSL s_server application
       when uisng PSK ciphersuites. */
    nx_secure_tls_psk_add(&client_tls_session, tls_psk, sizeof(tls_psk), "Client_identity", 15, "12345678", 8);

    /* Our target server will use this PSK entry. */
    nx_secure_tls_client_psk_set(&client_tls_session, tls_psk, sizeof(tls_psk), "Client_identity", 15, "12345678", 8);
#endif

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_client_socket_bind: 0x%x\n", status);
        error_counter++;
    }

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);

    if(status)
    {
        printf("Error in function nx_tcp_client_socket_connect: 0x%x\n", status);
        error_counter++;
    }

    tx_thread_resume(&ntest_0);

    status = nx_secure_tls_session_start(&client_tls_session, &client_socket, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
    {
        printf("Error in Client TLS handshake: 0x%02X\n", status);
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Receive the echoed and reversed data, and print it out. */
    status = nx_secure_tls_session_receive(&client_tls_session, &receive_packet, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status != NX_SECURE_TLS_ALERT_RECEIVED)
    {
        printf("Unexpected status of receive: %x\n", status);
        error_counter++;
    }

    /* End the TLS session. This is required to properly shut down the TLS connection. */
    status = nx_secure_tls_session_end(&client_tls_session, NX_WAIT_FOREVER);

    /* If the session did not shut down cleanly, this is a possible security issue. */
    if (status)
    {
        printf("Error in TLS Client session end: %x\n", status);
        error_counter++;
    }

    /* Disconnect this socket.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_WAIT_FOREVER); //NX_IP_PERIODIC_RATE * 10);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_socket_disconnect: 0x%x\n", status);
        error_counter++;
    }

    /* Bind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_client_socket_unbind: 0x%x\n", status);
        error_counter++;
    }

    /* Delete TLS session. */
    status = nx_secure_tls_session_delete(&client_tls_session);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_secure_tls_session_delete: %x\n", status);
        error_counter++;
    }

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if(status)
    {
        printf("Error in function nx_tcp_socket_delete: %x\n", status);
        error_counter++;
    }

    /* Check packet leak. */
    if ((pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total) ||
        (pool_1.nx_packet_pool_available != pool_1.nx_packet_pool_total))
    {
        printf("Packet leaked\n");
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

static void    ntest_0_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void    ntest_0_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if(socket != &server_socket)
        error_counter++;
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_receive_alert_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Receive Alert Test.............................N/A\n");
    test_control_return(3);
}
#endif
