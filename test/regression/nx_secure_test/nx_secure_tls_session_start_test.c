#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
#define __LINUX__

#define     DEMO_STACK_SIZE  4096 //  (3 * 1024 / sizeof(ULONG))

/* Define the IP thread's stack area.  */
#define IP_STACK_SIZE 4096 //(2 * 1024 / sizeof(ULONG))

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_BYTES  ((1536 + sizeof(NX_PACKET)) * 20)
#define NX_PACKET_POOL_SIZE (NX_PACKET_POOL_BYTES/sizeof(ULONG) + 64 / sizeof(ULONG))

/* Define the ARP cache area.  */
#define ARP_AREA_SIZE 1024 // (512 / sizeof(ULONG))

#define TOTAL_STACK_SPACE (2 * (DEMO_STACK_SIZE + IP_STACK_SIZE + NX_PACKET_POOL_SIZE + ARP_AREA_SIZE))


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;
static TX_THREAD               sync_thread;


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
static NX_SECURE_X509_CERT remote_certificate, remote_issuer, remote_issuer2;
static NX_SECURE_X509_CERT client_remote_certificate, client_remote_issuer;
static NX_SECURE_X509_CERT trusted_certificate;

static UCHAR remote_cert_buffer[2000];
static UCHAR remote_issuer_buffer[2000];
static UCHAR remote_issuer2_buffer[2000];
static UCHAR client_remote_cert_buffer[2000];
static UCHAR client_remote_issuer_buffer[2000];

static UCHAR server_packet_buffer[4000];
static UCHAR client_packet_buffer[4000];

static CHAR server_crypto_metadata[16000];
static CHAR client_crypto_metadata[16000];

static CHAR sync_thread_stack[1024];
static CHAR server_stack[DEMO_STACK_SIZE];
static CHAR client_stack[DEMO_STACK_SIZE];

/* Test PKI (3-level). */
#include "test_ca_cert.c"
#define ca_cert_der test_ca_cert_der
#define ca_cert_der_len test_ca_cert_der_len

/*  Cryptographic routines. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;


#ifndef __LINUX__
ULONG test_stack_area[TOTAL_STACK_SPACE + 2000];
#endif


typedef struct
{
    VOID(*test_server)();
    VOID(*test_client)();

} TLS_HANDSHAKE_TEST_DATA;

static void tls_server_setup();
static void tls_client_setup();

static void test_split_record_tcp_server();
static void test_split_record_client();
static void test_split_record_server();
static void test_split_record_tcp_client();



static TLS_HANDSHAKE_TEST_DATA test_data[] =
{
    { test_split_record_tcp_server, test_split_record_client },

    //{ test_split_record_server, test_split_record_tcp_client },
};


static ULONG pool_area[2][NX_PACKET_POOL_SIZE];

/* Define the counters used in the demo application...  */
ULONG                   error_counter;


/* Define thread prototypes.  */

static void    sync_thread_entry(ULONG thread_input);
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
void           nx_secure_tls_session_start_test_application_define(void *first_unused_memory)
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
    tx_thread_create(&sync_thread, "thread sync", sync_thread_entry, 0,
                     sync_thread_stack, sizeof(sync_thread_stack),
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     server_stack, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_DONT_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     client_stack, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_DONT_START);

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
    status = nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 600, pool_area[1], sizeof(pool_area[1]));

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


/* Timestamp function - should return Unix time formatted 32-bit integer. */
static ULONG tls_timestamp_function(void)
{
    // Return a fixed epoch - 1500939067 seconds = 07/24/2017 @ 11:31pm (UTC) 
    // 1541030400 = 0x5BDA4200L = 11/01/2018 @ 12:00AM (UTC)
    return(0x5BDA4200L); 
}

/* Callback invoked whenever TLS has to validate a certificate from a remote host. Additional checking
   of the certificate may be done by the application here. */
static ULONG certificate_verification_callback(NX_SECURE_TLS_SESSION *session, NX_SECURE_X509_CERT* certificate)
{
const CHAR *dns_tld = "certificate_with_policies"; //"NX Secure Device Certificate";
UINT status;
NX_SECURE_X509_CERTIFICATE_STORE *store;
USHORT key_usage_bitfield;

    /* Check DNS entry string. */
    status = nx_secure_x509_common_name_dns_check(certificate, (UCHAR*)dns_tld, strlen(dns_tld));
  
    if(status != NX_SUCCESS)
    {
        printf("Error in certificate verification: DNS name did not match CN\n");
        return(status);
    }    
    
    /* Check CRL revocation status. */
    store = &session -> nx_secure_tls_credentials.nx_secure_tls_certificate_store;
    

    /* Check key usage extension. */
    status = nx_secure_x509_key_usage_extension_parse(certificate, &key_usage_bitfield);

    if(status != NX_SUCCESS)
    {
        printf("Error in parsing key usage extension: 0x%x\n", status);
        return(status);
    }

    if((key_usage_bitfield & NX_SECURE_X509_KEY_USAGE_DIGITAL_SIGNATURE) == 0 ||
       (key_usage_bitfield & NX_SECURE_X509_KEY_USAGE_NON_REPUDIATION)   == 0 ||
       (key_usage_bitfield & NX_SECURE_X509_KEY_USAGE_KEY_ENCIPHERMENT)  == 0)
    {
        printf("Expected key usage bitfield bits not set!\n");
        return(NX_SECURE_X509_KEY_USAGE_ERROR);
    }

    /* Extended key usage - look for specific OIDs. */
    status = nx_secure_x509_extended_key_usage_extension_parse(certificate, NX_SECURE_TLS_X509_TYPE_PKIX_KP_TIME_STAMPING);

    if(status != NX_SUCCESS)
    {
        printf("Expected certificate extension not found!\n");
    }

    return(NX_SUCCESS);
}


/* Define the test threads.  */

/* -----===== SERVER =====----- */

/* Define a TLS name to test the Server Name Indication extension. */
#define TLS_SNI_SERVER_NAME "testing"

static CHAR *html_data =  "HTTP/1.1 200 OK\r\n" \
        "Date: Fri, 15 Sep 2016 23:59:59 GMT\r\n" \
        "Content-Type: text/html\r\n" \
        "Content-Length: 200\r\n\r\n" \
        "<html>\r\n"\
        "<body>\r\n"\
        "<b>Hello NetX Secure User!</b>\r\n"\
        "This is a simple webpage\r\n"\
        "served up using NetX Secure!\r\n"\
        "</body>\r\n"\
        "</html>\r\n";

/* Callback for ClientHello extensions processing. */
static ULONG tls_server_callback(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION *extensions, UINT num_extensions)
{
NX_SECURE_X509_DNS_NAME dns_name;
INT compare_value;
UINT status;
NX_SECURE_X509_CERT *cert_ptr;
#if 0
    /* Process clienthello extensions. */
    status = _nx_secure_tls_session_sni_extension_parse(tls_session, extensions, num_extensions, &dns_name);

#ifdef NX_SECURE_TLS_SNI_EXTENSION_DISABLED
    if(status != NX_SECURE_TLS_EXTENSION_NOT_FOUND)
    {
        printf("SNI extension should not exist\n");
        error_counter++;
    }
#else
    if(status != NX_SUCCESS)
    {
        printf("SNI extension parsing failed with status 0x%x\n", status);
        error_counter++;
    }

    /* NULL-terminate name string. */
    dns_name.nx_secure_x509_dns_name[dns_name.nx_secure_x509_dns_name_length] = 0;

    /* Make sure our SNI name matches. */
    compare_value = memcmp(dns_name.nx_secure_x509_dns_name, TLS_SNI_SERVER_NAME, strlen(TLS_SNI_SERVER_NAME));

    if(compare_value || dns_name.nx_secure_x509_dns_name_length != strlen(TLS_SNI_SERVER_NAME))
    {
        printf("Error in SNI processing. SNI name '%s' does not match '%s'\n", dns_name.nx_secure_x509_dns_name, TLS_SNI_SERVER_NAME);
        error_counter++;
    }
#endif

    /* Find a certificate based on it's unique ID. */
    _nx_secure_tls_server_certificate_find(tls_session, &cert_ptr, 1);

    /* Set the certificate we want to use. */
    nx_secure_tls_active_certificate_set(tls_session, cert_ptr);
#endif
    return(NX_SUCCESS);
	
}

static TX_SEMAPHORE test_start_server;
static TX_SEMAPHORE test_end_server;
static TX_SEMAPHORE test_start_client;
static TX_SEMAPHORE test_end_client;

static void    sync_thread_entry(ULONG thread_input)
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS session start Test..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    tx_semaphore_create(&test_start_server, "test_start_server", 0);
    tx_semaphore_create(&test_end_server, "test_end_server", 0);
    tx_semaphore_create(&test_start_client, "test_start_client", 0);
    tx_semaphore_create(&test_end_client, "test_end_client", 0);

    tx_thread_resume(&ntest_0);
    tx_thread_resume(&ntest_1);


    while (1)
    {
        /* Start a test when both client and server thread completed the previous test. */
        tx_semaphore_put(&test_start_server);
        tx_semaphore_put(&test_start_client);

        tx_semaphore_get(&test_end_client, TX_WAIT_FOREVER);
        tx_semaphore_get(&test_end_server, TX_WAIT_FOREVER);
    }
}


static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
UINT i;



    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
    {
        printf("Error in function nx_ip_status_check: 0x%x\n", status);
        error_counter++;
    }

    for (i = 0; i < sizeof(test_data) / sizeof(TLS_HANDSHAKE_TEST_DATA); i++)
    {
        tx_semaphore_get(&test_start_server, TX_WAIT_FOREVER);


        /* Create a socket.  */
        status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                      NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 16*1024,
                                      NX_NULL, ntest_0_disconnect_received);

        /* Check for error.  */
        if(status)
        {
            printf("Error in function nx_tcp_socket_create: 0x%x\n", status);
            error_counter++;
        }



        /* Setup this thread to listen.  */
        status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, ntest_0_connect_received);

        /* Check for error.  */
        if(status)
        {
            printf("Error in function nx_tcp_server_socket_listen: 0x%x\n", status);
            error_counter++;
        }


        /* Accept a client socket connection.  */
        status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);


        /* Check for error.  */
        if(status)
        {
            printf("Error in function nx_tcp_server_socket_accept: 0x%x\n", status);
            error_counter++;
        }


        /* Call the actual test function. */
        test_data[i].test_server();

        if (error_counter)
        {
            printf("ERROR! Test %d\n", i + 1);
            test_control_return(1);
        }


        /* Disconnect the server socket.  */
        status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE); // NX_IP_PERIODIC_RATE * 10);

        /* Unaccept the server socket.  */
        status = nx_tcp_server_socket_unaccept(&server_socket);

        /* Check for error.  */
        if (status)
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



        /* Delete the socket.  */
        status = nx_tcp_socket_delete(&server_socket);

        /* Check for error.  */
        if (status)
        {
            printf("Error in function nx_tcp_socket_delete: 0x%x\n", status);
            error_counter++;
        }

        tx_semaphore_put(&test_end_server);
    }

    tx_semaphore_get(&test_start_server, TX_WAIT_FOREVER);

    /* Determine if the test was successful.  */
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



/* -----===== CLIENT =====----- */

static ULONG tls_client_callback(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION *extensions, UINT num_extensions)
{
    /* Process serverhello extensions. */
    return(NX_SUCCESS);
}


static void    ntest_1_entry(ULONG thread_input)
{
UINT         status;
UINT i;


    for (i = 0; i < sizeof(test_data) / sizeof(TLS_HANDSHAKE_TEST_DATA); i++)
    {
        tx_semaphore_get(&test_start_client, TX_WAIT_FOREVER);

        /* Create a socket.  */
        status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                      NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1024*16,
                                      NX_NULL, NX_NULL);

        /* Check for error.  */
        if(status)
        {
            printf("Error in function nx_tcp_socket_create: 0x%x\n", status);
            error_counter++;
        }




        /* Bind the socket.  */
        status = nx_tcp_client_socket_bind(&client_socket, NX_ANY_PORT, NX_IP_PERIODIC_RATE);

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

        /* Call the actual test function. */
        test_data[i].test_client();

        if (error_counter)
        {
            printf("ERROR! Test %d\n", i + 1);
            test_control_return(1);
        }

        /* Disconnect this socket.  */
        status = nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE); //NX_IP_PERIODIC_RATE * 10);

        /* Bind the socket.  */
        status = nx_tcp_client_socket_unbind(&client_socket);

        /* Check for error.  */
        if(status)
        {
            printf("Error in TLS Client function nx_tcp_client_socket_unbind: 0x%x\n", status);
            error_counter++;
        }




        /* Delete the socket.  */
        status = nx_tcp_socket_delete(&client_socket);

        /* Check for error.  */
        if(status)
        {
            printf("Error in TLS Client function nx_tcp_socket_delete: %x\n", status);
            error_counter++;
        }

        tx_semaphore_put(&test_end_client);
    }

    tx_semaphore_get(&test_start_client, TX_WAIT_FOREVER);
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

static void tls_server_setup()
{
UINT status;

}
static NX_SECURE_X509_DNS_NAME dns_name;
static void tls_client_setup()
{
UINT status;


    /* Create a TLS session for our socket.  */
    status = nx_secure_tls_session_create(&client_tls_session,
                                          &nx_crypto_tls_ciphers,
                                          client_crypto_metadata,
                                          sizeof(client_crypto_metadata));

    /* Check for error.  */
    if (status)
    {
        printf("Error in function nx_secure_tls_session_create: 0x%x\n", status);
        error_counter++;
    }


    /* Setup our packet reassembly buffer. */
    nx_secure_tls_session_packet_buffer_set(&client_tls_session, client_packet_buffer, sizeof(client_packet_buffer));

    /* Make sure client certificate verification is disabled. */
    nx_secure_tls_session_client_verify_disable(&client_tls_session);

    /* Need to allocate space for the certificate coming in from the remote host. */
    nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));
    nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_issuer2, remote_issuer2_buffer, sizeof(remote_issuer2_buffer));

    /* Add a CA Certificate to our trusted store for verifying incoming server certificates. */
    nx_secure_x509_certificate_initialize(&trusted_certificate, ca_cert_der, ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(&client_tls_session, &trusted_certificate);


    /* Add a timestamp function for time checking and timestamps in the TLS handshake. */
    _nx_secure_tls_session_time_function_set(&client_tls_session, tls_timestamp_function);

    /* Setup the callback invoked when TLS has a certificate it wants to verify so we can
    do additional checks not done automatically by TLS. */
    _nx_secure_tls_session_certificate_callback_set(&client_tls_session, certificate_verification_callback);

    /* Set callback for server TLS extension handling. */
    _nx_secure_tls_session_client_callback_set(&client_tls_session, tls_client_callback);


    /* Set up a DNS name for the Server Name Indication extension. The server thread will compare
    * to make sure the name was sent and recieved appropriately. */
    nx_secure_x509_dns_name_initialize(&dns_name, TLS_SNI_SERVER_NAME, (USHORT)strlen(TLS_SNI_SERVER_NAME));
    nx_secure_tls_session_sni_extension_set(&client_tls_session, &dns_name);

}

/* Test of a server sending one record by calling multiple nx_tcp_socket_send. */
static void test_split_record_tcp_server()
{
    NX_PACKET *send_packet;
    NX_PACKET *receive_packet;
    ULONG      bytes_copied;
    UINT       status;


}

UINT _nx_secure_tls_send_clienthello(NX_SECURE_TLS_SESSION *tls_session, NX_PACKET *send_packet){return NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL; }

static void test_split_record_client()
{
    UINT status;

    tls_client_setup();

    status = _nx_secure_tls_session_start(&client_tls_session, &client_socket, NX_WAIT_FOREVER);

   EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
    // EXPECT_EQ(NX_SUCCESS, status);

}


#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_session_start_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Packet Chain Test..............................N/A\n");
    test_control_return(3);
}
#endif
