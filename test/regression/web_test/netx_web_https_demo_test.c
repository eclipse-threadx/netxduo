/* This is a small demo of the NetX HTTP Client Server API running on a 
   high-performance NetX TCP/IP stack.  */

#include   "tx_api.h"
#include   "nx_api.h"
/* If not using FileX, define this option and define the file writing services
   declared in filex_stub.h.    
#define      NX_WEB_HTTP_NO_FILEX
*/
#ifndef      NX_WEB_HTTP_NO_FILEX
#include    "fx_api.h"
#else
#include    "filex_stub.h"
#endif

#include   "nx_web_http_client.h"
#include   "nx_web_http_server.h"


#include "tx_api.h"
#include "nx_api.h"
#include "nx_crypto.h"
#include "nx_secure_tls_api.h"
#include "nx_secure_dtls_api.h"
#include "nx_secure_x509.h"
#include "test_utility.h"


/* For NetX Duo applications, determine which IP version to use. For IPv6, 
   set IP_TYPE to 6; for IPv4 set to 4. Note that for IPv6, you must enable
   USE_DUO so the application 'knows' to enabled IPv6 services on the IP task.  */

#ifdef NX_DISABLE_IPV4
#define     IP_TYPE     6
#else
#define     IP_TYPE     4
#endif /* NX_DISABLE_IPV4 */


#define     DEMO_STACK_SIZE         4096

/* Replace the 'ram' driver with your Ethernet driver. */
VOID        _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

static UINT authentication_check(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, 
                                 CHAR *resource, CHAR **name, CHAR **password, CHAR **realm);

/* Set up the HTTP client global variables. */

NX_SECURE_TLS_SESSION client_tls_session;
TX_THREAD       client_thread;
NX_WEB_HTTPS_CLIENT  my_client;
#define         CLIENT_PACKET_SIZE  (NX_WEB_HTTP_SERVER_MIN_PACKET_SIZE * 2)


/* Set up the HTTP server global variables */

NX_SECURE_TLS_SESSION server_tls_session;
NX_WEB_HTTP_SERVER  my_server;
NX_PACKET_POOL  server_pool;
NX_PACKET_POOL  client_pool;
TX_THREAD       server_thread;
NX_IP           server_ip;
NX_IP           client_ip;

NXD_ADDRESS     server_ip_address; 
#define         SERVER_PACKET_SIZE  (NX_WEB_HTTP_SERVER_MIN_PACKET_SIZE * 2)
 
void https_server_thread_entry(ULONG thread_input);
void https_client_thread_entry(ULONG thread_input);

/* HTTPS/TLS setup. */

#include "test_device_cert.c"

#include "test_ca_cert.c"
#define ca_cert_der test_ca_cert_der
#define ca_cert_der_len test_ca_cert_der_len

static CHAR crypto_metadata[8928 * NX_WEB_HTTP_SERVER_SESSION_MAX];
static UCHAR tls_packet_buffer[18500];
static NX_SECURE_X509_CERT certificate;
static NX_SECURE_X509_CERT trusted_certificate;
static NX_SECURE_X509_CERT remote_certificate, remote_issuer;
static UCHAR remote_cert_buffer[2000];
static UCHAR remote_issuer_buffer[2000];

/* Define the RAM disk memory.  */
static UCHAR media_memory[4096];
static CHAR ram_disk_memory[4096];
static FX_MEDIA ram_disk;

static UCHAR server_stack[16000];

extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

/* Gateway IP address - if needed! */
//#define GATEWAY_IP_ADDRESS IP_ADDRESS(192, 168, 1, 1)


/* Google.com IP address. */
//#define HTTP_SERVER_ADDRESS  IP_ADDRESS(172,217,11,174)

/* Local IP address. */
#define HTTP_SERVER_ADDRESS  IP_ADDRESS(192, 168, 1, 150)
#define HTTP_CLIENT_ADDRESS  IP_ADDRESS(192, 168, 1, 151)

VOID    _fx_ram_driver(FX_MEDIA *media_ptr) ;
VOID    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define the application's authentication check.  This is called by
   the HTTP server whenever a new request is received.  */
static UINT  authentication_check(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, 
            CHAR *resource, CHAR **name, CHAR **password, CHAR **realm)
{
    NX_PARAMETER_NOT_USED(server_ptr);
    NX_PARAMETER_NOT_USED(request_type);
    NX_PARAMETER_NOT_USED(resource);

    /* Just use a simple name, password, and realm for all 
       requests and resources.  */
    *name =     "name";
    *password = "password";

    *realm =    "NetX Duo HTTP demo";

    /* Request basic authentication.  */
    return(NX_WEB_HTTP_BASIC_AUTHENTICATE);
}

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_https_demo_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    tx_thread_create(&server_thread, "HTTPS Server thread", https_server_thread_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     NX_WEB_HTTP_SERVER_PRIORITY, NX_WEB_HTTP_SERVER_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "HTTPS Server Packet Pool", SERVER_PACKET_SIZE, 
                                    pointer, SERVER_PACKET_SIZE * 20);
    EXPECT_EQ(NX_SUCCESS, status);

    pointer = pointer + SERVER_PACKET_SIZE * 20;

    /* Check for pool creation error.  */
    if (status)
    {

        return;
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, "HTTP Server IP", HTTP_SERVER_ADDRESS, 
                          0xFFFFFF00UL, &server_pool, _nx_ram_network_driver,
                          pointer, 4096, 1);
    EXPECT_EQ(NX_SUCCESS, status);

    pointer =  pointer + 4096;

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status = nx_arp_enable(&server_ip, (void *) pointer, 1024);
    EXPECT_EQ(NX_SUCCESS, status);

    pointer = pointer + 1024;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&server_ip);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Set up the server's IPv4 address here. */
    server_ip_address.nxd_ip_address.v4 = HTTP_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    pointer =  pointer + 2048;

    /* Create the HTTP Client thread. */
    status = tx_thread_create(&client_thread, "HTTPS Client", https_client_thread_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     NX_WEB_HTTP_SERVER_PRIORITY + 2, NX_WEB_HTTP_SERVER_PRIORITY + 2, TX_NO_TIME_SLICE, TX_AUTO_START);
    EXPECT_EQ(NX_SUCCESS, status);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "HTTPS Client Packet Pool", SERVER_PACKET_SIZE, 
                                    pointer, SERVER_PACKET_SIZE * 20);
    EXPECT_EQ(NX_SUCCESS, status);

    pointer = pointer + SERVER_PACKET_SIZE * 20;

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip, "HTTPS Client IP", HTTP_CLIENT_ADDRESS, 
                          0xFFFFFF00UL, &client_pool, _nx_ram_network_driver,
                          pointer, 2048, 1);
    EXPECT_EQ(NX_SUCCESS, status);

    pointer =  pointer + 2048;

    nx_arp_enable(&client_ip, (void *) pointer, 1024);

    pointer =  pointer + 2048;

     /* Enable TCP traffic.  */
    nx_tcp_enable(&client_ip);

    return;
}

VOID https_client_thread_entry(ULONG thread_input)
{

UINT            status;
NX_PACKET       *my_packet;
NX_PACKET *receive_packet;
UCHAR receive_buffer[1000];
ULONG bytes;
NXD_ADDRESS    server_ip_address;

    NX_PARAMETER_NOT_USED(thread_input);
           
    printf("NetX Test:   Web HTTPS Demo Test.......................................");

    /* Give IP task and driver a chance to initialize the system. */
    tx_thread_sleep(7 * NX_IP_PERIODIC_RATE);
    
    status = nx_secure_tls_session_create(&client_tls_session, &nx_crypto_tls_ciphers, crypto_metadata, sizeof(crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);
    
    /* Create an HTTPS client instance.  */
    status = _nx_web_https_client_create(&my_client, "HTTP Client", &client_ip, &client_pool, 65535, &client_tls_session);
    EXPECT_EQ(NX_SUCCESS, status);
    
    /* Allocate space for packet reassembly. */
    status = nx_secure_tls_session_packet_buffer_set(my_client.nx_web_http_client_tls_session, tls_packet_buffer, sizeof(tls_packet_buffer));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add a CA Certificate to our trusted store for verifying incoming server certificates. */
    nx_secure_x509_certificate_initialize(&trusted_certificate, ca_cert_der, ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(&client_tls_session, &trusted_certificate);
    
    /* Need to allocate space for the certificate coming in from the remote host. */
    nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));
    
    /* Allocate a packet.  */
    //status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    status =  nx_packet_allocate(&client_pool, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    /* GET the test page */
    /* Use the 'NetX' service to send a GET request to the server (can only use IPv4 addresses). */
    server_ip_address.nxd_ip_address.v4 = HTTP_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    status =  nx_web_http_client_get_start(&my_client, &server_ip_address, "/https_server.sh",
                                       NX_NULL, 0, "name", "password", NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_web_http_client_get_packet(&my_client, &receive_packet, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);
                              
    status = nx_packet_data_extract_offset(receive_packet, 0, receive_buffer, 1000, &bytes);
    EXPECT_EQ(NX_SUCCESS, status);

    receive_buffer[bytes] = 0;
    //printf("Received: %s\n", receive_buffer);
    EXPECT_EQ((UINT)bytes, 12);
    EXPECT_EQ(receive_buffer[0], 'h');
    EXPECT_EQ(receive_buffer[1], 't');
    EXPECT_EQ(receive_buffer[2], 't');
    EXPECT_EQ(receive_buffer[3], 'p');
    EXPECT_EQ(receive_buffer[4], 's');
    EXPECT_EQ(receive_buffer[5], ' ');
    EXPECT_EQ(receive_buffer[6], 's');
    EXPECT_EQ(receive_buffer[7], 'e');
    EXPECT_EQ(receive_buffer[8], 'r');
    EXPECT_EQ(receive_buffer[9], 'v');
    EXPECT_EQ(receive_buffer[10], 'e');
    EXPECT_EQ(receive_buffer[11], 'r');
    
    status = nx_web_http_client_delete(&my_client);
    EXPECT_EQ(NX_SUCCESS, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}

/************* HTTP(S) Server *************************/


/* TLS setup callback, used to configure the TLS sessions for an HTTPS server. */
UINT server_tls_setup(NX_WEB_HTTP_SERVER *http_server_ptr, NX_TCPSERVER *socket_server)
{
UINT status;

    /* Initialize device certificate (used for all sessions in HTTPS server). */
    memset(&certificate, 0, sizeof(certificate));
    nx_secure_x509_certificate_initialize(&certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);

    /* Setup TLS session data for the TCP server. */
    status = nx_tcpserver_tls_setup(&http_server_ptr -> nx_web_http_server_tcpserver, &nx_crypto_tls_ciphers,
                                    crypto_metadata, sizeof(crypto_metadata), tls_packet_buffer, sizeof(tls_packet_buffer),
                                    &certificate, NX_NULL, 0, NX_NULL, 0);
    return(status);
}

UINT server_request_callback(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, CHAR *resource, NX_PACKET *packet_ptr)
{
ULONG        offset, length;
NX_PACKET   *response_pkt;
UCHAR       buffer[1440];
UINT i;
UINT status;

    /* Process multipart data. */
    if(request_type == NX_WEB_HTTP_SERVER_POST_REQUEST)
    {
        /* Get the content header. */
        while(nx_web_http_server_get_entity_header(server_ptr, &packet_ptr, buffer,
                                               sizeof(buffer)) == NX_SUCCESS)
        {

            /* Header obtained successfully. Get the content data location. */   
            while(nx_web_http_server_get_entity_content(server_ptr, &packet_ptr, &offset,
                                                    &length) == NX_SUCCESS)
            {
                /* Write content data to buffer. */
                nx_packet_data_extract_offset(packet_ptr, offset, buffer, length, 
                                              &length);
                buffer[length] = 0;
            }

            printf("Receive buffer of size %d:\n", (UINT)length);
            for(i = 0; i < length; ++i)
            {
                printf("%c", buffer[i]);
            }
        }

        /* Generate HTTP header. */
        status = nx_web_http_server_callback_generate_response_header(server_ptr,
        &response_pkt, NX_WEB_HTTP_STATUS_OK, 800, "text/html", 
        "Server: NetX HTTPS Experimental\r\n");

        if(status == NX_SUCCESS)
        {
            if(nx_web_http_server_callback_packet_send(server_ptr, response_pkt) !=
                                                   NX_SUCCESS)
            {
                nx_packet_release(response_pkt);
            }
        }
    }
    else
    {
        /* Indicate we have not processed the response to client yet.*/
        return(NX_SUCCESS);
    }


    /* Release the received client packet. */
    nx_packet_release(packet_ptr);

    /* Indicate the response to client is transmitted. */
    return(NX_WEB_HTTP_CALLBACK_COMPLETED);
  
}

/* Define the helper HTTP server thread.  */
void    https_server_thread_entry(ULONG thread_input)
{

UINT    status;
FX_FILE my_file;

    NX_PARAMETER_NOT_USED(thread_input);
    status = fx_media_format(&ram_disk,
                    _fx_ram_driver,               // Driver entry
                    ram_disk_memory,              // RAM disk memory pointer
                    media_memory,              // Media buffer pointer
                    sizeof(media_memory),      // Media buffer size
                    "MY_RAM_DISK",                // Volume Name
                    1,                            // Number of FATs
                    32,                           // Directory Entries
                    0,                            // Hidden sectors
                    256,                          // Total sectors
                    512,                          // Sector size
                    8,                            // Sectors per cluster
                    1,                            // Heads
                    1);                           // Sectors per track   
    EXPECT_EQ(NX_SUCCESS, status);
    
    /* Open the RAM disk.  */
    status = fx_media_open(&ram_disk, "RAM DISK", _fx_ram_driver, ram_disk_memory, media_memory, sizeof(media_memory)) ;
    status += fx_file_create(&ram_disk, "/https_server.sh");
    status += fx_file_open(&ram_disk, &my_file, "https_server.sh", FX_OPEN_FOR_WRITE);
    status += fx_file_write(&my_file, "https server", 12);
    status += fx_file_close(&my_file);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Give NetX a chance to initialize the system. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE * 7);

    /* Create the HTTPS Server. */
    status = nx_web_http_server_create(&my_server, "My HTTP Server", &server_ip, &ram_disk, &server_stack, sizeof(server_stack), &server_pool, authentication_check, server_request_callback);
    EXPECT_EQ(NX_SUCCESS, status);
    
    /* Start an HTTPS Server with TLS.  */
    status = nx_web_http_server_secure_start(&my_server, server_tls_setup, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* HTTP server ready to take requests! */
    /* Let the IP thread execute.    */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);      
        
    while(1)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);      
    }
    //return;
}



