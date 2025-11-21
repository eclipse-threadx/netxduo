/* This case tests server getting content. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#include    "nx_web_http_client.h"
#include    "nx_web_http_server.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && !defined(NX_DISABLE_PACKET_CHAIN)

#include "test_device_cert.c"
#include "test_ca_cert.c"
#define ca_cert_der test_ca_cert_der
#define ca_cert_der_len test_ca_cert_der_len

#define     DEMO_STACK_SIZE         4096

/* Set up FileX and file memory resources. */
static CHAR             ram_disk_memory[4096];
static FX_MEDIA         ram_disk;
static UCHAR            media_memory[4096];

static UCHAR            server_stack[16000];

/* Define device drivers.  */
extern void _fx_ram_driver(FX_MEDIA *media_ptr);
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

/* Set up the HTTP client global variables. */

#define         CLIENT_PACKET_SIZE  (NX_WEB_HTTP_CLIENT_MIN_PACKET_SIZE * 2)

static TX_THREAD           client_thread;
static NX_PACKET_POOL      client_pool;
static NX_WEB_HTTP_CLIENT  my_client;
static NX_IP               client_ip;
static UINT                error_counter;

/* Set up the HTTP server global variables */

#define         SERVER_PACKET_SIZE  (NX_WEB_HTTP_SERVER_MIN_PACKET_SIZE * 2)

static NX_WEB_HTTP_SERVER  my_server;
static NX_PACKET_POOL      server_pool;
static TX_THREAD           server_thread;
static NX_IP               server_ip;
static NXD_ADDRESS         server_ip_address;
static UINT                http_server_start = 0;
static UINT                http_client_stop = 0;

static void thread_client_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);

#define HTTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define HTTP_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)

#ifdef NX_WEB_HTTPS_ENABLE
static UINT                https_server_start = 0;
static UINT                https_client_stop = 0;
static UINT loop = 2;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
static CHAR crypto_metadata_server[20000 * NX_WEB_HTTP_SERVER_SESSION_MAX];
static CHAR crypto_metadata_client[20000 * NX_WEB_HTTP_SERVER_SESSION_MAX];
static UCHAR tls_packet_buffer[18500];
static NX_SECURE_X509_CERT certificate;
static NX_SECURE_X509_CERT trusted_certificate;
static NX_SECURE_X509_CERT remote_certificate, remote_issuer;
static UCHAR remote_cert_buffer[2000];
static UCHAR remote_issuer_buffer[2000];
#else
static UINT loop = 1;
#endif /* NX_WEB_HTTPS_ENABLE  */

static UINT  authentication_check(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, 
                                  CHAR *resource, CHAR **name, CHAR **password, CHAR **realm);
static UINT server_request_callback(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, CHAR *resource, NX_PACKET *packet_ptr);

static UINT test_count;

/* POST AAAAAAAAAA*/
static char pkt[] = {
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 /* AAAAAAAAAA */
};

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_server_content_process_test_application_define(void *first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;


    error_counter = 0;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    tx_thread_create(&server_thread, "HTTP Server thread", thread_server_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     NX_WEB_HTTP_SERVER_PRIORITY, NX_WEB_HTTP_SERVER_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "HTTP Server Packet Pool", SERVER_PACKET_SIZE, 
                                    pointer, SERVER_PACKET_SIZE*16);
    pointer = pointer + SERVER_PACKET_SIZE * 16;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, "HTTP Server IP", HTTP_SERVER_ADDRESS, 
                          0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1024,
                          pointer, 4096, 1);
    pointer =  pointer + 4096;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status = nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&server_ip);
    if (status)
        error_counter++;

    /* Create the HTTP Client thread. */
    status = tx_thread_create(&client_thread, "HTTP Client", thread_client_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              NX_WEB_HTTP_SERVER_PRIORITY + 2, NX_WEB_HTTP_SERVER_PRIORITY + 2, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "HTTP Client Packet Pool", CLIENT_PACKET_SIZE, 
                                    pointer, CLIENT_PACKET_SIZE*16);
    pointer = pointer + CLIENT_PACKET_SIZE * 16;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip, "HTTP Client IP", HTTP_CLIENT_ADDRESS, 
                          0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1024,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status  = nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&client_ip);
    if (status)
        error_counter++;
}

#ifdef NX_WEB_HTTPS_ENABLE
/* Define the TLS setup callback function.  */
static UINT tls_setup_callback(NX_WEB_HTTP_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *tls_session)
{
UINT status;


    /* Initialize and create TLS session.  */
    status = nx_secure_tls_session_create(tls_session, &nx_crypto_tls_ciphers, crypto_metadata_client, sizeof(crypto_metadata_client));
    
    /* Check status.  */
    if (status)
    {
        return(status);
    }

    /* Allocate space for packet reassembly.  */
    status = nx_secure_tls_session_packet_buffer_set(&(client_ptr -> nx_web_http_client_tls_session), tls_packet_buffer, sizeof(tls_packet_buffer));

    /* Check status.  */
    if (status)
    {
        return(status);
    }

    /* Add a CA Certificate to our trusted store for verifying incoming server certificates.  */
    nx_secure_x509_certificate_initialize(&trusted_certificate, ca_cert_der, ca_cert_der_len, NX_NULL, 0, NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    nx_secure_tls_trusted_certificate_add(&(client_ptr -> nx_web_http_client_tls_session), &trusted_certificate);

    /* Need to allocate space for the certificate coming in from the remote host.  */
    nx_secure_tls_remote_certificate_allocate(&(client_ptr -> nx_web_http_client_tls_session), &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(&(client_ptr -> nx_web_http_client_tls_session), &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));

    return(NX_SUCCESS);
}
#endif /* NX_WEB_HTTPS_ENABLE  */

void thread_client_entry(ULONG thread_input)
{
UINT            i;
UINT            status;
NX_PACKET       *send_packet;
NX_PACKET       *recv_packet;


    /* Give IP task and driver a chance to initialize the system. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = HTTP_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    /* First loop test HTTP, second loop test HTTPS.  */
    for (i = 0; i < loop ; i++)
    {
        if (i == 0)
        {

            /* Wait HTTP server started.  */
            while(!http_server_start)
            {
                tx_thread_sleep(NX_IP_PERIODIC_RATE);
            }
        }
#ifdef NX_WEB_HTTPS_ENABLE
        else
        {

            /* Wait HTTPS server started.  */
            while(!https_server_start)
            {
                tx_thread_sleep(NX_IP_PERIODIC_RATE);
            }
        }
#endif /* NX_WEB_HTTPS_ENABLE  */

        for (test_count = 0; test_count < 2; test_count++)
        {

            /* Create an HTTP client instance.  */
            status = nx_web_http_client_create(&my_client, "HTTP Client", &client_ip, &client_pool, 1536);

            /* Check status.  */
            if (status)
                error_counter++;

            /* Send POST request.  */
            if (i == 0)
            {
                status = nx_web_http_client_post_start(&my_client, &server_ip_address,
                                                       NX_WEB_HTTP_SERVER_PORT, "/test.txt?ad",
                                                       "www.abc.com", "name", "password", sizeof(pkt), NX_WAIT_FOREVER);
            }
#ifdef NX_WEB_HTTPS_ENABLE
            else
            {
                 status = nx_web_http_client_secure_connect(&my_client, &server_ip_address, NX_WEB_HTTPS_SERVER_PORT,
                                                         tls_setup_callback, NX_WAIT_FOREVER);
                 if (status)
                 {
                     printf("Error in nx_web_http_client_secure_connect: 0x%x\n", status);
                     error_counter++;
                 }

                 status = nx_web_http_client_request_initialize(&my_client,
                                                           NX_WEB_HTTP_METHOD_POST, /* GET, PUT, DELETE, POST, HEAD */
                                                           "/test.txt;12",
                                                           "www.abc.com",
                                                           sizeof(pkt), /* Used by PUT and POST */
                                                           NX_FALSE, /* If true, input_size is ignored. */
                                                           "name",
                                                           "password",
                                                           NX_WAIT_FOREVER);
                 if (status)
                 {
                     printf("Error in nx_web_http_client_request_initialize: 0x%x\n", status);
                     error_counter++;
                 }

                  status = nx_web_http_client_request_send(&my_client, NX_WAIT_FOREVER);
                 if (status)
                 {
                     printf("Error in nx_web_http_client_request_send: 0x%x\n", status);
                     error_counter++;
                 }
            }
#endif /* NX_WEB_HTTPS_ENABLE  */

            /* Allocate a packet.  */
            status = nx_web_http_client_request_packet_allocate(&my_client, &send_packet, NX_WAIT_FOREVER);

            /* Check status.  */
            if (status)
                error_counter++;

            /* Write test data into the packet payload.  */
            nx_packet_data_append(send_packet, pkt, sizeof(pkt), &client_pool, NX_WAIT_FOREVER);

            /* Send the POST data.  */
            status = nx_web_http_client_put_packet(&my_client, send_packet, 1 * NX_IP_PERIODIC_RATE);
            if (status)
            {
                nx_packet_release(send_packet);
                error_counter++;
            }

            /* Get response from server.  */
            while (1)
            {
                status = nx_web_http_client_response_body_get(&my_client, &recv_packet, NX_WAIT_FOREVER);

                if (status)
                    break;
                else
                    nx_packet_release(recv_packet);
            }

            /* Check status.  */
            if (status != NX_WEB_HTTP_GET_DONE)
                error_counter++;
            else
            {
                if (memcmp(recv_packet -> nx_packet_prepend_ptr, pkt, sizeof(pkt)) != 0)
                {
                    error_counter++;
                }
                nx_packet_release(recv_packet);
            }

            status = nx_web_http_client_delete(&my_client);
            if (status)
                error_counter++;
        }

        /* Set the flag.  */
        if (i == 0)
        {
            http_client_stop = 1;
        }
#ifdef NX_WEB_HTTPS_ENABLE
        else
        {
            https_client_stop = 1;
        }
#endif /* NX_WEB_HTTPS_ENABLE  */
    }

    if (server_pool.nx_packet_pool_available != server_pool.nx_packet_pool_total)
    {
        error_counter++;
    }
}


/* Define the helper HTTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT            i;
UINT            status;
FX_FILE         my_file;
UINT            server_port = NX_WEB_HTTP_SERVER_PORT;


    /* Print out test information banner.  */
    printf("NetX Test:   Web Server Content Process Test...........................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    fx_media_format(&ram_disk,
                    _fx_ram_driver,               // Driver entry
                    ram_disk_memory,              // RAM disk memory pointer
                    media_memory,                 // Media buffer pointer
                    sizeof(media_memory),         // Media buffer size
                    "MY_RAM_DISK",                // Volume Name
                    1,                            // Number of FATs
                    32,                           // Directory Entries
                    0,                            // Hidden sectors
                    256,                          // Total sectors
                    512,                          // Sector size
                    8,                            // Sectors per cluster
                    1,                            // Heads
                    1);                           // Sectors per track   
    
    /* Open the RAM disk.  */
    status = fx_media_open(&ram_disk, "RAM DISK", _fx_ram_driver, ram_disk_memory, media_memory, sizeof(media_memory)) ;
    status += fx_file_create(&ram_disk, "index.htm");
    status += fx_file_open(&ram_disk, &my_file, "index.htm", FX_OPEN_FOR_WRITE);
    status += fx_file_write(&my_file, "https server", 12);
    status += fx_file_close(&my_file);
    if(status)
        error_counter++;

    /* Give NetX a chance to initialize the system. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* First loop test HTTP, second loop test HTTPS.  */
    for (i = 0; i < loop; i++)
    {

        if (i == 1)
        {
            server_port = NX_WEB_HTTPS_SERVER_PORT;
        }

        /* Create the HTTP Server. */
        status = nx_web_http_server_create(&my_server, "My HTTP Server", &server_ip, server_port, &ram_disk,
                                           &server_stack, sizeof(server_stack), &server_pool,
                                           authentication_check, server_request_callback);
        if (status)
            error_counter++;

#ifdef NX_WEB_HTTPS_ENABLE
        /* Set TLS for HTTPS.  */
        if (i == 1)
        {
            /* Initialize device certificate (used for all sessions in HTTPS server). */
            memset(&certificate, 0, sizeof(certificate));
            nx_secure_x509_certificate_initialize(&certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);

            /* Setup TLS session data for the TCP server. */
            status = nx_web_http_server_secure_configure(&my_server, &nx_crypto_tls_ciphers,
                                                         crypto_metadata_server, sizeof(crypto_metadata_server), tls_packet_buffer, sizeof(tls_packet_buffer),
                                                         &certificate, NX_NULL, 0, NX_NULL, 0, NX_NULL, 0);
            if (status)
                error_counter++;
        }
#endif /* NX_WEB_HTTPS_ENABLE  */

        /* OK to start the HTTP Server.   */
        status = nx_web_http_server_start(&my_server);
        if (status)
            error_counter++;

        /* Set the flag.  */
        if (i == 0)
        {
            http_server_start = 1;

            /* Wait HTTP test finished.  */
            while(!http_client_stop)
            {
                tx_thread_sleep(NX_IP_PERIODIC_RATE);
            }
        }
#ifdef NX_WEB_HTTPS_ENABLE
        else
        {
            https_server_start = 1;

            /* Wait HTTPS test finished.  */
            while(!https_client_stop)
            {
                tx_thread_sleep(NX_IP_PERIODIC_RATE);
            }
        }
#endif /* NX_WEB_HTTPS_ENABLE  */

        status = nx_web_http_server_delete(&my_server);
        if (status)
            error_counter++;
    }

    /* Check packet pool.  */
    if (server_pool.nx_packet_pool_available != server_pool.nx_packet_pool_total)
    {
        error_counter++;
    }

    if (client_pool.nx_packet_pool_available != client_pool.nx_packet_pool_total)
    {
        error_counter++;
    }

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


/* Define the application's authentication check.  This is called by
   the HTTP server whenever a new request is received.  */
static UINT  authentication_check(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, 
                                  CHAR *resource, CHAR **name, CHAR **password, CHAR **realm)
{

    /* Just use a simple name, password, and realm for all 
       requests and resources.  */
    *name =     "name";
    *password = "password";
    *realm =    "NetX Duo HTTP demo";

    /* Request basic authentication.  */
    return(NX_WEB_HTTP_BASIC_AUTHENTICATE);
}

/* Define the server request callback function.  */
static UINT server_request_callback(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, CHAR *resource, NX_PACKET *packet_ptr)
{
UINT         length;
NX_PACKET   *response_pkt;
UCHAR        buffer[4000];
CHAR         param[10];
UINT         param_size;
ULONG        content_length;
UINT         status;


    memset(buffer, 0, sizeof(buffer));
    length = 0;

    /* Process content.  */
    if (request_type == NX_WEB_HTTP_SERVER_POST_REQUEST)
    {

        /* Get the content data location.  */
        if (test_count == 0)
        {
            status = nx_web_http_server_content_get(server_ptr, packet_ptr, 0, buffer, sizeof(buffer), &length);
        }
        else
        {
            status = nx_web_http_server_content_get_extended(server_ptr, packet_ptr, 0, buffer, sizeof(buffer), &length);
        }

        if (status)
        {
            return(status);
        }

        /* FIXME: HACK! The parameter and query parsing won't parse past the other symbol (e.g. ';' or '?')
                          so check queries with HTTP and params with HTTPS. */

#ifdef NX_WEB_HTTPS_ENABLE
        if(!server_ptr->nx_web_http_is_https_server)
        {
#endif
            /* Look for queries and parameters. */
            status = nx_web_http_server_query_get(packet_ptr, 0, param, &param_size, sizeof(param));

            if(status != NX_SUCCESS || strncmp(param, "ad", 2) != 0)
            {
                error_counter++;
            }
#ifdef NX_WEB_HTTPS_ENABLE
        }
        else
        {
            /* HTTPS, check params. */
            status = nx_web_http_server_param_get(packet_ptr, 0, param, &param_size, sizeof(param));

            if(status != NX_SUCCESS || strncmp(param, "12", 2) != 0)
            {
                error_counter++;
            }
        }
#endif

        status = nx_web_http_server_packet_content_find(server_ptr, &packet_ptr, &content_length);

        /* Release the received content packet.  */
        nx_packet_release(packet_ptr);

        if(status != NX_SUCCESS || content_length != sizeof(pkt))
        {
            error_counter++;
        }

        if (length != sizeof(pkt))
        {
            error_counter++;
        }

        if (memcmp(buffer, pkt, length) != 0)
        {
            error_counter++;
        }

        /* make sure we don't overwrite our buffer!  */
        if(length > sizeof(buffer))
        {
            length = sizeof(buffer);
        }

        /* Send HTTP header.  */
        status = nx_web_http_server_callback_response_send(server_ptr, NX_WEB_HTTP_STATUS_OK, buffer, NX_NULL);

        if(status)
        {
            return(status); 
        }

        status = nx_web_http_server_response_packet_allocate(server_ptr, &response_pkt, NX_IP_PERIODIC_RATE);

        if(status)
        {
            return(status); 
        }

        if(length > 0)
        {
            /* Only send what is in the buffer.  */
            status = nx_packet_data_append(response_pkt, buffer, length, server_ptr -> nx_web_http_server_packet_pool_ptr, NX_WAIT_FOREVER);
        }

        if(status == NX_SUCCESS)
        {
            if(nx_web_http_server_callback_packet_send(server_ptr, response_pkt) !=  NX_SUCCESS)
            {
                nx_packet_release(response_pkt);
            }
        }
    }
    else
    {
        /* Indicate we have not processed the response to client yet.  */
        return(NX_SUCCESS);
    }

    /* Indicate the response to client is transmitted.  */
    return(NX_WEB_HTTP_CALLBACK_COMPLETED);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_server_content_process_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Web Server Content Process Test...........................N/A\n"); 

    test_control_return(3);  
}      
#endif
