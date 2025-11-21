/* This case tests server send chunked packet to external client and process chunked packet from external client.  */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#include    "nx_web_http_server.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

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
extern  void _nx_pcap_network_driver(NX_IP_DRIVER*);

static UINT                error_counter;

/* Set up the HTTP server global variables */

#define         SERVER_PACKET_SIZE  (NX_WEB_HTTP_SERVER_MIN_PACKET_SIZE * 2)

static NX_WEB_HTTP_SERVER  my_server;
static NX_PACKET_POOL      server_pool;
static TX_THREAD           server_thread;
static NX_IP               server_ip;
static NXD_ADDRESS         server_ip_address;

static void thread_server_entry(ULONG thread_input);

#define HTTP_SERVER_ADDRESS  IP_ADDRESS(192,168,100,22)

#ifdef NX_WEB_HTTPS_ENABLE
static UINT loop = 2;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
static CHAR crypto_metadata_server[20000 * NX_WEB_HTTP_SERVER_SESSION_MAX];
static UCHAR tls_packet_buffer[18500];
static NX_SECURE_X509_CERT certificate;
static NX_SECURE_X509_CERT trusted_certificate;
static NX_SECURE_X509_CERT remote_certificate, remote_issuer;
static UCHAR remote_cert_buffer[2000];
static UCHAR remote_issuer_buffer[2000];
#else
static UINT loop = 1;
#endif /* NX_WEB_HTTPS_ENABLE  */

static UINT server_request_callback(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, CHAR *resource, NX_PACKET *packet_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_external_client_test_application_define(void *first_unused_memory)
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
                          0xFFFFFF00UL, &server_pool, _nx_pcap_network_driver,
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

    /* Enable ICMP.  */
    status = nx_icmp_enable(&server_ip);
    if (status)
        error_counter++;
}

/* Define the helper HTTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT            i;
UINT            status;
FX_FILE         my_file;
UINT            server_port = NX_WEB_HTTP_SERVER_PORT;


    /* Print out test information banner.  */
    printf("NetX Test:   Web External Client Test..................................");

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
                                           NX_NULL, server_request_callback);
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

        tx_thread_sleep(600 * NX_IP_PERIODIC_RATE);

        status = nx_web_http_server_delete(&my_server);
        if (status)
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

/* Define the server request callback function.  */
static UINT server_request_callback(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, CHAR *resource, NX_PACKET *packet_ptr)
{
NX_PACKET   *response_pkt;
UINT         status;
UINT         content_length = 0, length = 0;
UCHAR        buffer[4000];

    /* Process request.  */
    if(request_type == NX_WEB_HTTP_SERVER_GET_REQUEST)
    {

       /* Generate HTTP header.  */
        status = nx_web_http_server_callback_generate_response_header(server_ptr,
                                                                      &response_pkt, NX_WEB_HTTP_STATUS_OK, 6, "application/octet-stream", 
                                                                      NX_NULL);
        if (status)
        {
            return(status);
        }

        nx_packet_data_append(response_pkt, "abcdef", 6, server_ptr -> nx_web_http_server_packet_pool_ptr, NX_WAIT_FOREVER);

        status = nx_web_http_server_callback_packet_send(server_ptr, response_pkt);
        if (status)
        {
            nx_packet_release(response_pkt);
            return(status);
        }

    }
    else if(request_type == NX_WEB_HTTP_SERVER_POST_REQUEST)
    {

       /* Generate HTTP header.  */
        status = nx_web_http_server_callback_generate_response_header(server_ptr,
                                                                      &response_pkt, NX_WEB_HTTP_STATUS_OK, 0, "text/htm", 
                                                                      "Transfer-Encoding: chunked\r\n");
        if (status)
        {
            return(status);
        }

        status = nx_web_http_server_callback_packet_send(server_ptr, response_pkt);
        if (status)
        {
            nx_packet_release(response_pkt);
            return(status);
        }

        while (1)
        {
            status = nx_web_http_server_content_get(server_ptr, packet_ptr, content_length, buffer, sizeof(buffer), &length);

            if (status)
            {
                break;
            }

            status = nx_web_http_server_response_packet_allocate(server_ptr, &response_pkt, NX_WAIT_FOREVER);
            if (status)
            {
                return(status);
            }

            status = nx_web_http_server_response_chunked_set(server_ptr, length, response_pkt);
            if (status)
            {
                return(status);
            }

            nx_packet_data_append(response_pkt, buffer, length, server_ptr -> nx_web_http_server_packet_pool_ptr, NX_WAIT_FOREVER);

            status = nx_web_http_server_callback_packet_send(server_ptr, response_pkt);
            if (status)
            {
                nx_packet_release(response_pkt);
                return(status);
            }

            content_length += length;
        }


        status = nx_web_http_server_response_packet_allocate(server_ptr, &response_pkt, NX_WAIT_FOREVER);
        if (status)
        {
            return(status);
        }

        status = nx_web_http_server_response_chunked_set(server_ptr, 16, response_pkt);
        if (status)
        {
           return(status);
       }

       nx_packet_data_append(response_pkt, "NETX HTTP SERVER", 16, server_ptr -> nx_web_http_server_packet_pool_ptr, NX_WAIT_FOREVER);

       status = nx_web_http_server_callback_packet_send(server_ptr, response_pkt);
       if (status)
       {
           nx_packet_release(response_pkt);
           return(status);
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
void    netx_web_external_client_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Web External Client Test..................................N/A\n");

    test_control_return(3);  
}      
#endif
