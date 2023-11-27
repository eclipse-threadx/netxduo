/* This case tests basic GET method. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#include    "nx_web_http_client.h"
#include    "nx_web_http_server.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#ifdef NX_WEB_HTTPS_ENABLE
#include "globalsignrootca_cer.c"
#define ca_cert_der globalsignrootca_der
#define ca_cert_der_len globalsignrootca_der_len
#endif /* NX_WEB_HTTPS_ENABLE  */

#define     DEMO_STACK_SIZE         4096

/* Define device drivers.  */
extern  void _nx_pcap_network_driver(NX_IP_DRIVER*);

/* Set up the HTTP client global variables. */

#define         CLIENT_PACKET_SIZE  (NX_WEB_HTTP_CLIENT_MIN_PACKET_SIZE * 2)

static TX_THREAD           client_thread;
static NX_PACKET_POOL      client_pool;
static NX_WEB_HTTP_CLIENT  my_client;
static NX_IP               client_ip;
static UINT                error_counter;
static NXD_ADDRESS         server_ip_address;

static void thread_client_entry(ULONG thread_input);

#define GATEWAY_IP_ADDRESS   IP_ADDRESS(192, 168, 100, 1)
#if 1
#define HTTP_SERVER_ADDRESS  IP_ADDRESS(180, 149, 134, 141)/* weibo.com */
#define HOST_NAME "weibo.com"
#else
#define HTTP_SERVER_ADDRESS  IP_ADDRESS(115, 239, 210, 27)/* baidu.com */
#define HOST_NAME "www.baidu.com"
#endif
#define HTTP_CLIENT_ADDRESS  IP_ADDRESS(192, 168, 100, 22)

#ifdef NX_WEB_HTTPS_ENABLE
static UINT loop = 2;
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
static CHAR crypto_metadata_client[20000 * NX_WEB_HTTP_SERVER_SESSION_MAX];
static UCHAR tls_packet_buffer[18500];
static NX_SECURE_X509_CERT trusted_certificate;
static NX_SECURE_X509_CERT remote_certificate, remote_issuer;
static UCHAR remote_cert_buffer[4096];
static UCHAR remote_issuer_buffer[4096];

static UINT tls_setup_callback(NX_WEB_HTTP_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *tls_session);
#else
static UINT loop = 1;
#endif /* NX_WEB_HTTPS_ENABLE  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_external_server_test_application_define(void *first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;


    error_counter = 0;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Initialize the NetX system.  */
    nx_system_initialize();

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
                          0xFFFFFF00UL, &client_pool, _nx_pcap_network_driver,
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
NX_PACKET       *recv_packet;

    printf("NetX Test:   Web External Server Test..................................");

    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

#ifdef GATEWAY_IP_ADDRESS
    /* Setup gateway for communicating with the outside world. */
    status = nx_ip_gateway_address_set(&client_ip, GATEWAY_IP_ADDRESS);
    
    /* Check for errors.  */
    if (status)
    {
        printf("Error in setting gateway address: 0x%02x\n", status);
        return;
    }
#endif

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = HTTP_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    /* First loop test HTTP, second loop test HTTPS.  */
    for (i = 0; i < loop ; i++)
    {

        /* Create an HTTP client instance.  */
        status = nx_web_http_client_create(&my_client, "HTTP Client", &client_ip, &client_pool, 1536);

        /* Check status.  */
        if (status)
            error_counter++;

        /* Send a GET request.  */
        if (i == 0)
        {
            status = nx_web_http_client_get_start(&my_client, &server_ip_address,
                                                  NX_WEB_HTTP_SERVER_PORT, "/index.htm",
                                                  HOST_NAME,
                                                  NX_NULL, NX_NULL, NX_WAIT_FOREVER);
        }
#ifdef NX_WEB_HTTPS_ENABLE
        else
        {
            status = nx_web_http_client_get_secure_start(&my_client, &server_ip_address,
                                                         NX_WEB_HTTPS_SERVER_PORT, "/index.htm",
                                                         HOST_NAME, NX_NULL, NX_NULL,
                                                         tls_setup_callback, NX_WAIT_FOREVER);
        }
#endif /* NX_WEB_HTTPS_ENABLE  */

        /* Check status.  */
        if (status)
            error_counter++;

        while (1)
        {

            /* Get response from server.  */
            status = nx_web_http_client_response_body_get(&my_client, &recv_packet, 1 * NX_IP_PERIODIC_RATE);

            if (status)
            {
                break;
            }
            else
            {
                nx_packet_release(recv_packet);
            }
        }

        /* Check status.  */
        if (recv_packet)
            nx_packet_release(recv_packet);

        status = nx_web_http_client_delete(&my_client);
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

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_external_server_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Web External Server Test..................................N/A\n"); 

    test_control_return(3);  
}      
#endif

