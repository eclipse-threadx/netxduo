/* This case tests basic GET method. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#include    "nx_web_http_client.h"
#include    "nx_web_http_server.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

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
#define HTTP_SERVER_ADDRESS  IP_ADDRESS(191, 236, 16, 125)/* http://www.httpwatch.com/httpgallery/chunked/chunkedimage.aspx */
#define HTTP_CLIENT_ADDRESS  IP_ADDRESS(192, 168, 100, 22)
#define CHUNKED_TOTAL_SIZE   33653

static UINT loop = 1;

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_external_server_chunked_test_application_define(void *first_unused_memory)
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

void thread_client_entry(ULONG thread_input)
{
UINT            i;
UINT            status;
NX_PACKET       *recv_packet;
UINT            chunked_size = 0;

    printf("NetX Test:   Web External Server Chunked Test..........................");

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
        status = nx_web_http_client_get_start(&my_client, &server_ip_address,
                                              NX_WEB_HTTP_SERVER_PORT, "/httpgallery/chunked/chunkedimage.aspx",
                                              "www.httpwatch.com",
                                              NX_NULL, NX_NULL, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status)
            error_counter++;

        while (1)
        {

            /* Get response from server.  */
            status = nx_web_http_client_response_body_get(&my_client, &recv_packet, NX_WAIT_FOREVER);

            if (status)
            {
                break;
            }
            else
            {
                chunked_size += recv_packet -> nx_packet_length;
                nx_packet_release(recv_packet);
            }
        }

        /* Check status.  */
        if ((status != NX_WEB_HTTP_GET_DONE) || (chunked_size != CHUNKED_TOTAL_SIZE))
            error_counter++;
        else
            nx_packet_release(recv_packet);

        /* Check if all the packets are released.  */
        if (client_pool.nx_packet_pool_available != client_pool.nx_packet_pool_total)
            error_counter++;

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
void    netx_web_external_server_chunked_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Web External Server Chunked Test..........................N/A\n"); 

    test_control_return(3);  
}      
#endif

