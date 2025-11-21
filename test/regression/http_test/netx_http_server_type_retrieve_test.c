
#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#include    "nxd_http_server.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         4096

/* Set up FileX and file memory resources. */
static CHAR             *ram_disk_memory;
static FX_MEDIA         ram_disk;
static unsigned char    media_memory[512];

/* Define device drivers.  */
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);

/* Set up the HTTP client global variables. */
static UINT            error_counter;

/* Set up the HTTP server global variables */

#define         SERVER_PACKET_SIZE  (NX_HTTP_SERVER_MIN_PACKET_SIZE * 2)

static NX_HTTP_SERVER  my_server;
static NX_PACKET_POOL  server_pool;
static TX_THREAD       server_thread;
static NX_IP           server_ip;

 
static void thread_server_entry(ULONG thread_input);

#define HTTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_http_server_type_retrieve_test_application_define(void *first_unused_memory)
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
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "HTTP Server Packet Pool", SERVER_PACKET_SIZE, 
                                    pointer, SERVER_PACKET_SIZE*8);
    pointer = pointer + SERVER_PACKET_SIZE * 8;
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

    /* Create the HTTP Server.  */
    status = nx_http_server_create(&my_server, "My HTTP Server", &server_ip, &ram_disk, 
                          pointer, 2048, &server_pool, NX_NULL, NX_NULL);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
}

/* Define the helper HTTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{

UINT            status;
UCHAR           type[20];
UINT            type_length;

    /* Print out test information banner.  */
    printf("NetX Test:   HTTP Server Type Retrieve Test............................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Type is "text/html", should return 9.  */
    type_length = nx_http_server_type_get(&my_server, "test.htm", type);
    if (type_length != 9)
        error_counter++;
    type_length = nx_http_server_type_get_extended(&my_server, "test.htm", 8, type, sizeof(type));
    if (type_length != 9)
        error_counter++;

    /* The max size of destination string is not enough, should return 0. */
    type_length = nx_http_server_type_get_extended(&my_server, "test.htm", 8, type, 9);
    if (type_length != 0)
        error_counter++;

    /* Type is default "text/plain", should return 10.  */
    type_length = nx_http_server_type_get(&my_server, "test.xml", type);
    if (type_length != 10)
        error_counter++;
    type_length = nx_http_server_type_get_extended(&my_server, "test.xml", 8, type, sizeof(type));
    if (type_length != 10)
        error_counter++;

    /* The max size of destination string is not enough, should return 0. */
    type_length = nx_http_server_type_get_extended(&my_server, "test.xml", 8, type, 5);
    if (type_length != 0)
        error_counter++;

    /* Type is default "text/plain", should return 10.  */
    type_length = nx_http_server_type_get(&my_server, "test", type);
    if (type_length != 10)
        error_counter++;
    type_length = nx_http_server_type_get_extended(&my_server, "test", 4, type, sizeof(type));
    if (type_length != 10)
        error_counter++;

    /* The max size of destination string is not enough, should return 0. */
    type_length = nx_http_server_type_get_extended(&my_server, "test", 4, type, 5);
    if (type_length != 0)
        error_counter++;

    status = nx_http_server_delete(&my_server);
    if(status)
        error_counter++;

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
void    netx_http_server_type_retrieve_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   HTTP Server Type Retrieve Test............................N/A\n"); 

    test_control_return(3);  
}      
#endif

