/* If the method is unrecognized or not implemented by the origin server,
 * should repond 501.
 * change GET to AET to build a unrecognized method packet. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#ifdef __PRODUCT_NETXDUO__
#include    "nxd_http_client.h"
#include    "nxd_http_server.h"
#else
#include    "nx_http_client.h"
#include    "nx_http_server.h"
#endif

extern void     test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         4096

/* Set up FileX and file memory resources. */
static CHAR             *ram_disk_memory;
static FX_MEDIA         ram_disk;

/* Define device drivers.  */
extern void     _fx_ram_driver(FX_MEDIA *media_ptr);
extern void     _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);


/* This is a HTTP get packet captured by wireshark. 
 * curl 192.168.0.123 
 * GET: pkt[54] = 0x47, pkt[55] = 0x45, pkt[56] = 0x54
 * AET: pkt[54] = 'A' , pkt[55] = 0x45, pkt[56] = 0x54
 * */
static char pkt[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x57, 0xb8, 0xca, /* .."3DW.. */
    0x3a, 0x95, 0xdb, 0x0b, 0x08, 0x00, 0x45, 0x00, /* :.....E. */
    0x00, 0x75, 0x47, 0x4a, 0x40, 0x00, 0x80, 0x06, /* .uGJ@... */
    0x31, 0x04, 0xc0, 0xa8, 0x00, 0x69, 0xc0, 0xa8, /* 1....i.. */
    0x00, 0x7b, 0xe8, 0xeb, 0x00, 0x50, 0xe5, 0x59, /* .{...P.Y */
    0x56, 0x32, 0x41, 0xf1, 0x07, 0xf0, 0x50, 0x18, /* V2A...P. */
    0xfa, 0xf0, 0x65, 0x69, 0x00, 0x00, 0x47, 0x45, /* ..ei..GE */
    0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, /* T / HTTP */
    0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x55, 0x73, /* /1.1..Us */
    0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, /* er-Agent */
    0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c, 0x2f, 0x37, /* : curl/7 */
    0x2e, 0x33, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x48, /* .32.0..H */
    0x6f, 0x73, 0x74, 0x3a, 0x20, 0x31, 0x39, 0x32, /* ost: 192 */
    0x2e, 0x31, 0x36, 0x38, 0x2e, 0x30, 0x2e, 0x31, /* .168.0.1 */
    0x32, 0x33, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, /* 23..Acce */
    0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, /* pt:      */
    0x0a, 0x0d, 0x0a                                /* ... */
};

/* Set up the HTTP client global variables. */

#define         CLIENT_PACKET_SIZE  (NX_HTTP_SERVER_MIN_PACKET_SIZE * 2)

static TX_THREAD       client_thread;
static NX_PACKET_POOL  client_pool;
static NX_IP           client_ip;

static UINT            error_counter;
static NX_TCP_SOCKET   client_socket;

/* Set up the HTTP server global variables */

#define         SERVER_PACKET_SIZE  (NX_HTTP_SERVER_MIN_PACKET_SIZE * 2)

static NX_HTTP_SERVER  my_server;
static NX_PACKET_POOL  server_pool;
static TX_THREAD       server_thread;
static NX_IP           server_ip;
#ifdef __PRODUCT_NETXDUO__
static NXD_ADDRESS     server_ip_address;
static NXD_ADDRESS     client_ip_address;
#else
static ULONG           server_ip_address;
static ULONG           client_ip_address;
#endif

 
static void thread_client_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);

#define HTTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define HTTP_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_http_status_501_test_application_define(void *first_unused_memory)
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

    /* Set up the server's IPv4 address here. */
#ifdef __PRODUCT_NETXDUO__ 
    server_ip_address.nxd_ip_address.v4 = HTTP_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    client_ip_address.nxd_ip_address.v4 = HTTP_CLIENT_ADDRESS;
    client_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
#else
    server_ip_address = HTTP_SERVER_ADDRESS;
    client_ip_address = HTTP_CLIENT_ADDRESS;
#endif

    /* Create the HTTP Server.  */
    status = nx_http_server_create(&my_server, "My HTTP Server", &server_ip, &ram_disk, 
                          pointer, 2048, &server_pool, NX_NULL, NX_NULL);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Save the memory pointer for the RAM disk.  */
    ram_disk_memory =  pointer;

    /* Create the HTTP Client thread. */
    status = tx_thread_create(&client_thread, "HTTP Client", thread_client_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "HTTP Client Packet Pool", CLIENT_PACKET_SIZE, 
                                    pointer, CLIENT_PACKET_SIZE*8);
    pointer = pointer + CLIENT_PACKET_SIZE * 8;
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


void thread_client_entry(ULONG thread_input)
{

UINT            status;
NX_PACKET       *my_packet;
CHAR            *buffer_ptr;
NX_PACKET       *recv_packet;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&client_ip, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1024,
                                  NX_NULL, NX_NULL);
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 50295, 1 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Call connect to send an SYN.  */ 
    status = nx_tcp_client_socket_connect(&client_socket, HTTP_SERVER_ADDRESS, 80, 2 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Allocate a packet.  */
    status = nx_packet_allocate(&client_pool, &my_packet, NX_TCP_PACKET, 1 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Change 'G' to 'A' .*/
    pkt[54] = 'A';

    /* Write Aet packet into the packet payload.  */
    status = nx_packet_data_append(my_packet, &pkt[54] , (sizeof(pkt)-54), &client_pool, 1 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Send the packet out.  */
    status = nx_tcp_socket_send(&client_socket, my_packet, 1 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Receive the response from http server. */
    status =  nx_tcp_socket_receive(&client_socket, &recv_packet, 1 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;
    else
    {

        buffer_ptr = (CHAR *)recv_packet ->nx_packet_prepend_ptr;

        /* Check the status, If success , it should be 200. */
        if((buffer_ptr[9] != '5') || (buffer_ptr[10] != '0') || (buffer_ptr[11] != '1'))
            error_counter++;

        nx_packet_release(recv_packet);
    }

    tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);
    
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


/* Define the helper HTTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{

UINT            status;

    /* Print out test information banner.  */
    printf("NetX Test:   HTTP Status 501 Test......................................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* OK to start the HTTP Server.   */
    status = nx_http_server_start(&my_server);
    if(status)
        error_counter++;

    tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);

    status = nx_http_server_delete(&my_server);
    if(status)
        error_counter++;

}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_http_status_501_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   HTTP Status 501 Test......................................N/A\n"); 

    test_control_return(3);  
}      
#endif
