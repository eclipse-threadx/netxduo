/* This case tests the get content length task which should allow zero or more white
   spaces between field name (Content-Length) and value.
 */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#include    "nxd_http_client.h"
#include    "nxd_http_server.h"
extern void  test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         4096
#define     SERVER_PORT             80

/* Set up FileX and file memory resources. */
static CHAR             *ram_disk_memory;
static FX_MEDIA         ram_disk;
static unsigned char    media_memory[512];

/* Define device drivers.  */
extern void _fx_ram_driver(FX_MEDIA *media_ptr);
extern void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);
static void  http_test_initialize();
static UINT  nx_http_response_packet_send(NX_TCP_SOCKET *server_socket, UINT port, INT packet_number);


static char get_response_packet_nolabel[130] = {
0x48, 0x54,                                     /* ......HT */
0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x20, 0x32, /* TP/1.0 2 */
0x30, 0x30, 0x20, 0x0d, 0x0a, 0x53, 0x6f, 0x6e, /* 00 ..XXn */
0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, /* tent-Len */
0x67, 0x74, 0x68, 0x3a, 0x20, 0x34, 0x31, 0x35, /* gth: 415 */
0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, /* 4..Conte */
0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, /* nt-Type: */
0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, /*  text/pl */
0x61, 0x69, 0x6e, 0x0d, 0x0a, 0x0d, 0x0a, 0x3c, /* ain....< */
0x68, 0x74, 0x6d, 0x6c, 0x3e, 0x0d, 0x0a, 0x0d, /* html>... */
0x0a, 0x3c, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x0d, /* .<head>. */
0x0a, 0x0d, 0x0a, 0x3c, 0x74, 0x69, 0x74, 0x6c, /* ...<titl */
0x65, 0x3e, 0x4d, 0x61, 0x69, 0x6e, 0x20, 0x57, /* e>Main W */
0x69, 0x6e, 0x64, 0x6f, 0x77, 0x3c, 0x2f, 0x74, /* indow</t */
0x69, 0x74, 0x6c, 0x65, 0x3e, 0x0d, 0x0a, 0x3c, /* itle>..< */
0x2f, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x0d, 0x0a, /* /head>.. */
0x0d, 0x0a, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, /* ..<body> */

};

static int get_response_nolabel_size = 130;


static char get_response_packet_nolength[130] = {
0x48, 0x54,                                     /* ......HT */
0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x20, 0x32, /* TP/1.0 2 */
0x30, 0x30, 0x20, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, /* 00 ..Con */
0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, /* tent-Len */
0x67, 0x74, 0x68, 0x3a, 0x20, 0x20, 0x20, 0x20, /* gth:     */
0x20, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, /*  ..Conte */
0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, /* nt-Type: */
0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, /*  text/pl */
0x61, 0x69, 0x6e, 0x0d, 0x0a, 0x0d, 0x0a, 0x3c, /* ain....< */
0x68, 0x74, 0x6d, 0x6c, 0x3e, 0x0d, 0x0a, 0x0d, /* html>... */
0x0a, 0x3c, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x0d, /* .<head>. */
0x0a, 0x0d, 0x0a, 0x3c, 0x74, 0x69, 0x74, 0x6c, /* ...<titl */
0x65, 0x3e, 0x4d, 0x61, 0x69, 0x6e, 0x20, 0x57, /* e>Main W */
0x69, 0x6e, 0x64, 0x6f, 0x77, 0x3c, 0x2f, 0x74, /* indow</t */
0x69, 0x74, 0x6c, 0x65, 0x3e, 0x0d, 0x0a, 0x3c, /* itle>..< */
0x2f, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x0d, 0x0a, /* /head>.. */
0x0d, 0x0a, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, /* ..<body> */

};

static int get_response_packet_nolength_size = 130;

static char get_response_ok_packet[130] = {
0x48, 0x54,                                     /* ......HT */
0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x20, 0x32, /* TP/1.0 2 */
0x30, 0x30, 0x20, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, /* 00 ..Con */
0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, /* tent-Len */
0x67, 0x74, 0x68, 0x3a, 0x20, 0x20, 0x31, 0x30, /* gth:  10 */
0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, /* 4..Conte */
0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, /* nt-Type: */
0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, /*  text/pl */
0x61, 0x69, 0x6e, 0x0e, 0x0a, 0x0d, 0x0b, 0x3c, /* ain....< */
0x68, 0x74, 0x6d, 0x6c, 0x3e, 0x0d, 0x0a, 0x0e, /* html>... */
0x0a, 0x3c, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x0d, /* .<head>. */
0x0a, 0x0d, 0x0b, 0x3c, 0x74, 0x69, 0x74, 0x6c, /* ...<titl */
0x65, 0x3e, 0x4d, 0x61, 0x69, 0x6e, 0x20, 0x57, /* e>Main W */
0x69, 0x6e, 0x64, 0x6f, 0x77, 0x3c, 0x2f, 0x74, /* indow</t */
0x69, 0x74, 0x6c, 0x65, 0x3e, 0x0d, 0x0a, 0x3c, /* itle>..< */
0x2f, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x0d, 0x0a, /* /head>.. */
0x0e, 0x0b, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, /* ..<body> */

};

static int get_response_ok_size = 130;

static char get_response_bad_packet[202] = {
0x48, 0x54,                                     /* ......HT */
0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x20, 0x32, /* TP/1.0 2 */
0x30, 0x30, 0x20, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, /* 00 ..Con */
0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, /* tent-Len */
0x67, 0x74, 0x68, 0x3a, 0x20, 0x20, 0x31, 0x35, /* gth:  15 */
0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, /* 4..Conte */
0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, /* nt-Type: */
0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, /*  text/pl */
0x61, 0x69, 0x6e, 0x0d, 0x0a, 0x0e, 0x0a, 0x3c, /* ain....< */
0x68, 0x74, 0x6d, 0x6c, 0x3e, 0x0e, 0x0b, 0x0d, /* html>... */
0x0a, 0x3c, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x0d, /* .<head>. */
0x0a, 0x0e, 0x0a, 0x3c, 0x74, 0x69, 0x74, 0x6c, /* ...<titl */


0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, /* tent-Len */
0x67, 0x74, 0x68, 0x3a, 0x20, 0x20, 0x31, 0x35, /* gth:  15 */
0x34, 0x0d, 0x0b, 0x43, 0x6f, 0x6e, 0x74, 0x65, /* 4..Conte */
0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, /* nt-Type: */
0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, /*  text/pl */
0x61, 0x69, 0x6e, 0x0e, 0x0a, 0x0d, 0x0b, 0x3c, /* ain....< */
0x68, 0x74, 0x6d, 0x6c, 0x3e, 0x0e, 0x0a, 0x0d, /* html>... */
0x0a, 0x3c, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x0e, /* .<head>. */
0x0b, 0x0d, 0x0b, 0x3c, 0x74, 0x69, 0x74, 0x6c, /* ...<titl */

0x65, 0x3e, 0x4d, 0x61, 0x69, 0x6e, 0x20, 0x57, /* e>Main W */
0x69, 0x6e, 0x64, 0x6f, 0x77, 0x3c, 0x2f, 0x74, /* indow</t */
0x69, 0x74, 0x6c, 0x65, 0x3e, 0x0d, 0x0b, 0x3c, /* itle>..< */
0x2f, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x0e, 0x0a, /* /head>.. */
0x0d, 0x0b, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, /* ..<body> */

};

static int get_response_bad_size = 202;

#define RESPONSE_COUNT 4

typedef struct HTTP_RESPONSE_STRUCT
{
    char          *http_response_pkt_data;
    int           http_response_pkt_size;
} HTTP_RESPONSE;


static HTTP_RESPONSE       http_response[RESPONSE_COUNT];

/* Set up the HTTP client global variables. */

#define         CLIENT_PACKET_SIZE  (NX_HTTP_SERVER_MIN_PACKET_SIZE * 1)
#define         CLIENT_PACKET_POOL_SIZE ((CLIENT_PACKET_SIZE + sizeof(NX_PACKET)) * 5)
ULONG           client_packet_pool_area[CLIENT_PACKET_POOL_SIZE/4 + 4];

static TX_THREAD       client_thread;
static NX_HTTP_CLIENT  my_client;
static NX_PACKET_POOL  client_pool;
static NX_IP           client_ip;
static UINT            error_counter;
static UINT            client_received_response = NX_FALSE;

/* Set up the HTTP server global variables */

#define         SERVER_PACKET_SIZE  (NX_HTTP_SERVER_MIN_PACKET_SIZE * 1)
#define         SERVER_PACKET_POOL_SIZE ((SERVER_PACKET_SIZE + sizeof(NX_PACKET)) * 5)
ULONG           server_packet_pool_area[SERVER_PACKET_POOL_SIZE/4 + 4];

/* Define the IP thread stack areas.  */

ULONG           server_ip_thread_stack[2 * 1024 / sizeof(ULONG)];
ULONG           client_ip_thread_stack[2 * 1024 / sizeof(ULONG)];

/* Define the ARP cache areas.  */

ULONG             server_arp_space_area[512 / sizeof(ULONG)];
ULONG             client_arp_space_area[512 / sizeof(ULONG)];



static NX_TCP_SOCKET   server_socket;
static NX_PACKET_POOL  server_pool;
static TX_THREAD       server_thread;
static NX_IP           server_ip;
#ifdef __PRODUCT_NETXDUO__
static NXD_ADDRESS     server_ip_address;
#else
static ULONG           server_ip_address;
#endif

 
static void thread_client_entry(ULONG thread_input);
static void thread_server_entry(ULONG thread_input);

#define HTTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define HTTP_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)



#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_http_get_contentlength_packetleak_test_application_define(void *first_unused_memory)
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
    
    /* Create the HTTP Client thread. */
    status = tx_thread_create(&client_thread, "HTTP Client", thread_client_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;

    /* Initialize the NetX system.  */
    nx_system_initialize();
    

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "HTTP Server Packet Pool", SERVER_PACKET_SIZE,  (ULONG*)(((int)server_packet_pool_area + 15) & ~15) , SERVER_PACKET_POOL_SIZE);

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, 
                          "HTTP Server IP", 
                          HTTP_SERVER_ADDRESS, 
                          0xFFFFFF00UL, 
                          &server_pool, _nx_ram_network_driver_1024,
                          (UCHAR*)server_ip_thread_stack,
                          sizeof(server_ip_thread_stack),
                          1);
    
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status =  nx_arp_enable(&server_ip, (void *)server_arp_space_area, sizeof(server_arp_space_area));

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
#else
    server_ip_address = HTTP_SERVER_ADDRESS;
#endif

    /* Save the memory pointer for the RAM disk.  */
    ram_disk_memory =  pointer;

    /* Create the Client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "HTTP Client Packet Pool", CLIENT_PACKET_SIZE,  (ULONG*)(((int)client_packet_pool_area + 15) & ~15) , CLIENT_PACKET_POOL_SIZE);

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&client_ip, "HTTP Client IP", HTTP_CLIENT_ADDRESS, 
                          0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1024,
                          (UCHAR*)client_ip_thread_stack,
                          sizeof(client_ip_thread_stack),
                          1);
    if (status)
        error_counter++;

    status =  nx_arp_enable(&client_ip, (void *)client_arp_space_area, sizeof(client_arp_space_area));
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
NX_PACKET       *recv_packet;
UINT            i;
UINT            previously_available = 0;

    /* wait for the server to set up */
    tx_thread_sleep(50);

    /* Format the RAM disk - the memory for the RAM disk was setup in 
      tx_application_define above.  This must be set up before the client(s) start
      sending requests. */
    status = fx_media_format(&ram_disk, 
                            _fx_ram_driver,         /* Driver entry               */
                            ram_disk_memory,        /* RAM disk memory pointer    */
                            media_memory,           /* Media buffer pointer       */
                            sizeof(media_memory),   /* Media buffer size          */
                            "MY_RAM_DISK",          /* Volume Name                */
                            1,                      /* Number of FATs             */
                            32,                     /* Directory Entries          */
                            0,                      /* Hidden sectors             */
                            256,                    /* Total sectors              */
                            128,                    /* Sector size                */
                            1,                      /* Sectors per cluster        */
                            1,                      /* Heads                      */
                            1);                     /* Sectors per track          */

    /* Check the media format status.  */
    if (status != FX_SUCCESS)
        error_counter++;

    /* Open the RAM disk.  */
    status =  fx_media_open(&ram_disk, "RAM DISK", _fx_ram_driver, ram_disk_memory, media_memory, sizeof(media_memory));

    if (status != FX_SUCCESS)
        error_counter++;

    /* Open four client connections, to test the response to Get Start. */
    for (i = 0; i < 3; i++)
    {
    
        /* Create an HTTP client instance.  */
        status = nx_http_client_create(&my_client, "HTTP Client", &client_ip, &client_pool, 600);
        if (status)
            error_counter++;
    
        previously_available = client_pool.nx_packet_pool_available;
    
        /* Send a series of get requests to the Server, testing the ability to find Content-Length data
           with different formats, including the last test where the response is missing the length. */
    
#ifdef __PRODUCT_NETXDUO__ 
    
        /* Use the 'duo' service to send a GET request to the server (can use IPv4 or IPv6 addresses). */
        status =  nxd_http_client_get_start(&my_client, &server_ip_address, 
                                                "/client_test.htm", NX_NULL, 0, "", "", 50);
#else
    
        /* Use the 'NetX' service to send a GET request to the server (can only use IPv4 addresses). */
        status =  nx_http_client_get_start(&my_client, HTTP_SERVER_ADDRESS, "/client_test.htm", 
                                           NX_NULL, 0, "", "",50);
#endif  
    
        if (status !=  NX_SUCCESS)
        {
            if (client_pool.nx_packet_pool_available != previously_available)
            {
              error_counter++;
            }

        }
        else /* get start does not fail, we request a GET packet*/
        {

            tx_thread_sleep(10);
            previously_available = client_pool.nx_packet_pool_available;

            status =  nx_http_client_get_packet(&my_client, &recv_packet, 200);

            if (status != NX_SUCCESS)
            {
              if (client_pool.nx_packet_pool_available != previously_available)
              {
                 error_counter++;
              }            
            }
        }
        
        client_received_response = NX_TRUE;
        tx_thread_sleep(50);

        status = nx_http_client_delete(&my_client);
        if(status)
            error_counter++;
    }

    client_received_response = NX_TRUE;

}


/* Define the helper HTTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{

UINT         status;
NX_PACKET   *my_packet;
UINT         i, test_count;

    /* Print out test information banner.  */
    printf("NetX Test:   HTTP Get Content Length Packet Leak Test..................");

    /* Check for earlier error. */
    if(error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a TCP socket act as the HTTP server.  */
    status = nx_tcp_socket_create(&server_ip, &server_socket, "Socket Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 
                                  NX_IP_TIME_TO_LIVE, 2048, NX_NULL, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Bind the TCP socket to the IP port.  */
    status =  nx_tcp_server_socket_listen(&server_ip, SERVER_PORT, &server_socket, 5, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    http_test_initialize();

    test_count =  2;

    /* Act as the HTTP server to receive the Client query and send the HTTP server response.  */
    for (i = 0; i < test_count; i++ )
    {

        /* Wait for a connection request.  */
        status =  nx_tcp_server_socket_accept(&server_socket, NX_WAIT_FOREVER);
    
        /* Check status.  */
        if (status)
        {
            error_counter++;
        }
    
        /* Receive a TCP packet.  */
        status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status)
        {
            error_counter++;
        }       
        else
        {
          /* Release the packet.  */
          nx_packet_release(my_packet);

          /* Send the TCP response packet.  */
          status = nx_http_response_packet_send(&server_socket, 80, i);

          /* Check status.  */
          if (status)
          {        
              error_counter++; 
          }                  
        
          while(!client_received_response)
              tx_thread_sleep(50);
          
          client_received_response = NX_FALSE;
        }
        
        /* Unaccept the server socket.  */
        status =  nx_tcp_server_socket_unaccept(&server_socket);
    
        /* Unbind the UDP socket.  */
        status =  nx_tcp_server_socket_relisten(&server_ip, SERVER_PORT, &server_socket);
    
        /* Check status.  */
        if (status)
        {        
            error_counter++;   
        }        
    }
             
    /* Wait for a connection request.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 30 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status )
    {
        error_counter++; 
    }
    
    /* Receive a TCP packet.  */
    status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++; 
    }       

    /* Release the packet.  */
    nx_packet_release(my_packet);


    /* Send the TCP response packet.  */
    status = nx_http_response_packet_send(&server_socket, 80, 2);

    /* Check status.  */
    if (status)
    {        
        error_counter++; 

    }           
    
    /* Give Client a chance to process previous packet. */
    tx_thread_sleep(50);

    /* Send the fourth server response packet.  */
    status = nx_http_response_packet_send(&server_socket, 80, 3);

    /* Check status.  */
    if (status)
    {        
        error_counter++; 
    }           

    while(!client_received_response)
        tx_thread_sleep(50);

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&server_socket);

    /* Unbind the TCP socket.  */
    status =  nx_tcp_server_socket_unlisten(&server_ip, SERVER_PORT);

    /* Check status.  */
    if (status)
    {        
        error_counter++;   
    }
    /* Delete the TCP socket.  */
    status =  nx_tcp_socket_delete(&server_socket);

    /* Check status.  */
    if (status)
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
    };
   
}


static void  http_test_initialize()
{

    http_response[0].http_response_pkt_data = &get_response_packet_nolabel[0];
    http_response[0].http_response_pkt_size = get_response_nolabel_size;  

    http_response[1].http_response_pkt_data = &get_response_packet_nolength[0];
    http_response[1].http_response_pkt_size = get_response_packet_nolength_size;  

    http_response[2].http_response_pkt_data = &get_response_ok_packet[0];
    http_response[2].http_response_pkt_size = get_response_ok_size;  

    http_response[3].http_response_pkt_data = &get_response_bad_packet[0];
    http_response[3].http_response_pkt_size = get_response_bad_size;  

}


static UINT   nx_http_response_packet_send(NX_TCP_SOCKET *server_socket, UINT port, INT packet_number)
{
UINT        status;
NX_PACKET   *response_packet;


    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&server_pool, &response_packet, NX_TCP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Write the HTTP response messages into the packet payload!  */
    memcpy(response_packet -> nx_packet_prepend_ptr, http_response[packet_number].http_response_pkt_data, 
           http_response[packet_number].http_response_pkt_size);

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length =  http_response[packet_number].http_response_pkt_size;
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;

    /* Send the TCP packet with the correct port.  */
    status =  nx_tcp_socket_send(server_socket, response_packet, 200);

    /* Check the status.  */
    if (status)      
        nx_packet_release(response_packet);         

    return status;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_http_get_contentlength_packetleak_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   HTTP Get Content Length Packet Leak Test..................N/A\n"); 

    test_control_return(3);  
}      
#endif
