/* This case tests basic GET method. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
#include    "nx_web_http_client.h"
#include    "nx_web_http_server.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

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

static UINT loop = 1;

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_one_session_test_application_define(void *first_unused_memory)
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

    /* Create the HTTP Client thread. */
    status = tx_thread_create(&client_thread, "HTTP Client", thread_client_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              NX_WEB_HTTP_SERVER_PRIORITY + 2, NX_WEB_HTTP_SERVER_PRIORITY + 2, TX_NO_TIME_SLICE, TX_AUTO_START);
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
NX_PACKET       *recv_packet;


    /* Give IP task and driver a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Set server IP address.  */
    server_ip_address.nxd_ip_address.v4 = HTTP_SERVER_ADDRESS;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;


    /* Wait HTTP server started.  */
    while (!http_server_start)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    /* Create an HTTP client instance.  */
    status = nx_web_http_client_create(&my_client, "HTTP Client", &client_ip, &client_pool, 1536);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Connect to server.  */
    status = nx_web_http_client_connect(&my_client, &server_ip_address, NX_WEB_HTTP_SERVER_PORT, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Initialize the request.  */
    status = nx_web_http_client_request_initialize(&my_client, NX_WEB_HTTP_METHOD_GET, "/test.txt", "1.2.3.4",
                                                   0, NX_FALSE, "name", "password", NX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
        error_counter++;

    status = nx_web_http_client_request_header_add(&my_client, "Connection", 10, "close", 5, 1 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Send the request.  */
    status = nx_web_http_client_request_send(&my_client, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
        error_counter++;

    tx_thread_sleep(11 * NX_IP_PERIODIC_RATE);

    /* Get response from server.  */
    while (1)
    {
        status = nx_web_http_client_response_body_get(&my_client, &recv_packet, 1 * NX_IP_PERIODIC_RATE);

        if (status)
            break;
        else
            nx_packet_release(recv_packet);
    }

    /* Check status.  */
    if (status != NX_WEB_HTTP_GET_DONE)
        error_counter++;
    else
        nx_packet_release(recv_packet);

    /* Send a GET request.  */
    status = nx_web_http_client_get_start(&my_client, &server_ip_address,
                                          NX_WEB_HTTP_SERVER_PORT, "http://1.2.3.4/test.txt",
                                          "1.2.3.4", "name", "password", NX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Get response from server.  */
    while (1)
    {
        status = nx_web_http_client_response_body_get(&my_client, &recv_packet, 1 * NX_IP_PERIODIC_RATE);

        if (status)
            break;
        else
            nx_packet_release(recv_packet);
    }

    /* Check status.  */
    if (status != NX_WEB_HTTP_GET_DONE)
        error_counter++;
    else
        nx_packet_release(recv_packet);

    status = nx_web_http_client_delete(&my_client);
    if (status)
        error_counter++;

    /* Set the flag.  */
    http_client_stop = 1;
}

/* Define the helper HTTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT            i;
UINT            status;
FX_FILE         my_file;
UINT            server_port = NX_WEB_HTTP_SERVER_PORT;


    /* Print out test information banner.  */
    printf("NetX Test:   Web One Session Test......................................");

    /* Check for earlier error.  */
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
    status += fx_file_create(&ram_disk, "TEST.TXT");
    status += fx_file_open(&ram_disk, &my_file, "TEST.TXT", FX_OPEN_FOR_WRITE);
    status += fx_file_write(&my_file, "https server", 12);
    status += fx_file_close(&my_file);
    if(status)
        error_counter++;

    /* Give NetX a chance to initialize the system.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Create the HTTP Server. */
    status = nx_web_http_server_create(&my_server, "My HTTP Server", &server_ip, server_port, &ram_disk,
                                       &server_stack, sizeof(server_stack), &server_pool,
                                       NX_NULL, NX_NULL);
    if (status)
        error_counter++;

    my_server.nx_web_http_server_tcpserver.nx_tcpserver_sessions_count = 1;

    /* OK to start the HTTP Server.  */
    status = nx_web_http_server_start(&my_server);
    if (status)
        error_counter++;

    /* Set the flag.  */
    http_server_start = 1;

    /* Wait HTTP test finished.  */
    while (!http_client_stop)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    status = nx_web_http_server_delete(&my_server);
    if (status)
        error_counter++;

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
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_one_session_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Web One Session Test......................................N/A\n"); 

    test_control_return(3);  
}      
#endif

