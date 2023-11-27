/* This is a small demo of HTTP on the high-performance NetX TCP/IP stack.  
   This demo relies on ThreadX, NetX, and FileX to show a simple HTML 
   transfer from the client and then back from the server.  */

#include  "tx_api.h"
#include  "fx_api.h"
#include  "nx_api.h"
#include  "nx_web_http_client.h"
#include  "nx_web_http_server.h"
#include  "test_utility.h"
#define     DEMO_STACK_SIZE         4096    

/* Define the ThreadX and NetX object control blocks...  */

TX_THREAD               thread_0;
TX_THREAD               thread_1;
NX_PACKET_POOL          pool_0;
NX_PACKET_POOL          pool_1;
NX_IP                   ip_0;
NX_IP                   ip_1;
FX_MEDIA                ram_disk;

/* Define HTTP objects.  */

NX_WEB_HTTP_SERVER      my_server;
NX_WEB_HTTPS_CLIENT      my_client;

/* Define the counters used in the demo application...  */

ULONG                   error_counter;


/* Define the RAM disk memory.  */

UCHAR                   ram_disk_memory[32000];


/* Define function prototypes.  */

void    thread_0_entry(ULONG thread_input);
VOID    _fx_ram_driver(FX_MEDIA *media_ptr) ;
void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define the application's authentication check.  This is called by
   the HTTP server whenever a new request is received.  */
static UINT  authentication_check(NX_WEB_HTTP_SERVER *server_ptr, UINT request_type, 
            CHAR *resource, CHAR **name, CHAR **password, CHAR **realm)
{

    /* Just use a simple name, password, and realm for all 
       requests and resources.  */
    *name =     "name";
    *password = "password";
    *realm =    "NetX HTTP demo";

    /* Request basic authentication.  */
    return(NX_WEB_HTTP_BASIC_AUTHENTICATE);
}


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_http_demo_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            2, 2, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create packet pool.  */
    nx_packet_pool_create(&pool_0, "NetX Packet Pool 0", 640, pointer, 8192);
    pointer = pointer + 8192;

    /* Create an IP instance.  */
    nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 
                        0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                        pointer, 4096, 1);
    pointer =  pointer + 4096;

    /* Create another packet pool. */
    nx_packet_pool_create(&pool_1, "NetX Packet Pool 1", 640, pointer, 8192);
    pointer = pointer + 8192;
    
    /* Create another IP instance.  */
    nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 
                        0xFFFFFF00UL, &pool_1, _nx_ram_network_driver, 
                        pointer, 4096, 1);
    pointer = pointer + 4096;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
  
    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable TCP processing for both IP instances.  */
    nx_tcp_enable(&ip_0);
    nx_tcp_enable(&ip_1);
    
    /* Open the RAM disk.  */
    /* Format the media.  This needs to be done before opening it!  */
    status =  fx_media_format(&ram_disk, 
                            _fx_ram_driver,         // Driver entry
                            ram_disk_memory,        // RAM disk memory pointer
                            pointer,           // Media buffer pointer
                            4096,             // Media buffer size 
                            "MY_RAM_DISK",          // Volume Name
                            1,                      // Number of FATs
                            32,                     // Directory Entries
                            0,                      // Hidden sectors
                            511,                    // Total sectors 
                            128,                    // Sector size   
                            1,                      // Sectors per cluster
                            1,                      // Heads
                            1);                     // Sectors per track 
    EXPECT_EQ(0, status);

    status = fx_media_open(&ram_disk, "RAM DISK", 
                    _fx_ram_driver, ram_disk_memory, pointer, 4096) ;
    EXPECT_EQ(0, status);
    pointer += 4096;

    /* Create the NetX HTTP Server.  */
    status = nx_web_http_server_create(&my_server, "My HTTP Server", &ip_1, &ram_disk, 
                pointer, 4096, &pool_1, authentication_check, NX_NULL);
    EXPECT_EQ(NX_SUCCESS, status);
    pointer =  pointer + 4096;
    
    /* Start the HTTP Server.  */
    status = nx_web_http_server_start(&my_server);
    EXPECT_EQ(NX_SUCCESS, status);
}


/* Define the test thread.  */
void    thread_0_entry(ULONG thread_input)
{

NX_PACKET   *my_packet;
UINT        status;
NXD_ADDRESS server_ip_address;
UCHAR       buffer[100];
ULONG       bytes_received;


    printf("NetX Test:   Web HTTP Demo Test........................................");

    /* Create an HTTP client instance.  */
    status = nx_web_http_client_create(&my_client, "My Client", &ip_0, 
                                                            &pool_0, 600);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Prepare to send the simple 5-byte HTML file to the Server.  */
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_ip_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    status = nx_web_http_client_put_start(&my_client, &server_ip_address, 
                            "/test.htm", "name", "password", 5, 50);
#if 0
    status = nx_web_http_client_put_start(&my_client, &server_ip_address, 
                            "/test.htm", "", "", 5, 50);
#endif
    EXPECT_EQ(NX_SUCCESS, status);

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, 
                                                        NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Build a simple 103-byte HTML page.  */
    nx_packet_data_append(my_packet, "hello", 5, &pool_0, NX_WAIT_FOREVER);
    
    /* Complete the PUT by writing the total length.  */
    status =  nx_web_http_client_put_packet(&my_client, my_packet, 50);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Now GET the file back!  */
    status =  nx_web_http_client_get_start(&my_client, &server_ip_address, 
                    "/test.htm", NX_NULL, 0, "name", "password", 50);
#if 0
    status =  nx_web_http_client_get_start(&my_client, &server_ip_address, 
                    "/test.htm", NX_NULL, 0, "", "", 50);
#endif
    EXPECT_EQ(NX_SUCCESS, status);

    /* Get a packet.  */
    status =  nx_web_http_client_get_packet(&my_client, &my_packet, 20);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_packet_data_extract_offset(my_packet, 0, buffer, 100, &bytes_received);
    EXPECT_EQ(NX_SUCCESS, status);
    EXPECT_EQ((UINT)bytes_received, 5);
    EXPECT_EQ(buffer[0], 'h');
    EXPECT_EQ(buffer[1], 'e');
    EXPECT_EQ(buffer[2], 'l');
    EXPECT_EQ(buffer[3], 'l');
    EXPECT_EQ(buffer[4], 'o');
    nx_packet_release(my_packet);

    /* Flush the media.  */
    fx_media_flush(&ram_disk);

    printf("SUCCESS!\n");
    test_control_return(0);
}
