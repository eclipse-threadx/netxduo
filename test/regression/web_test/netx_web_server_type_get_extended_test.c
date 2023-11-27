/* This case tests basic GET method. */
#include    "tx_api.h"
#include    "nx_api.h"
#include    "fx_api.h"
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


static UINT                error_counter;

/* Set up the HTTP server global variables */

#define         SERVER_PACKET_SIZE  (NX_WEB_HTTP_SERVER_MIN_PACKET_SIZE * 2)

static NX_WEB_HTTP_SERVER  my_server;
static NX_PACKET_POOL      server_pool;
static TX_THREAD           server_thread;
static NX_IP               server_ip;
static NXD_ADDRESS         server_ip_address;

static void thread_server_entry(ULONG thread_input);

#define HTTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_web_server_type_get_extended_test_application_define(void *first_unused_memory)
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
}


/* Define the helper HTTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{
UINT            status;
FX_FILE         my_file;
UINT            server_port = NX_WEB_HTTP_SERVER_PORT;
UCHAR           type[20];
UINT            type_length;


    /* Print out test information banner.  */
    printf("NetX Test:   Web Server Type Retrieve Test.............................");

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

    /* Create the HTTP Server. */
    status = nx_web_http_server_create(&my_server, "My HTTP Server", &server_ip, server_port, &ram_disk,
                                       &server_stack, sizeof(server_stack), &server_pool,
                                       NX_NULL, NX_NULL);
    if (status)
        error_counter++;


    /* Type is "text/html", should return 9.  */
    status = nx_web_http_server_type_get_extended(&my_server, "test.htm", 8, type, sizeof(type), &type_length);
    if (status || type_length != 9)
        error_counter++;

    /* The max size of destination string is not enough, should return error. */
    status = nx_web_http_server_type_get_extended(&my_server, "test.htm", 8, type, 9, &type_length);
    if (status != NX_WEB_HTTP_ERROR)
        error_counter++;

    /* Type is default "text/plain", should return 10.  */
    status = nx_web_http_server_type_get_extended(&my_server, "test.xml", 8, type, sizeof(type), &type_length);
    if (status != NX_WEB_HTTP_EXTENSION_MIME_DEFAULT || type_length != 10)
        error_counter++;

    /* The max size of destination string is not enough, should return error. */
    status = nx_web_http_server_type_get_extended(&my_server, "test.xml", 8, type, 5, &type_length);
    if (status != NX_WEB_HTTP_ERROR)
        error_counter++;

    /* Type is default "text/plain", should return 10.  */
    status = nx_web_http_server_type_get_extended(&my_server, "test", 4, type, sizeof(type), &type_length);
    if (status != NX_WEB_HTTP_EXTENSION_MIME_DEFAULT || type_length != 10)
        error_counter++;

    /* The max size of destination string is not enough, should return error. */
    status = nx_web_http_server_type_get_extended(&my_server, "test", 4, type, 5, &type_length);
    if (status != NX_WEB_HTTP_ERROR)
        error_counter++;

    status = nx_web_http_server_delete(&my_server);
    if (status)
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
void    netx_web_server_type_get_extended_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Web Server Type Retrieve Test.............................N/A\n"); 

    test_control_return(3);  
}      
#endif

