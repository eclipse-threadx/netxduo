
#include    "tx_api.h"
#include    "fx_api.h" 
#include    "nx_api.h"
#include    "nxd_ftp_client.h"
#include    "nxd_ftp_server.h"
#include    "nx_tcp.h"

extern void     test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         4096

/* Define the ThreadX, NetX, and FileX object control blocks...  */
static TX_THREAD               server_thread;
static TX_THREAD               client_thread;
static NX_PACKET_POOL          server_pool;
static NX_IP                   server_ip;
static NX_PACKET_POOL          client_pool;
static NX_IP                   client_ip;
static FX_MEDIA                ram_disk;


/* Define the NetX FTP object control blocks.  */
static NX_FTP_CLIENT           ftp_client;
static NX_FTP_SERVER           ftp_server;

/* Define the counters used in the demo application...  */
static ULONG                   error_counter = 0;
static ULONG                   username_counter = 0;
static ULONG                   passwd_counter = 0;
static UINT                    test_done = NX_FALSE;


/* Define the memory area for the FileX RAM disk.  */
static UCHAR                   ram_disk_memory[32000];
static UCHAR                   ram_disk_sector_cache[512];


#define FTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define FTP_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)

extern UINT  _fx_media_format(FX_MEDIA *media_ptr, VOID (*driver)(FX_MEDIA *media), VOID *driver_info_ptr, UCHAR *memory_ptr, UINT memory_size,
                              CHAR *volume_name, UINT number_of_fats, UINT directory_entries, UINT hidden_sectors, 
                              ULONG total_sectors, UINT bytes_per_sector, UINT sectors_per_cluster, 
                              UINT heads, UINT sectors_per_track);

/* Define the FileX and NetX driver entry functions.  */
extern void     _fx_ram_driver(FX_MEDIA *media_ptr);
extern void     _nx_ram_network_driver_512(NX_IP_DRIVER *driver_req_ptr);
static void     my_ftp_packet_receive_server(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

static void    client_thread_entry(ULONG thread_input);
static void    thread_server_entry(ULONG thread_input);


/* Define server login/logout functions.  These are stubs for functions that would 
validate a client login request.   */
static UINT    server_login(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, ULONG client_ip_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info);
static UINT    server_logout(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, ULONG client_ip_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_access_control_commands_02_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
UCHAR   *pointer;


    /* Setup the working pointer.  */
    pointer =  (UCHAR *) first_unused_memory;

    /* Create a helper thread for the server. */
    tx_thread_create(&server_thread, "FTP Server thread", thread_server_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize NetX.  */
    nx_system_initialize();

    /* Create the packet pool for the FTP Server.  */
    status = nx_packet_pool_create(&server_pool, "NetX Server Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;
    if (status)
        error_counter++;

    /* Create the IP instance for the FTP Server.  */
    status = nx_ip_create(&server_ip, "NetX Server IP Instance", FTP_SERVER_ADDRESS, 0xFFFFFF00UL, 
                          &server_pool, _nx_ram_network_driver_512, pointer, 2048, 1);
    pointer = pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for server IP instance.  */
    status = nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable TCP.  */
    status = nx_tcp_enable(&server_ip);
    if (status)
        error_counter++;

    /* Create the FTP server.  */
    status =  nx_ftp_server_create(&ftp_server, "FTP Server Instance", &server_ip, &ram_disk, pointer, DEMO_STACK_SIZE, &server_pool,
                                   server_login, server_logout);
    pointer =  pointer + DEMO_STACK_SIZE;
    if (status)
        error_counter++;

    /* Now set up the FTP Client. */

    /* Create the main FTP client thread.  */
    status = tx_thread_create(&client_thread, "FTP Client thread ", client_thread_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + DEMO_STACK_SIZE ;
    if (status)
        error_counter++;

    /* Create a packet pool for the FTP client.  */
    status =  nx_packet_pool_create(&client_pool, "NetX Client Packet Pool", 256, pointer, 8192);
    pointer =  pointer + 8192;
    if (status)
        error_counter++;

    /* Create an IP instance for the FTP client.  */
    status = nx_ip_create(&client_ip, "NetX Client IP Instance", FTP_CLIENT_ADDRESS, 0xFFFFFF00UL, 
                          &client_pool, _nx_ram_network_driver_512, pointer, 2048, 1);
    pointer = pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for the FTP Client IP.  */
    status = nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable TCP for client IP instance.  */
    status = nx_tcp_enable(&client_ip);
    if (status)
        error_counter++;

}

/* Define the FTP client thread.  */

void    client_thread_entry(ULONG thread_input)
{


UINT        status;

    /* Format the RAM disk - the memory for the RAM disk was defined above.  */
    status = _fx_media_format(&ram_disk, 
                            _fx_ram_driver,                  /* Driver entry                */
                            ram_disk_memory,                 /* RAM disk memory pointer     */
                            ram_disk_sector_cache,           /* Media buffer pointer        */
                            sizeof(ram_disk_sector_cache),   /* Media buffer size           */
                            "MY_RAM_DISK",                   /* Volume Name                 */
                            1,                               /* Number of FATs              */
                            32,                              /* Directory Entries           */
                            0,                               /* Hidden sectors              */
                            256,                             /* Total sectors               */
                            128,                             /* Sector size                 */
                            1,                               /* Sectors per cluster         */
                            1,                               /* Heads                       */
                            1);                              /* Sectors per track           */

    /* Check status.  */
    if (status)
        error_counter++;

    /* Open the RAM disk.  */
    status = fx_media_open(&ram_disk, "RAM DISK", _fx_ram_driver, ram_disk_memory, ram_disk_sector_cache, sizeof(ram_disk_sector_cache));
    if (status)
        error_counter++;

    /* Create an FTP client.  */
    status =  nx_ftp_client_create(&ftp_client, "FTP Client", &client_ip, 2000, &client_pool);
    if (status) 
        error_counter++;

    /* Now connect with the NetX FTP (IPv4) server. */
    status =  nx_ftp_client_connect(&ftp_client, FTP_SERVER_ADDRESS, "name", "password", NX_IP_PERIODIC_RATE);
    if (status) 
        error_counter++;

    /* Disconnect from the server.  */
    status =  nx_ftp_client_disconnect(&ftp_client, NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Delete the FTP client.  */
    status =  nx_ftp_client_delete(&ftp_client);
    if (status)
        error_counter++;

    /* Set the flag.  */
    test_done = NX_TRUE;
}


/* Define the helper FTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{

UINT    status;

    /* Print out test information banner.  */
    printf("NetX Test:   FTP Server Access Control Commands Pass Test..............");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* OK to start the FTPv6 Server.   */
    status = nx_ftp_server_start(&ftp_server);
    if (status)
        error_counter++;

    server_ip.nx_ip_tcp_packet_receive = my_ftp_packet_receive_server;

    /* Wait for test.  */
    while(test_done == NX_FALSE)
        tx_thread_sleep(NX_IP_PERIODIC_RATE);

    status = nx_ftp_server_delete(&ftp_server);
    if(status)
        error_counter++;

    if((error_counter) && ( username_counter != 1 ) && ( passwd_counter != 1 ))
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

void           my_ftp_packet_receive_server(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER    *tcp_header_ptr;
UCHAR            *message;
static int       flag = 0;

    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    message = packet_ptr -> nx_packet_prepend_ptr + 20;

    /* Check the packet is a SYN one.  */
    if(*message == 'U')
    {
        if(!memcmp(message,"USER name",9))
        {
            username_counter++;
            flag = 0;
        }
    }
    /* Check if the PASSWORD command must be immediately preceded by the user name command. */
    else if (*message == 'P' && flag == 1)
    {
        if(!memcmp(message,"PASS password",13))
            passwd_counter++;

        server_ip.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    }
    /* Deal packets with default routing.  */

    flag ++;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Let server receives the SYN packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}

static UINT  server_login(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, ULONG client_ip_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info)
{
    /* Always return success.  */
    return(NX_SUCCESS);
}

static UINT  server_logout(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, ULONG client_ip_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info)
{
    /* Always return success.  */
    return(NX_SUCCESS);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_access_control_commands_02_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   FTP Server Access Control Commands Pass Test..............N/A\n"); 

    test_control_return(3);  
}      
#endif