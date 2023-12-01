/* Clent sends EPSV twice. */
#include    "tx_api.h"
#include    "fx_api.h" 
#include    "nx_api.h"
#include    "nxd_ftp_client.h"
#include    "nxd_ftp_server.h"

extern void     test_control_return(UINT);

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_RESET_DISCONNECT)

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

/* Define NetX Duo IP address for the NetX Duo FTP Server and Client. */
static NXD_ADDRESS             server_ip_address;
static NXD_ADDRESS             client_ip_address;

/* Define the counters used in the demo application...  */
static ULONG                   error_counter = 0;
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

static void    client_thread_entry(ULONG thread_input);
static void    thread_server_entry(ULONG thread_input);


/* Define server login/logout functions.  These are stubs for functions that would 
validate a client login request.   */
static UINT server_login6(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, NXD_ADDRESS *client_ipduo_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info);
static UINT server_logout6(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, NXD_ADDRESS *client_ipduo_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info);
extern UINT    (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_ipv6_epsv_test_application_define(void *first_unused_memory)
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

    /* Enable TCP.  */
    status = nx_tcp_enable(&server_ip);
    if (status)
        error_counter++;

    /* Create the FTP server.  */
    status =  nxd_ftp_server_create(&ftp_server, "FTP Server Instance", &server_ip, &ram_disk, pointer, DEMO_STACK_SIZE, &server_pool,
                                    server_login6, server_logout6);
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

    /* Enable TCP for client IP instance.  */
    status = nx_tcp_enable(&client_ip);
    if (status)
        error_counter++;

    /* Next set the NetX Duo FTP Server and Client addresses. */
    server_ip_address.nxd_ip_address.v6[3] = 0x105;
    server_ip_address.nxd_ip_address.v6[2] = 0x0;
    server_ip_address.nxd_ip_address.v6[1] = 0x0000f101;
    server_ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V6;

    client_ip_address.nxd_ip_address.v6[3] = 0x101;
    client_ip_address.nxd_ip_address.v6[2] = 0x0;
    client_ip_address.nxd_ip_address.v6[1] = 0x0000f101;
    client_ip_address.nxd_ip_address.v6[0] = 0x20010db8;
    client_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
}

/* Define the FTP client thread.  */

void    client_thread_entry(ULONG thread_input)
{

NX_PACKET   *my_packet, *recv_packet_ptr;
UINT        status;
UINT        iface_index, address_index;

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

    /* Here's where we make the FTP Client IPv6 enabled. */
    status = nxd_ipv6_enable(&client_ip);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nxd_icmp_enable(&client_ip); 

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }
    
    /* Set the Client link local and global addresses. */
    iface_index = 0;
    
    /* This assumes we are using the primary network interface (index 0). */
    status = nxd_ipv6_address_set(&client_ip, iface_index, NX_NULL, 10, &address_index);

    /* Check for link local address set error.  */
    if (status != NX_SUCCESS) 
    {
        error_counter++;
     }
    
     /* Set the host global IP address. We are assuming a 64 
       bit prefix here but this can be any value (< 128). */
    status = nxd_ipv6_address_set(&client_ip, iface_index, &client_ip_address, 64, &address_index);

    /* Check for global address set error.  */
    if (status != NX_SUCCESS) 
    {
        error_counter++;
     }

    /* Let NetX Duo validate the addresses. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Create an FTP client.  */
    status =  nx_ftp_client_create(&ftp_client, "FTP Client", &client_ip, 2000, &client_pool);
    if (status) 
        error_counter++;

    /* Now connect with the NetX FTP (IPv4) server. */
    status =  nxd_ftp_client_connect(&ftp_client, &server_ip_address, "name", "password", NX_IP_PERIODIC_RATE);
    if (status) 
        error_counter++;
    
    /* Enable passive mode. */
    status = nx_ftp_client_passive_mode_set(&ftp_client, NX_TRUE);
    if (status != NX_SUCCESS) 
    {
        error_counter++;
    }

    /* This sends EPSV commands and opens data socket.  */
    _nx_ftp_client_passive_transfer_setup(&ftp_client, NX_IP_PERIODIC_RATE);
    nx_tcp_socket_disconnect(&(ftp_client.nx_ftp_client_data_socket), NX_NO_WAIT);
    nx_tcp_client_socket_unbind(&(ftp_client.nx_ftp_client_data_socket));

    /* Request a file downloaded. This sends EPSV and STOR commands and opens another data socket.  */
    status =  nx_ftp_client_file_open(&ftp_client, "test.txt", NX_FTP_OPEN_FOR_WRITE, 100);
    if (status != NX_SUCCESS) 
    {
        error_counter++;
    }

    /* Allocate an FTP packet.  */
    status =  nx_packet_allocate(&client_pool, &my_packet, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {
        error_counter++;
    }

    /* Write ABCs into the packet payload  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    status =  nx_ftp_client_file_write(&ftp_client, my_packet, 500);
    if (status != NX_SUCCESS) 
    {
        nx_packet_release(my_packet);
    }
    
    /* This does not send a command. The data port is closed and the client state set to CONNECTED.  
       The server initiates closing the data socket connection. */
    status =  nx_ftp_client_file_close(&ftp_client, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Request a file downloaded. This sends EPSV and RETR commands and opens another data socket.  */
    status =  nx_ftp_client_file_open(&ftp_client, "test.txt", NX_FTP_OPEN_FOR_READ, 100);
    if (status != NX_SUCCESS) 
    {
        error_counter++;
    }

    do 
    {
        status =  nx_ftp_client_file_read(&ftp_client, &recv_packet_ptr, 500);
        if (status == NX_SUCCESS) 
        {
            nx_packet_release(recv_packet_ptr);
        }
    } while (status == NX_SUCCESS);
    
    /* Check for complete download. */
    if (status != NX_FTP_END_OF_FILE) 
    {
        error_counter++;
    }
    
    /* This does not send a command. The data port is closed and the client state set to CONNECTED.  
       The server initiates closing the data socket connection. */
    status =  nx_ftp_client_file_close(&ftp_client, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    status = nx_ftp_client_disconnect(&ftp_client, NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Delete the FTP client.  */
    status =  nx_ftp_client_delete(&ftp_client);
    if (status)
        error_counter++;

    /* Resume server thread.  */
    tx_thread_resume(&server_thread);
}

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
    if (((UINT)packet_ptr -> nx_packet_prepend_ptr & 0x3) != 0)
    {
        error_counter++;
    }

    return(NX_TRUE);
}


/* Define the helper FTP server thread.  */
void    thread_server_entry(ULONG thread_input)
{

UINT    status;
UINT    iface_index, address_index;

    /* Print out test information banner.  */
    printf("NetX Test:   FTP IPv6 EPSV Test........................................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    packet_process_callback = my_packet_process;

    /* Here's where we make the FTP server IPv6 enabled. */
    status = nxd_ipv6_enable(&server_ip);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {
        error_counter++;
     }

    status = nxd_icmp_enable(&server_ip); 

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {
        error_counter++;
     }

     /* Set the link local address with the host MAC address. */
    iface_index = 0;
    
    /* This assumes we are using the primary network interface (index 0). */
    status = nxd_ipv6_address_set(&server_ip, iface_index, NX_NULL, 10, &address_index);

    /* Check for link local address set error.  */
    if (status) 
    {
        error_counter++;
     }

    /* Set the host global IP address. We are assuming a 64 
       bit prefix here but this can be any value (< 128). */
    status = nxd_ipv6_address_set(&server_ip, iface_index, &server_ip_address, 64, &address_index);

    /* Check for global address set error.  */
    if (status) 
    {
        error_counter++;
     }
    
    /* Wait while NetX Duo validates the link local and global address. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* OK to start the FTPv6 Server.   */
    status = nx_ftp_server_start(&ftp_server);
    if (status)
        error_counter++;

    /* Wait for test.  */
    tx_thread_suspend(&server_thread);

    /* Only 4 control sockets should exist, all the data sockets need to be deleted.  */
    if (server_ip.nx_ip_tcp_created_sockets_count > 4)
        error_counter++;

    status = nx_ftp_server_delete(&ftp_server);
    if(status)
        error_counter++;

    if(error_counter != 0)
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


static UINT server_login6(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, NXD_ADDRESS *client_ipduo_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info)
{
    /* Always return success.  */
    return(NX_SUCCESS);
}

static UINT server_logout6(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, NXD_ADDRESS *client_ipduo_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info)
{
    /* Always return success.  */
    return(NX_SUCCESS);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_ipv6_epsv_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   FTP IPv6 EPSV Test........................................N/A\n"); 

    test_control_return(3);  
}      
#endif