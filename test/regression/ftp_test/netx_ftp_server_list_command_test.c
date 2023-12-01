
#include    "tx_api.h"
#include    "fx_api.h" 
#include    "nx_api.h"
#include    "nx_tcp.h"
#include    "nxd_ftp_client.h"
#include    "nxd_ftp_server.h"

extern void     test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         4096
#define     DEMO_DATA               "ABCDEFGHIJKLMNOPQRSTUVWXYZ "

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
static UINT    server_login(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, ULONG client_ip_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info);
static UINT    server_logout(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, ULONG client_ip_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info);
static UINT  ftp_client_directory_listing_get(NX_FTP_CLIENT *ftp_client_ptr, CHAR *directory_path, 
                                              NX_PACKET **packet_ptr, ULONG wait_option);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_server_list_command_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
UCHAR   *pointer;


    /* Set the data as 04/02/2021.  */
    fx_system_date_set(2021, 4, 2);
    
    /* Set the time as 08:05:30.  */
    fx_system_time_set(8, 5, 30);

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

NX_PACKET   *my_packet;
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

    /* Open a FTP file for writing.  */
    status =  nx_ftp_client_file_open(&ftp_client, "test.txt", NX_FTP_OPEN_FOR_WRITE, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {
        error_counter++;
     }

    /* Allocate a FTP packet.  */
    status =  nx_packet_allocate(&client_pool, &my_packet, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {
        error_counter++;
     }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, DEMO_DATA, sizeof(DEMO_DATA)); /* Use case of memcpy is verified. */

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  sizeof(DEMO_DATA);
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + sizeof(DEMO_DATA);

    /* Write the packet to the file test.txt.  */
    status =  nx_ftp_client_file_write(&ftp_client, my_packet, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        nx_packet_release(my_packet);
    }

    /* Close the file.  */
    status =  nx_ftp_client_file_close(&ftp_client, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }    

    /* Get directory listing (NLST). */
    status = ftp_client_directory_listing_get(&ftp_client, "", &my_packet, NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS) 
    {
        error_counter++;
    }
    else
    {

        /* Check the data.  */
        if (memcmp(my_packet -> nx_packet_prepend_ptr, "-rw-rw-rw-  1 owner group         28 APR 02 08:05 test.txt\r\n", my_packet -> nx_packet_length))
        {
            error_counter++;
        }
        nx_packet_release(my_packet);
    }

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
    printf("NetX Test:   FTP Server LIST Command Test..............................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* OK to start the ftp Server.   */
    status = nx_ftp_server_start(&ftp_server);
    if (status)
        error_counter++;

    /* Wait for test.  */
    while(test_done == NX_FALSE)
        tx_thread_sleep(1);
    
    status = nx_ftp_server_stop(&ftp_server);
    status += nx_ftp_server_delete(&ftp_server);
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

static UINT  ftp_client_directory_listing_get(NX_FTP_CLIENT *ftp_client_ptr, CHAR *directory_path, 
                                              NX_PACKET **packet_ptr, ULONG wait_option)
{

UINT        i;
UCHAR       *buffer_ptr;
NX_PACKET   *new_packet_ptr;
UINT        status;


    /* Set packet pointer to NULL.  */
    *packet_ptr =  NX_NULL;

    /* Ensure the client is the proper state for directory listing request.  */
    if (ftp_client_ptr -> nx_ftp_client_state != NX_FTP_STATE_CONNECTED)
        return(NX_FTP_NOT_CONNECTED);

    /* Transfer the data in active transfer mode. */
    status = _nx_ftp_client_active_transfer_setup(ftp_client_ptr, wait_option);

    /* Determine if set up successful.  */
    if (status)
    {
        return(status);
    }

    /* Allocate a packet for sending the NLST command.  */
    status = _nx_ftp_client_packet_allocate(ftp_client_ptr, &new_packet_ptr, wait_option);

    /* Determine if the packet allocation was successful.  */
    if (status != NX_SUCCESS)
    {

        /* Cleanup data socket.  */
        _nx_ftp_client_data_socket_cleanup(ftp_client_ptr, wait_option);

        /* Return error.  */
        return(status);
    }

    /* Check if out of boundary.  */
    if ((UINT)(new_packet_ptr -> nx_packet_data_end - new_packet_ptr -> nx_packet_prepend_ptr) < 7)
     {

        /* Cleanup data socket.  */
        _nx_ftp_client_data_socket_cleanup(ftp_client_ptr, wait_option);

        /* Release the packet.  */
        nx_packet_release(new_packet_ptr);

        /* Set the error status.  */
        return(NX_FTP_FAILED);
    }

    /* We have a packet, setup pointer to the buffer area.  */
    buffer_ptr =  new_packet_ptr -> nx_packet_prepend_ptr;

    /* Now build the actual LIST request.  */
    buffer_ptr[0] =  'L';
    buffer_ptr[1] =  'I';
    buffer_ptr[2] =  'S';
    buffer_ptr[3] =  'T';
    buffer_ptr[4] =  ' ';

    /* Copy the directory path into the buffer.  */    
    for(i = 0; directory_path[i]; i++)
    {

        /* Check if out of boundary.  */
        if ((i + 7) >= (UINT)(new_packet_ptr -> nx_packet_data_end - new_packet_ptr -> nx_packet_prepend_ptr))
        {

            /* Cleanup data socket.  */
            _nx_ftp_client_data_socket_cleanup(ftp_client_ptr, wait_option);

            /* Release the packet.  */
            nx_packet_release(new_packet_ptr);

            /* Set the error status.  */
            return(NX_FTP_FAILED);
        }

        /* Copy character of directory path.  */
        buffer_ptr[5+i] =  (UCHAR)directory_path[i];
    }

    /* Insert the CR/LF.  */
    buffer_ptr[5+i] =   13;
    buffer_ptr[5+i+1] = 10;

    /* Setup the length of the packet.  */
    new_packet_ptr -> nx_packet_length =  i + 7;

    /* Setup the packet append pointer.  */
    new_packet_ptr -> nx_packet_append_ptr =  new_packet_ptr -> nx_packet_prepend_ptr + new_packet_ptr -> nx_packet_length;

    /* Send the NLST message.  */
    status =  nx_tcp_socket_send(&(ftp_client_ptr -> nx_ftp_client_control_socket),  new_packet_ptr, wait_option);

    /* Determine if the send was unsuccessful.  */
    if (status)
    {

        /* Cleanup data socket.  */
        _nx_ftp_client_data_socket_cleanup(ftp_client_ptr, wait_option);

        /* Release the packet.  */
        nx_packet_release(new_packet_ptr);

        /* Return error.  */
        return(status);
    }

    /* Check if enable passive mode.  */
    if (ftp_client_ptr -> nx_ftp_client_passive_transfer_enabled == NX_FALSE)
    {

        /* Now wait for the data connection to connect.  */
        status =  nx_tcp_server_socket_accept(&(ftp_client_ptr -> nx_ftp_client_data_socket), wait_option);

        /* Determine if the accept was unsuccessful.  */
        if (status)
        {

            /* Cleanup data socket.  */
            _nx_ftp_client_data_socket_cleanup(ftp_client_ptr, wait_option);

            /* Return error.  */
            return(status);
        }
    }

    /* Now wait for response from the FTP server control port.  */
    status =  nx_tcp_socket_receive(&(ftp_client_ptr -> nx_ftp_client_control_socket), &new_packet_ptr, wait_option);    

    /* Determine if a packet was not received.  */
    if (status)
    {

        /* Cleanup data socket.  */
        _nx_ftp_client_data_socket_cleanup(ftp_client_ptr, wait_option);

        /* Error in NLST request to FTP server. */
        return(status);
    }

    /* We have a packet, setup pointer to the buffer area.  */
    buffer_ptr =  new_packet_ptr -> nx_packet_prepend_ptr;

    /* Check for 1xx message, signaling the data port was connected properly and ready for 
       transfer.  */
    if ((new_packet_ptr -> nx_packet_length < 3) || (buffer_ptr[0] != '1'))
    {

        /* Cleanup data socket.  */
        _nx_ftp_client_data_socket_cleanup(ftp_client_ptr, wait_option);

        /* Release the packet.  */
        nx_packet_release(new_packet_ptr);

        /* Error in NLST request to FTP server. */
        return(NX_FTP_EXPECTED_1XX_CODE);
    }

    /* Release the last packet.  */
    nx_packet_release(new_packet_ptr);

    /* Now read a listing packet from the data socket.  */
    status =  nx_tcp_socket_receive(&(ftp_client_ptr -> nx_ftp_client_data_socket), packet_ptr, wait_option);

    /* Determine if an error occurred.  */
    if (status)
    {

        /* Map all unsuccessful status to error.  */
        return(status); 
    }

    /* Cleanup data socket.  */
    _nx_ftp_client_data_socket_cleanup(ftp_client_ptr, wait_option);

    /* Return staus to caller.  */
    return(status);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_server_list_command_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   FTP Server LIST Command Test..............................N/A\n"); 

    test_control_return(3);  
}      
#endif