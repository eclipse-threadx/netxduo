
#include    "tx_api.h"
#include    "nx_api.h"
#include    "nxd_tftp_client.h"
#include    "nxd_tftp_server.h"
#include    "fx_api.h"

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

/* Define the NetX DUO TFTP object control blocks.  */

static NX_TFTP_CLIENT          client;
static NX_TFTP_SERVER          server;

/* Define the application global variables */

#define                        CLIENT_ADDRESS  IP_ADDRESS(1, 2, 3, 5)
#define                        SERVER_ADDRESS  IP_ADDRESS(1, 2, 3, 4)
#ifdef __PRODUCT_NETXDUO__
#define IP_TYPE 4
static NXD_ADDRESS             server_ip_address;
#else
static ULONG                   server_ip_address;
#endif
static UINT                    error_counter = 0;

/* Define buffer used in the demo application.  */
static UCHAR                   buffer[255];
static ULONG                   data_length;


/* Define the memory area for the FileX RAM disk.  */
static UCHAR                   ram_disk_memory[32000];
static UCHAR                   ram_disk_sector_cache[512];


/* Define function prototypes.  */

extern void     _fx_ram_driver(FX_MEDIA *media_ptr);
extern void     _nx_ram_network_driver_512(NX_IP_DRIVER *driver_req_ptr);

static void     client_thread_entry(ULONG thread_input);
static void     server_thread_entry(ULONG thread_input);


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tftp_malformed_packet_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
UCHAR   *pointer;


    /* Setup the working pointer.  */
    pointer =  (UCHAR *) first_unused_memory;

    /* Create the main TFTPv6 server thread.  */
    status = tx_thread_create(&server_thread, "TFTP Server Thread", server_thread_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              4,4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer += DEMO_STACK_SIZE ;

    /* Check for errors.  */
    if (status)
        error_counter++;


    /* Create the main TFTPv6 client thread at a slightly lower priority.  */
    status = tx_thread_create(&client_thread, "TFTP Client Thread", client_thread_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              5, 5, TX_NO_TIME_SLICE, TX_DONT_START);

    pointer += DEMO_STACK_SIZE ;

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Note: The data portion of a packet is exactly 512 bytes, but the packet payload size must 
       be at least 580 bytes. The remaining bytes are used for the UDP, IP, and Ethernet 
       headers and byte alignment requirements. */

    status =  nx_packet_pool_create(&server_pool, "TFTP Server Packet Pool", NX_TFTP_PACKET_SIZE, pointer, 8192);
    pointer = pointer + 8192;
    
    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Create the IP instance for the TFTP Server.  */
    status = nx_ip_create(&server_ip, "NetX Server IP Instance", SERVER_ADDRESS, 0xFFFFFF00UL, 
                                        &server_pool, _nx_ram_network_driver_512, pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable UDP.  */
    status =  nx_udp_enable(&server_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;


    /* Create the TFTP server.  */
#ifdef __PRODUCT_NETXDUO__ 
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_ip_address.nxd_ip_address.v4 = SERVER_ADDRESS;
#else
    server_ip_address = SERVER_ADDRESS;
#endif

#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_server_create(&server, "TFTP Server Instance", &server_ip, &ram_disk, 
                                      pointer, DEMO_STACK_SIZE, &server_pool);
#else
    status =  nx_tftp_server_create(&server, "TFTP Server Instance", &server_ip, &ram_disk, 
                                      pointer, DEMO_STACK_SIZE, &server_pool);
#endif

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Check for errors for the server.  */
    if (status)
        error_counter++;

    /* Create a packet pool for the TFTP client.  */

    /* Note: The data portion of a packet is exactly 512 bytes, but the packet payload size must 
       be at least 580 bytes. The remaining bytes are used for the UDP, IP, and Ethernet 
       headers and byte alignment requirements. */

    status =  nx_packet_pool_create(&client_pool, "TFTP Client Packet Pool", NX_TFTP_PACKET_SIZE, pointer, 8192);
    pointer =  pointer + 8192;

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the TFTP client.  */
    status = nx_ip_create(&client_ip, "TFTP Client IP Instance", CLIENT_ADDRESS, 0xFFFFFF00UL, 
                                                &client_pool, _nx_ram_network_driver_512, pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status =  nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable UDP for client IP instance.  */
    status +=  nx_udp_enable(&client_ip);
    status += nx_icmp_enable(&client_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    tx_thread_resume(&client_thread);
}

void server_thread_entry(ULONG thread_input)
{

UINT        status;
FX_FILE     my_file;
    
    /* Print out test information banner.  */
    printf("NetX Test:   TFTP Malformed Packet Test................................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Format the RAM disk - the memory for the RAM disk was defined above.  */
    status = fx_media_format(&ram_disk, 
                            _fx_ram_driver,                  /* Driver entry             */
                            ram_disk_memory,                 /* RAM disk memory pointer  */
                            ram_disk_sector_cache,           /* Media buffer pointer     */
                            sizeof(ram_disk_sector_cache),   /* Media buffer size        */
                            "MY_RAM_DISK",                   /* Volume Name              */
                            1,                               /* Number of FATs           */
                            32,                              /* Directory Entries        */
                            0,                               /* Hidden sectors           */
                            256,                            /* Total sectors            */
                            128,                             /* Sector size              */
                            1,                               /* Sectors per cluster      */
                            1,                               /* Heads                    */
                            1);                              /* Sectors per track        */

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Open the RAM disk.  */
    status = fx_media_open(&ram_disk, "RAM DISK", _fx_ram_driver, ram_disk_memory, ram_disk_sector_cache, sizeof(ram_disk_sector_cache));
    status += fx_file_create(&ram_disk, "test.txt");
    status += fx_file_open(&ram_disk, &my_file, "test.txt", FX_OPEN_FOR_WRITE);
    status += fx_file_write(&my_file, "TFTP server", 11);
    status += fx_file_close(&my_file);
    if (status)
        error_counter++;

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Start the NetX Duo TFTP server.  */
#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_server_start(&server);
#else
    status =  nx_tftp_server_start(&server);
#endif

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Run for a while */
    tx_thread_suspend(&server_thread);

#ifdef __PRODUCT_NETXDUO__
    nxd_tftp_server_delete(&server);
#else
    nx_tftp_server_delete(&server);
#endif

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

/* Define the TFTP client thread.  */
UCHAR write_data[] = {0x00, 0x02, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x4f, 0x43, 0x54, 0x45, 0x54, 0x00};
UCHAR read_data[] = {0x00, 0x01, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x4f, 0x43, 0x54, 0x45, 0x54, 0x00};
UCHAR test_write_data[] = {0x00, 0x02, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x00};
UCHAR test_read_data[] = {0x00, 0x01, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x00};
UCHAR test_write_data_1[] = {0x00, 0x02, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x4f, 0x43, 0x00, 0x45, 0x54, 0x00};
UCHAR test_read_data_1[] = {0x00, 0x01, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x4f, 0x43, 0x00, 0x45, 0x54, 0x00};
UCHAR *test_data[] = {
    test_write_data,
    test_write_data_1,
    test_read_data,
    test_read_data_1,
};
UINT test_data_size[] = {
    sizeof(test_write_data),
    sizeof(test_write_data_1),
    sizeof(test_read_data),
    sizeof(test_read_data_1),
};

void    client_thread_entry(ULONG thread_input)
{

NX_PACKET   *my_packet;
UINT        status;
UCHAR       *buffer_ptr;
UINT        i;
UINT        all_done = NX_FALSE;


    /* The TFTP services used below include the NetX equivalent service which will work with 
       NetX Duo TFTP.  However, it is recommended for developers to port their applications
       to the newer services that take the NXD_ADDRESS type and support both IPv4 and IPv6 
       communication.
    */

    /* Create a TFTP client.  */
#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_client_create(&client, "TFTP Client", &client_ip, &client_pool, IP_TYPE);
#else
    status =  nx_tftp_client_create(&client, "TFTP Client", &client_ip, &client_pool);
#endif

    /* Check status.  */
    if (status)
        error_counter++;

    for (i = 0; i < sizeof(test_data) / sizeof(UCHAR *); i++)
    {

#ifdef __PRODUCT_NETXDUO__
        status =  nxd_tftp_client_packet_allocate(&client_pool, &my_packet, NX_IP_PERIODIC_RATE, IP_TYPE);
#else
        status =  nx_tftp_client_packet_allocate(&client_pool, &my_packet, NX_IP_PERIODIC_RATE);
#endif

        /* Check status.  */
        if (status)
        {
            error_counter++;
            continue;
        }

        /* Write ABCs into the packet payload!  */
        memcpy(my_packet -> nx_packet_prepend_ptr, test_data[i], sizeof(test_write_data));

        /* Adjust the write pointer.  */
        my_packet -> nx_packet_length =  test_data_size[i];
        my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + test_data_size[i];

#ifdef __PRODUCT_NETXDUO__
        status =  nxd_udp_socket_send(&client.nx_tftp_client_socket, my_packet, &server_ip_address, NX_TFTP_SERVER_PORT);
#else
        status =  nx_udp_socket_send(&client.nx_tftp_client_socket, my_packet, SERVER_ADDRESS, NX_TFTP_SERVER_PORT);
#endif
        /* Check status.  */
        if (status)
        {
            error_counter++;
            nx_packet_release(my_packet);
            continue;
        }

        status =  nx_udp_socket_receive(&client.nx_tftp_client_socket, &my_packet, NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status == NX_SUCCESS)
        {

            /* Setup a pointer to the packet payload.  */
            buffer_ptr =  my_packet -> nx_packet_prepend_ptr;

            if ((buffer_ptr[0] != 0) || (buffer_ptr[1] != NX_TFTP_CODE_ERROR))
            {
                error_counter++;
            }

            nx_packet_release(my_packet);
        }
    }

    /* Open the same file for reading.  */
#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_client_file_open(&client, "test.txt", &server_ip_address, NX_TFTP_OPEN_FOR_READ, NX_IP_PERIODIC_RATE, IP_TYPE);
#else
    status =  nx_tftp_client_file_open(&client, "test.txt", SERVER_ADDRESS, NX_TFTP_OPEN_FOR_READ, NX_IP_PERIODIC_RATE);
#endif

    /* Check status.  */
    if (status)
        error_counter++;
    do
    {

    /* Read the file back.  */
#ifdef __PRODUCT_NETXDUO__
        status =  nxd_tftp_client_file_read(&client, &my_packet, NX_IP_PERIODIC_RATE, IP_TYPE);
#else
        status =  nx_tftp_client_file_read(&client, &my_packet, NX_IP_PERIODIC_RATE);
#endif
        /* Check for retranmission/dropped packet error. Benign. Try again... */
        if (status == NX_TFTP_INVALID_BLOCK_NUMBER)
        {
            continue;
        }
        else if (status == NX_TFTP_END_OF_FILE)
        {
            /* All done. */
            all_done = NX_TRUE;
        }
        else if (status)
        {
            error_counter++;

            /* Internal error, invalid packet or error on read. */
            break;
        }


        /* Do something with the packet data and release when done. */
        nx_packet_data_retrieve(my_packet, buffer, &data_length);
        buffer[data_length] = 0;
        nx_packet_release(my_packet);

    } while (all_done == NX_FALSE);

    /* Close the file again.  */
#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_client_file_close(&client, IP_TYPE);
#else
    status =  nx_tftp_client_file_close(&client);
#endif

    /* Check status.  */
    if (status)
        error_counter++;

    /* Delete the client.  */
#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_client_delete(&client);
#else
    status =  nx_tftp_client_delete(&client);
#endif

    /* Check status.  */
    if (status)
        error_counter++;

    tx_thread_resume(&server_thread);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tftp_malformed_packet_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TFTP Malformed Packet Test................................N/A\n"); 

    test_control_return(3);  
}      
#endif