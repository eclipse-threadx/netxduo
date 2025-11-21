
#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_udp.h"
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
static UCHAR                   buffer[50000000];
static UINT                    buffer_size = 50000000;
static UINT                    real_data_length = 50000000;
static UINT                    send_data_length;
static UINT                    receive_data_length;


/* Define the memory area for the FileX RAM disk.  */
static UCHAR                   ram_disk_memory[60000000];
static UCHAR                   ram_disk_sector_cache[512];

/* Define the TID variables.  */
static UINT                    client_port;
static UINT                    service_packet_number = 0; 
static UINT                    client_packet_number = 0;


/* Define function prototypes.  */

extern void     _fx_ram_driver(FX_MEDIA *media_ptr);       
extern void     _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);

static void     client_thread_entry(ULONG thread_input);
static void     server_thread_entry(ULONG thread_input);  


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tftp_large_data_test_application_define(void *first_unused_memory)
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

    status =  nx_packet_pool_create(&server_pool, "TFTP Server Packet Pool", NX_TFTP_PACKET_SIZE, pointer, 20480);
    pointer = pointer + 20480;
    
    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Create the IP instance for the TFTP Server.  */
    status = nx_ip_create(&server_ip, "NetX Server IP Instance", SERVER_ADDRESS, 0xFFFFFF00UL, 
                          &server_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);
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

    status =  nx_packet_pool_create(&client_pool, "TFTP Client Packet Pool", NX_TFTP_PACKET_SIZE, pointer, 20480);
    pointer =  pointer + 20480;

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the TFTP client.  */
    status = nx_ip_create(&client_ip, "TFTP Client IP Instance", CLIENT_ADDRESS, 0xFFFFFF00UL, 
                          &client_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);
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
                            10000 * 10,                      /* Total sectors            */
                            512,                             /* Sector size              */
                            10,                              /* Sectors per cluster      */
                            1,                               /* Heads                    */
                            1);                              /* Sectors per track        */

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Open the RAM disk.  */
    status = fx_media_open(&ram_disk, "RAM DISK", _fx_ram_driver, ram_disk_memory, ram_disk_sector_cache, sizeof(ram_disk_sector_cache));

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
}

/* Define the TFTP client thread.  */

void    client_thread_entry(ULONG thread_input)
{

NX_PACKET   *my_packet;
UINT        status;
UINT        packet_length;
UINT        all_done = NX_FALSE; 
ULONG       i;
ULONG       data_value;


    /* Print out test information banner.  */
    printf("NetX Test:   TFTP Large Data Test......................................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Generate a random number for write data.  */
    data_value = NX_RAND();

    /* Genearte the write data.  */
    for (i = 0; i < buffer_size / sizeof(ULONG); i ++)
    {
        ((ULONG*)buffer)[i] = data_value++;
    }

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
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Open a TFTP file for writing.  */
#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_client_file_open(&client, "test.txt", &server_ip_address, NX_TFTP_OPEN_FOR_WRITE, NX_IP_PERIODIC_RATE, IP_TYPE);
#else
    status =  nx_tftp_client_file_open(&client, "test.txt", SERVER_ADDRESS, NX_TFTP_OPEN_FOR_WRITE, NX_IP_PERIODIC_RATE);
#endif

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Loop to send the data.  */
    send_data_length = 0;
    while(send_data_length < real_data_length)
    {

        /* Allocate a TFTP packet.  */
#ifdef __PRODUCT_NETXDUO__
        status =  nxd_tftp_client_packet_allocate(&client_pool, &my_packet, NX_IP_PERIODIC_RATE, IP_TYPE);
#else
        status =  nx_tftp_client_packet_allocate(&client_pool, &my_packet, NX_IP_PERIODIC_RATE);
#endif
        /* Check status.  */
        if (status)
        {
            error_counter++;
            break;
        }

        /* Write ABCs into the packet payload!  */
        if (send_data_length + 512 < real_data_length)
            packet_length = 512;
        else
            packet_length = real_data_length - send_data_length;
                                      
        /* Write ABCs into the packet payload!  */
        status = nx_packet_data_append(my_packet, buffer + send_data_length, packet_length, &client_pool, NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status)
        {
            error_counter++;
            break;
        }

        /* Write this packet to the file via TFTP.  */
#ifdef __PRODUCT_NETXDUO__
        status =  nxd_tftp_client_file_write(&client, my_packet, NX_IP_PERIODIC_RATE, IP_TYPE);
#else
        status =  nx_tftp_client_file_write(&client, my_packet, NX_IP_PERIODIC_RATE);
#endif

        /* Check status.  */
        if (status)
        {
            error_counter++;
            break;
        }

        send_data_length += packet_length;
    }

    /* Check the send length.  */
    if ((error_counter) ||(send_data_length != real_data_length))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Close this file.  */
#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_client_file_close(&client, IP_TYPE);
#else
    status =  nx_tftp_client_file_close(&client);
#endif

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                 
    /* Open the same file for reading.  */
#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_client_file_open(&client, "test.txt", &server_ip_address, NX_TFTP_OPEN_FOR_READ, NX_IP_PERIODIC_RATE, IP_TYPE);
#else
    status =  nx_tftp_client_file_open(&client, "test.txt", SERVER_ADDRESS, NX_TFTP_OPEN_FOR_READ, NX_IP_PERIODIC_RATE);
#endif

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    receive_data_length = 0;
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
        nx_packet_data_retrieve(my_packet, buffer, (ULONG *)&packet_length);
        receive_data_length += packet_length;
        nx_packet_release(my_packet);
    } while (all_done == NX_FALSE);
                    
    /* Check the send length.  */
    if ((error_counter) ||(receive_data_length != real_data_length))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Close the file again.  */
#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_client_file_close(&client, IP_TYPE);
#else
    status =  nx_tftp_client_file_close(&client);
#endif

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the client.  */
#ifdef __PRODUCT_NETXDUO__
    status =  nxd_tftp_client_delete(&client);
#else
    status =  nx_tftp_client_delete(&client);
#endif

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
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
void    netx_tftp_large_data_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TFTP Large Data Test......................................N/A\n"); 

    test_control_return(3);  
}      
#endif