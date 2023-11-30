
#include    "tx_api.h"
#include    "nx_api.h"
#include    "nxd_tftp_client.h"
#include    "nxd_tftp_server.h"
#include    "fx_api.h"
#ifdef FEATURE_NX_IPV6   
#include   "nx_ipv6.h"

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
                                                 
#define IP_TYPE                6
#define CLIENT_ADDRESS         IP_ADDRESS(1, 2, 3, 5)
#define SERVER_ADDRESS         IP_ADDRESS(1, 2, 3, 4)
static NXD_ADDRESS             client_ip_address;    
static NXD_ADDRESS             server_ip_address;
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
extern void     test_control_return(UINT);

static void     client_thread_entry(ULONG thread_input);
static void     server_thread_entry(ULONG thread_input);


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tftp_ipv6_basic_test_application_define(void *first_unused_memory)
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
                                   
    /* Set the server ipv6 address.  */
    server_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    server_ip_address.nxd_ip_address.v6[0] = 0x20010000;
    server_ip_address.nxd_ip_address.v6[1] = 0x00000000;
    server_ip_address.nxd_ip_address.v6[2] = 0x00000000;
    server_ip_address.nxd_ip_address.v6[3] = 0x10000001;

    /* Set interfaces' address */
    status = nxd_ipv6_address_set(&server_ip, 0, &server_ip_address,64, NX_NULL);

    /* Check for errors.  */
    if (status)
        error_counter++;
                          
    /* Enable UDP for Server IP instance.  */
    status =  nx_udp_enable(&server_ip);
    status += nxd_ipv6_enable(&server_ip);
    status += nxd_icmp_enable(&server_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;


    /* Create the TFTP server.  */
    status =  nxd_tftp_server_create(&server, "TFTP Server Instance", &server_ip, &ram_disk, 
                                     pointer, DEMO_STACK_SIZE, &server_pool);

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
                             
    /* Set ipv6 version and address.  */
    client_ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    client_ip_address.nxd_ip_address.v6[0] = 0x20010000;
    client_ip_address.nxd_ip_address.v6[1] = 0x00000000;
    client_ip_address.nxd_ip_address.v6[2] = 0x00000000;
    client_ip_address.nxd_ip_address.v6[3] = 0x10000010;

    /* Set interfaces' address */
    status = nxd_ipv6_address_set(&client_ip, 0, &client_ip_address,64, NX_NULL);

    /* Enable UDP for client IP instance.  */
    status =  nx_udp_enable(&client_ip); 
    status += nxd_ipv6_enable(&client_ip);
    status += nxd_icmp_enable(&client_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    tx_thread_resume(&client_thread);
}

void server_thread_entry(ULONG thread_input)
{

UINT        status;
    
    /* Print out test information banner.  */
    printf("NetX Test:   TFTP IPv6 Basic Test......................................");

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

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Start the NetX Duo TFTP server.  */
    status =  nxd_tftp_server_start(&server);

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Run for a while */
    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);

    nxd_tftp_server_delete(&server);

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

void    client_thread_entry(ULONG thread_input)
{

NX_PACKET   *my_packet;
UINT        status;
UINT        all_done = NX_FALSE;


    /* The TFTP services used below include the NetX equivalent service which will work with 
       NetX Duo TFTP.  However, it is recommended for developers to port their applications
       to the newer services that take the NXD_ADDRESS type and support both IPv4 and IPv6 
       communication.
    */

    /* Create a TFTP client.  */
    status =  nxd_tftp_client_create(&client, "TFTP Client", &client_ip, &client_pool, IP_TYPE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Open a TFTP file for writing.  */
    status =  nxd_tftp_client_file_open(&client, "test.txt", &server_ip_address, NX_TFTP_OPEN_FOR_WRITE, NX_IP_PERIODIC_RATE, IP_TYPE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Allocate a TFTP packet.  */
    status =  nxd_tftp_client_packet_allocate(&client_pool, &my_packet, NX_IP_PERIODIC_RATE, IP_TYPE);
    /* Check status.  */
    if (status)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Write this packet to the file via TFTP.  */
    status =  nxd_tftp_client_file_write(&client, my_packet, NX_IP_PERIODIC_RATE, IP_TYPE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Close this file.  */
    status =  nxd_tftp_client_file_close(&client, IP_TYPE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Open the same file for reading.  */
    status =  nxd_tftp_client_file_open(&client, "test.txt", &server_ip_address, NX_TFTP_OPEN_FOR_READ, NX_IP_PERIODIC_RATE, IP_TYPE);

    /* Check status.  */
    if (status)
        error_counter++;
    do
    {

        /* Read the file back.  */
        status =  nxd_tftp_client_file_read(&client, &my_packet, NX_IP_PERIODIC_RATE, IP_TYPE);

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
    status =  nxd_tftp_client_file_close(&client, IP_TYPE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Delete the client.  */
    status =  nxd_tftp_client_delete(&client);

    /* Check status.  */
    if (status)
        error_counter++;
}     
#endif
