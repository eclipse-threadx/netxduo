/* This case tests the FTP server on handling two session listen situation. */
#include  "tx_api.h"
#include  "fx_api.h" 
#include  "nx_api.h"
#include <stdio.h>
#include <stdlib.h>
extern void    test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && !defined(NX_DISABLE_RESET_DISCONNECT)



#include    "nxd_ftp_server.h"

#define     DEMO_STACK_SIZE         4096
#define     LOOP                    100


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               server_thread;
static NX_PACKET_POOL          pool_server;
static NX_PACKET_POOL          pool_client;
static NX_IP                   ip_server;
static NX_IP                   ip_client;
static NX_TCP_SOCKET           test_sockets[3];
static TX_SEMAPHORE            sema_0;

/* Define FTP objects.  */

static NX_FTP_SERVER           ftp_server;
static FX_MEDIA                ram_disk;

/* Define the memory area for the FileX RAM disk.  */
static UCHAR                   ram_disk_memory[32000];
static UCHAR                   ram_disk_sector_cache[512];

static UINT                    data_received;
static UCHAR                   send_buff[256];
static UCHAR                   recv_buff[256];


#define         SERVER_ADDRESS          IP_ADDRESS(1,2,3,4)
#define         CLIENT_ADDRESS          IP_ADDRESS(1,2,3,5)


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define function prototypes.  */

static void    thread_server_entry(ULONG thread_input);
static void    thread_test_entry(ULONG thread_input);

/* Replace the 'ram' driver with your actual Ethernet driver. */
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void     _fx_ram_driver(FX_MEDIA *media_ptr);



/* Define server login/logout functions.  These are stubs for functions that would 
   validate a client login request.   */
static UINT    server_login(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, ULONG client_ip_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info);
static UINT    server_logout(struct NX_FTP_SERVER_STRUCT *ftp_server_ptr, ULONG client_ip_address, UINT client_port, CHAR *name, CHAR *password, CHAR *extra_info);

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_two_listen_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
CHAR    *pointer;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    tx_thread_create(&server_thread, "server thread", thread_server_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create packet pool.  */
    status = nx_packet_pool_create(&pool_server, "Server NetX Packet Pool", 600, pointer, 8192);
    pointer = pointer + 8192;
    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_server, "Server NetX IP Instance", SERVER_ADDRESS,
                          0xFFFFFF00UL, &pool_server, _nx_ram_network_driver_512,
                          pointer, 4096, 1);
    pointer =  pointer + 4096;
    if(status)
        error_counter++;

    /* Create another packet pool. */
    status = nx_packet_pool_create(&pool_client, "Client NetX Packet Pool", 600, pointer, 8192);
    pointer = pointer + 8192;
    if(status)
        error_counter++;

    /* Create another IP instance.  */
    status = nx_ip_create(&ip_client, "Client NetX IP Instance", CLIENT_ADDRESS,
                          0xFFFFFF00UL, &pool_client, _nx_ram_network_driver_512,
                          pointer, 4096, 1);
    pointer = pointer + 4096;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_server, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_client, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_server);
    status += nx_tcp_enable(&ip_client);
    if(status)
        error_counter++;

    /* Create the FTP server.  */
    status =  nx_ftp_server_create(&ftp_server, "FTP Server Instance", &ip_server, &ram_disk, pointer, DEMO_STACK_SIZE, &pool_server,
                                   server_login, server_logout);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Check for errors.  */
    if (status)
        error_counter++;

    status = tx_semaphore_create(&sema_0, "Semaphore", 0);
    if (status)
        error_counter++;
}

/* Define the Server thread.  */
static void    thread_server_entry(ULONG thread_input)
{

UINT    i;
UINT    status;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   FTP Two Listen Test.......................................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Format the RAM disk - the memory for the RAM disk was defined above.  */
    status = fx_media_format(&ram_disk, 
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

    /* OK to start the ftp Server.   */
    status = nx_ftp_server_start(&ftp_server);
    if (status)
        error_counter++;

    /* Initialize test sockets. */
    for (i = 0; i < sizeof(test_sockets) / sizeof(NX_TCP_SOCKET); i++)
    {

        /* Create Client socket.  */
        status =  nx_tcp_socket_create(&ip_client, &test_sockets[i], "Client Socket",
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                NX_NULL, NX_NULL);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
            return;
        }

        /* Bind the socket.  */
        status =  nx_tcp_client_socket_bind(&test_sockets[i], NX_ANY_PORT, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
            break;
        }
    }

    /* Connect to Telnet server. */
    status = nx_tcp_client_socket_connect(&test_sockets[0], SERVER_ADDRESS, NX_FTP_SERVER_CONTROL_PORT, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }

    /* Send data to Telnet server. */
    nx_packet_allocate(&pool_client, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
    nx_packet_data_append(packet_ptr, "PASS 1234\r\n", 11, &pool_client, NX_NO_WAIT);
    nx_tcp_socket_send(&test_sockets[0], packet_ptr, NX_NO_WAIT);

    /* Disconnect immediately. */
    nx_tcp_socket_disconnect(&test_sockets[0], NX_IP_PERIODIC_RATE);

    if (tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE))
    {
        error_counter++;
    }

    /* Let another two sockets connect to Telnet server without block. */
    nx_tcp_client_socket_connect(&test_sockets[1], SERVER_ADDRESS, NX_FTP_SERVER_CONTROL_PORT, NX_NO_WAIT);
    nx_tcp_client_socket_connect(&test_sockets[2], SERVER_ADDRESS, NX_FTP_SERVER_CONTROL_PORT, NX_NO_WAIT);

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Make sure the state of sockets is ESTABLISHED. */
    if (test_sockets[1].nx_tcp_socket_state != NX_TCP_ESTABLISHED)
    {
        error_counter++;
    }
    if (test_sockets[2].nx_tcp_socket_state != NX_TCP_ESTABLISHED)
    {
        error_counter++;
    }

    status = nx_ftp_server_stop(&ftp_server);
    status += nx_ftp_server_delete(&ftp_server);
    if (status)
        error_counter++;

    if (error_counter)
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
    tx_semaphore_put(&sema_0);
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
void    netx_ftp_two_listen_test_application_define(void *first_unused_memory)
#endif
{
    /* Print out test information banner.  */
    printf("NetX Test:   FTP Two Listen Test.......................................N/A\n");
    test_control_return(3);
}
#endif


