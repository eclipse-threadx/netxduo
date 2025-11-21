/* This is a small demo of NetX FTP on the high-performance NetX TCP/IP stack.  This demo 
   relies on ThreadX, NetX, and FileX to show a simple directory listing get from the client 
   in passive mode transfer, except the server refuses the passive mode request.  */



#include    "tx_api.h"
#include    "fx_api.h" 
#include    "nx_api.h"
#include    "nxd_ftp_client.h"

extern   void  test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048
#define     PACKET_PAYLOAD          1518
                  

/* Define the ThreadX, NetX, and FileX object control blocks...  */

static NX_TCP_SOCKET           server_socket;
static NX_TCP_SOCKET           server_socket_passive;
static TX_THREAD               client_thread;
static TX_THREAD               server_thread;
static NX_PACKET_POOL          client_pool;
static NX_PACKET_POOL          server_pool;
static NX_IP                   client_ip;
static NX_IP                   server_ip;
static FX_MEDIA                ram_disk;


/* Define the NetX FTP object control block.  */
static NX_FTP_CLIENT           ftp_client;

typedef struct FTP_RESPONSE_STRUCT
{
    char          *ftp_response_pkt_data;
    int           ftp_response_pkt_size;
} FTP_RESPONSE;

#define NUM_RESPONSES      4
static  FTP_RESPONSE       ftp_response[NUM_RESPONSES];

#define LOGIN_RESPONSES    3
static  FTP_RESPONSE       ftp_login[LOGIN_RESPONSES];

/* Define the counters used in the demo application...  */

static  UINT            error_counter = 0;


/* Define the memory area for the FileX RAM disk.  */

UCHAR                   ram_disk_memory[32000];
UCHAR                   ram_disk_sector_cache[512];

#define FTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define FTP_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)

#define     SERVER_PORT                 21
#define     SERVER_PASSIVE_PORT1        21017
#define     SERVER_PASSIVE_PORT2        21018

extern UINT  _fx_media_format(FX_MEDIA *media_ptr, VOID (*driver)(FX_MEDIA *media), VOID *driver_info_ptr, UCHAR *memory_ptr, UINT memory_size,
                        CHAR *volume_name, UINT number_of_fats, UINT directory_entries, UINT hidden_sectors, 
                        ULONG total_sectors, UINT bytes_per_sector, UINT sectors_per_cluster, 
                        UINT heads, UINT sectors_per_track);

/* Define the FileX and NetX driver entry functions.  */
VOID    _fx_ram_driver(FX_MEDIA *media_ptr);


static  void   server_thread_entry(ULONG thread_input);
static  void   client_thread_entry(ULONG thread_input);
static  UINT   nx_ftp_response_packet_send(NX_TCP_SOCKET *server_socket, UINT port, INT packet_number);
static  UINT   nx_ftp_login_packet_send(NX_TCP_SOCKET *server_socket, UINT port, INT packet_number);
static  void   ftp_test_initialize();

extern   void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);


/* There are for logging in */
static char welcome_220_response[21] = {
0x32, 0x32, 0x30, 0x20, 0x44, 0x20, 0x63, 0x6f, /* 220 ... */
0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x20, 0x73, 0x75, /* mmand su */
0x65, 0x74, 0x29, 0x0d, 0x0a                    /* et).. */
};

static int welcome_220_response_size = 21;

static char password_request_331[17] = {
0x33, 0x33, 0x31, 0x20,                          /* 331 ... */
0x30, 0x20, 0x43, 0x57, 0x44, 0x20, 0x63, 0x6f, /* 0 CWD co */
0x65, 0x74, 0x29, 0x0d, 0x0a                    /* et).. */
};

static int password_request_331_size = 17;

static char logged_in_230_response[13] = {
0x32, 0x33, 0x30, 0x20, 0x44, 0x20, 0x63, 0x6f, /* 230 ... */
0x65, 0x74, 0x29, 0x0d, 0x0a                    /* et).. */
};

static int logged_in_230_response_size = 13;


/* These are for downloading information. */
static char cwd_250_response[23] = {
0x32, 0x35,                                     /* D0v...25 */
0x30, 0x20, 0x43, 0x57, 0x44, 0x20, 0x63, 0x6f, /* 0 CWD co */
0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x20, 0x73, 0x75, /* mmand su */
0x65, 0x74, 0x29, 0x0d, 0x0a                    /* et).. */
};

static int cwd_250_response_size = 23;

static char pasv_nlst_500_response[43] = {
0x35, 0x30,                                     /* D.r...50 */
0x30, 0x20, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x69, /* 0 Denied */
0x6e, 0x67, 0x20, 0x50, 0x61, 0x73, 0x73, 0x69, /* ng Passi */
0x76, 0x65, 0x20, 0x4d, 0x6f, 0x64, 0x65, 0x20, /* ve Mode  */
0x28, 0x31, 0x2c, 0x32, 0x2c, 0x33, 0x2c, 0x34, /* (1,2,3,4 */ 
0x2c, 0x38, 0x32, 0x2c, 0x32, 0x35, 0x29, 0x0d, /* ,82,25)*/
0x0a                                            /* ... */
};

static int pasv_nlst_500_response_size = 43;


static char quit_221_response[24] = {
0x32, 0x32,                                     /* 221 .... */
0x31, 0x20, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, /* 1 Transf */
0x65, 0x72, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x6c, /* er compl */
0x65, 0x74, 0x65, 0x2e, 0x0d, 0x0a              /* ete... */
};

static int quit_221_response_size = 24;



/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_client_pasv_denied_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
UCHAR   *pointer;

    
    /* Setup the working pointer.  */
    pointer =  (UCHAR *) first_unused_memory;

    /* Initialize NetX.  */
    nx_system_initialize();

    /* Set up the FTP Server. */

    /* Create the main FTP server thread.  */
    status = tx_thread_create(&server_thread, "FTP Server thread ", server_thread_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE ;

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "FTP Server Packet Pool", 700, 
                                    pointer , 700*10);

    pointer = pointer + 700*10;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, 
                          "FTP Server IP", 
                          FTP_SERVER_ADDRESS, 
                          0xFFFFFF00UL, 
                          &server_pool, _nx_ram_network_driver_1024,
                          pointer, DEMO_STACK_SIZE, 1);

    pointer = pointer + DEMO_STACK_SIZE;
    
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status =  nx_arp_enable(&server_ip, (void *) pointer, 1024);

    pointer = pointer + 1024;

    if (status)
        error_counter++;

     /* Enable TCP traffic.  */
    status = nx_tcp_enable(&server_ip);
    if (status)
        error_counter++;


    /* Set up the FTP Client. */

    /* Create the main FTP client thread.  */
    status = tx_thread_create(&client_thread, "FTP Client thread ", client_thread_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE ;

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }

    /* Create a packet pool for the FTP client.  */
    status =  nx_packet_pool_create(&client_pool, "NetX Client Packet Pool", PACKET_PAYLOAD, pointer, 25*PACKET_PAYLOAD);
    
        /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }
    
    pointer =  pointer + 25*PACKET_PAYLOAD;

    /* Create an IP instance for the FTP client.  */
    status = nx_ip_create(&client_ip, "NetX Client IP Instance", FTP_CLIENT_ADDRESS, 0xFFFFFF00UL, 
                          &client_pool, _nx_ram_network_driver_1024, pointer, DEMO_STACK_SIZE, 1);
    
        /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }
    
    pointer = pointer + DEMO_STACK_SIZE;

    /* Enable ARP and supply ARP cache memory for the FTP Client IP.  */
    nx_arp_enable(&client_ip, (void *) pointer, 1024);

    pointer = pointer + 1024;

    /* Enable TCP for client IP instance.  */
    nx_tcp_enable(&client_ip);
    nx_icmp_enable(&client_ip);
    
    return;

}

/* Define the FTP client thread.  */

void    client_thread_entry(ULONG thread_input)
{

NX_PACKET   *my_packet;
UINT        status;

    /* Let the server set up. */
    tx_thread_sleep(20);

    NX_PARAMETER_NOT_USED(thread_input);

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
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Open the RAM disk.  */
    status = fx_media_open(&ram_disk, "RAM DISK", _fx_ram_driver, ram_disk_memory, ram_disk_sector_cache, sizeof(ram_disk_sector_cache));

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Create an FTP client.  */
    status =  nx_ftp_client_create(&ftp_client, "FTP Client", &client_ip, 2000, &client_pool);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        error_counter++;
     }
          
    /* Now connect with the NetX FTP (IPv4) server on the control socket. */
    status =  nx_ftp_client_connect(&ftp_client, FTP_SERVER_ADDRESS, "User", "password", 500);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        error_counter++;
     }
   
    /* Enable passive mode. */
    status = nx_ftp_client_passive_mode_set(&ftp_client, NX_TRUE);
    if (status != NX_SUCCESS) 
    {

        error_counter++;
    }

    /* Set directory to /Users/Self. This does not require the PASV command. */
    status = nx_ftp_client_directory_default_set(&ftp_client, "\\Users\\Self", 100);

    if (status != NX_SUCCESS) 
    {

        error_counter++;
    }

    /* Get directory listing (NLST) ; this is where the Client sends the PASV command and opens another data socket .*/
    status = nx_ftp_client_directory_listing_get(&ftp_client, "", &my_packet, 100);

    /* The server refuses the PASV request so this should not succeed! */
    if (status == NX_SUCCESS) 
    {

        error_counter++;
    }

    /* Disconnect from the server.  */
    status = nx_ftp_client_disconnect(&ftp_client, NX_IP_PERIODIC_RATE);

    if (status != NX_SUCCESS) 
    {

        error_counter++;
    }

    /* Delete the FTP client.  */
    nx_ftp_client_delete(&ftp_client);

}


/* Define the helper FTP server thread.  */
void    server_thread_entry(ULONG thread_input)
{

UINT         status;
NX_PACKET   *my_packet;
UINT         i;

    /* Print out test information banner.  */
    printf("NetX Test:   FTP Passive Mode Transfer PASV Refused Test..............."); 

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a TCP socket as the FTP server.  */
    status = nx_tcp_socket_create(&server_ip, &server_socket, "Socket Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 
                                  NX_IP_TIME_TO_LIVE, 2048, NX_NULL, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }
    
    /* Create a secondary TCP socket as the FTP server passive mode connection. Do not bind a port yet  */
    status = nx_tcp_socket_create(&server_ip, &server_socket_passive, "Passive Socket Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 
                                  NX_IP_TIME_TO_LIVE, 2048, NX_NULL, NX_NULL);

    /* Bind the TCP socket to the FTP control port.  */
    status =  nx_tcp_server_socket_listen(&server_ip, SERVER_PORT, &server_socket, 5, NX_NULL);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }
    
    /* Wait for a connection request.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Load up the server 'responses'. */
    ftp_test_initialize();
 
    /* Let the client log in */

    for (i = 0; i < LOGIN_RESPONSES; i++)
    {

        status = nx_ftp_login_packet_send(&server_socket, 80, i);

        /* Check status.  */
        if (status)
        {        
            error_counter++; 
        } 

        if (i != 2) 
        {
        
            status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

            /* Check status.  */
            if (status)
            {
                error_counter++;
            }       
            else
            {

              /* Release the packet.  */
              nx_packet_release(my_packet);
            }
        }
    }

    /* this is CWD */
    status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }       
    else
    {

      /* Release the packet.  */
      nx_packet_release(my_packet);
    }

    /* Respond to CWD command. */
    status = nx_ftp_response_packet_send(&server_socket, 80, 0);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

     /* this is the PASV request*/
    status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }       
    else
    {

        /* Release the packet.  */
        nx_packet_release(my_packet);
    }

    status = nx_ftp_response_packet_send(&server_socket, 80, 1);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* this is the QUIT command. */
    status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }       
    else
    {

       /* Release the packet.  */
       nx_packet_release(my_packet);
    }

    status = nx_ftp_response_packet_send(&server_socket, 80, 2);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Delete the TCP socket.  */
    nx_tcp_socket_delete(&server_socket);
    
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {

        printf("SUCCESS!\n");
        test_control_return(0);
    };

    return;
       
}


static void  ftp_test_initialize()
{

/* Logging in responses */

    ftp_login[0].ftp_response_pkt_data = &welcome_220_response[0];
    ftp_login[0].ftp_response_pkt_size = welcome_220_response_size ; 
   
    ftp_login[1].ftp_response_pkt_data = &password_request_331[0];
    ftp_login[1].ftp_response_pkt_size = password_request_331_size ; 

    ftp_login[2].ftp_response_pkt_data = &logged_in_230_response[0];
    ftp_login[2].ftp_response_pkt_size = logged_in_230_response_size ; 

/* Download data responses */
    ftp_response[0].ftp_response_pkt_data = &cwd_250_response[0];
    ftp_response[0].ftp_response_pkt_size = cwd_250_response_size ;  
    
    ftp_response[1].ftp_response_pkt_data = &pasv_nlst_500_response[0];
    ftp_response[1].ftp_response_pkt_size = pasv_nlst_500_response_size  ; 
     
    ftp_response[2].ftp_response_pkt_data = &quit_221_response[0];
    ftp_response[2].ftp_response_pkt_size = quit_221_response_size  ;


}



static UINT   nx_ftp_login_packet_send(NX_TCP_SOCKET *server_socket, UINT port, INT packet_number)
{
UINT        status;
NX_PACKET   *login_packet;


    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&server_pool, &login_packet, NX_TCP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Write the FTP response messages into the packet payload!  */
    memcpy(login_packet -> nx_packet_prepend_ptr, ftp_login[packet_number].ftp_response_pkt_data, 
           ftp_login[packet_number].ftp_response_pkt_size);

    /* Adjust the write pointer.  */
    login_packet -> nx_packet_length =  ftp_login[packet_number].ftp_response_pkt_size;
    login_packet -> nx_packet_append_ptr =  login_packet -> nx_packet_prepend_ptr + login_packet -> nx_packet_length;

    /* Send the TCP packet with the correct port.  */
    status =  nx_tcp_socket_send(server_socket, login_packet, 100);

    /* Check the status.  */
    if (status)      
        nx_packet_release(login_packet);         

    return status;
}


static UINT   nx_ftp_response_packet_send(NX_TCP_SOCKET *server_socket, UINT port, INT packet_number)
{

UINT        status;
NX_PACKET   *response_packet;


    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&server_pool, &response_packet, NX_TCP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Write the FTP response messages into the packet payload!  */
    memcpy(response_packet -> nx_packet_prepend_ptr, ftp_response[packet_number].ftp_response_pkt_data, 
           ftp_response[packet_number].ftp_response_pkt_size);

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length =  ftp_response[packet_number].ftp_response_pkt_size;
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;

    /* Send the TCP packet with the correct port.  */
    status =  nx_tcp_socket_send(server_socket, response_packet, 100);

    /* Check the status.  */
    if (status)      
        nx_packet_release(response_packet);         

    return status;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_client_pasv_denied_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   FTP Passive Mode Transfer PASV Refused Test...............N/A\n"); 

    test_control_return(3);  
}      
#endif
