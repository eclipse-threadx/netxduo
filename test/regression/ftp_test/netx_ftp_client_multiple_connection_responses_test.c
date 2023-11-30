#include    "tx_api.h"
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

/* Define the NetX FTP object control block.  */

static NX_FTP_CLIENT           ftp_client;


/* Define the counters used in the demo application...  */

static  UINT            error_counter = 0;
static  UINT            client_thread_done = NX_FALSE;


#define FTP_SERVER_ADDRESS  IP_ADDRESS(1,2,3,4)
#define FTP_CLIENT_ADDRESS  IP_ADDRESS(1,2,3,5)

#define     SERVER_PORT                 21
#define     SERVER_PASSIVE_PORT1        21017
#define     SERVER_PASSIVE_PORT2        21018


static  void   server_thread_entry(ULONG thread_input);
static  void   client_thread_entry(ULONG thread_input);
static  UINT   nx_ftp_response_packet_send(NX_TCP_SOCKET *server_socket, UCHAR *data, UINT data_size);

extern   void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);


/* There are for logging in */
static UCHAR welcome_220_response_1[27] = {
0x32, 0x32, 0x30, 0x2d, 0x4d, 0x69, 0x63, 0x72,  /* 220-Micr */
0x6f, 0x73, 0x6f, 0x66, 0x74, 0x20, 0x46, 0x54,  /* osoft FT */
0x50, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,  /* PServic  */
0x65, 0x0d, 0x0a                                 /* e..      */
};

static UINT welcome_220_response_1_size = 27;

static UCHAR welcome_220_response_2[21] = {
0x32, 0x32, 0x30, 0x20, 0x57, 0x69, 0x6e, 0x68, /* 220 Winh */
0x6f, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x20, /* ost.com  */
0x46, 0x54, 0x50, 0x0d, 0x0a                    /* FTP..    */
};

static UINT welcome_220_response_2_size = 21;

static UCHAR password_request_331[23] = {
0x33, 0x33, 0x31, 0x20, 0x50, 0x61, 0x73, 0x73, /* 331 Pass */
0x77, 0x6f, 0x72, 0x64, 0x20, 0x72, 0x65, 0x71, /* word req */
0x75, 0x69, 0x72, 0x65, 0x64, 0x0d, 0x0a        /* uired.. */
};

static UINT password_request_331_size = 23;

static UCHAR logged_in_230_response[21] = {
0x32, 0x33, 0x30, 0x20, 0x55, 0x73, 0x65, 0x72, /* 230 User */
0x20, 0x6c, 0x6f, 0x67, 0x67, 0x65, 0x64, 0x20, /*  logged  */
0x69, 0x6e, 0x2e, 0x0d, 0x0a                    /* in... */
};

static UINT logged_in_230_response_size = 21;

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ftp_client_multiple_connection_response_test_application_define(void *first_unused_memory)
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

UINT        status;

    /* Let the server set up. */
    tx_thread_sleep(20);

    NX_PARAMETER_NOT_USED(thread_input);

    /* Create an FTP client.  */
    status =  nx_ftp_client_create(&ftp_client, "FTP Client", &client_ip, 2000, &client_pool);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        error_counter++;
     }
          
    /* Now connect with the NetX FTP (IPv4) server on the control socket. */
    status =  nx_ftp_client_connect(&ftp_client, FTP_SERVER_ADDRESS, "equenet0_alpha1", "29Pi2A792N", 500);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        error_counter++;
     }

    /* Delete the FTP client.  */
    nx_ftp_client_disconnect(&ftp_client, 0);
    nx_ftp_client_delete(&ftp_client);

    client_thread_done = NX_TRUE;
}


/* Define the helper FTP server thread.  */
void    server_thread_entry(ULONG thread_input)
{

UINT         status;
NX_PACKET   *my_packet;

    /* Print out test information banner.  */
    printf("NetX Test:   FTP Client Multiple Connection Response Test.............."); 

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

    /* Send welcome response.  */
    if (nx_ftp_response_packet_send(&server_socket, welcome_220_response_1, welcome_220_response_1_size))
    {
        error_counter++;
    }
    if (nx_ftp_response_packet_send(&server_socket, welcome_220_response_2, welcome_220_response_2_size))
    {
        error_counter++;
    }

    /* Receive USER request message.  */
    status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if ((status) || (memcmp(my_packet ->nx_packet_prepend_ptr, "USER equenet0_alpha1", sizeof("USER equenet0_alpha1") - 1)))
    {
        error_counter++;
    }
    else
    {

        /* Release the packet.  */
        nx_packet_release(my_packet);
    }

    /* Send password required message.  */
    if (nx_ftp_response_packet_send(&server_socket, password_request_331, password_request_331_size))
    {
        error_counter++;
    }

    /* Receive PASS request message.  */
    status =  nx_tcp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if ((status) || (memcmp(my_packet ->nx_packet_prepend_ptr, "PASS 29Pi2A792N", sizeof("USER 29Pi2A792N") - 1)))
    {
        error_counter++;
    }
    else
    {

        /* Release the packet.  */
        nx_packet_release(my_packet);
    }

    /* Send logged in message.  */
    if (nx_ftp_response_packet_send(&server_socket, logged_in_230_response, logged_in_230_response_size))
    {
        error_counter++;
    }

    /* Wait for client thread.  */
    while (client_thread_done == NX_FALSE)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    nx_tcp_socket_disconnect(&server_socket, 0);
    nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
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

static UINT   nx_ftp_response_packet_send(NX_TCP_SOCKET *server_socket, UCHAR *data, UINT data_size)
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
    memcpy(response_packet -> nx_packet_prepend_ptr, data, data_size);

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length = data_size;
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
void    netx_ftp_client_multiple_connection_response_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   FTP Client Multiple Connection Response Test..............N/A\n"); 

    test_control_return(3);  
}      
#endif
