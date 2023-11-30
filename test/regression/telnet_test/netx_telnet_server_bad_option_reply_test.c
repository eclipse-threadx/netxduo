/* This test checks for the Telnet Server to handle invalid telnet client option replies and unsupported client telnet options
   in response to the server offering ECHO, Suppress Go Ahead and asks the peer not to ECHO (Don't Echo).
   The Telnet Client is programmed to respond with a WILL ECHO (to the server WILL ECHO), a WILL [0x99 unknown option] and Won't Echo. 
   The server should not accept these options so a successful test is if echo and SGA are not enabled on the Telnet server.  

   Required configuration settings:
      
   NX_TELNET_SERVER_OPTION_DISABLE not defined
   NX_TELNET_SERVER_USER_CREATE_PACKET_POOL  defined
*/

#include  "tx_api.h"
#include  "nx_api.h"


extern void    test_control_return(UINT);

#if defined(NX_TELNET_SERVER_USER_CREATE_PACKET_POOL) && !defined(NX_DISABLE_IPV4)

#include  "nxd_telnet_client.h"
#include  "nxd_telnet_server.h"


#define     DEMO_STACK_SIZE         4096    


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               server_thread;
static TX_THREAD               client_thread;
static NX_PACKET_POOL          pool_server;
static NX_PACKET_POOL          pool_client;
static NX_IP                   ip_server;
static NX_IP                   ip_client;


/* Define TELNET server object.  */

static NX_TELNET_SERVER        my_server;
static NX_TELNET_CLIENT        my_client;

#define         SERVER_ADDRESS          IP_ADDRESS(1,2,3,4)     
#define         CLIENT_ADDRESS          IP_ADDRESS(1,2,3,5)     



/* Define the counters and flags used in the demo application...  */

static ULONG                   error_counter;

/* Define timeout in ticks for connecting and sending/receiving data. */

#define                        TELNET_TIMEOUT  200


static void    thread_server_entry(ULONG thread_input);
static void    thread_client_entry(ULONG thread_input);

extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);

static UCHAR                   send_buff[256];

/* Define the application's TELNET Server callback routines.  */

static void    telnet_new_connection(NX_TELNET_SERVER *server_ptr, UINT logical_connection); 
static void    telnet_receive_data(NX_TELNET_SERVER *server_ptr, UINT logical_connection, NX_PACKET *packet_ptr);
static void    telnet_connection_end(NX_TELNET_SERVER *server_ptr, UINT logical_connection);



/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_telnet_server_bad_option_reply_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
CHAR    *pointer;

    error_counter = 0;
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the server thread.  */
    status = tx_thread_create(&server_thread, "Telnet Server thread", thread_server_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            12, 12, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;


    if (status)
    {
        printf("Error creating Server thread 0x%x\n", status);
    }

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the server packet pool.  */
    nx_packet_pool_create(&pool_server, "Server NetX Packet Pool", 600, pointer, 8192);
    pointer = pointer + 8192;

    /* Create the Server IP instance.  */
    nx_ip_create(&ip_server, "Server NetX IP Instance", SERVER_ADDRESS, 
                        0xFFFFFF00UL, &pool_server, _nx_ram_network_driver_512,
                        pointer, 4096, 1);

    pointer =  pointer + 4096;


    /* Enable ARP and supply ARP cache memory for the server.  */
    nx_arp_enable(&ip_server, (void *) pointer, 1024);
    pointer = pointer + 1024;
  
    /* Enable TCP processing for both IP instances.  */
    nx_tcp_enable(&ip_server);
    nx_icmp_enable(&ip_server);


    /* Create the NetX Duo TELNET Server.  */
    status =  nx_telnet_server_create(&my_server, "Telnet Server", &ip_server, 
                    pointer, 2048, telnet_new_connection, telnet_receive_data, 
                    telnet_connection_end);

    /* Check for errors.  */
    if (status)
        error_counter++;


    pointer = pointer + 2048;

    /* Create the Client thread.  */
    status = tx_thread_create(&client_thread, "Telnet Client thread", thread_client_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            12, 12, TX_NO_TIME_SLICE, TX_AUTO_START);

    if (status)
    {
        error_counter++;
    }

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the client packet pool.  */
    status = nx_packet_pool_create(&pool_client, "Client NetX Packet Pool", 600, pointer, 8192);
    if (status)
    {
        error_counter++;
    }
    pointer = pointer + 8192;

    /* Create the Client IP instance.  */
    status = nx_ip_create(&ip_client, "Client NetX IP Instance", CLIENT_ADDRESS, 
                        0xFFFFFF00UL, &pool_client, _nx_ram_network_driver_512,
                        pointer, 4096, 1);
    if (status)
    {
        error_counter++;
    }

    pointer =  pointer + 4096;

    /* Enable ARP and supply ARP cache memory for the client.  */
    nx_arp_enable(&ip_client, (void *) pointer, 1024);
    pointer = pointer + 1024;
  
    /* Enable TCP and ICMP processing for client IP instance.  */
    nx_tcp_enable(&ip_client);
    nx_icmp_enable(&ip_client);


    return;
}

static void    thread_client_entry(ULONG thread_input)
{

UINT status;
NX_PACKET *my_packet, *my_packet2, *rcv_packet;

    tx_thread_sleep(100);

    /* Create a TELENT client instance.  */
    status =  nx_telnet_client_create(&my_client, "TELNET Client", &ip_client, 6 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Connect the TELNET client to the TELNET Server at port 23 over IPv4.  */
    status =  nx_telnet_client_connect(&my_client, SERVER_ADDRESS, NX_TELNET_SERVER_PORT, 200);
    if (status)
        error_counter++;


    /* This should be the welcome message. */
    status =  nx_telnet_client_packet_receive(&my_client, &rcv_packet, TELNET_TIMEOUT);

    if (status)
        error_counter++;

    /* To do verify this is just a hello message. */

    nx_packet_release(rcv_packet);

    /* Server should be negotiating options. */
    status =  nx_telnet_client_packet_receive(&my_client, &rcv_packet, TELNET_TIMEOUT);

    if (status)
        error_counter++;

    /* Parse the options. Should be will echo don't echo and will suppress go ahead */

    nx_packet_release(rcv_packet);

    /* Prepare a WILL ECHO reply. This is invalid since the server just indicated it would enable ECHO  */
    send_buff[0] = 0xFF;
    send_buff[1] = 0xFB; /* WILL */
    send_buff[2] = 0x01;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_client, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Build a simple 1-byte message.  */
    nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_client, NX_WAIT_FOREVER);

    /* Send the packet to the TELNET Server.  */
    status =  nx_telnet_client_packet_send(&my_client, my_packet, TELNET_TIMEOUT);
    if (status)
        error_counter++;

    /* Prepare a second reply: WONT ECHO, DO [unknown option] */
    send_buff[0] = 0xFF;
    send_buff[1] = 0xFC;
    send_buff[2] = 0x01;
    send_buff[0] = 0xFF;
    send_buff[1] = 0xFD;
    send_buff[2] = 0x99; /* No idea what this is but we don't support it*/

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_client, &my_packet2, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Load the reply in to the packet.  */
    nx_packet_data_append(my_packet2, send_buff, sizeof(send_buff), &pool_client, NX_WAIT_FOREVER);

    /* Send the packet to the TELNET Server.  */
    status =  nx_telnet_client_packet_send(&my_client, my_packet2, TELNET_TIMEOUT);
    if (status)
        error_counter++;

    tx_thread_sleep(200);

    /* Now disconnect form the TELNET Server.  */
    nx_telnet_client_disconnect(&my_client, 100);

    /* Delete the TELNET Client.  */
    status =  nx_telnet_client_delete(&my_client);
    if (status)
        error_counter++;

}

/* Define the Telnet Server thread.  */
static void    thread_server_entry(ULONG thread_input)
{

UINT        status;


    tx_thread_sleep(20);

    /* Print out test information banner.  */    
    printf("NetX Test:   Telnet Server Bad Option Reply Test.......................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* We have defined the NX_TELNET_CREATE_PACKET_POOL option for sending
       Telnet options (not disabled). So set the telnet packet pool. */
    status = nx_telnet_server_packet_pool_set(&my_server, &pool_server);

    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Start the TELNET Server.  */
    status =  nx_telnet_server_start(&my_server);

    /* Check for errors.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    do
    {
        /* Check if the client connection is still live. */
        
        tx_thread_sleep(100);
    }while (my_server.nx_telnet_server_open_connections == 1);

    status =  nx_telnet_server_stop(&my_server);

    /* Check for errors.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;

    }

    if  (error_counter || 
        (my_server.nx_telnet_server_client_list[0].nx_telnet_client_agree_server_will_SGA_success == NX_TRUE) ||
        (my_server.nx_telnet_server_client_list[0].nx_telnet_client_agree_server_will_echo_success == NX_TRUE))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    else

    {

        printf("SUCCESS!\n");
        test_control_return(0);
    }

    return;
}


/* This routine is called by the NetX Telnet Server whenever a new Telnet client 
   connection is established.  */
static void  telnet_new_connection(NX_TELNET_SERVER *server_ptr, UINT logical_connection)
{

UINT        status;
NX_PACKET   *packet_ptr;


    /* Allocate a packet for client greeting. */
    status =  nx_packet_allocate(&pool_server, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);

    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }

    if (pool_server.nx_packet_pool_available < 2)
    {
        printf("Packet pool getting low...\n");
    }
    /* Build a banner message and a prompt.  */
    nx_packet_data_append(packet_ptr, "**** Welcome to NetX TELNET Server ****\r\n\r\n\r\n", 45, &pool_server, NX_NO_WAIT);
  
    /* Send the packet to the client.  */
    status =  nx_telnet_server_packet_send(server_ptr, logical_connection, packet_ptr, TELNET_TIMEOUT);

    if (status != NX_SUCCESS)
    {
        error_counter++;
        nx_packet_release(packet_ptr);
    }
  
    return;
}


/* This routine is called by the NetX Telnet Server whenever data is present on a Telnet client 
   connection.  */          
static void  telnet_receive_data(NX_TELNET_SERVER *server_ptr, UINT logical_connection, NX_PACKET *packet_ptr)
{

UINT    status;
UCHAR   alpha;



    /* This demo just echoes the character back and on <cr,lf> sends a new prompt back to the
       client.  A real system would most likely buffer the character(s) received in a buffer 
       associated with the supplied logical connection and process according to it.  */


    /* Just throw away carriage returns.  */
    if ((packet_ptr -> nx_packet_prepend_ptr[0] == '\r') && (packet_ptr -> nx_packet_length == 1))
    {
        nx_packet_release(packet_ptr);
        return;
    }


    /* Setup new line on line feed.  */
    if ((packet_ptr -> nx_packet_prepend_ptr[0] == '\n') || (packet_ptr -> nx_packet_prepend_ptr[1] == '\n'))
    {

        /* Clean up the packet.  */
        packet_ptr -> nx_packet_length =  0;
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_data_start + NX_TCP_PACKET;
        packet_ptr -> nx_packet_append_ptr =   packet_ptr -> nx_packet_data_start + NX_TCP_PACKET;

        /* Build the next prompt.  */
        nx_packet_data_append(packet_ptr, "\r\nNETX> ", 8, &pool_server, NX_NO_WAIT);

        /* Send the packet to the client.  */
        status =  nx_telnet_server_packet_send(server_ptr, logical_connection, packet_ptr, TELNET_TIMEOUT);

        if (status)
        {
            nx_packet_release(packet_ptr);
            error_counter++;
        }

        return;
    }

    /* Pickup first character (usually only one from client).  */
    alpha =  packet_ptr -> nx_packet_prepend_ptr[0];

    /* Echo character.  */
    status =  nx_telnet_server_packet_send(server_ptr, logical_connection, packet_ptr, TELNET_TIMEOUT);

    if (status != NX_SUCCESS)
    {
        error_counter++;
        nx_packet_release(packet_ptr);
    }

    /* Check for a disconnection.  */
    if (alpha == 'q')
    {

        /* Initiate server disconnection.  */
        nx_telnet_server_disconnect(server_ptr, logical_connection);
    }
}


/* This routine is called by the NetX Telnet Server whenever the client disconnects.  */
static void  telnet_connection_end(NX_TELNET_SERVER *server_ptr, UINT logical_connection)
{

    /* Cleanup any application specific connection or buffer information.  */
}

#else /* NX_TELNET_SERVER_USER_CREATE_PACKET_POOL */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_telnet_server_bad_option_reply_test_application_define(void *first_unused_memory)       
#endif
{
    printf("NetX Test:   Telnet Server Bad Option Reply Test.......................N/A\n");
    test_control_return(3);
}
#endif /* NX_TELNET_SERVER_USER_CREATE_PACKET_POOL */

