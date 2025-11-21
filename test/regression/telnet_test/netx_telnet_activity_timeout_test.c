/* This test checks for the Telnet Server to keep track of the length of inactivity on all its connections
   If the timeout is exceeded it should close the connection. 

   The following symbols and options must be set:

   NX_TELNET_SERVER_USER_CREATE_PACKET_POOL  defined
   NX_TELNET_TIMEOUT_PERIOD = 2
   NX_TELNET_ACTIVITY_TIMEOUT = 10
    
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
static TX_THREAD               client1_thread;
static TX_THREAD               client2_thread;
static NX_PACKET_POOL          pool_server;
static NX_PACKET_POOL          pool_client;
static NX_IP                   ip_server;
static NX_IP                   ip_client;

/* Define TELNET objects.  */

static NX_TELNET_SERVER        my_server;
static NX_TELNET_CLIENT        my_client1;
static NX_TELNET_CLIENT        my_client2;

static UCHAR                   send_buff[256];
static UCHAR                   recv_buff[256];


#define         SERVER_ADDRESS          IP_ADDRESS(1,2,3,4)
#define         CLIENT_ADDRESS          IP_ADDRESS(1,2,3,5)


/* Define the counters used in the demo application...  */

static  ULONG              clients_connected = 0;
static  ULONG              total_disconnects = 0;
static  ULONG              total_connections = 0;
static  ULONG              error_counter = 0;


/* Define timeout in ticks for connecting and sending/receiving data. */

#define                 TELNET_TIMEOUT          200
#define                 SHORT_TELNET_TIMEOUT    50

/* Define function prototypes.  */

static void    thread_server_entry(ULONG thread_input);
static void    thread_client1_entry(ULONG thread_input);
static void    thread_client2_entry(ULONG thread_input);

/* Replace the 'ram' driver with your actual Ethernet driver. */
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define the application's TELNET Server callback routines.  */

static void    telnet_new_connection(NX_TELNET_SERVER *server_ptr, UINT logical_connection); 
static void    telnet_receive_data(NX_TELNET_SERVER *server_ptr, UINT logical_connection, NX_PACKET *packet_ptr);
static void    telnet_connection_end(NX_TELNET_SERVER *server_ptr, UINT logical_connection);


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_telnet_activity_timeout_test_application_define(void *first_unused_memory)       
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

    /* Create the client 1 thread.  */
    tx_thread_create(&client1_thread, "client 1 thread", thread_client1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Create the client 2 thread.  */
    tx_thread_create(&client2_thread, "client 2 thread", thread_client2_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);

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

    /* Create the NetX Duo TELNET Server.  */
    status =  nx_telnet_server_create(&my_server, "Telnet Server", &ip_server, 
                    pointer, 2048, telnet_new_connection, telnet_receive_data, 
                    telnet_connection_end);

    pointer = pointer + 2048;

    /* Check for errors.  */
    if (status)
        error_counter++;

    status = nx_telnet_server_packet_pool_set(&my_server, &pool_server);

    /* Check for errors.  */
    if (status)
        error_counter++;
}

/* Define the Server thread.  */
void    thread_server_entry(ULONG thread_input)
{

UINT    status;
UINT    current_connections; 


    tx_thread_sleep(20);

    /* Print out test information banner.  */
    printf("NetX Test:   Telnet Activity Timeout Test..............................");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Start the TELNET Server.  */
    status =  nx_telnet_server_start(&my_server);
    if (status)
        error_counter++;

    /* Wait a few beats to let clients connect. */
    while(!clients_connected)
    {
        tx_thread_sleep(50);
    } 

    /* Check on the number of current connections. */
    do
    {
        
        nx_telnet_server_get_open_connection_count(&my_server, &current_connections);
        tx_thread_sleep(50);

    }while (current_connections > 0);

    /* Kill remaining clients connections if any. */
    status =  nx_telnet_server_stop(&my_server);

    if (status)
        error_counter++;

    tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);

    status = nx_telnet_server_delete(&my_server);
    if (status)
        error_counter++;

    if ((my_server.nx_telnet_server_activity_timeouts != 1) ||
        (total_connections != 2) ||
        (total_disconnects != 2))
    {
        error_counter++;
    }

    /* Wait for thread2 to complete. */
    while(clients_connected)
        tx_thread_sleep(100);

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

/* This routine is called by the NetX Telnet Server whenever a new Telnet client 
   connection is established.  */
void  telnet_new_connection(NX_TELNET_SERVER *server_ptr, UINT logical_connection)
{

UINT        status;
NX_PACKET   *packet_ptr;

    
    total_connections++;

    /* Allocate a packet for client greeting. */
    status =  nx_packet_allocate(&pool_server, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
    if (status)
        error_counter++;

    /* Build a banner message and a prompt.  */
    nx_packet_data_append(packet_ptr, "**** Welcome to NetX TELNET Server ****\r\n\r\n\r\n", 45, 
                          &pool_server, NX_NO_WAIT);

    nx_packet_data_append(packet_ptr, "NETX> ", 6, &pool_server, NX_NO_WAIT);
    
    /* Send the packet to the client.  */
    status =  nx_telnet_server_packet_send(server_ptr, logical_connection, packet_ptr, TELNET_TIMEOUT);

    if (status)
    {
        error_counter++;
        nx_packet_release(packet_ptr);
    }
}


/* This routine is called by the NetX Telnet Server whenever data is present on a Telnet client 
   connection.  */          
void  telnet_receive_data(NX_TELNET_SERVER *server_ptr, UINT logical_connection, NX_PACKET *packet_ptr)
{

UINT    status;
UCHAR   alpha;
ULONG   bytes_copied;


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
            error_counter++;
            nx_packet_release(packet_ptr);
        }

        return;
    }

    /* Verify data. */
    status = nx_packet_data_retrieve(packet_ptr, recv_buff, &bytes_copied);
    if (status)
    {
        error_counter++;
    }

    if (bytes_copied != sizeof(send_buff))
    {
        error_counter++;
    }

    if (memcmp(send_buff, recv_buff, sizeof(send_buff)) != 0)
    {
        error_counter++;
    }

    /* Pickup first character (usually only one from client).  */
    alpha =  packet_ptr -> nx_packet_prepend_ptr[0];

    /* Echo character.  */
    status =  nx_telnet_server_packet_send(server_ptr, logical_connection, packet_ptr, TELNET_TIMEOUT);
    if (status)
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
void  telnet_connection_end(NX_TELNET_SERVER *server_ptr, UINT logical_connection)
{

    total_disconnects++;

    /* Cleanup any application specific connection or buffer information.  */
    return;
}


/* Define the client1 thread.  */
void    thread_client1_entry(ULONG thread_input)
{

NX_PACKET  *my_packet;
UINT        status;
UINT        i;
UINT        packets_sent= 0;

    tx_thread_sleep(100);

    /* Create a TELENT client instance.  */
    status =  nx_telnet_client_create(&my_client1, "TELNET Client1", &ip_client, 6 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Connect the TELNET client to the TELNET Server at port 23 over IPv4.  */
    status =  nx_telnet_client_connect(&my_client1, SERVER_ADDRESS, NX_TELNET_SERVER_PORT, TELNET_TIMEOUT);
    if (status)
        error_counter++;
    else
        clients_connected++;

    /* Initialize the buffers. */
    for (i = 0; i < sizeof(send_buff); i++)
    {
        send_buff[i] = (UCHAR)(i & 0xFF);
    }
    send_buff[0] = 0xFF;
    send_buff[1] = 0xFF;
    send_buff[2] = 0xFF;
    memset(recv_buff, 0, sizeof(recv_buff));

    while (packets_sent< 2)
    {
    
        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_client, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
        if (status)
            error_counter++;
    
        /* Build a simple 1-byte message.  */
        nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_client, NX_WAIT_FOREVER);
    
        /* Send the packet to the TELNET Server.  */
        status =  nx_telnet_client_packet_send(&my_client1, my_packet, TELNET_TIMEOUT);
        if (status)
            error_counter++;
    
        /* Pickup the Server header.  */
        status =  nx_telnet_client_packet_receive(&my_client1, &my_packet, TELNET_TIMEOUT);
        if (status)
            error_counter++;
    
        /* At this point the packet should contain the Server's banner
           message sent by the Server callback function below.  Just
           release it for this demo.  */
        nx_packet_release(my_packet);
    
        /* Pickup the Server echo of the character.  */
        status =  nx_telnet_client_packet_receive(&my_client1, &my_packet, 4000);
        if (status)
            error_counter++;
    
        /* At this point the packet should contain the character 'a' that
           we sent earlier.  Just release the packet for now.  */
        nx_packet_release(my_packet);

        packets_sent++;
    }

    /* Now disconnect form the TELNET Server.  */
    nx_telnet_client_disconnect(&my_client1, TELNET_TIMEOUT);
    clients_connected--;

    /* Delete the TELNET Client.  */
    status =  nx_telnet_client_delete(&my_client1);
    if (status)
        error_counter++;

}


/* Define the client2 thread.  */
void    thread_client2_entry(ULONG thread_input)
{

NX_PACKET  *my_packet;
UINT        status;
UINT        i;

    tx_thread_sleep(110);

    /* Create a TELENT client instance.  */
    status =  nx_telnet_client_create(&my_client2, "TELNET Client2", &ip_client, 6 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Connect the TELNET client to the TELNET Server at port 23 over IPv4.  */
    status =  nx_telnet_client_connect(&my_client2, SERVER_ADDRESS, NX_TELNET_SERVER_PORT, TELNET_TIMEOUT);
    if (status)
        error_counter++;
    else
        clients_connected++;

    /* Initialize the buffers. */
    for (i = 0; i < sizeof(send_buff); i++)
    {
        send_buff[i] = (UCHAR)(i & 0xFF);
    }
    send_buff[0] = 0xFF;
    send_buff[1] = 0xFF;
    send_buff[2] = 0xFF;
    memset(recv_buff, 0, sizeof(recv_buff));

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_client, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Build a simple 1-byte message.  */
    nx_packet_data_append(my_packet, send_buff, sizeof(send_buff), &pool_client, NX_WAIT_FOREVER);

    /* Put in a long sleep time exceeding the activity timeout. */
    tx_thread_sleep(1200);

    /* Send the packet to the TELNET Server.  */
    status =  nx_telnet_client_packet_send(&my_client2, my_packet, TELNET_TIMEOUT);

    /* The server should have disconnected so check for 0x38/Not connected error*/
    if (status == NX_NOT_CONNECTED)
    {

        /* Disconnect form the TELNET Server.  */
        nx_telnet_client_disconnect(&my_client2, TELNET_TIMEOUT);
        clients_connected--;

        /* Delete TELNET Client2.  */
        status =  nx_telnet_client_delete(&my_client2);
        if (status)
            error_counter++;

        return;
    }

    /* This call should not succeed. */
    error_counter++;

    /* Now disconnect form the TELNET Server.  */
    nx_telnet_client_disconnect(&my_client2, TELNET_TIMEOUT);
    clients_connected--;

    /* Delete the TELNET Client.  */
    status =  nx_telnet_client_delete(&my_client2);

}


#else /* NX_TELNET_SERVER_USER_CREATE_PACKET_POOL */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_telnet_activity_timeout_test_application_define(void *first_unused_memory)       
#endif
{
    printf("NetX Test:   Telnet Activity Timeout Test..............................N/A\n");
    test_control_return(3);
}
#endif /* NX_TELNET_SERVER_USER_CREATE_PACKET_POOL */





