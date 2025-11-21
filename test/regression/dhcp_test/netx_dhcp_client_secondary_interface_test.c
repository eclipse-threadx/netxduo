/* Testing the multiple interface DHCP Client */

/* This test checks that the DHCP Client can run on the secondary interface,
   only using the nx_dhcp_set_interface_index for backward compatibility.
 
   Set MAX PHYSICAL INTERFACES to 2, NX_DHCP_CLIENT_MAX_INTERFACES to 1
   and run the demo. 
 */


#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_ram_network_driver_test_1500.h"
#include    "nxd_dhcp_client.h"


extern  void  test_control_return(UINT);


#if (NX_MAX_PHYSICAL_INTERFACES >= 2)

#define     DEMO_STACK_SIZE         4096
#define     PACKET_PAYLOAD          1518
     
                  
/* Define the ThreadX, NetX object control blocks...  */

static NX_UDP_SOCKET           server_socket;
static TX_THREAD               client_thread;
static TX_THREAD               server_thread;
static NX_PACKET_POOL          client_pool;
static NX_PACKET_POOL          server_pool;
static NX_IP                   client_ip;
static NX_IP                   server_ip;


/* Define the NetX FTP object control block.  */
static NX_DHCP                dhcp_client;
static UINT                   bound0 = NX_FALSE;
static UINT                   bound1 = NX_FALSE;

static ULONG dhcp_xid = 0;


typedef struct DHCP_RESPONSE_STRUCT
{
    char          *dhcp_response_pkt_data;
    int           dhcp_response_pkt_size;
} DHCP_RESPONSE;

#define NUM_RESPONSES      2
static  DHCP_RESPONSE      dhcp_response[NUM_RESPONSES];

/* Define the counters used in the demo application...  */

static  UINT            error_counter = 0;
static  UINT            client_running = NX_TRUE;


static   void  server_thread_entry(ULONG thread_input);
static   void  client_thread_entry(ULONG thread_input);

static  UINT   nx_dhcp_response_packet_send(NX_UDP_SOCKET *server_socket, UINT port, INT packet_number);
static  void   dhcp_test_initialize();
static  void   dhcp_interface_state_change(NX_DHCP *dhcp_ptr, UINT iface_index, UCHAR new_state);
static  ULONG  dhcp_get_dhcp_data(UCHAR *data, UINT size);

extern  void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);


/* Note that the network is 192.2.2.0 and the MAC address is 11 22 33 44 56
   because there are four entities (server 2 interfaces, client 2 interfaces
   and the ram driver increases the MAC sequentially starting from
   11 22 33 44 56. */
static char offer_response[300] = {

0x02, 0x01, 0x06, 0x00, 0x2a, 0x3e, /* {.....T. */
0xF0, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0xc0, 0x01, 0x01, 0xf7, 0xc0, 0x01, /* ........ */
0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x59, 0x00, 0x00, 0x00, 0x00, /* T....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, /* ......c. */
0x53, 0x63, 0x35, 0x01, 0x02, 0x01, 0x04, 0xff, /* Sc5..... */
0xff, 0xff, 0x00, 0x3a, 0x04, 0x00, 0x06, 0xac, /* ...:.... */
0x98, 0x3b, 0x04, 0x00, 0x0b, 0xae, 0x0a, 0x33, /* .;.....3 */
0x04, 0x00, 0x0d, 0x59, 0x30, 0x36, 0x04, 0xc0, /* ...Y06.. */
0x01, 0x01, 0x01, 0x03, 0x04, 0xc0, 0x01, 0x01, /* ........ */
0x01, 0x06, 0x04, 0xc0, 0x01, 0x01, 0x01, 0xff, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};

static int offer_response_size = 300;

/* Frame (342 bytes) */
static char ack_response[300] = {

0x02, 0x01, 0x06, 0x00, 0x2a, 0x3e, /* {.....T. */
0xF0, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
//0x00, 0x00, 0xc0, 0x02, 0x02, 0x01, 0xc0, 0x02, /* ........ */
0x00, 0x00, 0xc0, 0x01, 0x01, 0xf7, 0xc0, 0x01, /* ........ */
0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x59, 0x00, 0x00, 0x00, 0x00, /* T....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, /* ......c. */
0x53, 0x63, 0x35, 0x01, 0x05, 0x3a, 0x04, 0x00, /* Sc5..:.. */
0x06, 0xac, 0x98, 0x3b, 0x04, 0x00, 0x0b, 0xae, /* ...;.... */
0x0a, 0x33, 0x04, 0x00, 0x0d, 0x59, 0x30, 0x36, /* .3...Y06 */
0x04, 0xc0, 0x01, 0x01, 0x01, 0x01, 0x04, 0xff, /* ........ */
0xff, 0xff, 0x00, 0x03, 0x04, 0xc0, 0x01, 0x01, /* ........ */
0x01, 0x06, 0x04, 0xc0, 0x01, 0x01, 0x01, 0xff, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};

static int ack_response_size = 300;

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_secondary_interface_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
UCHAR   *pointer;

    
    /* Setup the working pointer.  */
    pointer =  (UCHAR *) first_unused_memory;

    /* Initialize NetX.  */
    nx_system_initialize();

    /* Set up the FTP Server. */

    /* Create the main server thread.  */
    status = tx_thread_create(&server_thread, "Server thread ", server_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + DEMO_STACK_SIZE ;

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "Server Packet Pool", PACKET_PAYLOAD, 
                                    pointer , PACKET_PAYLOAD*6);

    pointer = pointer + (PACKET_PAYLOAD*6);
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&server_ip, 
                          "Server IP", 
                          IP_ADDRESS(192,2,2,1), 
                          0xFFFFFF00UL, 
                          &server_pool, _nx_ram_network_driver_1024,
                          pointer, DEMO_STACK_SIZE, 1);

    pointer = pointer + DEMO_STACK_SIZE;
    
    if (status)
        error_counter++;

    pointer = pointer + 2048;

    status = nx_ip_interface_attach(&server_ip, "Client1 IP", IP_ADDRESS(192,1,1,1), 0xFFFFFF00UL, _nx_ram_network_driver_1024);
    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for the server IP instance.  */
    status =  nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

     /* Enable UDP traffic.  */
    status = nx_udp_enable(&server_ip);
    if (status)
        error_counter++;


    /* Set up the Client. */

    /* Create the main client thread.  */
    status = tx_thread_create(&client_thread, "Client thread ", client_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + DEMO_STACK_SIZE ;

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Create a packet pool for the client.  */
    status =  nx_packet_pool_create(&client_pool, "Client Packet Pool", PACKET_PAYLOAD, pointer, 10*PACKET_PAYLOAD);
    
        /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }
    
    pointer =  pointer + 10*PACKET_PAYLOAD;

    /* Create an IP instance for the client.  */
    status = nx_ip_create(&client_ip, " Client0 IP Instance", IP_ADDRESS(0,0,0,0), 0xFFFFFF00UL, 
                                                &client_pool, _nx_ram_network_driver_1024, pointer, 2048, 1);
    
        /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }
    
    pointer = pointer + 2048;

    status = nx_ip_interface_attach(&client_ip, "Client1 IP", IP_ADDRESS(0,0,0,0), 0xFFFFFF00UL, _nx_ram_network_driver_1024);
    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for the Client IP.  */
    nx_arp_enable(&client_ip, (void *) pointer, 1024);

    pointer = pointer + 1024;

    /* Enable UDP for client IP instance.  */
    nx_udp_enable(&client_ip);
    nx_icmp_enable(&client_ip);
    
    return;

}

/* Define the DHCP client thread.  */

static void    client_thread_entry(ULONG thread_input)
{

UINT        status, actual_status;
UINT        time_keeper = 0;


    tx_thread_sleep(NX_IP_PERIODIC_RATE / 5);

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp0");
    if (status)
        error_counter++;

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

    /* Register state change callbacks.  */
    status =  nx_dhcp_interface_state_change_notify(&dhcp_client, dhcp_interface_state_change);
    if (status)
        error_counter++;

    /* Only interface 1 should be active! */
    status = nx_dhcp_set_interface_index(&dhcp_client, 1);
    if (status)
        error_counter++;

    /* Start the DHCP Client.  */
    status =  nx_dhcp_start(&dhcp_client);
    if (status)
        error_counter++;

    while(bound1 != NX_TRUE)
    {

        time_keeper += 100;
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
        if (time_keeper >= 1000) 
        {
            error_counter++;
            break;
        }
    }

    if ((bound1 != NX_TRUE) || (bound0 == NX_TRUE))
    {
        error_counter++;
    }
    
    /* Verify interface 0 does not have a valid IP address. */
    status =  nx_ip_interface_status_check(&client_ip, 0, NX_IP_ADDRESS_RESOLVED, (ULONG *) &actual_status, NX_NO_WAIT);

    if (status == NX_SUCCESS) 
    {
        error_counter++;
    }

    /* Verify interface 1 has a valid IP address. */
    status =  nx_ip_interface_status_check(&client_ip, 1, NX_IP_ADDRESS_RESOLVED, (ULONG *) &actual_status, NX_NO_WAIT);

    if (status != NX_SUCCESS) 
    {
        error_counter++;
    }

    client_running = NX_FALSE;
    nx_dhcp_release(&dhcp_client);

}


/* Define the helper FTP server thread.  */
static void    server_thread_entry(ULONG thread_input)
{

UINT         status;
NX_PACKET   *my_packet;
UINT         i;

    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Client Secondary Interface Test......................"); 

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a  socket as the  server.  */
    status = nx_udp_socket_create(&server_ip, &server_socket, "Socket Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,  
                                  NX_IP_TIME_TO_LIVE, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }
    
    status =  nx_udp_socket_bind(&server_socket, NX_DHCP_SERVER_UDP_PORT, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Load up the server 'responses'. */
    dhcp_test_initialize();
    i = 0;

    /* Wait for Client requests */
    while ( i < NUM_RESPONSES)
    {
      
        if (i <= 1) 
        {
            
            status =  nx_udp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

            /* Check status.  */
            if (status)
            {

                error_counter++;
            }       
            else
            {

                dhcp_xid = dhcp_get_dhcp_data(my_packet -> nx_packet_prepend_ptr + NX_BOOTP_OFFSET_XID, 4);

                /* Release the packet.  */
                nx_packet_release(my_packet);
               
                status = nx_dhcp_response_packet_send(&server_socket, 68, i);
            }
        }    
        
        /* Check status.  */
        if (status)
        {        

            error_counter++; 
        } 

        
        /* Advance the index for the next response. */
        i++;
    } 

    /* Check status.  */
    if (status)
    {

        error_counter++;
    }   
     
     /* Should get one more message from the Client, a DECLINE message.     */
    status =  nx_udp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {

        error_counter++;
    }       

    /* Wait for the client thread to terminate. */
    while(client_running == NX_TRUE)
      tx_thread_sleep(20);

    /* Delete the UDP socket.  */
    nx_udp_socket_delete(&server_socket);

    if(error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {

        printf("SUCCESS!\n");
        test_control_return(0);
    };
}


static void  dhcp_test_initialize()
{


/* Download data responses */
    dhcp_response[0].dhcp_response_pkt_data = &offer_response[0];
    dhcp_response[0].dhcp_response_pkt_size = offer_response_size ;  
    
    dhcp_response[1].dhcp_response_pkt_data = &ack_response[0];
    dhcp_response[1].dhcp_response_pkt_size = ack_response_size ;
}



static UINT   nx_dhcp_response_packet_send(NX_UDP_SOCKET *server_socket_ptr, UINT port, INT packet_number)
{
UINT        status;
NX_PACKET   *response_packet;
UCHAR       *work_ptr;


    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&server_pool, &response_packet, NX_TCP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Write the  response messages into the packet payload!  */
    memcpy(response_packet -> nx_packet_prepend_ptr, dhcp_response[packet_number].dhcp_response_pkt_data, 
           dhcp_response[packet_number].dhcp_response_pkt_size);


    /* Now replace the XID in the server message with what we know is the Client XID. */
    work_ptr = (UCHAR *)(response_packet -> nx_packet_prepend_ptr  + NX_BOOTP_OFFSET_XID);
    NX_CHANGE_ULONG_ENDIAN(dhcp_xid);
    memcpy(work_ptr, (void const *)(&dhcp_xid), 4);


    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length =  dhcp_response[packet_number].dhcp_response_pkt_size;
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;


    /* Send the  packet with the correct port.  */
    status = nx_udp_socket_interface_send(server_socket_ptr, response_packet, 0xFFFFFFFF, 68, 1);

    /* Check the status.  */
    if (status)      
        nx_packet_release(response_packet);         

    return status;
}

static void dhcp_interface_state_change(NX_DHCP *dhcp_ptr, UINT iface_index, UCHAR new_state)
{

    if (iface_index == 0)
    {  
        if (new_state == NX_DHCP_STATE_BOUND) 
        {
            bound0 = NX_TRUE;
        }
    }
    else
    {
        if (new_state == NX_DHCP_STATE_BOUND) 
        {
            bound1 = NX_TRUE;
        }

    }
    return;
}


static ULONG  dhcp_get_dhcp_data(UCHAR *data, UINT size)
{

ULONG   value = 0;

   
    /* Process the data retrieval request.  */
    while (size-- > 0)
    {

        /* Build return value.  */
        value = (value << 8) | *data++;
    }

    /* Return value.  */
    return(value);
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcp_client_secondary_interface_test_application_define(void * first_unused_memory)
#endif
{
    
    printf("NetX Test:   DHCP Client Secondary Interface Test......................N/A!\n"); 
    test_control_return(3);
}     
#endif /* (NX_MAX_PHYSICAL_INTERFACES >= 2) */







