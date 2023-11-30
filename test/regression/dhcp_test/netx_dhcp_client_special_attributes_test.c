/* Testing the multiple interface DHCP Client */

/* Test the DHCP CLient with 2 physical interfaces, set NX_DHCP_CLIENT_MAX_INTERFACES = 1
   and run the demo. It sets several attributes (request IP, skip discovery message,
   set state change callback, before setting the interface to 1. The DHCP Client should
   transfer those attributes to the new active interface, and clear them on the old interface.*/


#include    "tx_api.h"
#include    "nx_api.h"
#include    "nxd_dhcp_client.h"

#define     DEMO_STACK_SIZE         4096
#define     PACKET_PAYLOAD          1518
                  
#define REQUEST_CLIENT_IP
#ifdef  REQUEST_CLIENT_IP
#define CLIENT_IP_ADDRESS          IP_ADDRESS(192,1,1,66)
#endif

/* Define the ThreadX, NetX object control blocks...  */

NX_UDP_SOCKET           server_socket;
TX_THREAD               client_thread;
TX_THREAD               server_thread;
NX_PACKET_POOL          client_pool;
NX_PACKET_POOL          server_pool;
NX_IP                   client_ip;
NX_IP                   server_ip;


/* Define the NetX FTP object control block.  */
NX_DHCP                dhcp_client;

typedef struct DHCP_RESPONSE_STRUCT
{
    char          *dhcp_response_pkt_data;
    int           dhcp_response_pkt_size;
} DHCP_RESPONSE;

#define NUM_RESPONSES      2
static  DHCP_RESPONSE      dhcp_response[NUM_RESPONSES];

/* Define the counters used in the demo application...  */

static  UINT            error_counter = 0;
static  UINT            client_running = NX_FALSE;


#define SERVER_PORT      67


/* Replace the 'ram' driver with your Ethernet driver. */
extern  VOID nx_driver_ram_driver(NX_IP_DRIVER*); 

void    server_thread_entry(ULONG thread_input);
void    client_thread_entry(ULONG thread_input);

static  UINT   nx_dhcp_response_packet_send(NX_UDP_SOCKET *server_socket, UINT port, INT packet_number);
static  void   dhcp_test_initialize();
static  void   dhcp_interface_state_change1(NX_DHCP *dhcp_ptr, UCHAR new_state);

extern   void  test_control_return(UINT);
extern   void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);


/* Note that the network is 192.2.2.0 and the MAC address is 11 22 33 44 56
   because there are four entities (server 2 interfaces, client 2 interfaces
   and the ram driver increases the MAC sequentially starting from
   11 22 33 44 56. */
static char offer_response[300] = {

0x02, 0x01, 0x06, 0x00, 0x2a, 0x3e, /* {.....T. */
0xF0, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
#ifdef REQUEST_CLIENT_IP
0x00, 0x00, 0xc0, 0x01, 0x01, 0x43, 0xc0, 0x01, /* ........ */
#else
0x00, 0x00, 0xc0, 0x01, 0x01, 0xF7, 0xc0, 0x01, /* ........ */
#endif
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
#ifdef REQUEST_CLIENT_IP
0x00, 0x00, 0xc0, 0x01, 0x01, 0x43, 0xc0, 0x01, /* ........ */
#else
0x00, 0x00, 0xc0, 0x01, 0x01, 0xf7, 0xc0, 0x01, /* ........ */
#endif
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
void    netx_dhcp_cilent_special_attributes_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
UCHAR   *pointer;

    
    /* Setup the working pointer.  */
    pointer =  (UCHAR *) first_unused_memory;

    /* Initialize NetX.  */
    nx_system_initialize();

    /* Set up the DHCP Server. */

    /* Create the main server thread.  */
    status = tx_thread_create(&server_thread, "Server thread ", server_thread_entry, 0,  
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
    status =  nx_packet_pool_create(&server_pool, "Server Packet Pool", 700, 
                                    pointer , 700*10);

    pointer = pointer + 700*10;
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
        return;
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
        return;
    }

    /* Create a packet pool for the client.  */
    status =  nx_packet_pool_create(&client_pool, "Client Packet Pool", PACKET_PAYLOAD, pointer, 25*PACKET_PAYLOAD);
    
        /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }
    
    pointer =  pointer + 25*PACKET_PAYLOAD;

    /* Create an IP instance for the client.  */
    status = nx_ip_create(&client_ip, " Client0 IP Instance", IP_ADDRESS(0,0,0,0), 0xFFFFFF00UL, 
                                                &client_pool, _nx_ram_network_driver_1024, pointer, 2048, 1);
    
        /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }
    
    pointer = pointer + 2048;

    status = nx_ip_interface_attach(&client_ip, "Client1 IP", IP_ADDRESS(0,0,0,0), 0xFFFFFF00UL, _nx_ram_network_driver_1024);
    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }

    /* Enable ARP and supply ARP cache memory for the Client IP.  */
    nx_arp_enable(&client_ip, (void *) pointer, 1024);

    pointer = pointer + 1024;

    /* Enable UDP for client IP instance.  */
    nx_udp_enable(&client_ip);
    nx_icmp_enable(&client_ip);
    

    return;

}

/* Define the FTP client thread.  */

void    client_thread_entry(ULONG thread_input)
{

UINT        status;



#ifdef REQUEST_CLIENT_IP
ULONG       requested_ip;
UINT        skip_discover_message = NX_FALSE;
#endif

    tx_thread_sleep(20);

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp0");
    if (status)
        error_counter++;


    status = nx_dhcp_clear_broadcast_flag(&dhcp_client, NX_TRUE);

    /* Set the client IP if the host is configured to do so. */
    if (status)
        error_counter++;

#ifdef REQUEST_CLIENT_IP
    requested_ip = (ULONG)CLIENT_IP_ADDRESS;

    /* Request a specific IP address using the DHCP client address option. */
    status = nx_dhcp_request_client_ip(&dhcp_client, requested_ip, skip_discover_message);
    if (status)
        error_counter++;

#endif

    /* Register state change variable.  */
    status =  nx_dhcp_state_change_notify(&dhcp_client, dhcp_interface_state_change1);
    if (status)
        error_counter++;

    /* Note that we call this after setting the stage change notify and clear broadcast service.
       DHCP CLient defaults these to the primary interface unless the dhcp interface has been set.
       If this host is configured for multiple interfaces, this call will reset these attributes on
       both interfaces. */
    status = nx_dhcp_set_interface_index(&dhcp_client, 1);
    if (status)
        error_counter++;

    /* Start the DHCP Client.  */
    status =  nx_dhcp_start(&dhcp_client);
    if (status)
        error_counter++;

    while(dhcp_client.nx_dhcp_interface[1].nx_dhcp_state != NX_DHCP_STATE_BOUND)
    {
        tx_thread_sleep(100);
    }

    nx_dhcp_release(&dhcp_client);

}


/* Define the helper FTP server thread.  */
void    server_thread_entry(ULONG thread_input)
{

UINT         status;
NX_PACKET   *my_packet;
UINT         i;

    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Client ARP Probe Multiple Interface Test1............\n");

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a  socket as the  server.  */
    status = nx_udp_socket_create(&server_ip, &server_socket, "Socket Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,  NX_IP_TIME_TO_LIVE, 5);

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

                printf("ERRO7R!\n");
                error_counter++;
            }       
            else
            {
                printf("\nRECVd %dth packet\n", i);

                /* Release the packet.  */
                nx_packet_release(my_packet);
               
               printf("Server sending response back. \n");
               status = nx_dhcp_response_packet_send(&server_socket, 68, i);
            }
        }    
        else
        {

#ifdef NX_DHCP_CLIENT_SEND_ARP_PROBE
            /* Wait for the dhcp client to start the ARP probe process. */
            while (dhcp_client.nx_dhcp_interface[1].nx_dhcp_probe_count == 0)
                tx_thread_sleep(10);
#endif

            printf("No one should send a Probe reply\n");
        }
        
        /* Check status.  */
        if (status)
        {        

            printf("ERROR8!\n");
            error_counter++; 
        } 

        
        /* Advance the index for the next response. */
        i++;
    } 

    /* Check status.  */
    if (status)
    {

        printf("ERRO7R!\n");
        error_counter++;
    }    
     /* Should get one more message from the Client, a DECLINE message.     */
    status =  nx_udp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {

        printf("ERRO7R!\n");
        error_counter++;
    }       


    printf("All done, waiting for client to go away\n");

    /* Wait for the client to terminate the connection. */
    while(client_running != NX_TRUE)
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
NXD_ADDRESS ip_address;

    ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    ip_address.nxd_ip_address.v4 = 0xFFFFFFFF;


    printf("Sending %dth  response\n", packet_number);
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

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length =  dhcp_response[packet_number].dhcp_response_pkt_size;
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;

    /* Send the  packet with the correct port.  */
    status = nxd_udp_socket_source_send(server_socket_ptr, response_packet, &ip_address, 68, 1);

    /* Check the status.  */
    if (status)      
        nx_packet_release(response_packet);         

    return status;
}

void dhcp_interface_state_change1(NX_DHCP *dhcp_ptr, UCHAR new_state)
{

//UINT dhcp_state;

    //dhcp_state = (UINT)new_state;

    
    return;
}


