/* Testing the multiple interface DHCP Client */

/* Test with NX_DHCP_CLIENT_SEND_ARP_PROBE enabled on the DHCP Client.  Only using
   one interface at present.  To get this to work with a RAM driver, the 'DHCP server'
   assigns its own address to the DHCP Client. When the Client sends the ARP probe
   the server will automatically respond. On receiving this ARP message, the Client
   IP stores it in its table. On the next expiration between sending probes, the Client
   checks the ARP table, finds this entry and declares the IP address is not unique.
   It sends a DECLINE message and start again in the INIT state. */

   // jlc to do
   // need to add a way to confirm DECLINE is sent e.g. add declines_recvd to the struct? 
   // need a way to 'stop' the client test. Right now it spins endlessly.
   // test on NetX DUo 5.11 with the new ARP send probe/handle conflict logic


#include    "tx_api.h"
#include    "nx_api.h"
#ifdef __PRODUCT_NETXDUO__
#include    "nxd_dhcp_client.h"
#else
#include     "nx_dhcp.h"
#endif

#define     DEMO_STACK_SIZE         4096
#define     PACKET_PAYLOAD          1518
                  
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

#define NUM_RESPONSES      3
static  DHCP_RESPONSE      dhcp_response[NUM_RESPONSES];

/* Define the counters used in the demo application...  */

static  UINT            error_counter = 0;
static  UINT            client_running = NX_FALSE;
static  UINT            state_changes[2] = {0,0};
static  UINT renews[2] = {0,0};
static  UINT rebinds[2] = {0,0};
static  UINT bounds[2] = {0,0};

#define SERVER_PORT      67


/* Replace the 'ram' driver with your Ethernet driver. */
extern  VOID nx_driver_ram_driver(NX_IP_DRIVER*); 

void    server_thread_entry(ULONG thread_input);
void    client_thread_entry(ULONG thread_input);

static  UINT   nx_dhcp_response_packet_send(NX_UDP_SOCKET *server_socket, UINT port, INT packet_number);
static  void   dhcp_test_initialize();
static  UINT   send_arp_reply(NX_DHCP *dhcp_ptr, UINT iface_index);
static  void   dhcp_state_change(NX_DHCP *dhcp_ptr, UCHAR new_state);
static  void   dhcp_interface_state_change0(NX_DHCP *dhcp_ptr, UCHAR new_state);
static  void   dhcp_interface_state_change1(NX_DHCP *dhcp_ptr, UCHAR new_state);

extern   void  test_control_return(UINT);
extern   void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);


static char offer_response[300] = {

0x02, 0x01, 0x06, 0x00, 0x31, 0x9D, /* {.....T. */
0x58, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0xc0, 0x02, 0x02, 0x01, 0xc0, 0x02, /* ........    192.2.2.1*/
//0x00, 0x00, 0xc0, 0x02, 0x02, 0xf7, 0xc0, 0x02, /* ........ '192.2.2.247*/
0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x57, 0x00, 0x00, 0x00, 0x00, /* T....... */
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
0x02, 0x02, 0x01, 0x03, 0x04, 0xc0, 0x02, 0x02, /* ........ */
0x01, 0x06, 0x04, 0xc0, 0x02, 0x02, 0x01, 0xff, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};

static int offer_response_size = 300;

/* Frame (342 bytes) */
static char ack_response[300] = {

0x02, 0x01, 0x06, 0x00, 0x31, 0x9D, /* {.....T. */
0x58, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0xc0, 0x02, 0x02, 0x01, 0xc0, 0x02, /* ........ */
//0x00, 0x00, 0xc0, 0x02, 0x02, 0xf7, 0xc0, 0x02, /* ........ */
0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x57, 0x00, 0x00, 0x00, 0x00, /* T....... */
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
0x04, 0xc0, 0x02, 0x02, 0x01, 0x01, 0x04, 0xff, /* ........ */
0xff, 0xff, 0x00, 0x03, 0x04, 0xc0, 0x02, 0x02, /* ........ */
0x01, 0x06, 0x04, 0xc0, 0x02, 0x02, 0x01, 0xff, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};

static int ack_response_size = 300;

// this isn't used but just leave it here.
static char arp_response[60] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x57, // dest
0x00, 0x0c, 0xf1, 0x7d, 0xca, 0xa6, // source
0x08, 0x06, 
0x00, 0x01, 
0x08, 0x00, 
0x06, 0x04, 0x00, 0x02, 
0x00, 0x0c, 0xf1, 0x7d, 0xca, 0xa6, // source mac - who cares, someone else
0xc0, 0x02, 0x02, 0xF7,             // source IP - node who owns IP address already
0x00, 0x11, 0x22, 0x33, 0x44, 0x57, // target mac - dhcp client mac
0x00, 0x00, 0x00, 0x0,              // target IP - should be zeroes?
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* .\...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00                          /* .... */
};

static int arp_response_size = 60;

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_cilent_arpprobe_fails_test_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&client_ip, "NetX Client IP Instance", IP_ADDRESS(0,0,0,0), 0xFFFFFF00UL, 
                                                &client_pool, _nx_ram_network_driver_1024, pointer, 2048, 1);
    
        /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }
    
    pointer = pointer + 2048;

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



    /* Let the server set up. */
    tx_thread_sleep(30);

#ifdef REQUEST_CLIENT_IP
ULONG       requested_ip;
UINT        skip_discover_message = NX_FALSE;
#endif

    tx_thread_sleep(20);

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp0");
    if (status)
        error_counter++;

    /* Set the client IP if the host is configured to do so. */
#ifdef REQUEST_CLIENT_IP

    requested_ip = (ULONG)CLIENT_IP_ADDRESS;

    /* Request a specific IP address using the DHCP client address option. */
    status = nx_dhcp_request_client_ip(&dhcp_client, requested_ip, skip_discover_message);
    if (status)
        error_counter++;

#endif

    /* Register state change variable.  */
    status =  nx_dhcp_state_change_notify(&dhcp_client, dhcp_state_change);
    if (status)
        error_counter++;
    
    status =  nx_dhcp_interface_state_change_notify(&dhcp_client, 0, dhcp_interface_state_change0);
    if (status)
        error_counter++;
    status =  nx_dhcp_interface_state_change_notify(&dhcp_client, 1, dhcp_interface_state_change1);
    if (status)
        error_counter++;
    
    /* Start the DHCP Client.  */
    status =  nx_dhcp_start(&dhcp_client);
    if (status)
        error_counter++;

    while(client_running == NX_FALSE) 
    {
        tx_thread_sleep(100);
    }

    // jlc add status_interface check on IP address
    // then wait for ****; 
    // if declines != 1; error
    // if state != INIT/SELECTING error

}


/* Define the helper FTP server thread.  */
void    server_thread_entry(ULONG thread_input)
{

UINT         status;
NX_PACKET   *my_packet;
UINT         i;

    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Client ARP Probe Multiple Interface Test1............\n"); // jlc remove the \n

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
            
            /* Wait for the dhcp client to start the ARP probe process. */
            while (dhcp_client.nx_dhcp_interface[0].nx_dhcp_probe_count == 0)
                tx_thread_sleep(10);
            printf("Owner should send the Probe reply\n");
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
 
    dhcp_response[2].dhcp_response_pkt_data = &arp_response[0];
    dhcp_response[2].dhcp_response_pkt_size = arp_response_size ;         

}



static UINT   nx_dhcp_response_packet_send(NX_UDP_SOCKET *server_socket, UINT port, INT packet_number)
{
UINT        status;
NX_PACKET   *response_packet;

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
    status =  nx_udp_socket_send(server_socket, response_packet, 0xFFFFFFFF, 68);
                          

    /* Check the status.  */
    if (status)      
        nx_packet_release(response_packet);         

    return status;
}

UINT send_arp_reply(NX_DHCP *dhcp_ptr, UINT iface_index)
{
  
UINT             status;  
NX_PACKET       *request_ptr;
ULONG           *message_ptr;
NX_IP_DRIVER    driver_request;
NX_IP           *ip_ptr;
NX_INTERFACE    *dhcp_interface;
ULONG lsw, msw, sender_ip_address;

    ip_ptr = dhcp_ptr -> nx_dhcp_ip_ptr;
    
    /* Allocate a packet to build the ARP message in.  */
    status = nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &request_ptr, NX_PHYSICAL_HEADER, NX_NO_WAIT);
    if (status != NX_SUCCESS)
    {

        /* Error getting packet, so just get out!  */
        return status;
    }
      /* Stamp the packet with the outgoing interface information. */
    dhcp_interface = &(ip_ptr -> nx_ip_interface[iface_index]);   
    request_ptr -> nx_packet_ip_interface = dhcp_interface;

    /* Build the ARP request packet.  */

    /* Setup the size of the ARP message.  */
    request_ptr -> nx_packet_length =  28;

    /* Setup the append pointer to the end of the message.  */
    request_ptr -> nx_packet_append_ptr =  request_ptr -> nx_packet_prepend_ptr + 28;

    /* Setup the pointer to the message area.  */
    message_ptr =  (ULONG *) request_ptr -> nx_packet_prepend_ptr;

    /* Write the Hardware type into the message.  */
    *message_ptr =      (ULONG) (1 << 16) | (0x08);
    *(message_ptr+1) =  (ULONG) (6 << 24) | (4 << 16) | 2;
    /* Sender mac address */
    msw = 0x0c; 
    lsw = 0xf17dcaa6;
    *(message_ptr+2) =  (ULONG) (msw << 16) |(lsw >> 16);
    
    /* Rest of sender mac address and sender IP address */
    sender_ip_address = dhcp_ptr -> nx_dhcp_interface[iface_index].nx_dhcp_ip_address;
    *(message_ptr+3) =  (ULONG) ((lsw << 16) | (sender_ip_address >> 16));
    
    /* Target mac address */
    msw = 0x11;
    lsw = 0x22334457;
    *(message_ptr+4) =  (msw << 16) |(lsw >> 16);
    *(message_ptr+4) =  (sender_ip_address << 16) | (msw & NX_LOWER_16_MASK);
    *(message_ptr+5) =  lsw;
    
    /* Target address */
    *(message_ptr+6) =  (ULONG) 0x0;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+1));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+2));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+3));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+4));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+5));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+6));

    /* Send the ARP request to the driver.  */
    driver_request.nx_ip_driver_ptr                  =  ip_ptr;
    driver_request.nx_ip_driver_command              =  NX_LINK_ARP_SEND;
    driver_request.nx_ip_driver_packet               =  request_ptr;
    driver_request.nx_ip_driver_physical_address_msw =  0xFFFFUL;
    driver_request.nx_ip_driver_physical_address_lsw =  0xFFFFFFFFUL;  
    driver_request.nx_ip_driver_interface            =  dhcp_interface;
    (dhcp_interface -> nx_interface_link_driver_entry) (&driver_request);

    return NX_SUCCESS;
}

// jlc this does not get called. Is that correct behavior?
void dhcp_state_change(NX_DHCP *dhcp_ptr, UCHAR new_state)
{

    dhcp_interface_state_change0(dhcp_ptr, new_state);
}

void dhcp_interface_state_change0(NX_DHCP *dhcp_ptr, UCHAR new_state)
{

UINT dhcp_state;

    dhcp_state = (UINT)new_state;


    /* Increment state changes counter.  */
    state_changes[0]++;
    
    if (dhcp_state == NX_DHCP_STATE_RENEWING)
    {
       renews[0]++;
    }
    else if (dhcp_state == NX_DHCP_STATE_REBINDING)
    {
       rebinds[0]++;
    }
    else if (dhcp_state == NX_DHCP_STATE_BOUND)
    {
       bounds[0]++;
    }    
    
    return;
}


void dhcp_interface_state_change1(NX_DHCP *dhcp_ptr, UCHAR new_state)
{

UINT dhcp_state;

    dhcp_state = (UINT)new_state;


    /* Increment state changes counter.  */
    state_changes[1]++;
    
    if (dhcp_state == NX_DHCP_STATE_RENEWING)
    {
       renews[1]++;
    }
    else if (dhcp_state == NX_DHCP_STATE_REBINDING)
    {
       rebinds[1]++;
    }
    else if (dhcp_state == NX_DHCP_STATE_BOUND)
    {
       bounds[1]++;
    }    
    
    return;
}


