
#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_dhcp_client.h"
#include   "nxd_dhcp_server.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         NX_PACKET_SIZE * 8
                                                               
#define     NX_DHCP_SERVER_IP_ADDRESS_0 IP_ADDRESS(10,0,0,1)   
#define     START_IP_ADDRESS_LIST_0     IP_ADDRESS(10,0,0,2)
#define     END_IP_ADDRESS_LIST_0       IP_ADDRESS(10,0,0,5)


typedef struct DHCP_TEST_STRUCT
{
    char          *dhcp_test_pkt_data;
    int           dhcp_test_pkt_size;
} DHCP_TEST;

#define CLIENT_MSG_COUNT    2
static  DHCP_TEST           dhcp_test[CLIENT_MSG_COUNT];
UINT    client_complete = NX_FALSE;

/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               client_thread;
static NX_PACKET_POOL          client_pool;
static NX_IP                   client_ip;

static TX_THREAD               server_thread;
static NX_PACKET_POOL          server_pool;
static NX_IP                   server_ip;
static NX_DHCP_SERVER          dhcp_server;
static NX_UDP_SOCKET           client_socket;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static CHAR                    *pointer;  

/* Define thread prototypes.  */

static void    server_thread_entry(ULONG thread_input);
static void    client_thread_entry(ULONG thread_input);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_1024(struct NX_IP_DRIVER_STRUCT *driver_req);  
static UINT    nx_dhcp_response_packet_send(NX_UDP_SOCKET *client_socket, UINT packet_number);
static void    dhcp_test_initialize();
           
/* Frame (366 bytes) */
static char discover[366] = {
0x01, 0x01,                                     /* .C.4.... */
0x06, 0x00, 0x42, 0x2a, 0x4c, 0xf5, 0x00, 0x00, /* ..B*L... */
0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x80, 0x86, 0xf2, 0x83, 0x15, 0xd5, /* ........ */
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
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01, /* ..c.Sc5. */
0x01, 0x3d, 0x07, 0x01, 0x80, 0x86, 0xf2, 0x83, /* .=...... */
0x15, 0xd5, 0x0c, 0x06, 0x57, 0x59, 0x2d, 0x50, /* ....WY-P */
0x53, 0x54, 0x3c, 0x08, 0x4d, 0x53, 0x46, 0x54, /* ST<.MSFT */
0x20, 0x35, 0x2e, 0x30, 0x37, 0x0c, 0x01, 0x0f, /*  5.07... */
0x03, 0x06, 0x2c, 0x2e, 0x2f, 0x1f, 0x21, 0x79, /* ..,./.!y */
0xf9, 0x2b, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, /* .+...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};

static int discover_size = 304;

/* Frame (385 bytes) */
static char request[385] = {
0x01, 0x01,                                     /* .C.GO... */
0x06, 0x00, 0x42, 0x2a, 0x4c, 0xf5, 0x04, 0x00, /* ..B*L... */
0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x80, 0x86, 0xf2, 0x83, 0x15, 0xd5, /* ........ */
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
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01, /* ..c.Sc5. */
0x03, 0x3d, 0x07, 0x01, 0x80, 0x86, 0xf2, 0x83, /* .=...... */
0x15, 0xd5, 0x32, 0x04, 0x0a, 0x00, 0x00, 0x02, /* ..2..... */
0x36, 0x04, 0x0a, 0x00, 0x00, 0x01, 0x0c, 0x06, /* 6....... */
0x57, 0x59, 0x2d, 0x50, 0x53, 0x54, 0x51, 0x14, /* WY-PSTQ. */
0x00, 0x00, 0x00, 0x57, 0x59, 0x2d, 0x50, 0x53, /* ...WY-PS */
0x54, 0x2e, 0x66, 0x63, 0x69, 0x2e, 0x73, 0x6d, /* T.fci.sm */
0x69, 0x2e, 0x61, 0x64, 0x3c, 0x08, 0x4d, 0x53, /* i.ad<.MS */
0x46, 0x54, 0x20, 0x35, 0x2e, 0x30, 0x37, 0x0c, /* FT 5.07. */
0x01, 0x0f, 0x03, 0x06, 0x2c, 0x2e, 0x2f, 0x1f, /* ....,./. */
0x21, 0x79, 0xf9, 0x2b, 0x00, 0x00, 0x00, 0x01, /* !y.+.... */
0x00                                            /* . */
};

static int request_size = 323;


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_server_improper_term_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the client thread.  */
    tx_thread_create(&client_thread, "thread client", client_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the server thread.  */
    tx_thread_create(&server_thread, "thread server", server_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;
    
    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Client.  */
    status = nx_ip_create(&client_ip, "DHCP Client", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &client_pool, 
                          _nx_ram_network_driver_1024, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;
    
    /* Create an IP instance for the DHCP Server.  */
    status = nx_ip_create(&server_ip, "DHCP Server", NX_DHCP_SERVER_IP_ADDRESS_0, 0xFFFFFF00UL, &server_pool, 
                          _nx_ram_network_driver_1024, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for DHCP Client IP.  */
    status =  nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;
    
    /* Enable ARP and supply ARP cache memory for DHCP Server IP.  */
    status =  nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&client_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
    
    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&server_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&client_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&server_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    return;
}

/* Define the test threads.  */

void    server_thread_entry(ULONG thread_input)
{

UINT        status;
UINT        iface_index;
UINT        addresses_added;

    printf("NetX Test:   DHCP Server Improper Termination Test.....................");

    /* Check for earlier errors.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create the DHCP Server.  */
    status =  nx_dhcp_server_create(&dhcp_server, &server_ip, pointer, DEMO_STACK_SIZE,  "DHCP Server", &server_pool);

    pointer = pointer + DEMO_STACK_SIZE;
    
    /* Check for errors creating the DHCP Server. */
    if (status)
        error_counter++;

    /* Load the assignable DHCP IP addresses for the first interface.  */
    iface_index = 0;

    status = nx_dhcp_create_server_ip_address_list(&dhcp_server, iface_index, START_IP_ADDRESS_LIST_0, 
                                                   END_IP_ADDRESS_LIST_0, &addresses_added);

    /* Check for errors creating the list. */
    if (status)
    {
        error_counter++;
    }

    /* Verify all the addresses were added to the list. */
    if (addresses_added != 4)
    {
        error_counter++;
    }

    /* Start DHCP Server task.  */
    status = nx_dhcp_server_start(&dhcp_server);

    /* Check for errors starting up the DHCP server.  */
    if (status)
    {
        error_counter++;
    }

    while(!client_complete)
        tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);

    /* Check that the server did not receive a valid request */
    if (dhcp_server.nx_dhcp_requests_received > 0)
    {
        error_counter++;
    }

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

    return;
}


/* This thread task simulates DHCP Client sending requests. */
void    client_thread_entry(ULONG thread_input)
{                      

NX_PACKET   *my_packet;
UINT        i;
ULONG      actual_status;
UINT       status;


    /* Check for earlier errors.  */
    if(error_counter)
    {
        client_complete = NX_TRUE;
        return;
    }

#ifdef FEATURE_NX_IPV6
    /* Sleep 4 seconds to finish DAD.  */
   tx_thread_sleep(4 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&server_ip, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status...*/
    if(status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }

    /* Load up the Client messages. */
    dhcp_test_initialize();

    status = nx_udp_socket_create(&client_ip, &client_socket, "Client Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&client_socket, 68, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }

    /* Act as the DHCP Client to send DHCP discover and request packets.  */
    for (i = 0; i < CLIENT_MSG_COUNT; i++ )
    {

        /* Send the DHCP client packet.  */
        status = nx_dhcp_response_packet_send(&client_socket,  i);

        /* Check status.  */
        if (status)
        {        
            error_counter++; 
        }  

        /* Receive a UDP packet.  */
        status =  nx_udp_socket_receive(&client_socket, &my_packet, NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status)
        {

            if (i == 1)
            {

                /* This is correct. The Client should not get a message because the server rejected the request packet. */
            }
            else /* i == 0*/
            {
                /* There should be a response to the discovery message, so this is an error. */
                error_counter++;
                continue;
            }
            
        }
        else
        {
            nx_packet_release(my_packet);
        }

    }

    status = nx_udp_socket_unbind(&client_socket);

    /* Delete the UDP socket.  */
    status |=  nx_udp_socket_delete(&client_socket);

    /* Check status.  */
    if (status)
    {        
        error_counter++;
    }

    client_complete = NX_TRUE;
}


static UINT   nx_dhcp_response_packet_send(NX_UDP_SOCKET *client_socket, UINT packet_number)
{

UINT        status;
NX_PACKET   *client_packet;



    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&client_pool, &client_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return status;
    }

    memset(client_packet -> nx_packet_prepend_ptr, 0, (client_packet -> nx_packet_data_end - client_packet -> nx_packet_prepend_ptr));

    /* Write the DHCP Client messages into the packet payload!  */
    memcpy(client_packet -> nx_packet_prepend_ptr, 
           dhcp_test[packet_number].dhcp_test_pkt_data, 
           dhcp_test[packet_number].dhcp_test_pkt_size); 

    /* Adjust the write pointer.  */
    client_packet -> nx_packet_length =  dhcp_test[packet_number].dhcp_test_pkt_size; 
    client_packet -> nx_packet_append_ptr =  client_packet -> nx_packet_prepend_ptr + client_packet -> nx_packet_length;

    /* Send the UDP packet with the correct port.  */
    status =  nx_udp_socket_send(client_socket, client_packet, IP_ADDRESS(255,255,255,255), 67);
    /* Check the status.  */
    if (status)      
    {
        error_counter++;
        nx_packet_release(client_packet);         
    }

    return status;
}

static void dhcp_test_initialize()
{
    dhcp_test[0].dhcp_test_pkt_data = &discover[0];
    dhcp_test[0].dhcp_test_pkt_size = discover_size;  
    dhcp_test[1].dhcp_test_pkt_data = &request[0];
    dhcp_test[1].dhcp_test_pkt_size = request_size;  


}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_server_improper_term_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NetX DHCP Server Improper Termination Test................N/A\n"); 

    test_control_return(3);  
}      
#endif
