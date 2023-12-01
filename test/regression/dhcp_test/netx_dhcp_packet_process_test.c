/* The DHCPREQUEST message MUST use the same value in the DHCP message header's 'secs' field and be sent to the same IP 
 * broadcast address as the original DHCPDISCOVER message.
 * rfc 2131, page 16, 3.1 Client-server interaction - allocating a network address
 */
#include   "tx_api.h"
#include   "nx_api.h"
#include   "netx_dhcp_clone_function.h"
#include   "nx_ipv4.h"
#include   "nxd_dhcp_client.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         NX_PACKET_SIZE * 8

#define     NX_DHCP_SERVER_IP_ADDRESS_0 IP_ADDRESS(10,0,0,1)   
#define     START_IP_ADDRESS_LIST_0     IP_ADDRESS(10,0,0,10)
#define     END_IP_ADDRESS_LIST_0       IP_ADDRESS(10,0,0,19)

#define     NX_DHCP_SUBNET_MASK_0       IP_ADDRESS(255,255,255,0)
#define     NX_DHCP_DEFAULT_GATEWAY_0   IP_ADDRESS(10,0,0,1)
#define     NX_DHCP_DNS_SERVER_0        IP_ADDRESS(10,0,0,1)


/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               client_thread;
static NX_PACKET_POOL          client_pool;
static NX_IP                   client_ip;
static NX_DHCP                 dhcp_client;

static TX_THREAD               server_thread;
static NX_PACKET_POOL          server_pool;
static NX_IP                   server_ip;
static NX_UDP_SOCKET           server_socket;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static CHAR                    *pointer;

static UINT                    test_done = NX_FALSE;

/* Define thread prototypes.  */

static void    server_thread_entry(ULONG thread_input);
static void    client_thread_entry(ULONG thread_input);
static UINT   nx_dhcp_response_packet_send(NX_UDP_SOCKET *server_socket_ptr, INT packet_number);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

typedef struct DHCP_RESPONSE_STRUCT
{
    UCHAR          *dhcp_response_pkt_data;
    UINT            dhcp_response_pkt_size;
} DHCP_RESPONSE;

static DHCP_RESPONSE            dhcp_response[3];

/* Frame (342 bytes) */
static unsigned char offer[342] = {
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x15, /* ........ */
0x5d, 0x02, 0x1e, 0x0f, 0x08, 0x00, 0x45, 0x10, /* ].....E. */
0x01, 0x48, 0x00, 0x00, 0x00, 0x00, 0x80, 0x11, /* .H...... */
0x76, 0xec, 0xc0, 0xa8, 0x02, 0x01, 0xff, 0xff, /* v....... */
0xff, 0xff, 0x00, 0x43, 0x00, 0x44, 0x01, 0x34, /* ...C.D.4 */
0xb0, 0x32, 0x02, 0x01, 0x06, 0x00, 0x22, 0x33, /* .2...."3 */
0x44, 0x6f, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, /* Do...... */
0x00, 0x00, 0xc0, 0xa8, 0x02, 0xc5, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, /* ........ */
0x22, 0x33, 0x44, 0x57, 0x00, 0x00, 0x00, 0x00, /* "3DW.... */
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
0x53, 0x63, 0x35, 0x01, 0x02, 0x36, 0x04, 0xc0, /* Sc5..6.. */
0xa8, 0x02, 0x01, 0x33, 0x04, 0x00, 0x00, 0x1b, /* ...3.... */
0xfe, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, /* ........ */
0x04, 0xc0, 0xa8, 0x02, 0x01, 0x06, 0x04, 0xc0, /* ........ */
0xa8, 0x02, 0x01, 0x2a, 0x04, 0x7c, 0x6c, 0x14, /* ...*.|l. */
0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_ntp_option_test_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&client_ip, "DHCP Client", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;
    
    /* Create an IP instance for the DHCP Server.  */
    status = nx_ip_create(&server_ip, "DHCP Server", NX_DHCP_SERVER_IP_ADDRESS_0, 0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);

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
UINT        i = 0;
UINT        index;
NX_PACKET   *my_packet;
UCHAR       *option_ptr;
UINT        option_size;

    printf("NetX Test:   DHCP Client NTP Option test...............................");

#ifdef __PRODUCT_NETXDUO__
    /* Update the MAC address.  */
    status = nx_ip_interface_physical_address_set(&server_ip, 0, 0x00000015, 0x5d021e0f, NX_TRUE);

    /* Check for errors. */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#else
    server_ip.nx_ip_interface[0].nx_interface_physical_address_msw = 0x00000015;
    server_ip.nx_ip_interface[0].nx_interface_physical_address_lsw = 0x5d021e0f;
#endif

    /* Create a  socket as the  server.  */
    status = nx_udp_socket_create(&server_ip, &server_socket, "Socket Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,  NX_IP_TIME_TO_LIVE, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status =  nx_udp_socket_bind(&server_socket, NX_DHCP_SERVER_UDP_PORT, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    dhcp_response[0].dhcp_response_pkt_data = (char*)offer;
    dhcp_response[0].dhcp_response_pkt_size = sizeof(offer);
    dhcp_response[1].dhcp_response_pkt_data = offer;
    dhcp_response[1].dhcp_response_pkt_size = sizeof(offer);
    dhcp_response[2].dhcp_response_pkt_data = offer;
    dhcp_response[2].dhcp_response_pkt_size = sizeof(offer);

    /* Wait for Client requests (DISCOVER and REQEUST).  */
    for (i = 0; i < 3; i++)
    {

        /* Receive DHCP message.  */
        status =  nx_udp_socket_receive(&server_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);



        /* Release the packet.  */
        nx_packet_release(my_packet);

        /* Send response.  */
        status = nx_dhcp_response_packet_send(&server_socket, i);

        switch (i)
        {
        case 0:
            client_pool.nx_packet_pool_available = NX_FALSE;
            break;
        case 1:
            client_pool.nx_packet_pool_available = NX_TRUE;
            dhcp_client.nx_dhcp_ip_ptr->nx_ip_interface[0].nx_interface_physical_address_msw = 17;
            dhcp_client.nx_dhcp_ip_ptr->nx_ip_interface[0].nx_interface_physical_address_lsw = 123456;
            break;
        case 2:
            dhcp_client.nx_dhcp_ip_ptr->nx_ip_interface[0].nx_interface_physical_address_msw = 18;
            break;
        default:
            break;
        }

        if (status)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    } 

    /* Wait for test done.  */
    while(test_done == NX_FALSE)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
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

/* Define the test threads.  */

void    client_thread_entry(ULONG thread_input)
{

UINT        status;
UINT        i = 0;
ULONG       ntp_server_address;
UINT        ntp_server_address_size = 4;

#ifdef __PRODUCT_NETXDUO__
    /* Update the MAC address.  */
    status = nx_ip_interface_physical_address_set(&client_ip, 0, 0x00000011, 0x22334457, NX_TRUE);

    /* Check for errors. */
    if (status)
    {
        error_counter++;
    }
#else
    client_ip.nx_ip_interface[0].nx_interface_physical_address_msw = 0x00000011;
    client_ip.nx_ip_interface[0].nx_interface_physical_address_lsw = 0x22334457;
#endif

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    if (status)
    {
        error_counter++;
    }

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

    /* Request NTP.  */
    status =  nx_dhcp_user_option_request(&dhcp_client, NX_DHCP_OPTION_NTP_SVR);
    if (status)
    {
        error_counter++;
    }

    for (i = 0; i < 2; i++)
    {
        /* Start the DHCP Client.  */
        status =  nx_dhcp_start(&dhcp_client);
        if (status)
        {
            error_counter++;
        }

        tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

        /* Stopping the DHCP client. */
        nx_dhcp_stop(&dhcp_client);
    }

    /* All done. Return resources to NetX and ThreadX. */
    nx_dhcp_delete(&dhcp_client);

    test_done = NX_TRUE;

    return;
}


static UINT   nx_dhcp_response_packet_send(NX_UDP_SOCKET *server_socket_ptr, INT packet_number)
{
UINT        status;
NX_PACKET   *response_packet;

    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&server_pool, &response_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Write the  response messages into the packet payload!  */
    memcpy(response_packet -> nx_packet_prepend_ptr, dhcp_response[packet_number].dhcp_response_pkt_data + (14 + 20 + 8),
           dhcp_response[packet_number].dhcp_response_pkt_size - (14 + 20 + 8));

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length =  dhcp_response[packet_number].dhcp_response_pkt_size - (14 + 20 + 8);
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;

    /* Fake the transaction id.  */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_xid = 0x2233446f;

    /* Send the packet.  */
    status = nx_udp_socket_send(server_socket_ptr, response_packet, IP_ADDRESS(255, 255, 255, 255), NX_DHCP_CLIENT_UDP_PORT);

    /* Check the status.  */
    if (status)
    {
        nx_packet_release(response_packet);
    }

    return status;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_ntp_option_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Client NTP Option test...............................N/A\n"); 

    test_control_return(3);  
}      
#endif