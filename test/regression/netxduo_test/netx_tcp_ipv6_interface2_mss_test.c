/* This NetX test use the second interface send a larger packet with IPv6 address 
   to test the TCP MSS process procedure.  */

#include    "tx_api.h"
#include    "nx_api.h"

extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && (NX_MAX_PHYSICAL_INTERFACES > 1)
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     1

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static CHAR                    rcv_buffer[600];
static INT                     recv_length = 0;

static CHAR                    msg[600];

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
static NXD_ADDRESS             ipv6_address_3;
static NXD_ADDRESS             ipv6_address_4;

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_ipv6_interface2_mss_test_application_define(void *first_unused_memory)
#endif
{
    CHAR       *pointer;
    UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = _nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += _nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1,2,3,5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    status += nx_ip_interface_attach(&ip_0,"Second Interface",IP_ADDRESS(2,2,3,4),0xFFFFFF00UL,  _nx_ram_network_driver_512);
    status += nx_ip_interface_attach(&ip_1,"Second Interface",IP_ADDRESS(2,2,3,5),0xFFFFFF00UL,  _nx_ram_network_driver_512);

    /* Set ipv6 version and address.  */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x10000001;

    ipv6_address_2.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_2.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_2.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[3] = 0x10000002;

    ipv6_address_3.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_3.nxd_ip_address.v6[0] = 0x30010000;
    ipv6_address_3.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_3.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_3.nxd_ip_address.v6[3] = 0x20000003;

    ipv6_address_4.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_4.nxd_ip_address.v6[0] = 0x30010000;
    ipv6_address_4.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_4.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_4.nxd_ip_address.v6[3] = 0x20000004;

    /* Set interfaces' address */
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_2, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_0, 1, &ipv6_address_3, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 1, &ipv6_address_4, 64, NX_NULL);

    if(status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status = nxd_ipv6_enable(&ip_1);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);
    status = nxd_icmp_enable(&ip_1);

    /* Check ARP enable status.  */
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
    UINT       status;
    NX_PACKET   *my_packet1;
    int         i;

    for(i=0;i<600;i++)
    {
        msg[i]=rand();
    }

    /* Print out test information banner.  */
    printf("NetX Test:   TCP IPv6 Interface2 MSS Test..............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
        NX_PROTOCOL_NEXT_HEADER_HOP_BY_HOP, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 600,
        NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Attempt to connect the socket.  */
    tx_thread_relinquish();

    /* Determine if the timeout error occurred.  */
    if((status != NX_SUCCESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Call connect to send a SYN  */ 
    status = _nxd_tcp_client_socket_connect(&client_socket, &ipv6_address_4, 12, 5 * NX_IP_PERIODIC_RATE);

    /* Point to new receive function */
    ip_1.nx_ip_tcp_packet_receive = packet_receive;

    status = nx_packet_allocate(&pool_0, &my_packet1, NX_IPv6_TCP_PACKET, NX_WAIT_FOREVER);

    if((status != NX_SUCCESS))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* create packet */
    memcpy(my_packet1 -> nx_packet_prepend_ptr, &msg[0], 550);
    my_packet1 -> nx_packet_length = 550;
    my_packet1 -> nx_packet_append_ptr = my_packet1 -> nx_packet_prepend_ptr + 550;
    my_packet1 -> nx_packet_ip_version = NX_IP_VERSION_V6;

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Send packet */
    status += nx_tcp_socket_send(&client_socket, my_packet1, 2 * NX_IP_PERIODIC_RATE);

    tx_thread_relinquish();

     if((status != NX_SUCCESS))
     {
         printf("ERROR!\n");
         test_control_return(1);
     }

     if(status)
     {
         error_counter++;
     }

     if(error_counter)
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

static void    thread_1_entry(ULONG thread_input)
{
    UINT       status;
    ULONG      actual_status;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
        NX_PROTOCOL_NEXT_HEADER_HOP_BY_HOP, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 650,
        NX_NULL, thread_1_disconnect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, thread_1_connect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    if(status)
        error_counter++;

}

static void    thread_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void    thread_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if(socket != &server_socket)
        error_counter++;
}

static void    packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

    UINT length;

    /* Data length equal to packet length - 20 */
    length = packet_ptr -> nx_packet_length - 20;

    if(length > client_socket.nx_tcp_socket_connect_mss)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Copy the packet */
    memcpy(&rcv_buffer[recv_length], packet_ptr -> nx_packet_prepend_ptr + 20, length);
    recv_length += length;

    /* Check whether or not the last packet */
    if(length < client_socket.nx_tcp_socket_connect_mss)
    {
        /* The packet is the lastest packet, compare the packet and receive_length */
        if(memcmp(rcv_buffer,msg,packet_ptr -> nx_packet_length) || recv_length != 550)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Point to default function */
        ip_1.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    
    }

    /* Set client_socket's outstangding bytes to 0 */
    client_socket.nx_tcp_socket_tx_outstanding_bytes = 0;

    _nx_tcp_packet_receive(ip_ptr, packet_ptr);

}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_ipv6_interface2_mss_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP IPv6 Interface2 MSS Test..............................N/A\n");

    test_control_return(3);

}
#endif
