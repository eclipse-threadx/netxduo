/* This NetX IPsec basic test using AES.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);
#if defined(FEATURE_NX_IPV6) && defined(NX_TUNNEL_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nx_ipv6.h"
#include   "nx_tunnel.h"
#define     DEMO_STACK_SIZE         4096

#define MSG "abcdefghijklmnopqrstuvwxyz"

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;

static ULONG                   notify_calls = 0;

NXD_ADDRESS                    ipv6_address_1;
NXD_ADDRESS                    ipv6_address_2;
NXD_ADDRESS                    ipv6_address_3;
NXD_ADDRESS                    ipv6_address_4;

/* Define the counters used in the demo application...  */

static ULONG                   thread_0_counter =  0;
static ULONG                   thread_1_counter =  0;
static ULONG                   error_counter =     0;
static CHAR                    rcv_buffer[200];


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);

static void    receive_packet_function(NX_UDP_SOCKET *socket_ptr);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

static NX_ADDRESS_SELECTOR   address_selector_0;
static NX_ADDRESS_SELECTOR   address_selector_1;
static NX_TUNNEL             tunnel_0;
static NX_TUNNEL             tunnel_1;

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_tunnel_ipv4_ipv6_basic_test_application_define(void *first_unused_memory)
#endif
{

    CHAR    *pointer;
    UINT    status; 

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    thread_0_counter =  0;
    thread_1_counter =  0;
    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;


    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1,2,3,5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;


    status += nx_ip_interface_attach(&ip_0,"Second Interface",IP_ADDRESS(2,2,3,4),0xFFFFFF00UL,  _nx_ram_network_driver_1500);
    status += nx_ip_interface_attach(&ip_1,"Second Interface",IP_ADDRESS(2,2,3,5),0xFFFFFF00UL,  _nx_ram_network_driver_1500);

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

    status += nxd_ipv6_address_set(&ip_0, 1, &ipv6_address_3, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 1, &ipv6_address_4, 64, NX_NULL);

    if (status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status = nxd_ipv6_enable(&ip_1);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);
    status = nxd_icmp_enable(&ip_1);

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    status = nx_tunnel_enable(&ip_0);
    status += nx_tunnel_enable(&ip_1);

    /* Check Tunnel enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

    UINT        status;
    NX_PACKET   *my_packet;
    CHAR        *msg = MSG;
    UINT        free_port;

    /* Print out some test information banners.  */
    printf("NetX Test:   TUNNEL UDP IPV4_6 Basic Processing Test.......");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create TUNNEL.  */
    address_selector_0.nx_selector_src_address_start.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_0.nx_selector_src_address_start.nxd_ip_address.v4 = 0x01000000;

    address_selector_0.nx_selector_src_address_end.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_0.nx_selector_src_address_end.nxd_ip_address.v4 = 0x02000000;

    address_selector_0.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_0.nx_selector_dst_address_start.nxd_ip_address.v4 = 0x01000000;

    address_selector_0.nx_selector_dst_address_end.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_0.nx_selector_dst_address_end.nxd_ip_address.v4 = 0x02000000;

    /* add tunnel address.  */
    address_selector_0.nx_selector_src_tunnel_address = ipv6_address_3;
    address_selector_0.nx_selector_dst_tunnel_address = ipv6_address_4;

    /* Set up TUNNEL */
    status = nx_tunnel_create(&ip_0, &tunnel_0,NX_IP_VERSION_V6,address_selector_0);

    if (status)
        error_counter++;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);

    /* Get the port that is actually bound to this socket.  */
    status =  nx_udp_socket_port_get(&socket_0, &free_port);

    /* Check status.  */
    if ((status) || (free_port != 0x88))
    {

        printf("ERROR!\n");
        test_control_return(31);
    }

    /* Disable checksum logic for this socket.  */
    status =  nx_udp_socket_checksum_disable(&socket_0);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup the ARP entry for the UDP send.  */
    nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(2, 2, 3, 5), 0, 0);

    /* Let other threads run again.  */
    tx_thread_relinquish();

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &msg[0], 26);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  26;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 26;

    /* Suspend thread1 */
    tx_thread_suspend(&thread_1);

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Determine if the status is valid.  */
    if (status)
    {
        error_counter++;
        nx_packet_release(my_packet);
    }

    tx_thread_resume(&thread_1);    

    tx_thread_relinquish();   

}


static void    thread_1_entry(ULONG thread_input)
{

    UINT            status;
    NX_PACKET       *packet_ptr;
    ULONG           recv_length = 0;

    /* Create TUNNEL.  */
    address_selector_1.nx_selector_src_address_start.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_1.nx_selector_src_address_start.nxd_ip_address.v4 = 0x01000000;

    address_selector_1.nx_selector_src_address_end.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_1.nx_selector_src_address_end.nxd_ip_address.v4 = 0x02000000;

    address_selector_1.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_1.nx_selector_dst_address_start.nxd_ip_address.v4 = 0x01000000;

    address_selector_1.nx_selector_dst_address_end.nxd_ip_version = NX_IP_VERSION_V4;
    address_selector_1.nx_selector_dst_address_end.nxd_ip_address.v4 = 0x02000000;

    /* add tunnel address.  */
    address_selector_1.nx_selector_src_tunnel_address = ipv6_address_4;
    address_selector_1.nx_selector_dst_tunnel_address = ipv6_address_3;

    /* Set up TUNNEL */
    status = nx_tunnel_create(&ip_1, &tunnel_1,NX_IP_VERSION_V6,address_selector_1);

    if (status)
        error_counter++;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        test_control_return(1);
    }

    /* Register the receive notify function.  */
    status =  nx_udp_socket_receive_notify(&socket_1, receive_packet_function);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, 0x89, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        test_control_return(1);
    }

    /* Supsend thread 0.  */
    tx_thread_resume(&thread_0);

    tx_thread_relinquish();   

    /* Receive a UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &packet_ptr, TX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;
    else
    {
        if(packet_ptr -> nx_packet_length == 0)
            error_counter++;

        memcpy(&rcv_buffer[recv_length], packet_ptr -> nx_packet_prepend_ptr, packet_ptr -> nx_packet_length);
        recv_length = packet_ptr -> nx_packet_length;

        /* Release the packet.  */
        nx_packet_release(packet_ptr);
    }

    if(recv_length != 26)
        error_counter++;

    if(memcmp(rcv_buffer, (void*)MSG, recv_length))
        error_counter++;

    /* Determine if the test was successful.  */
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

static void    receive_packet_function(NX_UDP_SOCKET *socket_ptr)
{

    if (socket_ptr == &socket_1)
        notify_calls++;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_tunnel_ipv4_ipv6_basic_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   TUNNEL UDP IPV4_6 Basic Processing Test...................N/A\n");

    test_control_return(3);

}
#endif /* NX_TUNNEL_ENABLE */