/* Here are the test points. 
 * socket's port is not equal to the source port
 * multi threads suspend for the packet
 * udp queue is full
 * */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_udp.h"

extern void  test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4) 
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static TX_THREAD               thread_2;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1;
#endif /* FEATURE_NX_IPV6 */

UINT                           packet_count;

/* The 2 ports will hashed to the same index. */
#define PORT_1           0x00000100
#define PORT_2           0x00008100

#define QUEUE_SIZE       5

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_2_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    my_udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_packet_receive_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    packet_count = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_2, "thread 2", thread_2_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 256*20);
    pointer = pointer + 256*20;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 traffic.  */
    status += nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    /* Enable ICMP processing for both IP instances.  */
    status +=  nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

    /* Set source and destination address with global address. */    
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010DB8;
    address_0.nxd_ip_address.v6[1] = 0x00010001;
    address_0.nxd_ip_address.v6[2] = 0x021122FF;
    address_0.nxd_ip_address.v6[3] = 0xFE334456;

    address_1.nxd_ip_version = NX_IP_VERSION_V6;
    address_1.nxd_ip_address.v6[0] = 0x20010DB8;
    address_1.nxd_ip_address.v6[1] = 0x00010001;
    address_1.nxd_ip_address.v6[2] = 0x021122FF;
    address_1.nxd_ip_address.v6[3] = 0xFE334499;

    status += nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &address_1, 64, NX_NULL);

#endif /* FEATURE_NX_IPV6 */

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
UINT        free_port;
UINT        port;
INT         i;


    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Packet Receive Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* Sleep 5 seconds to finish DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#else
    tx_thread_sleep(NX_IP_PERIODIC_RATE);
#endif

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        test_control_return(1);
    }

    /* Pickup the first free port for 0x88.  */
    status =  nx_udp_free_port_find(&ip_0, 0x88, &free_port);

    /* Check status.  */
    if ((status) || (free_port != 0x88))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test checksum enable/disable before bind. */

    status = nx_udp_socket_checksum_disable(&socket_0);
    if(status != NX_NOT_BOUND)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_checksum_enable(&socket_0);
    if(status != NX_NOT_BOUND)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get socket port before bind. */
    status = nx_udp_socket_port_get(&socket_0, &port);
    if(status != NX_NOT_BOUND)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Receive packet before bind. */
    status = nx_udp_socket_receive(&socket_0, &my_packet, NX_IP_PERIODIC_RATE/10);
    if(status != NX_NOT_BOUND)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get the port that is actually bound to this socket.  */
    status =  nx_udp_socket_port_get(&socket_0, &free_port);

    /* Check status.  */
    if ((status) || (free_port != 0x88))
    {

        printf("ERROR!\n");
        test_control_return(31);
    }

    /* Setup the ARP entry for the UDP send.  */
    nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0, 0);


#ifdef FEATURE_NX_IPV6
    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_udp_socket_source_send(&socket_0, my_packet, &address_1, PORT_1, 0);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send packet to an invalid port (PORT_2) which is mapped to the same index with PORT_1. */
    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_udp_socket_source_send(&socket_0, my_packet, &address_1, PORT_2, 0);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_suspend(&thread_0);
#endif

    
    tx_thread_resume(&thread_1);
    i = -2;
    while(i < QUEUE_SIZE)
    {
        i++;

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, 5 * NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), PORT_1, 0);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    tx_thread_suspend(&thread_0);


    /* Send a packet whose udp_header_word_1 will be modified. */

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), PORT_1, 0);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), PORT_1, 0);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_resume(&thread_1);
    /* Suspend  to trigger _nx_udp_receive_cleanup. */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 2 * NX_IP_PERIODIC_RATE);
    tx_thread_suspend(&thread_0);


    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_0);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_0);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
    

static void    thread_1_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
#ifdef FEATURE_NX_IPV6
ULONG       src_address;
UINT        src_port;
#endif
UINT        i;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, QUEUE_SIZE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, PORT_1, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* Receive a UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 7 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    
    status = nx_udp_packet_info_extract(my_packet, &src_address, NX_NULL, &src_port, NX_NULL);
    if(status != NX_INVALID_PACKET)
    {
        printf("ERROR!\n");
        test_control_return(1);

    }

    if(memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet.  */
    status =  nx_packet_release(my_packet);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    tx_thread_suspend(&thread_1);
    i = 0;
    while(i < QUEUE_SIZE)
    {
        i++;

        status =  nx_udp_socket_receive(&socket_1, &my_packet, 2 * NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        if(memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28))
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Release the packet.  */
        status =  nx_packet_release(my_packet);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

    }

    /* Queue is empty, no more packet. */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 2 * NX_IP_PERIODIC_RATE);
    if(status != NX_NO_PACKET)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_resume(&thread_0);

    /* Change udp receive function to my routine. */ 
    ip_1.nx_ip_udp_packet_receive = my_udp_packet_receive;

    tx_thread_suspend(&thread_1);

    /* Suspend  to trigger _nx_udp_receive_cleanup. */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 2 * NX_IP_PERIODIC_RATE);

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_1);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_1);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_resume(&thread_0);


}

static void    thread_2_entry(ULONG thread_input)
{

#ifdef FEATURE_NX_IPV6
UINT        status;
NX_PACKET   *my_packet;


    /* Receive a UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 7 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_NO_PACKET)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    tx_thread_resume(&thread_0);

#endif

}

static void    my_udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_UDP_HEADER   *udp_header_ptr;
    
    if(packet_count == 0)
    {
        udp_header_ptr = (NX_UDP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
        /* Change the udp packet length to maximum.*/
        udp_header_ptr -> nx_udp_header_word_1 = udp_header_ptr -> nx_udp_header_word_1 | 0xFFFF0000;
        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
        _nx_udp_packet_receive(ip_ptr, packet_ptr);
        packet_count++;
    }
    else
    {
        socket_1.nx_udp_socket_id = 1234;
        _nx_udp_packet_receive(ip_ptr, packet_ptr);
        socket_1.nx_udp_socket_id = NX_UDP_ID;
        ip_1.nx_ip_udp_packet_receive = _nx_udp_packet_receive;
    }
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_packet_receive_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Packet Receive Test...................................N/A\n");
    test_control_return(3);
}
#endif /* __PRODUCT_NETXDUO__ */
