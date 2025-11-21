/* This NetX test concentrates on the IP Delete operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"
#include   "nx_igmp.h"
#include   "nx_arp.h"
#include   "nx_rarp.h"
#include   "nx_udp.h"
#include   "nx_tcp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_IP                   ip_2;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static NX_TCP_SOCKET           client_socket;
static NX_UDP_SOCKET           socket_0;
static UCHAR                   ip_stack[2048];
static UCHAR                   ip_stack_1[2048];
static UCHAR                   ip_stack_2[2048];
static UCHAR                   arp_stack[1024];
static UCHAR                   ping_done;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    _nx_ram_network_driver_test(NX_IP_DRIVER *driver_req_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_delete_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    /* Initialize the counters. */
    error_counter = 0;
    ping_done = NX_FALSE;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,
            pointer, DEMO_STACK_SIZE,
            3, 3, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    ip_stack, sizeof(ip_stack), 1);

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, arp_stack, sizeof(arp_stack));

    if (status)
        error_counter++;

    /* Enable TCP processing for IP instances.  */
    status = nx_tcp_enable(&ip_0);

    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);

    if (status)
        error_counter++;
}


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;
UINT        old_threshold;
#ifdef FEATURE_NX_IPV6
NXD_ADDRESS ipv6_address;
#endif /* FEATURE_NX_IPV6 */


    /* Print out test information banner.  */
    printf("NetX Test:   IP Delete Operation Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the IP instance.  */
    status =  nx_ip_delete(&ip_0);

    /* Check for an error.  */
    if (status != NX_SOCKETS_BOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&client_socket);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the IP instance.  */
    status =  nx_ip_delete(&ip_0);

    /* Check for an error.  */
    if (status != NX_SOCKETS_BOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

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

    /* Delete the IP instance.  */
    status =  nx_ip_delete(&ip_0);

    /* Check for an error.  */
    if (status != NX_SOCKETS_BOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&client_socket);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the IP instance.  */
    status =  nx_ip_delete(&ip_0);

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          ip_stack, sizeof(ip_stack), 1);

    /* Create IP instances.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(2, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                           ip_stack_1, sizeof(ip_stack_1), 1);

    /* Create IP instances.  */
    status += nx_ip_create(&ip_2, "NetX IP Instance 2", IP_ADDRESS(3, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                           ip_stack_2, sizeof(ip_stack_2), 1);

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete IP instances.  */
    status =  nx_ip_delete(&ip_2);
    status +=  nx_ip_delete(&ip_1);
    status +=  nx_ip_delete(&ip_0);

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check RAW queue is cleared after IP is deleted. */
    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          ip_stack, sizeof(ip_stack), 1);

    /* Enable RAW traffic.  */
    status += nx_ip_raw_packet_enable(&ip_0);

    /* Allocate a packet. */
    status += nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(packet_ptr, "ABC", 3, &pool_0, NX_WAIT_FOREVER);

    /* Send the RAW packet. */
    status += nx_ip_raw_packet_send(&ip_0, packet_ptr, IP_ADDRESS(1, 2, 3, 9), NX_IP_NORMAL);

    /* Delete the IP instance.  */
    status += nx_ip_delete(&ip_0);

    /* Check for error and pool available.  */
    if ((status) || (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_LOOPBACK_INTERFACE
    /* Check RAW queue is cleared after IP is deleted. */
    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          ip_stack, sizeof(ip_stack), 1);

    /* Enable RAW traffic.  */
    status += nx_ip_raw_packet_enable(&ip_0);

    /* Allocate a packet. */
    status += nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(packet_ptr, "ABC", 3, &pool_0, NX_WAIT_FOREVER);

    /* Send the RAW packet. */
    status += nx_ip_raw_packet_send(&ip_0, packet_ptr, IP_ADDRESS(127, 0, 0, 1), NX_IP_NORMAL);

    /* Delete the IP instance.  */
    status += nx_ip_delete(&ip_0);

    /* Check for error and pool available.  */
    if ((status) || (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_LOOPBACK_INTERFACE  */


#ifndef NX_ENABLE_ICMP_ADDRESS_CHECK
    /* Check ICMP queue is cleared after IP is deleted. */
    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          ip_stack, sizeof(ip_stack), 1);

    /* Enable ICMP.  */
    status += nx_icmp_enable(&ip_0);

    /* Allocate a packet. */
    status += nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(packet_ptr, "ABCEFGHIJKLMNOPQRSTUVWXYZ", 26, &pool_0, NX_WAIT_FOREVER);

    /* Disable preemption temporarily. */
    tx_thread_preemption_change(&ntest_0, 0, &old_threshold);

    /* Call _nx_icmp_packet_receive to directly receive the packet.  */
    _nx_icmp_packet_receive(&ip_0, packet_ptr);

    /* Delete the IP instance.  */
    status += nx_ip_delete(&ip_0);

    /* Restore preemption. */
    tx_thread_preemption_change(&ntest_0, old_threshold, &old_threshold);

    /* Check for error and pool available.  */
    if ((status) || (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_ENABLE_ICMP_ADDRESS_CHECK */


    /* Check IGMP queue is cleared after IP is deleted. */
    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          ip_stack, sizeof(ip_stack), 1);

    /* Enable IGMP.  */
    status += nx_igmp_enable(&ip_0);

    /* Allocate a packet. */
    status += nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(packet_ptr, "ABCEFGHIJKLMNOPQRSTUVWXYZ", 26, &pool_0, NX_WAIT_FOREVER);

    /* Disable preemption temporarily. */
    tx_thread_preemption_change(&ntest_0, 0, &old_threshold);

    /* Call _nx_igmp_packet_receive to directly receive the packet.  */
    _nx_igmp_packet_receive(&ip_0, packet_ptr);

    /* Delete the IP instance.  */
    status += nx_ip_delete(&ip_0);

    /* Restore preemption. */
    tx_thread_preemption_change(&ntest_0, old_threshold, &old_threshold);

    /* Check for error and pool available.  */
    if ((status) || (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Check TCP queue is cleared after IP is deleted. */
    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          ip_stack, sizeof(ip_stack), 1);

    /* Enable TCP.  */
    status += nx_tcp_enable(&ip_0);

    /* Allocate a packet. */
    status += nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(packet_ptr, "ABCEFGHIJKLMNOPQRSTUVWXYZ", 26, &pool_0, NX_WAIT_FOREVER);

    /* Disable preemption temporarily. */
    tx_thread_preemption_change(&ntest_0, 0, &old_threshold);

    /* Call _nx_tcp_packet_receive to directly receive the packet.  */
    _nx_tcp_packet_receive(&ip_0, packet_ptr);

    /* Delete the IP instance.  */
    status += nx_ip_delete(&ip_0);

    /* Restore preemption. */
    tx_thread_preemption_change(&ntest_0, old_threshold, &old_threshold);

    /* Check for error and pool available.  */
    if ((status) || (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Check UDP queue is cleared after IP is deleted. */
    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          ip_stack, sizeof(ip_stack), 1);

    /* Enable UDP.  */
    status += nx_tcp_enable(&ip_0);

    /* Allocate a packet. */
    status += nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(packet_ptr, "ABCEFGHIJKLMNOPQRSTUVWXYZ", 26, &pool_0, NX_WAIT_FOREVER);

    /* Disable preemption temporarily. */
    tx_thread_preemption_change(&ntest_0, 0, &old_threshold);

    /* Call _nx_udp_packet_receive to directly receive the packet.  */
    _nx_udp_packet_receive(&ip_0, packet_ptr);

    /* Delete the IP instance.  */
    status += nx_ip_delete(&ip_0);

    /* Restore preemption. */
    tx_thread_preemption_change(&ntest_0, old_threshold, &old_threshold);

    /* Check for error and pool available.  */
    if ((status) || (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Check ARP queue is cleared after IP is deleted. */
    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          ip_stack, sizeof(ip_stack), 1);

    /* Enable ARP.  */
    status += nx_arp_enable(&ip_0, arp_stack, sizeof(arp_stack));

    /* Allocate a packet. */
    status += nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(packet_ptr, "ABCEFGHIJKLMNOPQRSTUVWXYZ", 26, &pool_0, NX_WAIT_FOREVER);

    /* Disable preemption temporarily. */
    tx_thread_preemption_change(&ntest_0, 0, &old_threshold);

    /* Call _nx_arp_packet_deferred_receive to directly receive the packet.  */
    _nx_arp_packet_deferred_receive(&ip_0, packet_ptr);

    /* Delete the IP instance.  */
    status += nx_ip_delete(&ip_0);

    /* Restore preemption. */
    tx_thread_preemption_change(&ntest_0, old_threshold, &old_threshold);

    /* Check for error and pool available.  */
    if ((status) || (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Check RARP queue is cleared after IP is deleted. */
    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          ip_stack, sizeof(ip_stack), 1);

    /* Enable RARP.  */
    status += nx_rarp_enable(&ip_0);
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Allocate a packet. */
    status += nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    status += nx_packet_data_append(packet_ptr, "ABCEFGHIJKLMNOPQRSTUVWXYZ", 26, &pool_0, NX_WAIT_FOREVER);

    /* Disable preemption temporarily. */
    tx_thread_preemption_change(&ntest_0, 0, &old_threshold);

    /* Call _nx_rarp_packet_deferred_receive to directly receive the packet.  */
    _nx_rarp_packet_deferred_receive(&ip_0, packet_ptr);

    /* Delete the IP instance.  */
    status += nx_ip_delete(&ip_0);

    /* Restore preemption. */
    tx_thread_preemption_change(&ntest_0, old_threshold, &old_threshold);

    /* Check for error and pool available.  */
    if ((status) || (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* Test packet queued on ND cache. */
    /* Create IP instances.  */
    nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                 ip_stack, sizeof(ip_stack), 1);

    nxd_ipv6_enable(&ip_0);
    nxd_icmp_enable(&ip_0);
    nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[0] = 0xFE800000;
    ipv6_address.nxd_ip_address.v6[1] = 0;
    ipv6_address.nxd_ip_address.v6[2] = 0;
    ipv6_address.nxd_ip_address.v6[3] = 1;
    nxd_icmp_ping(&ip_0, &ipv6_address, "", 0, &packet_ptr, NX_NO_WAIT);

    /* Delete the IP instance.  */
    nx_ip_delete(&ip_0);

    /* Check for pool available.  */
    if (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* FEATURE_NX_IPV6 */


#ifdef __PRODUCT_NETXDUO__
    /* Check ICMP suspension list is cleared after IP is deleted. */
    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          ip_stack, sizeof(ip_stack), 1);

    /* Enable ARP and ICMP.  */
    status += nx_arp_enable(&ip_0, arp_stack, sizeof(arp_stack));
    status += nx_icmp_enable(&ip_0);

    /* Resume thread 1 and let it start to ping. */
    tx_thread_resume(&ntest_1);

    /* Delete the IP instance.  */
    status += nx_ip_delete(&ip_0);

    /* Check for error and pool available.  */
    if ((status) || (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available) ||
        (ping_done == NX_FALSE))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* __PRODUCT_NETXDUO__ */

    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_test,
                          ip_stack, sizeof(ip_stack), 1);

    /* Delete IP with sleep in driver. */
    status += nx_ip_delete(&ip_0);
    if (status || error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}


static void    ntest_1_entry(ULONG thread_input)
{
NX_PACKET  *packet_ptr;
UINT        status;

    /* Ping an address not existed. */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 4), "", 0, &packet_ptr, NX_WAIT_FOREVER);

    if (status == NX_SUCCESS)
    {

        /* No response should be received. */
        printf("ERROR!\n");
        test_control_return(1);
    }

    ping_done = NX_TRUE;
}

static void  _nx_ram_network_driver_test(NX_IP_DRIVER *driver_req_ptr)
{
    if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_UNINITIALIZE)
    {
        if (tx_thread_sleep(1))
        {
            error_counter++;
        }
    }
    _nx_ram_network_driver_256(driver_req_ptr);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_delete_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Delete Operation Test..................................N/A\n"); 

    test_control_return(3);  
}      
#endif
