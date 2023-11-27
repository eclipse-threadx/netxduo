/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && (NX_MAX_PHYSICAL_INTERFACES > 1)
#include    "nx_udp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;


/* Define the counters used in the demo application...  */

static ULONG                   thread_0_counter;
static ULONG                   thread_1_counter;

static ULONG                   error_counter;
static ULONG                   notify_calls =  0;

static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
static NXD_ADDRESS             ipv6_address_3;
static NXD_ADDRESS             ipv6_address_4;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    receive_packet_function(NX_UDP_SOCKET *socket_ptr);
extern void    test_control_return(UINT status);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_ipv6_interface2_test_1_test_application_define(void *first_unused_memory)
#endif
{

    CHAR    *pointer;
    UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    thread_0_counter =  0;
    thread_1_counter =  0;
    error_counter =  0;
    notify_calls =  0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* .  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        3, 3, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

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

    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2,2,3,4), 0xFFFFFF00UL, _nx_ram_network_driver_512);
    status += nx_ip_interface_attach(&ip_1, "Second Interface", IP_ADDRESS(2,2,3,5), 0xFFFFFF00UL, _nx_ram_network_driver_512);

    if(status)
        error_counter++;

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

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    /* Enable ICMP for IP Instance 0 and 1.  */
    status += nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Set interfaces' address */
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_2, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_0, 1, &ipv6_address_3, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 1, &ipv6_address_4, 64, NX_NULL);

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

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
    ULONG       udp_packets_sent, udp_bytes_sent, udp_packets_received, udp_bytes_received, udp_invalid_packets, udp_receive_packets_dropped, udp_checksum_errors;
    ULONG       packets_sent, bytes_sent, packets_received, bytes_received, packets_queued, receive_packets_dropped, checksum_errors;


    /* Print out some test information banners.  */
    printf("NetX Test:   UDP IPv6 Interface2 Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

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

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);

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
        test_control_return(1);
    }

    /* Disable checksum logic for this socket.  */
    status =  nx_udp_socket_checksum_disable(&socket_0);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


#ifndef NX_DISABLE_IPV6_DAD
    /* Try to send before DAD done. */
    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the UDP packet.  */
    status =  nxd_udp_socket_source_send(&socket_0, my_packet, &ipv6_address_4, 0x89, 0);

    if (status != NX_NO_INTERFACE_ADDRESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    nx_packet_release(my_packet);


    /* Sleep for DAD */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* NX_DISABLE_IPV6_DAD */

    /* Let other threads run.  */
    tx_thread_resume(&thread_1);
    tx_thread_relinquish();

    /* Send 1000 packets without checksum.  */
    thread_0_counter =  0;
    while ((thread_0_counter < 1000) && (error_counter == 0))
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            break;

        /* Write ABCs into the packet payload!  */
        memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

        /* Adjust the write pointer.  */
        my_packet -> nx_packet_length =  28;
        my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

        /* Send the UDP packet.  */
        status =  nxd_udp_socket_send(&socket_0, my_packet, &ipv6_address_4, 0x89);

        /* Check status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Increment thread 0's counter.  */
        thread_0_counter++;

        /* Relinquish to thread 1 so it can pickup the message.  */
        tx_thread_relinquish();
    }

    /* Now, enable the checksum.  */
    status =  nx_udp_socket_checksum_enable(&socket_0);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send another 1000 packets with checksum enabled.  */
    while ((thread_0_counter < 2000) && (error_counter == 0))
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            break;

        /* Write ABCs into the packet payload!  */
        memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

        /* Adjust the write pointer.  */
        my_packet -> nx_packet_length =  28;
        my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

        /* Send the UDP packet.  */
        status =  nxd_udp_socket_send(&socket_0, my_packet, &ipv6_address_4, 0x89);

        /* Check status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Increment thread 0's counter.  */
        thread_0_counter++;

        /* Relinquish to thread 1 so it can pickup the message.  */
        tx_thread_relinquish();
    }

    /* Get UDP socket information.  */
    status =  nx_udp_socket_info_get(&socket_0, &packets_sent, &bytes_sent, &packets_received, &bytes_received, 
        &packets_queued, &receive_packets_dropped, &checksum_errors);

#ifndef NX_DISABLE_TCP_INFO

    if ((packets_sent != 2000) || (bytes_sent != 2000*28))
    {
        error_counter++;
    }
#endif
    /* Check status.  */
    if ((error_counter) || (status) || (thread_0_counter != 2000) || (thread_1_counter != 2000) || 
        (packets_received) || (bytes_received) || (packets_queued) || (receive_packets_dropped) || (checksum_errors))
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

    /* Get UDP information.  */
    status =  nx_udp_info_get(&ip_0, &udp_packets_sent, &udp_bytes_sent, &udp_packets_received, &udp_bytes_received, 
        &udp_invalid_packets, &udp_receive_packets_dropped, &udp_checksum_errors);

#ifndef NX_DISABLE_TCP_INFO
    if ((udp_packets_sent != 2000) || (udp_bytes_sent != 2000*28))
    {
        error_counter++;
    }
#endif
    /* Check status.  */
    if ((error_counter) || (status) || (thread_0_counter != 2000) || (thread_1_counter != 2000) || 
        (udp_packets_received) || (udp_bytes_received) || (udp_invalid_packets) || (udp_receive_packets_dropped) || (udp_checksum_errors) || (notify_calls != 2000))
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

    UINT        status;
    UINT        protocol, port, interface_index;
    NX_PACKET   *my_packet;
    NXD_ADDRESS    ipv6_address;


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

    /* Get 1000 packets.  */
    thread_1_counter =  0;
    while (1)
    {

        /* Receive a UDP packet.  */
        status =  nx_udp_socket_receive(&socket_1, &my_packet, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            break;

        /* Get the source IP and port.  */
        status =  nxd_udp_source_extract(my_packet, &ipv6_address, &port);

        /* Check status.  */
        if ((status)|| (port != 0x88) ||
            (ipv6_address.nxd_ip_version != NX_IP_VERSION_V6)||
            (ipv6_address.nxd_ip_address.v6[0] != ipv6_address_3.nxd_ip_address.v6[0])||
            (ipv6_address.nxd_ip_address.v6[1] != ipv6_address_3.nxd_ip_address.v6[1])||
            (ipv6_address.nxd_ip_address.v6[2] != ipv6_address_3.nxd_ip_address.v6[2])||
            (ipv6_address.nxd_ip_address.v6[3] != ipv6_address_3.nxd_ip_address.v6[3]))
            break;     

        /* Get the source IP and port.  */
        status =  nxd_udp_packet_info_extract(my_packet, &ipv6_address, &protocol, &port, &interface_index);
                          
        /* Check status.  */
        if ((status)|| (port != 0x88) || (protocol != 0x11) || (interface_index != 1) ||
            (ipv6_address.nxd_ip_version != NX_IP_VERSION_V6)||
            (ipv6_address.nxd_ip_address.v6[0] != ipv6_address_3.nxd_ip_address.v6[0])||
            (ipv6_address.nxd_ip_address.v6[1] != ipv6_address_3.nxd_ip_address.v6[1])||
            (ipv6_address.nxd_ip_address.v6[2] != ipv6_address_3.nxd_ip_address.v6[2])||
            (ipv6_address.nxd_ip_address.v6[3] != ipv6_address_3.nxd_ip_address.v6[3]))
            break;   

        /* Release the packet.  */
        status =  nx_packet_release(my_packet);

        /* Check status.  */
        if (status != NX_SUCCESS)
            break;

        /* Increment thread 1's counter.  */
        thread_1_counter++;
    }

    /* Get another 1000 packets.  */
    while (thread_1_counter < 2000)
    {

        /* Receive a UDP packet.  */
        status =  nx_udp_socket_receive(&socket_1, &my_packet, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            break;

        /* Release the packet.  */
        status =  nx_packet_release(my_packet);

        /* Check status.  */
        if (status != NX_SUCCESS)
            break;

        /* Increment thread 1's counter.  */
        thread_1_counter++;
    }

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_1);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_1);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
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
void           netx_udp_ipv6_interface2_test_1_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   UDP IPv6 Interface2 Test..................................N/A\n");

    test_control_return(3);

}
#endif
