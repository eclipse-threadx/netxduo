/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_udp.h"

extern void  test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1;
#endif /* FEATURE_NX_IPV6 */


/* Define the counters used in the demo application...  */

static ULONG                   thread_0_counter;
static ULONG                   thread_1_counter;
static ULONG                   error_counter;
static ULONG                   notify_calls =  0;
static ULONG                   total_packets = 2000;
static ULONG                   modify_packets = 0;
static ULONG                   invalid_packets;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    receive_packet_function(NX_UDP_SOCKET *socket_ptr);
extern UINT    (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
#ifdef FEATURE_NX_IPV6
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
#endif /* FEATURE_NX_IPV6 */
static VOID    udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_basic_processing_test_application_define(void *first_unused_memory)
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
    invalid_packets = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* .  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
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

    /* Check enable status.  */
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

    status = nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL);
    status = nxd_ipv6_address_set(&ip_1, 0, &address_1, 64, NX_NULL);

    total_packets = 4000;
    packet_process_callback = NX_NULL;
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
ULONG       packets_sent, bytes_sent, packets_received, bytes_received, packets_queued, receive_packets_dropped, checksum_errors;


    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Basic Processing Test.................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* Sleep 5 seconds to finish DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */

    /* Filter UDP packet. */
    ip_1.nx_ip_udp_packet_receive = udp_packet_receive;

    /* Let the IP threads and thread 1 execute.    */
    tx_thread_relinquish();

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

    /* Setup the ARP entry for the UDP send.  */
    nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0, 0);

    /* Let other threads run again.  */
    tx_thread_relinquish();

    /* Send 1000 ipv4 packets without checksum.  */
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
        status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

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

    /* Send another 1000 ipv4 packets with checksum enabled.  */
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
        status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

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

    /* Now, disable the checksum.  */
    status =  nx_udp_socket_checksum_disable(&socket_0);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    packet_process_callback = my_packet_process;

    /* Send another 1000 ipv6 packets without checksum enabled.  */
    while ((thread_0_counter < 3000) && (error_counter == 0))
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
        status =  nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);

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

    /* Send another 1000 ipv6 packets with checksum enabled.  */
    while ((thread_0_counter < 4000) && (error_counter == 0))
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
        status =  nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);

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
#endif /* FEATURE_NX_IPV6 */

    /* Get nothing from UDP socket.  */
    status =  nx_udp_socket_info_get(&socket_0, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get UDP socket information.  */
    status =  nx_udp_socket_info_get(&socket_0, &packets_sent, &bytes_sent, &packets_received, &bytes_received, 
                                                &packets_queued, &receive_packets_dropped, &checksum_errors);
    
#ifndef NX_DISABLE_UDP_INFO

    if ((packets_sent != total_packets) || (bytes_sent != total_packets*28))
    {
        error_counter++;
    }
#endif

#if defined(NX_DISABLE_UDP_RX_CHECKSUM)
    /* Modified packets are processed as normal packets. */
    modify_packets = 0;
#elif defined(NX_ENABLE_INTERFACE_CAPABILITY)
    /* Packets with checksum error are dropped by driver directly. */
    if(ip_0.nx_ip_interface[0].nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_UDP_RX_CHECKSUM)
        notify_calls += modify_packets;
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

    /* Check status.  */
    if ((error_counter) || (status) || (thread_0_counter != total_packets) || (thread_1_counter != total_packets - modify_packets) || 
        (packets_received) || (bytes_received) || (packets_queued) || (receive_packets_dropped) || (checksum_errors) || (notify_calls != total_packets))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_IP_INFO
    if (invalid_packets != ip_0.nx_ip_invalid_transmit_packets)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_IP_INFO */

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

    /* Get 4000 packets.  */
    thread_1_counter =  0;
    while (1)
    {

        /* Receive a UDP packet.  */
        status =  nx_udp_socket_receive(&socket_1, &my_packet, 10 * NX_IP_PERIODIC_RATE);

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


#ifdef FEATURE_NX_IPV6
static UINT    my_packet_process(NX_IP * ip_ptr,NX_PACKET * packet_ptr)
{

    /* Check if it is a UDP packet with IPv6 header.  */
    if ((packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6) &&
        (*(packet_ptr -> nx_packet_prepend_ptr + 6) == NX_PROTOCOL_UDP))
    {

        /* Yes it is a UDP packet with IPv6 header.  */
#ifndef NX_DISABLE_UDP_RX_CHECKSUM
        /* Check if checksum field is 0.  */
        if ((*(packet_ptr -> nx_packet_prepend_ptr + 46) == 0) &&
            (*(packet_ptr -> nx_packet_prepend_ptr + 47) == 0))
        {

            /* The checksum field is 0.  */
            error_counter++;
        }
        else
#endif /* NX_DISABLE_UDP_RX_CHECKSUM */
        {

            /* Modify first 1000 packets. Set checksum field to 0.  */
            if (modify_packets < 1000)
            {
                *(packet_ptr -> nx_packet_prepend_ptr + 46) = 0;
                *(packet_ptr -> nx_packet_prepend_ptr + 47) = 0;
                modify_packets++;
            }
        }
    }

    return NX_TRUE;
}
#endif /* FEATURE_NX_IPV6 */


static VOID    udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_PACKET *invalid_pkt_ptr;

    /* Send a UDP packet with no interface. */
    if (nx_packet_copy(packet_ptr, &invalid_pkt_ptr, &pool_0, NX_NO_WAIT))
    {
        error_counter++;
    }
    else
    {

        /* Set interface to NULL. */
#ifdef __PRODUCT_NETXDUO__
        invalid_pkt_ptr -> nx_packet_address.nx_packet_interface_ptr = NX_NULL;
        invalid_packets++;

        /* Send the packet. */
        _nx_ip_packet_send(&ip_0, invalid_pkt_ptr, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL, 
                           0x80, NX_IP_UDP, NX_FRAGMENT_OKAY, IP_ADDRESS(1, 2, 3, 5));
#else
        invalid_pkt_ptr -> nx_packet_ip_interface = NX_NULL;
        invalid_packets++;

        /* Send the packet. */
        _nx_ip_packet_send(&ip_0, invalid_pkt_ptr, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL, 
                           0x80, NX_IP_UDP, NX_FRAGMENT_OKAY);
#endif
    }

    /* Process this packet. */
    _nx_udp_packet_receive(ip_ptr, packet_ptr);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_basic_processing_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   UDP Basic Processing Test.................................N/A\n"); 

    test_control_return(3);  
}      
#endif
