/* This NetX test concentrates on the raw packet IP send/receive operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_udp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *ip_0_memory_ptr;
static CHAR                   *ip_1_memory_ptr;
static CHAR                   *arp_0_memory_ptr;
static CHAR                   *arp_1_memory_ptr;
static NX_TCP_SOCKET           tcp_server_socket;
static NX_TCP_SOCKET           tcp_client_socket;
static NX_UDP_SOCKET           udp_server_socket;
static NX_UDP_SOCKET           udp_client_socket;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_raw_packet_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    ip_0_memory_ptr =  NX_NULL;
    ip_1_memory_ptr =  NX_NULL;
    arp_0_memory_ptr =  NX_NULL;
    arp_1_memory_ptr =  NX_NULL;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
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

    /* Create IP instances.  */
    ip_0_memory_ptr =  pointer;
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    ip_1_memory_ptr =  pointer;
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 10), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    arp_0_memory_ptr =  pointer;
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    arp_1_memory_ptr =  pointer;
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
}


#ifndef NX_DISABLE_FRAGMENTATION
static UCHAR buff[256];
#endif /* NX_DISABLE_FRAGMENTATION */

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_address;
ULONG       mask;
ULONG       value;
ULONG       ip_total_packets_sent;
ULONG       ip_total_bytes_sent;
ULONG       ip_total_packets_received;
ULONG       ip_total_bytes_received;
ULONG       ip_invalid_packets;
ULONG       ip_receive_packets_dropped;
ULONG       ip_receive_checksum_errors;
ULONG       ip_send_packets_dropped;
ULONG       ip_total_fragments_sent;
ULONG       ip_total_fragments_received;
NX_PACKET   *my_packet;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Raw Packet Test........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup the IP address.  */
    status =  nx_ip_address_get(&ip_0, &ip_address, &mask);

    /* Check for an error.  */
    if ((status) || (ip_address != IP_ADDRESS(1, 2, 3, 9)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the IP address.  */
    status =  nx_ip_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 13), 0xFFFFFF00UL);
    status += nx_ip_address_get(&ip_0, &ip_address, &mask);

    /* Check for an error.  */
    if ((status) || (ip_address != IP_ADDRESS(1, 2, 3, 13)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete both IP instances.  */
    status =  nx_ip_delete(&ip_0);
    status += nx_ip_delete(&ip_1);

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create IP instances.  */
    status =  nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    ip_0_memory_ptr, 2048, 1);
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    ip_1_memory_ptr, 2048, 1);
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status +=  nx_arp_enable(&ip_0, (void *) arp_0_memory_ptr, 1024);
    status +=  nx_arp_enable(&ip_1, (void *) arp_1_memory_ptr, 1024);

    /* Enable TCP for IP instances. */
    status += nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Enable UDP for IP instances. */
    status += nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check the status of the IP instances.  */
    status +=  nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &value, NX_IP_PERIODIC_RATE);

    /* Check for an error.  */
    if ((status) || (value != NX_IP_INITIALIZE_DONE))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Call driver directly.  */
    status =  nx_ip_driver_direct_command(&ip_0, NX_LINK_GET_STATUS, &value);

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable and disable forwarding.  */
    status =  nx_ip_forwarding_enable(&ip_0);
    status += nx_ip_forwarding_disable(&ip_0);

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
#ifndef NX_DISABLE_FRAGMENTATION
    /* Enable and disable fragmenting.  */
    status =  nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_disable(&ip_0);
    status +=  nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);
    status += nx_ip_fragment_disable(&ip_1);
    status += nx_ip_fragment_enable(&ip_1);

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Set the gateway address.  */
    status =  nx_ip_gateway_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 87));

    /* Check for an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get IP info.  */
    status =  nx_ip_info_get(&ip_0, &ip_total_packets_sent, 
                                    &ip_total_bytes_sent,
                                    &ip_total_packets_received,
                                    &ip_total_bytes_received,
                                    &ip_invalid_packets,
                                    &ip_receive_packets_dropped,
                                    &ip_receive_checksum_errors,
                                    &ip_send_packets_dropped,
                                    &ip_total_fragments_sent,
                                    &ip_total_fragments_received);

    /* Check status.  */
    if ((status) || (ip_total_packets_sent) || (ip_total_bytes_sent) || (ip_total_packets_received) ||
        (ip_total_bytes_received) || (ip_invalid_packets) || (ip_receive_packets_dropped) || (ip_receive_checksum_errors) ||
        (ip_send_packets_dropped) || (ip_total_fragments_sent) || (ip_total_fragments_received))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable raw IP packet sending and receiving. This can only be done between two NetX nodes.  */
    status =  nx_ip_raw_packet_enable(&ip_0);
    status += nx_ip_raw_packet_enable(&ip_1);

#ifndef NX_DISABLE_FRAGMENTATION
    /* Allocate a packet.  */
    status +=  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Write ABCs into the packet payload!  */
    status += nx_packet_data_append(my_packet, buff, sizeof(buff), &pool_0, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the raw IP packet.  */
    status =  nx_ip_raw_packet_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_FRAGMENTATION */

    /* Allocate another packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;
    
#ifdef __PRODUCT_NETXDUO__
    /* Send the second raw IP packet.  */
    status =  nx_ip_raw_packet_source_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0, NX_IP_NORMAL);
#else
    status =  nx_ip_raw_packet_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL);
#endif /* __PRODUCT_NETXDUO__ */

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate another packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;
    
    /* Send the third raw IP packet.  */
    status =  nx_ip_raw_packet_send(&ip_0, my_packet, IP_ADDRESS(1, 2, 3, 5), NX_IP_NORMAL);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
#ifndef NX_DISABLE_FRAGMENTATION
    /* Now, pickup the three raw packets that should be queued on the other IP instance.  */
    status =  nx_ip_raw_packet_receive(&ip_1, &my_packet, NX_IP_PERIODIC_RATE);
    status += nx_packet_release(my_packet); 
    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_FRAGMENTATION */
     
    /* Receive the second packet.  */
    status =  nx_ip_raw_packet_receive(&ip_1, &my_packet, NX_IP_PERIODIC_RATE);
    status += nx_packet_release(my_packet); 
    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Receive the third packet.  */
    status =  nx_ip_raw_packet_receive(&ip_1, &my_packet, NX_IP_PERIODIC_RATE);
    status += nx_packet_release(my_packet); 
    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
   
    /* Attempt to receive a packet on an empty queue.... should be an error.  */
    status =  nx_ip_raw_packet_receive(&ip_1, &my_packet, NX_NO_WAIT);

    /* Check status.  */
    if (status != NX_NO_PACKET)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check TCP connection when raw packet is enabled. */
    /* Create a server socket.  */
    status = nx_tcp_socket_create(&ip_1, &tcp_server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                  NX_NULL, NX_NULL);

    /* Setup this thread to listen.  */
    status += nx_tcp_server_socket_listen(&ip_1, 12, &tcp_server_socket, 5, NX_NULL);

    /* Create a client socket.  */
    status += nx_tcp_socket_create(&ip_0, &tcp_client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                   NX_NULL, NX_NULL);

    /* Bind the socket.  */
    status += nx_tcp_client_socket_bind(&tcp_client_socket, 12, NX_WAIT_FOREVER);

    /* Connect to server. */
    nx_tcp_client_socket_connect(&tcp_client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_NO_WAIT);

    /* If accept return successfully, then it handles an illegal option length for MSS.  */
    status += nx_tcp_server_socket_accept(&tcp_server_socket, NX_IP_PERIODIC_RATE);

    /* Check if client is in establish state. */
    status += nx_tcp_socket_state_wait(&tcp_client_socket, NX_TCP_ESTABLISHED, NX_NO_WAIT);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, 5 * NX_IP_PERIODIC_RATE);

    /* Append data. */
    status += nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_NO_WAIT);

    /* Send a packet from server to client. */
    status += nx_tcp_socket_send(&tcp_server_socket, my_packet, NX_NO_WAIT);

    /* Receive packet from server. */
    status += nx_tcp_socket_receive(&tcp_client_socket, &my_packet, 5 * NX_IP_PERIODIC_RATE);

    /* Check status and received data. */
    if(status || memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28))
        status++;

    /* Release packet. */
    status += nx_packet_release(my_packet);

    /* Disconnect. */
    nx_tcp_socket_disconnect(&tcp_server_socket, NX_NO_WAIT);
    nx_tcp_socket_disconnect(&tcp_client_socket, NX_NO_WAIT);  
    nx_tcp_server_socket_unaccept(&tcp_server_socket);

    /* Check if both sockets are closed. */
    status += nx_tcp_socket_state_wait(&tcp_client_socket, NX_TCP_CLOSED, NX_NO_WAIT);
    status += nx_tcp_socket_state_wait(&tcp_client_socket, NX_TCP_CLOSED, NX_NO_WAIT);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Check UDP connection when raw packet is enabled. */
    /* Create two UDP sockets.  */
    status = nx_udp_socket_create(&ip_0, &udp_client_socket, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    status += nx_udp_socket_create(&ip_1, &udp_server_socket, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Bind the UDP socket to the IP port.  */
    status +=  nx_udp_socket_bind(&udp_client_socket, 0x89, NX_NO_WAIT);
    status +=  nx_udp_socket_bind(&udp_server_socket, 0x89, NX_NO_WAIT);

    /* Allocate a packet.  */
    status +=  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, 5 * NX_IP_PERIODIC_RATE);

    /* Append data. */
    status += nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_NO_WAIT);

    /* Send the UDP packet.  */
    status +=  nx_udp_socket_send(&udp_client_socket, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Receive a UDP packet.  */
    status +=  nx_udp_socket_receive(&udp_server_socket, &my_packet, 5 * NX_IP_PERIODIC_RATE);    

    /* Check status and received data. */
    if(status || memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28))
        status++;

    /* Unbind the UDP socket.  */
    status +=  nx_udp_socket_unbind(&udp_client_socket);
    status +=  nx_udp_socket_unbind(&udp_server_socket);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }       


    /* Disable the raw IP capability on both IP instances.  */
    status =  nx_ip_raw_packet_disable(&ip_0);
    status += nx_ip_raw_packet_disable(&ip_1);

    /* Check status.  */
    if (status)
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
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_raw_packet_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Raw Packet Test........................................N/A\n"); 

    test_control_return(3);  
}      
#endif

