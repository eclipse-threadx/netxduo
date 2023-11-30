/* This NetX test use the second interface send a larger packet with IPv6 address 
   to test the TCP MSS process procedure.  */

#include    "tx_api.h"
#include    "nx_api.h"

extern void    test_control_return(UINT status);

#ifdef FEATURE_NX_IPV6
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


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_ipv6_basic_processing_test_application_define(void *first_unused_memory)
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

    /* Set interfaces' address */
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_2, 64, NX_NULL);

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
UINT            status;
NX_PACKET       *my_packet;
NXD_ADDRESS     peer_address;
ULONG           peer_port;
ULONG           mss;
ULONG           packets_sent, bytes_sent, packets_received, bytes_received, retransmit_packets, packets_queued, checksum_errors, socket_state, transmit_queue_depth, transmit_window, receive_window;
                
    /* Print out test information banner.  */
    printf("NetX Test:   TCP IPv6 Basic Processing Test............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                  NX_PROTOCOL_NEXT_HEADER_HOP_BY_HOP, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
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
                             
    /* Get the peer socket info before connection established, should be fail.  */
    status = nxd_tcp_socket_peer_info_get(&client_socket, &peer_address, &peer_port);

    /* Check for error.  */
    if(status != NX_NOT_CONNECTED)
        error_counter++;

    /* Call connect to send a SYN  */ 
    status = nxd_tcp_client_socket_connect(&client_socket, &ipv6_address_2, 12, 5 * NX_IP_PERIODIC_RATE);
       
    /* Check for error.  */
    if(status)
        error_counter++;

    /* Get the socket mss.  */
    status =  nx_tcp_socket_mss_get(&client_socket, &mss);

    /* Check for error.  */
    if (status)
        error_counter++;     

    /* Get the peer socket info.  */
    status = nxd_tcp_socket_peer_info_get(&client_socket, &peer_address, &peer_port);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Check the peer address and peer port.  */
    if((peer_port != 12) ||
            (peer_address.nxd_ip_version != NX_IP_VERSION_V6) ||
            (peer_address.nxd_ip_address.v6[0] != 0x20010000) ||
            (peer_address.nxd_ip_address.v6[1] != 0x00000000) ||
            (peer_address.nxd_ip_address.v6[2] != 0x00000000) ||
            (peer_address.nxd_ip_address.v6[3] != 0x10000002))
        error_counter++;

    /* Send the packet to server.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_IPv6_TCP_PACKET, NX_WAIT_FOREVER);

    if(status)   
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;
    my_packet -> nx_packet_ip_version = NX_IP_VERSION_V6;

#ifndef NX_DISABLE_ERROR_CHECKING
    /* Modify the ip version of connect address. */
    client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = 0;

    /* Send the packet. */
    status = nx_tcp_socket_send(&client_socket, my_packet, 2 * NX_IP_PERIODIC_RATE); 

    /* It must fail since ip version is invalid. */
    if (status != NX_NOT_CONNECTED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING */

    client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V6;

    /* Delete the Ipv6 address. */
    nxd_ipv6_address_delete(&ip_0, 0);

    /* Send the packet. */
    status = nx_tcp_socket_send(&client_socket, my_packet, 2 * NX_IP_PERIODIC_RATE); 

    /* It must fail since address is invalid. */
    if (status != NX_NO_INTERFACE_ADDRESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the address. */
    nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);

    /* Wait 5 seconds for DAD. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Send packet */
    status = nx_tcp_socket_send(&client_socket, my_packet, 2 * NX_IP_PERIODIC_RATE); 

    /* Check for error.  */
    if(status)
        error_counter++;   

    /* Disconnect this socket.  */
    status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Determine if the status is valid.  */
    if (status)
        error_counter++;

    /* Get the peer socket info before connection established, should be fail.  */
    status = nxd_tcp_socket_peer_info_get(&client_socket, &peer_address, &peer_port);

    /* Check for error.  */
    if(status != NX_NOT_CONNECTED)
        error_counter++;

    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Get information about this socket.  */
    status =  nx_tcp_socket_info_get(&client_socket, &packets_sent, &bytes_sent, 
            &packets_received, &bytes_received, 
            &retransmit_packets, &packets_queued,
            &checksum_errors, &socket_state,
            &transmit_queue_depth, &transmit_window,
            &receive_window);

#ifndef NX_DISABLE_TCP_INFO

    if((packets_sent != 1) || (bytes_sent != 28))
        error_counter++;
#endif

    /* Check for errors.  */
    if ((error_counter) || (status) || (packets_received) || (bytes_received) ||
            (retransmit_packets) || (packets_queued) || (checksum_errors) || (socket_state != NX_TCP_CLOSED) ||
            (transmit_queue_depth) || (transmit_window != 100) || (receive_window != 200))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

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
    NX_PACKET       *packet_ptr;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
            NX_PROTOCOL_NEXT_HEADER_HOP_BY_HOP, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
            NX_NULL, thread_1_disconnect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, thread_1_connect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Inject the SYN packet. */
    ip_1.nx_ip_tcp_packet_receive = tcp_packet_receive;

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    if(status)
        error_counter++;

    /* Receive a TCP message from the socket.  */
    status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;
    else
        /* Release the packet.  */
        nx_packet_release(packet_ptr);

    /* Disconnect the server socket.  */
    status =  nx_tcp_socket_disconnect(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Unlisten on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, 12);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&server_socket);   

    /* Check for error.  */
    if (status)
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

static void    tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_IPV6_HEADER *ipv6_header;   
NX_PACKET      *loopback_src_port;
NX_PACKET      *broadcast_source;
ULONG           broadcast[4] = {0xFF020000, 0, 0, 0x01};
ULONG           checksum;
ULONG          *source_ip, *dest_ip;
NX_TCP_HEADER  *tcp_header_ptr;   
    
    /* Set the source IP equal to destination IP. Verify whether or not system crashes. */

    /* Copy from the original packet. */
    nx_packet_copy(packet_ptr, &loopback_src_port, &pool_0, NX_NO_WAIT);   

    /* Get IPv6 header. */
    ipv6_header = (NX_IPV6_HEADER *)loopback_src_port -> nx_packet_ip_header;

    /* Copy the dest ip to source ip field. */
    COPY_IPV6_ADDRESS(ipv6_header -> nx_ip_header_destination_ip, 
                      ipv6_header -> nx_ip_header_source_ip);

    /* Calculate the checksum. */
    source_ip = ipv6_header -> nx_ip_header_source_ip;
    dest_ip = ipv6_header -> nx_ip_header_destination_ip;
    tcp_header_ptr = (NX_TCP_HEADER *) loopback_src_port -> nx_packet_prepend_ptr;    
    tcp_header_ptr -> nx_tcp_header_word_4 = 0;
    checksum = _nx_ip_checksum_compute(loopback_src_port, NX_PROTOCOL_TCP,
                                       loopback_src_port -> nx_packet_length,
                                       source_ip, dest_ip);
    checksum = ~checksum & NX_LOWER_16_MASK;
    tcp_header_ptr -> nx_tcp_header_word_4 = (checksum << NX_SHIFT_BY_16);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

    /* Pass the packet. */
    _nx_tcp_packet_receive(ip_ptr, loopback_src_port);

#ifndef NX_DISABLE_TCP_INFO
    if (ip_ptr -> nx_ip_tcp_invalid_packets != 1)
        error_counter++;
#endif /* NX_DISABLE_TCP_INFO */

    /* Copy from the original packet. */
    nx_packet_copy(packet_ptr, &broadcast_source, &pool_0, NX_NO_WAIT);   

    /* Get IPv6 header. */
    ipv6_header = (NX_IPV6_HEADER *)broadcast_source -> nx_packet_ip_header;

    /* Copy the broadcast address to source IP field. */
    COPY_IPV6_ADDRESS(broadcast, ipv6_header -> nx_ip_header_source_ip);

    /* Calculate the checksum. */
    source_ip = ipv6_header -> nx_ip_header_source_ip;
    dest_ip = ipv6_header -> nx_ip_header_destination_ip;
    tcp_header_ptr = (NX_TCP_HEADER *)broadcast_source -> nx_packet_prepend_ptr;    
    tcp_header_ptr -> nx_tcp_header_word_4 = 0;
    checksum = _nx_ip_checksum_compute(broadcast_source, NX_PROTOCOL_TCP,
                                       broadcast_source -> nx_packet_length,
                                       source_ip, dest_ip);
    checksum = ~checksum & NX_LOWER_16_MASK;
    tcp_header_ptr -> nx_tcp_header_word_4 = (checksum << NX_SHIFT_BY_16);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

    /* Pass the packet. */
    _nx_tcp_packet_receive(ip_ptr, broadcast_source);

#ifndef NX_DISABLE_TCP_INFO
    if (ip_ptr -> nx_ip_tcp_invalid_packets != 2)
        error_counter++;
#endif /* NX_DISABLE_TCP_INFO */

    /* Restore tcp receive function pointer. */
    ip_ptr -> nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

    /* Pass the packet. */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_ipv6_basic_processing_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP IPv6 Basic Processing Test............................N/A\n");

    test_control_return(3);     
}
#endif
