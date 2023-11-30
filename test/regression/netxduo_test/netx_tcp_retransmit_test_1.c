/* This case tests whether ACK number and window size is updated in retransmitted packet. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ip.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#ifdef __PRODUCT_NETXDUO__
#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static ULONG                   drop_packet;
static NX_PACKET              *retransmission_packet;
static ULONG                   window_size;
static ULONG                   ack_number;
static ULONG                   retransmission_window_size;
static ULONG                   retransmission_ack_number;
static UCHAR                   pool_area[20480];

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
#endif /* FEATURE_NX_IPV6 */

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static VOID    test_cleanup(VOID);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_retransmit_test_1_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    drop_packet = 0;
    retransmission_packet = NX_NULL;
    window_size = 0;
    ack_number = 0;
    retransmission_window_size = 0;
    retransmission_ack_number = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1024, pool_area, sizeof(pool_area));

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                           pointer, 2048, 2);
    pointer = pointer + 2048;
    if(status)
        error_counter++;

#ifndef NX_DISABLE_IPV4
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;
#endif

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
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

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    if(status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
}

/* Define the test threads.  */
static UCHAR send_buffer[3000];

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NX_PACKET *packet_ptr;
UINT       old_threshold;
UINT       i; 

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Retransmit Test 1.....................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let server thread listen first. */
    tx_thread_relinquish();

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, 1 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Connect to server.  */ 
#ifdef FEATURE_NX_IPV6
    status = nxd_tcp_client_socket_connect(&client_socket, &ipv6_address_2, 12, 5 * NX_IP_PERIODIC_RATE);
#else

    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */

    /* Check the connection status.  */
    if(status != NX_SUCCESS)
        error_counter++;

    /* The callback function is used to drop the first data packet to trigger retransmission.  */
    advanced_packet_process_callback = my_packet_process;

    /* Allocate a packet and fill data. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 1 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;
    else
    {
        status = nx_packet_data_append(packet_ptr, send_buffer, client_socket.nx_tcp_socket_tx_window_congestion, 
                                       &pool_0, 1 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
            error_counter++;
    }

    /* The packet will be fragmented into 4 TCP packet. Drop 4 packets. */
    drop_packet = 4;

    /* Send the pacekt. */
    status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_NO_WAIT);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Disable preemption.  */
    tx_thread_priority_change(tx_thread_identify(), 0, &old_threshold);
    for (i = 0; i < 3; i++)
    {

        /* Allocate a packet and fill data. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 1 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
            error_counter++;
        else
        {

            status = nx_packet_data_append(packet_ptr, send_buffer, 100, 
                                           &pool_0, 1 * NX_IP_PERIODIC_RATE);
            if(status != NX_SUCCESS)
                error_counter++;
        }

        /* Send another pacekt. */
        status = nx_tcp_socket_send(&client_socket, packet_ptr, 2 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
        {
            error_counter++;
            nx_packet_release(packet_ptr);
        }
    }

    /* Restore preemption.  */
    tx_thread_priority_change(tx_thread_identify(), old_threshold, &old_threshold);

    /* Check ACK number and window size. */
    if ((window_size == retransmission_window_size) ||
        (ack_number == retransmission_ack_number))
    {

        /* Window size or ACK number is not updated. */
        error_counter++;
    }
    else if ((retransmission_ack_number != client_socket.nx_tcp_socket_rx_sequence) ||
#ifdef NX_ENABLE_TCP_WINDOW_SCALING
             (retransmission_window_size != (client_socket.nx_tcp_socket_rx_window_current << client_socket.nx_tcp_snd_win_scale_value)))
#else
             (retransmission_window_size != client_socket.nx_tcp_socket_rx_window_current))
#endif
    {

        /* Window size or ACK number is not updated to current value of socket. */
        error_counter++;
    }

    /* Coverage test for function _nx_tcp_cleanup_deferred. */
    test_cleanup();

    /* Determine if the test was successful.  */
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

static void    ntest_1_entry(ULONG thread_input)
{
UINT            status;
NX_PACKET *packet_ptr;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1170,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Allocate a packet and fill data. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, 1 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;
    else
    {
        status = nx_packet_data_append(packet_ptr, send_buffer, 100, &pool_0, 1 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
            error_counter++;
    }

    /* Send the pacekt. */
    status = nx_tcp_socket_send(&server_socket, packet_ptr, NX_NO_WAIT);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Make sure thread 0 is the first thread waiting for NX_IP_TCP_CLEANUP_DEFERRED event. */
    tx_thread_suspend(&ntest_1);
    nx_tcp_socket_disconnect(&server_socket, 1 * NX_IP_PERIODIC_RATE);
}

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER *header_ptr;

    /* Skip packets from IP1*/
    if (ip_ptr != &ip_0)
    {
        return NX_TRUE;
    }

    /* Skip none TCP packets. */
#ifdef FEATURE_NX_IPV6
    if (packet_ptr -> nx_packet_length < 60)
#else
    if (packet_ptr -> nx_packet_length < 40)
#endif
    {
        return NX_TRUE;
    }

    if (drop_packet != 0)
    {

        /* This packet should be dropped. */
        *operation_ptr = NX_RAMDRIVER_OP_DROP;

        if (drop_packet == 4)
        {
            retransmission_packet = packet_ptr;

            /* Get TCP header. */
#ifdef FEATURE_NX_IPV6
            header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 40);
#else
            header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);
#endif

            /* Get window size and ACK number. */
            ack_number = header_ptr -> nx_tcp_acknowledgment_number;
            window_size = header_ptr -> nx_tcp_header_word_3;
            NX_CHANGE_ULONG_ENDIAN(ack_number);
            NX_CHANGE_ULONG_ENDIAN(window_size);
            window_size = window_size & NX_LOWER_16_MASK;
        }

        drop_packet--;
    }
    else if (packet_ptr == retransmission_packet)
    {

        /* Get TCP header. */
#ifdef FEATURE_NX_IPV6
        header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 40);
#else
        header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);
#endif

        /* Get window size and ACK number. */
        retransmission_ack_number = header_ptr -> nx_tcp_acknowledgment_number;
        retransmission_window_size = header_ptr -> nx_tcp_header_word_3;
        NX_CHANGE_ULONG_ENDIAN(retransmission_ack_number);
        NX_CHANGE_ULONG_ENDIAN(retransmission_window_size);
        retransmission_window_size = retransmission_window_size & NX_LOWER_16_MASK;

        retransmission_packet = NX_NULL;
    }

    return NX_TRUE;
}


static VOID    test_cleanup(VOID)
{
UINT        old_threshold;
ULONG       ip_events;

    /* Disable preemption.  */
    tx_thread_priority_change(tx_thread_identify(), 0, &old_threshold);

    /* Wakeup thread 1. */
    tx_thread_resume(&ntest_1);

    /* Get NX_IP_TCP_CLEANUP_DEFERRED event. */
    tx_event_flags_get(&ip_1.nx_ip_events, NX_IP_TCP_CLEANUP_DEFERRED, TX_OR_CLEAR, &ip_events, TX_WAIT_FOREVER);

    /* Make sure _nx_tcp_cleanup_deferred is set. */
    if (ntest_1.tx_thread_suspend_cleanup != _nx_tcp_cleanup_deferred)
    {
        error_counter++;
    }

    /* Delete IP_1 so IP thread is terminated. */
    tx_thread_terminate(&ntest_1);

    /* Restore preemption.  */
    tx_thread_priority_change(tx_thread_identify(), old_threshold, &old_threshold);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_retransmit_test_1_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Retransmit Test 1.....................................N/A\n");

    test_control_return(3);  
}      
#endif
