/* 3.8 TCP, in LISTEN state, MUST send a RST after receiving a spurious SYN,ACK that potentially corresponds to an old SYN.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#if defined(__PRODUCT_NETXDUO__)
#include   "nx_ipv4.h"
#include   "nx_ipv6.h"
#else
#include   "nx_ip.h"
#endif
#include   "nx_packet.h"
#include   "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           server_socket;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   syn_ack_counter;
static ULONG                   rst_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
extern USHORT  _nx_ip_checksum_compute(NX_PACKET *, int, UINT, ULONG *, ULONG *);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_3_08(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive_3_08(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_3_08_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    syn_ack_counter = 0;
    rst_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if(status)
        error_counter++;
    
    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT                        status;
ULONG                       actual_status;
NX_IP                       *ip_ptr;
NX_PACKET                   *packet_ptr;
NX_TCP_HEADER               *tcp_header_ptr;
ULONG                       *option_word_1;
ULONG                       *option_word_2;
#if defined(__PRODUCT_NETXDUO__)
        NX_IPV4_HEADER    *ip_header_ptr;
ULONG                       val;
#else
        NX_IP_HEADER      *ip_header_ptr;
#endif
ULONG                       checksum;
ULONG                       source;
ULONG                       dest;
#if defined(__PRODUCT_NETXDUO__)
ULONG                       *source_ip, *dest_ip;
#else
ULONG                       source_ip, dest_ip;
ULONG                       temp;
#endif

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Spec 3.08 Test........................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a static ARP entry.  */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0x00112233, 0x4456);

    if(status)
        error_counter++;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                  NX_NULL, ntest_0_disconnect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, ntest_0_connect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    if(server_socket.nx_tcp_socket_state != NX_TCP_LISTEN_STATE)
        error_counter++;

    ip_ptr = server_socket.nx_tcp_socket_ip_ptr;

    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

#ifdef __PRODUCT_NETXDUO__
    packet_ptr -> nx_packet_append_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_TCP_SYN_SIZE;
    packet_ptr -> nx_packet_length =  NX_TCP_SYN_SIZE;
#else
    packet_ptr -> nx_packet_append_ptr =  packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_SYN);
    packet_ptr -> nx_packet_length =  sizeof(NX_TCP_SYN);
#endif

    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    option_word_1 = (ULONG *)(tcp_header_ptr + 1);
    option_word_2 = option_word_1 + 1;

    /*Build TCP header.  */
    tcp_header_ptr -> nx_tcp_header_word_0 = (ULONG) server_socket.nx_tcp_socket_port;
    tcp_header_ptr -> nx_tcp_sequence_number = 1000;
    tcp_header_ptr -> nx_tcp_acknowledgment_number = 0;
    tcp_header_ptr -> nx_tcp_header_word_3 = NX_TCP_SYN_HEADER | NX_TCP_SYN_BIT | NX_TCP_ACK_BIT | (server_socket.nx_tcp_socket_rx_window_current);
    tcp_header_ptr -> nx_tcp_header_word_4 = 0;
    *option_word_1 = NX_TCP_MSS_OPTION;
    *option_word_2 = NX_TCP_OPTION_END;

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4); 
    NX_CHANGE_ULONG_ENDIAN(*option_word_1);
    NX_CHANGE_ULONG_ENDIAN(*option_word_2);

    source = 0x01020305;
    dest = 0x01020304;

#if defined(__PRODUCT_NETXDUO__)
    dest_ip = &dest;
    source_ip = &source;
    checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                           packet_ptr -> nx_packet_length,
                                           source_ip, dest_ip);
    checksum = ~checksum & NX_LOWER_16_MASK;
#elif defined(__PRODUCT_NETX__)
    dest_ip = dest;
    source_ip = source;
    checksum = _nx_tcp_checksum(packet_ptr, source_ip, dest_ip);
#endif

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
    tcp_header_ptr -> nx_tcp_header_word_4 = (checksum << NX_SHIFT_BY_16);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

#if defined(__PRODUCT_NETXDUO__)
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr - sizeof(NX_IPV4_HEADER);
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length + sizeof(NX_IPV4_HEADER);
#elif defined(__PRODUCT_NETX__)
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr - sizeof(NX_IP_HEADER);
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length + sizeof(NX_IP_HEADER);
#endif

#if defined(__PRODUCT_NETXDUO__)
    ip_header_ptr =  (NX_IPV4_HEADER *) packet_ptr -> nx_packet_prepend_ptr;
#elif defined(__PRODUCT_NETX__)
    ip_header_ptr =  (NX_IP_HEADER *) packet_ptr -> nx_packet_prepend_ptr;
#endif

    /*Build IP header.  */
    ip_header_ptr -> nx_ip_header_word_0 =  (NX_IP_VERSION | (0xFFFF & packet_ptr -> nx_packet_length));
#ifdef NX_ENABLE_IP_ID_RANDOMIZATION
    ip_header_ptr -> nx_ip_header_word_1 =  (((ULONG)NX_RAND()) << NX_SHIFT_BY_16);
#else
    ip_header_ptr -> nx_ip_header_word_1 =  (ip_ptr -> nx_ip_packet_id++ << NX_SHIFT_BY_16);
#endif /* NX_ENABLE_IP_ID_RANDOMIZATION */
    ip_header_ptr -> nx_ip_header_word_2 =  ((server_socket.nx_tcp_socket_time_to_live << NX_IP_TIME_TO_LIVE_SHIFT) | NX_IP_TCP);
    ip_header_ptr -> nx_ip_header_source_ip =  0x01020305;
    ip_header_ptr -> nx_ip_header_destination_ip =  0x01020304;

#ifdef __PRODUCT_NETX__

    /* Build the IP header checksum.  */
    temp =       ip_header_ptr -> nx_ip_header_word_0;
    checksum =   (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
    temp =       ip_header_ptr -> nx_ip_header_word_1;
    checksum +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
    temp =       ip_header_ptr -> nx_ip_header_word_2;
    checksum +=  (temp >> NX_SHIFT_BY_16);
    temp =       ip_header_ptr -> nx_ip_header_source_ip;
    checksum +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
    temp =       ip_header_ptr -> nx_ip_header_destination_ip;
    checksum +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);

    /* Add in the carry bits into the checksum.  */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);
    
    /* Do it again in case previous operation generates an overflow.  */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);    

    /* Now store the checksum in the IP header.  */
    ip_header_ptr -> nx_ip_header_word_2 =  ip_header_ptr -> nx_ip_header_word_2 | (NX_LOWER_16_MASK & (~checksum));
#endif

    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_source_ip);
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_destination_ip);

#ifdef __PRODUCT_NETXDUO__
    checksum = _nx_ip_checksum_compute(packet_ptr, NX_IP_VERSION_V4, 20, NULL, NULL);
    val = (ULONG)(~checksum);
    val = val & NX_LOWER_16_MASK;

    /* Convert to network byte order. */
    NX_CHANGE_ULONG_ENDIAN(val);

    /* Now store the checksum in the IP header.  */
    ip_header_ptr -> nx_ip_header_word_2 =  ip_header_ptr -> nx_ip_header_word_2 | val;
#endif

    advanced_packet_process_callback = my_packet_process_3_08;

    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_3_08;

    _nx_ip_packet_deferred_receive(ip_ptr, packet_ptr);

    /* Unlisten on the server port.  */
    status = nx_tcp_server_socket_unlisten(&ip_0, 12);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Determine if the test was successful.  */
    if((error_counter) || (syn_ack_counter != 1) || (rst_counter != 1))
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

static void    ntest_0_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void    ntest_0_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if(socket != &server_socket)
        error_counter++;
}

static UINT    my_packet_process_3_08(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER       *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
   
    if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)
    {
        rst_counter++;

        /* RST packet has been processed. */ 
        advanced_packet_process_callback = NX_NULL;
    }

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    return NX_TRUE;
}

static void    my_tcp_packet_receive_3_08(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER      *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT))
        syn_ack_counter++;

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Deal packets with default routing.  */
    ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;

    /* Let server receives the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_3_08_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 3.08 Test........................................N/A\n"); 

    test_control_return(3);  
}      
#endif