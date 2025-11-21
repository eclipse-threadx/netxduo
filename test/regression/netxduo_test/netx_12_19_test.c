/* 12.19:TCP MUST assume a default send MSS of 536 if MSS option is not received at connection setup.  */

/*  Procedure
    1.Client_socket connect server_socket.
    2.When server_socket received SYN, then clean the MSS option, deal the packet with default receive function.
    3.Check the connect_mss of server_socket has been changed to be 536.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#if defined(__PRODUCT_NETXDUO__)
#include   "nx_ipv4.h"
#else
#include   "nx_ip.h"
#endif

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   syn_counter;


/* Define thread prototypes.  */


static void    ntest_0_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    my_tcp_packet_receive_12_19(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_12_19(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern USHORT  _nx_ip_checksum_compute(NX_PACKET *packet_ptr, int protocol, 
                                       UINT data_length, ULONG* src_ip_addr,
                                       ULONG* dest_ip_addr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_12_19_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    syn_counter = 0;


    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create another IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create an IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                           pointer, 2048, 1);
    pointer = pointer + 2048;


    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;



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


static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if(status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }

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

    /* Point to my routing   */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_12_19;

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    if(syn_counter == 1)
    {
        /*Check if the connection has established*/
        if((client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED) || (server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED))
            error_counter++;
    }
    else
        error_counter++;

    if(server_socket.nx_tcp_socket_connect_mss != 536)
        error_counter++;

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;


    /* Unlisten on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_0, 12);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

}



static void    ntest_1_entry(ULONG thread_input)
{
UINT       status;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Spec 12.19 Test.......................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    advanced_packet_process_callback = my_packet_process_12_19;

    /* Attempt to connect the socket.  */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Disconnect this socket.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    status = nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Determine if the test was successful.  */
    if((error_counter != 0 ) || (syn_counter != 1 ))
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

    /* Check for the proper socket and port.   */ 
    if((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void    ntest_0_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if(socket != &server_socket)
        error_counter++;
}




static UINT    my_packet_process_12_19(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER *tcp_header_ptr;
ULONG         *option_word_1;
ULONG          checksum;

#if defined(__PRODUCT_NETXDUO__)
ULONG         *source_ip, *dest_ip;
#elif defined(__PRODUCT_NETX__)
ULONG         source_ip, dest_ip;
#else
#error "NetX Product undefined."
#endif


    tcp_header_ptr = (NX_TCP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);
    option_word_1 = (ULONG *)(tcp_header_ptr + 1);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* If this is a tcp packet but not an ARP packet or other kind packet. */
    if(packet_ptr -> nx_packet_length >= 40)
    {
        /* Modify the syn packet   */
        if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && !(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) && !(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
        {

            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

            NX_CHANGE_ULONG_ENDIAN(*option_word_1);

            /*Clean the MSS option*/
            *option_word_1 = *option_word_1 & 0x00000000;
            NX_CHANGE_ULONG_ENDIAN(*option_word_1);

#if defined(__PRODUCT_NETXDUO__)
            packet_ptr -> nx_packet_prepend_ptr += sizeof(NX_IPV4_HEADER);
            packet_ptr -> nx_packet_length -= sizeof(NX_IPV4_HEADER);
#else
            packet_ptr -> nx_packet_prepend_ptr += sizeof(NX_IP_HEADER);
            packet_ptr -> nx_packet_length -= sizeof(NX_IP_HEADER);
#endif

            tcp_header_ptr -> nx_tcp_header_word_4 = tcp_header_ptr -> nx_tcp_header_word_4 & 0xFFFF0000;


#if defined(__PRODUCT_NETXDUO__)
            dest_ip = &client_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4;
            source_ip = &client_socket. nx_tcp_socket_connect_interface -> nx_interface_ip_address;
            checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                               packet_ptr -> nx_packet_length,
                                               source_ip, dest_ip);
            checksum = ~checksum & NX_LOWER_16_MASK;
#elif defined(__PRODUCT_NETX__)
            dest_ip = client_socket.nx_tcp_socket_connect_ip;
            source_ip = ip_1.nx_ip_address;
            checksum = _nx_tcp_checksum(packet_ptr, source_ip, dest_ip);
#endif

            /* Move the checksum into header.  */
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
            tcp_header_ptr -> nx_tcp_header_word_4 = (checksum << NX_SHIFT_BY_16);
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);


#if defined(__PRODUCT_NETXDUO__)
            packet_ptr -> nx_packet_prepend_ptr -= sizeof(NX_IPV4_HEADER);
            packet_ptr -> nx_packet_length += sizeof(NX_IPV4_HEADER);
#else
            packet_ptr -> nx_packet_prepend_ptr -= sizeof(NX_IP_HEADER);
            packet_ptr -> nx_packet_length += sizeof(NX_IP_HEADER);
#endif

            advanced_packet_process_callback = NX_NULL;
        }
        else
            NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    }
    return NX_TRUE;

}


static void   my_tcp_packet_receive_12_19(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER   *header_ptr;
ULONG           *option_word_1;

    header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    option_word_1 = (ULONG *)(header_ptr + 1);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Server receives a syn packet   */
    if((header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && !(header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) && !(header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
    {
        NX_CHANGE_ULONG_ENDIAN(*option_word_1);

        /*Check whether the packet have the MSS option*/
        if(!(*option_word_1))
            syn_counter++;

        NX_CHANGE_ULONG_ENDIAN(*option_word_1);

        /* Point to default function   */
        ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    }

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Deal with default function   */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_12_19_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 12.19 Test.......................................N/A\n"); 

    test_control_return(3);  
}      
#endif

