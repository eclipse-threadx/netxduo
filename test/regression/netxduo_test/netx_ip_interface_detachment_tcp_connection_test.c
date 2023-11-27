/* This case test if the tcp connections has been reset after interface detachment. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ip.h"
#include   "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   syn_ack_counter;
static ULONG                   ack_drop_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_detachment_tcp_connection_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter    = 0;
    syn_ack_counter  = 0;
    ack_drop_counter = 0;

    /* Create the main threads.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
            pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
            pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Attach the 2nd interface to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver);
    if(status != NX_SUCCESS)     
        error_counter++;

    /* Attach the 2nd interface to IP instance1 */
    status = nx_ip_interface_attach(&ip_1, "2nd interface", IP_ADDRESS(4, 3, 2, 11), 0xFF000000, _nx_ram_network_driver_1500);
    if(status != NX_SUCCESS)   
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    if(status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT    status;
ULONG   actual_status;

    printf("NetX Test:   IP Interface Detachment TCP connection Test...............");

    /* Check earlier error. */
    if(error_counter)
    {                            
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    status = nx_tcp_socket_create(&ip_0, &server_socket, "Server Socket",
            NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
            NX_NULL, NX_NULL);
    if(status)
        error_counter++;

    status = nx_tcp_server_socket_listen(&ip_0, 12, &server_socket, 5, NX_NULL);
    if(status)
        error_counter++;

    status = nx_tcp_server_socket_accept(&server_socket, NX_NO_WAIT);
    if(status != NX_IN_PROGRESS)
        error_counter++;

    /* Detach the 2nd interface(4.3.2.10) from ip_0. */
    status = nx_ip_interface_detach(&ip_0, 1);
    if(status)
        error_counter++;

    /* Detachment should not reset the listening TCP socket. */
    if(server_socket.nx_tcp_socket_state != NX_TCP_SYN_RECEIVED)
        error_counter++;

    /* Attach the 2nd interface(4.3.2.10) removed before to ip_0. */
    nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver);

    /* ntest_0 relinquishes the CPU. */
    tx_thread_suspend(&ntest_0);

    /* Check if server is SYN_RECV. Now, the server has receiced a SYN. */
    if(server_socket.nx_tcp_socket_state != NX_TCP_SYN_RECEIVED)
        error_counter++;

    /* Detach the 2nd interface(4.3.2.10) from ip_0. */
    status = nx_ip_interface_detach(&ip_0, 1);
    if(status)
        error_counter++;

    /* Detachment should reset the TCP server  socket which is in connection building progress . */
    if(server_socket.nx_tcp_socket_state != NX_TCP_LISTEN_STATE)
        error_counter++;

    /* Attach the 2nd interface(4.3.2.10) removed before to ip_0. */
    nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver);

    /* ntest_0 relinquished the CPU. */
    tx_thread_suspend(&ntest_0);

    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Relisten the TCP server socket. */
    status += nx_tcp_server_socket_relisten(&ip_0, 12, &server_socket);

    status += nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    if(server_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED)
       error_counter++;

    /* Detach the 2nd interface(4.3.2.10) from ip_0. */
    status = nx_ip_interface_detach(&ip_0, 1);
    if(status)
        error_counter++;

    /* Detachment should reset the established TCP connection. */
    if(server_socket.nx_tcp_socket_state != NX_TCP_LISTEN_STATE)
        error_counter++;
    
    /* ntest_0 relinquished the CPU. */
    tx_thread_suspend(&ntest_0);

    /* Clean. */
    status = nx_tcp_server_socket_unaccept(&server_socket);
    status += nx_tcp_server_socket_unlisten(&ip_0, 12);
    status += nx_tcp_socket_delete(&server_socket);
    if(status)
        error_counter++;

    if((error_counter) || (syn_ack_counter != 1) || (ack_drop_counter != 1))
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

UINT    status;
ULONG   actual_status;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    status = nx_tcp_socket_create(&ip_1, &client_socket, "Client Socket",
            NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
            NX_NULL, NX_NULL);

    status += nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Deal the packet with my routing.  */
    advanced_packet_process_callback = my_packet_process;

    /* Deal the packet with my routing. */
    ip_1.nx_ip_tcp_packet_receive = my_tcp_packet_receive;

    /* Attempt to connect the socket.  */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(4, 3, 2, 10), 12, NX_NO_WAIT);
    if(status != NX_IN_PROGRESS)
        error_counter++;

    /* ntest_1 relinquishes the CPU. */
    tx_thread_resume(&ntest_0);

    /* Detach the 2nd interface(4.3.2.11) from ip_1. */
    status = nx_ip_interface_detach(&ip_1, 1);
    if(status)
        error_counter++;

    /* Detachment should reset the TCP server  socket which is in connection building progress . */
    if(client_socket.nx_tcp_socket_state != NX_TCP_CLOSED)
        error_counter++;

    /* Attach the 2nd interface(4.3.2.11) removed before to ip_1. */
    nx_ip_interface_attach(&ip_1, "2nd interface", IP_ADDRESS(4, 3, 2, 11), 0xFF000000, _nx_ram_network_driver_1500);

    /* ntest_1 relinquishes the CPU. */
    tx_thread_resume(&ntest_0);

    /* Attempt to connect the socket again.  */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(4, 3, 2, 10), 12, 5 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    if(client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED)
        error_counter++;

    /* Detach the 2nd interface(4.3.2.11) from ip_1. */
    status = nx_ip_interface_detach(&ip_1, 1);
    if(status)
        error_counter++;

    /* Detachment should reset the established TCP connection. */
    if(client_socket.nx_tcp_socket_state != NX_TCP_CLOSED)
        error_counter++;

    /* Clean. */
    status = nx_tcp_client_socket_unbind(&client_socket);
    status += nx_tcp_socket_delete(&client_socket);
    if(status)
        error_counter++;

    /* ntest_1 relinquishes the CPU. */
    tx_thread_resume(&ntest_0);
}


static void    my_tcp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER    *tcp_header_ptr;

    /* Point to TCP HEADER.  */
    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr ->nx_tcp_header_word_3);

    if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && 
       (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT))
    {
        syn_ack_counter++;
        ip_ptr -> nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    }

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr ->nx_tcp_header_word_3);

    /* Let server receives the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);
}


static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER    *tcp_header_ptr;

    if(syn_ack_counter == 1)
    {
        /* Point to TCP HEADER.  */
        tcp_header_ptr = (NX_TCP_HEADER *)((packet_ptr -> nx_packet_prepend_ptr) + 20);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

        if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT))
        {
            /* Drop the ACK packet in order to postpone the connection. */
            *operation_ptr = NX_RAMDRIVER_OP_DROP;

            ack_drop_counter++;

            advanced_packet_process_callback = NULL;
        }

       NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    }

    return NX_TRUE;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_detachment_tcp_connection_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Interface Detachment TCP connection Test...............N/A\n");
    test_control_return(3);

}
#endif
