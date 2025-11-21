/* 9.17 TCP, in SYN-RCVD state, reached through active OPEN, MUST inform "connection refused" to application on recv a RST.
   and socket state MUST go to CLOSED state on RST.*/

/* RFC 793, Section 3.9, page 70, Event Processing. 
The user need not be informed.  If this connection was 
initiated with an active OPEN (i.e., came from SYN-SENT state) 
then the connection was refused, signalthe user "connection refused".  
In either case, all segmentson the retransmission queue should be removed. 
And in the active OPEN case, enter the CLOSED state and delete the TCB,and return.  */

/* Procedure
1. Client_1 sends a SYN to Client_2.
2. Use my_packet_process_9_17 function to drop the SYN packet.
3. Client_2 sends a SYN to Client_1.
4. Client_1 send a SYN+ACK to Client_2.
5. Use my_packet_process_9_17 function to drop the SYN+ACK packet.
6. Client_2 sends a RST to Client_1.
7. Check the connection return status and the Client_1 state.  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_tcp.h"
#include    "nx_ram_network_driver_test_1500.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_1_socket;
static NX_TCP_SOCKET           client_2_socket;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   syn_counter;
static ULONG                   rst_counter;

/* Define thread prototypes.  */
static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);

extern void    _nx_ram_network_driver_3000(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_3000(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_9_17(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    my_tcp_packet_receive_9_17(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_9_17_application_define(void *first_unused_memory)
#endif
{

CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    /* Initialize the counters.  */
    error_counter = 0;
    syn_counter = 0;
    rst_counter = 0;

    /* Create the client thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the server thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_3000,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_3000,
                           pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
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

/* Define the client thread.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT       status;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 9.17 Test........................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_1_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_1_socket, 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Deal the SYN packet with my routing  */
    advanced_packet_process_callback = my_packet_process_9_17;
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_9_17;

    /* Call connect to send a SYN  */ 
    status = nx_tcp_client_socket_connect(&client_1_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Judge the Client state.  */
    if((rst_counter != 1) || (client_1_socket.nx_tcp_socket_state != NX_TCP_CLOSED) || status != NX_NOT_CONNECTED)
    {
        error_counter++;
    }

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_1_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_1_socket);

    /* Check for error.  */
    if(status)
        error_counter++;
}

/* Define the server thread.  */

static void    ntest_1_entry(ULONG thread_input)
{

UINT       status;
ULONG      actual_status;
NX_TCP_HEADER   header_ptr;


    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_2_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    status = nx_tcp_client_socket_bind(&client_2_socket, 12, NX_IP_PERIODIC_RATE);


    /* Call connect to send a SYN  */ 
    status = nx_tcp_client_socket_connect(&client_2_socket, IP_ADDRESS(1, 2, 3, 4), 12, NX_NO_WAIT);


    /* Send RST.  */
    header_ptr.nx_tcp_header_word_3 = header_ptr.nx_tcp_header_word_3 | NX_TCP_ACK_BIT | NX_TCP_RST_BIT;
    
    header_ptr.nx_tcp_acknowledgment_number = client_1_socket.nx_tcp_socket_rx_sequence;
    header_ptr.nx_tcp_sequence_number       = client_1_socket.nx_tcp_socket_tx_sequence + 1;
    _nx_tcp_packet_send_rst(&client_2_socket, &header_ptr);
    
    tx_thread_sleep(1);

    /* Return error.  */
    if((error_counter) || (syn_counter != 2 ) || (rst_counter != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Return success.  */
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}

static UINT    my_packet_process_9_17(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

NX_TCP_HEADER   *tcp_header_ptr;

    if (ip_ptr != &ip_0)
        return NX_TRUE;

    tcp_header_ptr = (NX_TCP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* If this is a tcp packet but not an ARP packet or other kind packet. */
    if(packet_ptr -> nx_packet_length >= 40)
    {
        /* Check if it is a SYN packet.  */
        if (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) && (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && (syn_counter == 0))
        {
            syn_counter++;

            /*Drop the packet*/
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }

        else if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) && (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && (syn_counter == 2))
        {
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
            advanced_packet_process_callback = NX_NULL;
        }
    }
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    return NX_TRUE;

}

void    my_tcp_packet_receive_9_17(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_TCP_HEADER   *tcp_header_ptr;

    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check the packet is a SYN one.  */
    if (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) && (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && (syn_counter == 1))
    {
        syn_counter++;
    }
    /* Check the packet is a RST one.  */
    else if (client_1_socket.nx_tcp_socket_state == NX_TCP_SYN_RECEIVED)
    {
        if(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)
        {
            rst_counter++;

            /* Deal packets with default routing.  */
            ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
        }
    }    

    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Let server receives the packet.  */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr); 
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_9_17_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 9.17 Test........................................N/A\n"); 

    test_control_return(3);  
}      
#endif