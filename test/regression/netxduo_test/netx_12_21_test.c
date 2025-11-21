/* 12.21:TCP MUST be able to receive MSS option in SYN,ACK segment and calculate the effective send segment size appropriately.  */

/*  Procedure
    1.Connect
    2.Client_socket's connect_MSS should equal server_socket's MSS.(client_socket's MSS = 1460, server_socket's MSS = 88)
    3. A packet should be intercepted by function my_tcp_packet_receive_12_21 which is sent from client socket to server socket.
    4. Check: the packet should be a SYN packet, increment the syn_counter. Whether or not calling the defaulted packet receiving function.
    5. Check if all of the packets we catched can connected to the my_packet we send*/

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#if defined(__PRODUCT_NETXDUO__)
#include   "nx_ipv4.h"
#else
#include   "nx_ip.h"
#endif
#include   <time.h> 
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the counters used in the demo application...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

/* Define the counters used in the demo applicaton...  */

static ULONG                   error_counter;
static ULONG                   syn_ack_counter;
static ULONG                   data_counter;
static ULONG                   mss_option_12_21;
static ULONG                   packet_length_12_21;

static UCHAR                   callback_rcv_buffer[200];
static UINT                    callback_rcv_length;
static UCHAR                   rcv_buffer[200];
static UINT                    rcv_length;
static UCHAR                   data_12_21[200];

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *server_socket);
static void    rand_12_21();
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    my_tcp_packet_receive_12_21(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_12_21(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_12_21_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    syn_ack_counter = 0;
    data_counter = 0;
    mss_option_12_21 = 0;
    packet_length_12_21 = 200;
    rcv_length = 0;
    callback_rcv_length = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
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

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
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

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
NX_PACKET  *my_packet;



    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 12.21 Test.......................................");

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 300,
                                  NX_NULL, NX_NULL);


    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_socket, 12, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_12_21;

    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /*Check if the MSS option of server socket has calculated to the appropriate 88(server_socket's MSS) which the SYN,ACK packet from client socket carried*/
    if(client_socket.nx_tcp_socket_connect_mss != mss_option_12_21)
        error_counter++;

    advanced_packet_process_callback = my_packet_process_12_21;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Create a 200-byte length message randomly. */
    rand_12_21();

    /* Fill in the packet with data.     */
    status = nx_packet_data_append(my_packet, data_12_21, packet_length_12_21, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status)
        error_counter++;

    /* Send the packet out!  */
    status =  nx_tcp_socket_send(&client_socket, my_packet, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;


    /* Disconnect this socket.  */
    status = nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /*Check if the content of the callback_rcv_buffer which appended by all the received packets' payload is the data_12_18 sent before*/
    if(!memcmp(callback_rcv_buffer, data_12_21, packet_length_12_21))
        data_counter++;

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    status += nx_tcp_socket_delete(&client_socket);
    
    /* Check for error.  */
    if(status)
        error_counter++;

    
    /* Check for error.  */
    if((error_counter !=0) || (syn_ack_counter != 1) || (data_counter != 2))
    {
        printf("ERROR\n");
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
UINT       status;
ULONG      actual_status;
NX_PACKET  *my_packet;
ULONG      bytes_copied;

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                  NX_NULL, ntest_1_disconnect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup this thread to listen.  */
    status = nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, ntest_1_connect_received);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    while(!(nx_tcp_socket_receive(&server_socket, &my_packet, NX_IP_PERIODIC_RATE)))
    {
        /*Check if the packet is fragmented by TCP layer.*/
        if(my_packet -> nx_packet_length > mss_option_12_21)
            error_counter++;

        /* Retrieve data from packet to the receive buffer. */
        status = nx_packet_data_retrieve(my_packet, &rcv_buffer[rcv_length], &bytes_copied);
        if(status)
            error_counter++;

        rcv_length += bytes_copied;
    }

    /*Check if the content which connected by all the received packets is the data_12_21 sent from the client socket*/
    if(!memcmp(rcv_buffer, data_12_21, packet_length_12_21))
        data_counter++;

    /* Disconnect the server socket.  */
    status = nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Unaccept the server socket.  */
    status = nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Unlisten on the server port.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, 12);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&server_socket);

    /* Check for error.  */
    if(status)
        error_counter++;


}

static void    ntest_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}

static void    ntest_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if(socket != &server_socket)
        error_counter++;
}

static void rand_12_21()
{
UINT       flag;
UINT       j, k = 0;

    srand((unsigned)time(NULL)); 
    for(j = 0;j < 200;j++)
    {
        flag = rand() & 1; 
        if(flag)
            data_12_21[k++] = 'A' + rand() % 26;
        else
            data_12_21[k++] = 'a' + rand() % 26;
    }
}


static UINT    my_packet_process_12_21(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
#if defined(__PRODUCT_NETXDUO__)
NX_IPV4_HEADER    *ip_header_ptr = (NX_IPV4_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);
#else
NX_IP_HEADER    *ip_header_ptr = (NX_IP_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);
#endif

    if((packet_ptr -> nx_packet_length) > 40)
    {
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

        /*Check if the packet is fragmented by IP layer.*/
        if(!(ip_header_ptr->nx_ip_header_word_1& NX_IP_FRAGMENT_MASK))
        {
            /*Check if the packet is fragmented by TCP layer*/
            if((packet_ptr->nx_packet_length - 40) > mss_option_12_21)
                error_counter++;
        }
        else
            error_counter++;

        /* Append the intercepted packet's content to the receive buffer. */
        memcpy(&callback_rcv_buffer[callback_rcv_length], packet_ptr->nx_packet_prepend_ptr + 40, packet_ptr -> nx_packet_length - 40);
        callback_rcv_length = callback_rcv_length + packet_ptr -> nx_packet_length - 40;

        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);
    }

    return NX_TRUE;
}

static void    my_tcp_packet_receive_12_21(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER  *header_ptr;
ULONG           option_words;

    header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Client receives a SYN+ACK packet.  */
    if((header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && (header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT) && !(header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
    {
        /* It is a SYN+ACK packet.  */
        syn_ack_counter++;

        /*Get the MSS option kind*/
        option_words =  (header_ptr -> nx_tcp_header_word_3 >> 28) - 5;

        /*Get the MSS option form the SYN packet.*/
        _nx_tcp_mss_option_get((packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER)), option_words*sizeof(ULONG), &mss_option_12_21);  

        ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    }

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    _nx_tcp_packet_receive(ip_ptr, packet_ptr);

}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_12_21_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 12.21 Test.......................................N/A\n"); 

    test_control_return(3);  
}      
#endif