/*  12.20:TCP MUST ignore MSS option in data segment.  */

/*  Procedure
    1.Connect
    2.Allocate a data packet with MSS_OPTION but not SYN packet
    3.Client socket sends the packet to server socket
    4.Check whether server_socket's connect_mss changed or not  */

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
static ULONG                   mss_option_12_20;
static ULONG                   data_packet_counter;
static UCHAR                   data_12_20[20];

/* Define thread prototypes.  */


static void    ntest_0_entry(ULONG thread_input);
static void    ntest_0_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_0_disconnect_received(NX_TCP_SOCKET *server_socket);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    my_tcp_packet_receive_12_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
extern USHORT  _nx_ip_checksum_compute(NX_PACKET *packet_ptr, int protocol, 
                                       UINT data_length, ULONG* src_ip_addr,
                                       ULONG* dest_ip_addr);
static void    rand_12_20();
extern UINT    _nx_packet_data_append(NX_PACKET *packet_ptr, VOID *data_start, ULONG data_size,NX_PACKET_POOL *pool_ptr, ULONG wait_option);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process_12_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_12_20_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;
    error_counter = 0;
    mss_option_12_20 = 20;
    data_packet_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 1", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 0", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create another IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);

    if(status)
        error_counter++;

    status = nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */




static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
NX_PACKET               *my_packet;

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

    /* Accept a client socket connection.  */
    status = nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;


    /* Let server checks the packet.  */
    ip_0.nx_ip_tcp_packet_receive = my_tcp_packet_receive_12_20;

    status = nx_tcp_socket_receive(&server_socket, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;
    else
    {
        /* Check data length and payload */
        if((my_packet -> nx_packet_length == 20) && (!memcmp(my_packet -> nx_packet_prepend_ptr, data_12_20, 20)))
            data_packet_counter++;

        /* Release the packet.  */
        nx_packet_release(my_packet);
    }

    /*Check if the mss of client socket has changed*/
    if(server_socket.nx_tcp_socket_connect_mss == mss_option_12_20)
        error_counter++;

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
    printf("NetX Test:   TCP Spec 12.20 Test.......................................");

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

    /* Attempt to connect the socket.  */
    status = nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    advanced_packet_process_callback = my_packet_process_12_20;
    _nx_tcp_packet_send_syn(&client_socket,client_socket.nx_tcp_socket_tx_sequence);

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

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Check for error.  */
    if((error_counter != 0) || (data_packet_counter != 2))
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


static void rand_12_20()
{
    UINT       flag;
    UINT       j,k=0;

    srand((unsigned)time(NULL)); 
    for(j=0;j<20;j++)
    {
        flag=rand()%2; 
        if(flag) data_12_20[k++]='A'+rand()%26;
        else data_12_20[k++]='a'+rand()%26;
    }
}

static UINT    my_packet_process_12_20(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

NX_TCP_HEADER         *tcp_header_ptr;
ULONG                 *option_word_1;


ULONG                  val;
ULONG                  checksum;
ULONG                  checksum_ip;
ULONG                  temp;
#if defined(__PRODUCT_NETXDUO__)
        NX_IPV4_HEADER *ip_header_ptr;
#else
        NX_IP_HEADER   *ip_header_ptr;
#endif

#if defined(__PRODUCT_NETXDUO__)
ULONG                  *source_ip, *dest_ip;
#elif defined(__PRODUCT_NETX__)
ULONG                  source_ip, dest_ip;
#else
#error "NetX Product undefined."
#endif

#if defined(__PRODUCT_NETXDUO__)
    ip_header_ptr = (NX_IPV4_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);
#else
    ip_header_ptr = (NX_IP_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);
#endif
    tcp_header_ptr = (NX_TCP_HEADER*)((packet_ptr -> nx_packet_prepend_ptr) + 20);
    option_word_1 = (ULONG *)(tcp_header_ptr + 1);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Construct a data segment with mss option based on the SYN packet*/
    if((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) && !(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
    {
        /*Delete the SYN bit.*/
        tcp_header_ptr -> nx_tcp_header_word_3 = tcp_header_ptr -> nx_tcp_header_word_3 ^ NX_TCP_SYN_BIT;

        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    
        NX_CHANGE_ULONG_ENDIAN(*option_word_1);

        /*Modify the MSS option value to 20*/
        *option_word_1 = *option_word_1 & 0xFFFF0000;
        *option_word_1 = *option_word_1 | 0x00000014;
        NX_CHANGE_ULONG_ENDIAN(*option_word_1);

        rand_12_20();
        nx_packet_data_append(packet_ptr, data_12_20, 20, &pool_0, NX_IP_PERIODIC_RATE);


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

        /*Modify the packet length in ip header.*/
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);
        ip_header_ptr -> nx_ip_header_word_0 = ip_header_ptr -> nx_ip_header_word_0 & 0xFFFF0000;
        ip_header_ptr -> nx_ip_header_word_0 = ip_header_ptr -> nx_ip_header_word_0 | 0x00000044;
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);


        ip_header_ptr -> nx_ip_header_word_2 =  ip_header_ptr -> nx_ip_header_word_2 & 0x0000FFFF;


        temp =       ip_header_ptr -> nx_ip_header_word_0;
        checksum_ip =   (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
        temp =       ip_header_ptr -> nx_ip_header_word_1;
        checksum_ip +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
        temp =       ip_header_ptr -> nx_ip_header_word_2;
        checksum_ip +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
        temp =       ip_header_ptr -> nx_ip_header_source_ip;
        checksum_ip +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);
        temp =       ip_header_ptr -> nx_ip_header_destination_ip;
        checksum_ip +=  (temp >> NX_SHIFT_BY_16) + (temp & NX_LOWER_16_MASK);

        /* Fold a 4-byte value into a two byte value */
        checksum_ip = (checksum_ip >> 16) + (checksum_ip & 0xFFFF);

        /* Do it again in case previous operation generates an overflow */
        checksum_ip = (checksum_ip >> 16) + (checksum_ip & 0xFFFF);          

        /* Convert to host byte order. */
        NX_CHANGE_USHORT_ENDIAN(checksum_ip);

        val = (ULONG)(~checksum_ip);
        val = val & NX_LOWER_16_MASK;

        /* Convert to network byte order. */
        NX_CHANGE_ULONG_ENDIAN(val);

        /* Now store the checksum in the IP header.  */
        ip_header_ptr -> nx_ip_header_word_2 =  ip_header_ptr -> nx_ip_header_word_2 | val;

        /* Modify the new sequence of client socket. */
        client_socket.nx_tcp_socket_tx_sequence += 20;

        advanced_packet_process_callback = NX_NULL;
    }
    else
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    return NX_TRUE;
}



static void    my_tcp_packet_receive_12_20 (NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_TCP_HEADER  *tcp_header_ptr;
ULONG          option_words;
ULONG          mss;

    tcp_header_ptr = (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /*Check if both the sockets are in ESTABLISHED state*/
    if(server_socket.nx_tcp_socket_state == NX_TCP_ESTABLISHED)
    {

        /*Get the option kind*/
        option_words =  (tcp_header_ptr -> nx_tcp_header_word_3 >> 28) - 5;
                       
        /*Get the MSS option form the SYN packet.*/
        _nx_tcp_mss_option_get((packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER)), option_words*sizeof(ULONG), &mss);

        if(mss == mss_option_12_20)
            data_packet_counter++;

        /* Point to default function   */
        ip_0.nx_ip_tcp_packet_receive = _nx_tcp_packet_receive;
    }

    /* Deal with default function   */
    _nx_tcp_packet_receive(ip_ptr, packet_ptr);

}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_12_20_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Spec 12.20 Test.......................................N/A\n"); 

    test_control_return(3);  
}      
#endif

