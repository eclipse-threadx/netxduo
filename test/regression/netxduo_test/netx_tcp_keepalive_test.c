/* This NetX test concentrates on the basic TCP Keepalive operation.  
   keepalive expiration time is 60s, 
   After initial expiration, retry every 10s,
   Retry a maximum of 10 tims.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"  
#include   "nx_ram_network_driver_test_1500.h"
                           
extern void    test_control_return(UINT status);

#if defined(NX_ENABLE_TCP_KEEPALIVE) && (NX_TCP_KEEPALIVE_INITIAL == 60) && (NX_TCP_KEEPALIVE_RETRY == 10) && (NX_TCP_KEEPALIVE_RETRIES == 10) && !defined(NX_DISABLE_IPV4)                                      

#define     DEMO_STACK_SIZE         2048
                                         
/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;       


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;
static ULONG                   ip_0_ack_counter =  0; 
static ULONG                   ip_1_ack_counter =  0;
static ULONG                   ip_0_rst_counter =  0;
static ULONG                   ip_1_rst_counter =  0;  

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);  
static void    thread_0_disconnect_received(NX_TCP_SOCKET *server_socket);
static void    thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_keepalive_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;
                             
    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}           

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;               

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Keepalive Test........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                    NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                    NX_NULL, thread_0_disconnect_received);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 11, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;    

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;    
                 
    /* Set the callback function to detect the socket keepalive packet.  */
    advanced_packet_process_callback = my_packet_process;

    /* Waiting for keepalive message.  */
    tx_thread_sleep(200 * NX_IP_PERIODIC_RATE);

    /* Check the socket state.  */
#ifdef __PRODUCT_NETXDUO__
    if ((client_socket.nx_tcp_socket_state != NX_TCP_CLOSED) || (server_socket.nx_tcp_socket_state != NX_TCP_LISTEN_STATE))
#else
    if ((client_socket.nx_tcp_socket_state != NX_TCP_CLOSED) || (server_socket.nx_tcp_socket_state != NX_TCP_CLOSED))
#endif
    {            
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the counter.  */
#ifdef __PRODUCT_NETXDUO__
    if ((error_counter !=0) || (ip_0_ack_counter != 10) || (ip_0_rst_counter != 1) || (ip_1_ack_counter != 10) || (ip_1_rst_counter != 1))
#else    
    if ((error_counter !=0) || (ip_0_ack_counter != 9) || (ip_0_rst_counter != 1) || (ip_1_ack_counter != 9) || (ip_1_rst_counter != 1))
#endif
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

UINT            status;
ULONG           actual_status;


    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        error_counter++;
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                NX_NULL, thread_1_disconnect_received);
                                
    /* Check for error.  */
    if (status)
        error_counter++;    

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;
}

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_TCP_HEADER        *tcp_header_ptr;
                             

    /* Only detect the TCP packet.  */
    if (packet_ptr ->nx_packet_length < 40)
        return NX_TRUE;

    /* Get the TCP header.  */
    tcp_header_ptr = (NX_TCP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + 20);

    /* Swap the data.  */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);

    /* Check if the packet is an ACK packet.  */
    if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)
    {             

        /* Check the IP ptr.   */
        if (ip_ptr == &ip_0)
            ip_0_ack_counter ++;
        else    
            ip_1_ack_counter ++;
    }

    /* Release the keepalive packet to let socket resend the packet.  */  
    *operation_ptr = NX_RAMDRIVER_OP_DROP;

    return NX_TRUE;
}  

static void  thread_0_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if (socket == &client_socket)
        ip_0_rst_counter++;
}

static void  thread_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if (socket == &server_socket)
        ip_1_rst_counter++;
}    
#else      
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_keepalive_test_application_define(void *first_unused_memory)
#endif
{      

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Keepalive Test........................................N/A\n");   
    test_control_return(3); 
}
#endif

