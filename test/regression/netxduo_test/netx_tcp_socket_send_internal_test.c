/* This NetX test concentrates on the branches coverage for _nx_tcp_socket_send_internal functions,
   697         [ +  - ]:          1 :                 if (preempted == NX_TRUE)

   706         [ +  - ]:          1 :                 if (send_packet != packet_ptr)
*/

#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           tcp_socket;
static UCHAR                   pool_area[8192];
static UCHAR                   send_buffer[3000];


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static UINT                    thread1_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_socket_send_internal_test_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    thread1_counter = 0;

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

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
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
UINT       status;
NX_PACKET *packet_ptr;

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Socket Send Internal Test.............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_0, &tcp_socket, "TCP Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                  NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;


    /* Set TCP socket as establish.  */
    tcp_socket.nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    tcp_socket.nx_tcp_socket_connect_interface = &ip_0.nx_ip_interface[0];
    tcp_socket.nx_tcp_socket_bound_next = &tcp_socket;
    tcp_socket.nx_tcp_socket_tx_window_advertised = 65535;
    tcp_socket.nx_tcp_socket_tx_window_congestion = 65535;
    tcp_socket.nx_tcp_socket_tx_outstanding_bytes = 0;  
    tcp_socket.nx_tcp_socket_mss = 216;
    tcp_socket.nx_tcp_socket_transmit_sent_head = NX_NULL;


    /* Allocate a packet and fill data. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
    if(status != NX_SUCCESS)  
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Append data.  */
    status = nx_packet_data_append(packet_ptr, send_buffer, 100, &pool_0, NX_NO_WAIT);
    if(status != NX_SUCCESS) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let thread1 to check the state. */
    tx_thread_relinquish();

    /* Send packet, get the mutex after check the socket state, .  */
    status = _nx_tcp_socket_send_internal(&tcp_socket, packet_ptr, 2 * NX_IP_PERIODIC_RATE);  

    if(status != NX_NOT_CONNECTED) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Determine if the test was successful.  */
    if ((thread1_counter != 1) || (error_counter))
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

    /* Update the counter.  */
    thread1_counter ++;

    /* Place protection while we check the sequence number for the new TCP packet.  */
    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);

    /* Sleep one second.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Change the state.  */
    tcp_socket.nx_tcp_socket_state = NX_TCP_CLOSED;

    /* Release the mutex before a blocking call. */
    tx_mutex_put(&(ip_0.nx_ip_protection));
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tcp_socket_send_internal_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Socket Send Internal Test.............................N/A\n");

    test_control_return(3);  
}      
#endif
