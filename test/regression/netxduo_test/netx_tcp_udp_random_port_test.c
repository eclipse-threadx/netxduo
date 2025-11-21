/* This NetX test concentrates on the TCP and UDP free port find.
 * The port is random but not incremental. Follow section 3.3.1, RFC 6056.  */


#include   "tx_api.h"
#include   "nx_api.h"

#define     DEMO_STACK_SIZE 2048
#define     TEST_LOOP       100


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           tcp_socket[2];
static NX_UDP_SOCKET           udp_socket[2];

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

extern void  test_control_return(UINT status);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_tcp_udp_random_port_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable TCP traffic.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check for TCP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
}


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UCHAR       not_incremental;
UINT        status;
UINT        previous_port;
UINT        port;
UINT        i;


    /* Print out some test information banners.  */
    printf("NetX Test:   TCP UDP Random Port Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                     
    /* Create a TCP socket.  */
    nx_tcp_socket_create(&ip_0, &tcp_socket[0], "TCP Socket 0", 
                         NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                         NX_NULL, NX_NULL);
    nx_tcp_socket_create(&ip_0, &tcp_socket[1], "TCP Socket 1", 
                         NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                         NX_NULL, NX_NULL);

    status =  nx_tcp_client_socket_bind(&tcp_socket[1], NX_ANY_PORT, NX_WAIT_FOREVER);
    if (status != NX_SUCCESS)
        error_counter++;

    /* TCP random port test. */
    not_incremental = NX_FALSE;
    nx_tcp_client_socket_port_get(&tcp_socket[1], &previous_port);

    for (i = 0; i < TEST_LOOP; i++)
    {

        previous_port++;
        if (previous_port == NX_MAX_PORT)
        {
            previous_port = 1;
        }
        status =  nx_tcp_client_socket_bind(&tcp_socket[i & 1], NX_ANY_PORT, NX_WAIT_FOREVER);
        if (status != NX_SUCCESS)
            error_counter++;

        nx_tcp_client_socket_port_get(&tcp_socket[i & 1], &port);

        /* Check whether free_port is increased by one of previous_port. */
        if (port != previous_port)
        {
            not_incremental = NX_TRUE;
        }

        nx_tcp_client_socket_unbind(&tcp_socket[1 - (i & 1)]);

        previous_port = port;
    }

    if (not_incremental == NX_FALSE)
    {
        error_counter++;
    }
                     
    /* Create a UDP socket.  */
    nx_udp_socket_create(&ip_0, &udp_socket[0], "UDP Socket 0", NX_IP_NORMAL,
                         NX_FRAGMENT_OKAY, 0x80, 5);
    nx_udp_socket_create(&ip_0, &udp_socket[1], "UDP Socket 1", NX_IP_NORMAL,
                         NX_FRAGMENT_OKAY, 0x80, 5);

    status =  nx_udp_socket_bind(&udp_socket[1], NX_ANY_PORT, TX_WAIT_FOREVER);
    if (status != NX_SUCCESS)
        error_counter++;

    /* UDP random port test. */
    not_incremental = NX_FALSE;
    nx_udp_socket_port_get(&udp_socket[1], &previous_port);

    for (i = 0; i < TEST_LOOP; i++)
    {

        previous_port++;
        if (previous_port == NX_MAX_PORT)
        {
            previous_port = 1;
        }
        status =  nx_udp_socket_bind(&udp_socket[i & 1], NX_ANY_PORT, TX_WAIT_FOREVER);
        if (status != NX_SUCCESS)
            error_counter++;

        nx_udp_socket_port_get(&udp_socket[i & 1], &port);

        /* Check whether free_port is increased by one of previous_port. */
        if (port != previous_port)
        {
            not_incremental = NX_TRUE;
        }

        nx_udp_socket_unbind(&udp_socket[1 - (i & 1)]);

        previous_port = port;
    }

    if (not_incremental == NX_FALSE)
    {
        error_counter++;
    }

    /* Check status.  */
    if (error_counter)
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
