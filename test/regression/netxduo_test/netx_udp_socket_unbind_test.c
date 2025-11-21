/* This NetX test concentrates on the UDP socket unbind operation.  */


#include   "tx_api.h"
#include   "nx_api.h"

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static TX_THREAD               thread_2;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;
static NX_UDP_SOCKET           socket_2;
static NX_UDP_SOCKET           socket_3;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* The 2 ports will hashed to the same index. */
#define CLIENT_PORT_1           0x00000100
#define CLIENT_PORT_2           0x00008100

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    thread_2_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    test_control_return(UINT status);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_socket_unbind_test_application_define(void *first_unused_memory)
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

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_2, "thread 2", thread_2_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;

    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Socket Unbind  Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status)
        error_counter++;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_3, "Socket 3", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status)
        error_counter++;

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, CLIENT_PORT_1, 2 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Bind the UDP socket to the IP port which is mapped to the same index with CLIENT_PORT_1.  */
    status =  nx_udp_socket_bind(&socket_3, CLIENT_PORT_2, 2 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    
    /* Let socket 1 bind to CLIENT_PORT_1 that socket 0 has bound to . */
    tx_thread_suspend(&thread_0);

    /* Unbind the socket 1, socket_1 is in bound process now. */
    status = nx_udp_socket_unbind(&socket_1);
    if (status)
        error_counter++;

    /* Let socket 1 and socket 2 bind to CLIENT_PORT_1 that socket 0 has bound to again. */
    tx_thread_resume(&thread_2);
    tx_thread_suspend(&thread_0);

    /* Unbind the UDP socket. thread_1 and thread_2 is suspended for CLIENT_PORT_1 now, and  */
    /* socket_3 is bound to the port which has the same hash index with CLIENT_PORT_1. */
    status =  nx_udp_socket_unbind(&socket_0);
    if (status)
        error_counter++;

    status = nx_udp_socket_unbind(&socket_3);
    status = nx_udp_socket_delete(&socket_3);

    /* Let thread 1  and thread 2 finish the job. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    status =  nx_udp_socket_bind(&socket_0, CLIENT_PORT_1, 2 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    tx_thread_resume(&thread_2);
    tx_thread_sleep(NX_IP_PERIODIC_RATE/2);

    status =  nx_udp_socket_unbind(&socket_0);
    if (status)
        error_counter++;

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_0);
    if (status)
        error_counter++;


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
    

static void    thread_1_entry(ULONG thread_input)
{

UINT        status;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status)
        error_counter++;

    /* Bind the UDP socket to CLIENT_PORT_1 that socket_0 has bound to. */
    status = nx_udp_socket_bind(&socket_1, CLIENT_PORT_1, 5 * NX_IP_PERIODIC_RATE);
    if (status != NX_PORT_UNAVAILABLE)
        error_counter++;

    tx_thread_resume(&thread_0);
    /* Bind the UDP socket to CLIENT_PORT_1 that socket_0 has bound to. */
    status = nx_udp_socket_bind(&socket_1, CLIENT_PORT_1, 5 * NX_IP_PERIODIC_RATE);

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_1);

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_1);
}

static void    thread_2_entry(ULONG thread_input)
{
UINT status;
    
    /* Suspend this thread, resume thread_0. */
    tx_thread_resume(&thread_0);
    tx_thread_suspend(&thread_2);

    status = nx_udp_socket_create(&ip_0, &socket_2, "Socket 2", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if(status)
        error_counter++;

    /* Bind the socket to CLIENT_PORT_1 that socket_0 has bound to. */
    status = nx_udp_socket_bind(&socket_2, CLIENT_PORT_1, 5 * NX_IP_PERIODIC_RATE);

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_2);

    tx_thread_suspend(&thread_2);
    status =  nx_udp_socket_bind(&socket_2, CLIENT_PORT_1, 5 * NX_IP_PERIODIC_RATE);
}
