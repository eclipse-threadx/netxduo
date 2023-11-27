/* This NetX test concentrates on the UDP port unreachable.  */


#include   "nx_api.h"

extern void  test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_ICMPV4_ERROR_MESSAGE) && !defined(NX_DISABLE_ICMP_INFO) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_port_unreachable_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the client thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
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

    /* Create an IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable UDP traffic.  */
    status +=  nx_udp_enable(&ip_0);
    status +=  nx_udp_enable(&ip_1);

    /* Enable ICMP.  */
    status +=  nx_icmp_enable(&ip_0);
    status +=  nx_icmp_enable(&ip_1);

    /* Check for errors.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;


    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Port Unreachable Test.................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Append data.  */
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Verify the ICMPv4 error message is received. */
    if (ip_0.nx_ip_icmp_unhandled_messages != 1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Now create socket 1 and bind to port 0x8089. The hash value of 0x8089 is the same as 0x89. */
    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, 0x8089, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Append data.  */
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Verify the ICMPv4 error message is received. */
    if (ip_0.nx_ip_icmp_unhandled_messages != 2)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_0);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_0);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_1);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_1);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_port_unreachable_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Port Unreachable Test.................................N/A\n");
    test_control_return(3);
}
#endif 
