/* This NetX test concentrates on the processing of duplicated fragments.  */


#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void  test_control_return(UINT status);
#if !defined(NX_DISABLE_FRAGMENTATION) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048
#define     SEND_SIZE               3000


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1;
#endif /* FEATURE_NX_IPV6 */

static UINT                    fragments_count;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static UCHAR                   send_buf[SEND_SIZE];
static UCHAR                   pool_area[102400];

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_duplicate_test_application_define(void *first_unused_memory)
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

    /* Create the server thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1000, pool_area, sizeof(pool_area));

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for both IP instances.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    status +=  nx_udp_enable(&ip_1);

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 traffic.  */
    status += nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    /* Enable ICMP processing for both IP instances.  */
    status +=  nxd_icmp_enable(&ip_0);
    status +=  nxd_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

    /* Set global address. */    
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0xFE800000;
    address_0.nxd_ip_address.v6[1] = 0x00000000;
    address_0.nxd_ip_address.v6[2] = 0x00000000;
    address_0.nxd_ip_address.v6[3] = 0x00000001;

    address_1.nxd_ip_version = NX_IP_VERSION_V6;
    address_1.nxd_ip_address.v6[0] = 0xFE800000;
    address_1.nxd_ip_address.v6[1] = 0x00000000;
    address_1.nxd_ip_address.v6[2] = 0x00000000;
    address_1.nxd_ip_address.v6[3] = 0x00000002;

    status = nxd_ipv6_address_set(&ip_0, 0, &address_0, 10, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &address_1, 10, NX_NULL);

#endif /* FEATURE_NX_IPV6 */

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable IP fragmentation logic on both IP instances.  */
    status =  nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);

    /* Check for IP fragment enable errors.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;
UINT        i;


    /* Print out some test information banners.  */
    printf("NetX Test:   IP Fragmentation Duplicate Test...........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* Sleep 5 seconds to finish DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */


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

#ifdef FEATURE_NX_IPV6
    for (i = 0; i < 2; i++)
#else
    for (i = 0; i < 1; i++)
#endif
    {

        /* Reset the testing data. */
        memset(send_buf, i, sizeof(send_buf));
        fragments_count = 0;

        /* Set callback function to duplicate the second fragments. */
        advanced_packet_process_callback = packet_process;

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Append data.  */
        status = nx_packet_data_append(my_packet, send_buf, sizeof(send_buf), &pool_0, NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        if (i == 0)
        {
            status = nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);
        }
#ifdef FEATURE_NX_IPV6
        else
        {
            status = nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);
        }
#endif /* FEATURE_NX_IPV6 */


        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Clear the callback function. */
        advanced_packet_process_callback = NX_NULL;
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
}
    

static void    thread_1_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;
UINT        i;

#ifdef FEATURE_NX_IPV6
    /* Sleep 5 seconds to finish DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */


    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, 0x89, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    for (i = 0; i < 2; i++)
#else
    for (i = 0; i < 1; i++)
#endif
    {

        /* Receive a UDP packet.  */
        status =  nx_udp_socket_receive(&socket_1, &my_packet, 5 * NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        if(my_packet -> nx_packet_length != sizeof(send_buf))
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Release the packet.  */
        status =  nx_packet_release(my_packet);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
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

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    /* Ignore packets from IP_1. */
    if (ip_ptr == &ip_1)
        return NX_TRUE;

    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
    {
        if ((packet_ptr -> nx_packet_length > 28) &&
            (*(packet_ptr -> nx_packet_prepend_ptr + 9) == NX_PROTOCOL_UDP))
        {

            /* It's a UDP packet. */
            if (fragments_count == 1)
            {
                *operation_ptr = 2 * NX_RAMDRIVER_OP_DELAY;
                *delay_ptr = NX_IP_PERIODIC_RATE;
            }
            else if (fragments_count == 2)
            {
                *operation_ptr = NX_RAMDRIVER_OP_DUPLICATE;
            }

            fragments_count++;
        }
    }
#ifdef FEATURE_NX_IPV6
    else
    {
        if ((packet_ptr -> nx_packet_length > 48) &&
            (*(packet_ptr -> nx_packet_prepend_ptr + 6) == NX_PROTOCOL_NEXT_HEADER_FRAGMENT))
        {

            /* It's a UDP packet. */
            if(fragments_count == 1)
            {
                *operation_ptr = NX_RAMDRIVER_OP_DELAY;
                *delay_ptr = NX_IP_PERIODIC_RATE;
            }
            else if (fragments_count == 2)
            {
                *operation_ptr = NX_RAMDRIVER_OP_DUPLICATE;
            }

            fragments_count++;
        }
    }
#endif /* FEATURE_NX_IPV6 */

    return NX_TRUE;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_duplicate_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out some test information banners.  */
    printf("NetX Test:   IP Fragmentation Duplicate Test...........................N/A\n");
    test_control_return(3);
}
#endif 
