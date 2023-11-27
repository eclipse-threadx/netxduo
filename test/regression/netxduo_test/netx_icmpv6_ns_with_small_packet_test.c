/* This NetX test concentrates on the ICMPV6 NS operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_IPV6_DAD)
#include    "nx_ip.h"
#include    "nx_ipv6.h"
#include    "nx_icmpv6.h"

#define     DEMO_STACK_SIZE    2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;   
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the test application...  */
static ULONG                   error_counter;
static ULONG                   NS_counter;

/* Define thread prototypes.  */        
static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
extern UINT    (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr); 

/* Define what the initial system looks like.  */ 
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmpv6_ns_with_small_packet_test_application_define(void *first_unused_memory)
#endif
{

    CHAR    *pointer;
    UINT    status;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NX_IPv6_ICMP_PACKET, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check IP create status.  */
    if(status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);

    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nxd_icmp_enable(&ip_0);

    /* Check ICMP enable status.  */
    if (status)
        error_counter++;
}


/* Define the test threads.  */  
static void    ntest_0_entry(ULONG thread_input)
{

UINT             status = 0;
UINT             address_index;

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 NS With Small Packet Test..........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Hook link driver to check packets. */
    packet_process_callback = packet_process;

    /* Set the IPv6 linklocal address for IP instance 0.  */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, &address_index);

    /* Check the status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);     

    /* Check the NS counter.  */
    if(NS_counter != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_ICMPV6_HEADER          *header_ptr;    


    /* Points to the ICMP message header.  */
    header_ptr =  (NX_ICMPV6_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_IPV6_HEADER));

    /* Determine the message type and call the appropriate handler.  */
    if (header_ptr -> nx_icmpv6_header_type == NX_ICMPV6_NEIGHBOR_SOLICITATION_TYPE)
    {

        /* Update the NS counter.  */
        NS_counter ++; 
    }
                                     
    return NX_TRUE;
}

#else  
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmpv6_ns_with_small_packet_test_application_define(void *first_unused_memory)
#endif
{   

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 NS With Small Packet Test..........................N/A\n");

    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */  
