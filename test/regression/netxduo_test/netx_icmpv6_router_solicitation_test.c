/* Test ICMPv6 Router Solicitation for _nx_packet_allocate failure in _nx_icmpv6_send.rs. */

#include    "tx_api.h"
#include    "nx_api.h"   
#include    "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_ICMPV6_ROUTER_SOLICITATION)
 
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"  
#include    "nx_icmpv6.h"

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;  
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;  
static ULONG                   rs_counter;

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_icmpv6_router_solicitation_test_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    /* Initialize the value.  */
    error_counter = 0;
    rs_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;
  
    /* Enable IPv6 */
    status += nxd_ipv6_enable(&ip_0); 

    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;        

    /* Enable IPv6 ICMP  */
    status += nxd_icmp_enable(&ip_0); 

    /* Check IPv6 ICMP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT                status;
UINT                address_index;

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 Router Solicitation Test..........................."); 

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
     
    /* Set the callback function to process the RS packet.  */
    advanced_packet_process_callback = my_packet_process;

    /* Set the linklocal address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, &address_index); 

    /* Check the status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the Router */
    if (ip_0.nx_ip_interface[0].nx_ipv6_rtr_solicitation_count != 3)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Sleep 5 seconds for linklocal address DAD and (NX_ICMPV6_RTR_SOLICITATION_INTERVAL*3) for Router Solicitation.  */
    tx_thread_sleep((5 + (NX_ICMPV6_RTR_SOLICITATION_INTERVAL * 3)) * NX_IP_PERIODIC_RATE);
    
    /* Check the Router Solicitation count. */
    if (ip_0.nx_ip_interface[0].nx_ipv6_rtr_solicitation_count != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the error.  */
    if((error_counter) ||(rs_counter != 1))
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

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{                 

UINT                       status;
UINT                       i;
UINT                       packet_counter;
NX_ICMPV6_HEADER          *header_ptr;
NX_PACKET                 *tmp_packet[16];


    /* Points to the ICMP message header.  */
    header_ptr =  (NX_ICMPV6_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_IPV6_HEADER));

    /* Determine the message type and call the appropriate handler.  */
    if (header_ptr -> nx_icmpv6_header_type == NX_ICMPV6_ROUTER_SOLICITATION_TYPE)
    {

        /* Update the RS counter.  */
        rs_counter ++;
    }

    /* Check the rs_counter, allocate all packets to let ip_0 send RS failure.  */
    if (rs_counter == 1)
    {

        /* Release the RS packet.  */
        nx_packet_release(packet_ptr);

        /* Get the available packet.  */
        packet_counter = pool_0.nx_packet_pool_available;

        /* Loop to allocate the all packets from pool_0.  */
        for (i = 0; i < packet_counter; i++)
        {

            /* Allocate a packet.  */
            status =  nx_packet_allocate(&pool_0, &tmp_packet[i], NX_UDP_PACKET, TX_WAIT_FOREVER);   

            /* Check the status.  */
            if (status)
                error_counter++;   
        }
    }

    return NX_FALSE;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_icmpv6_router_solicitation_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 Router Solicitation Test...........................N/A\n");   
    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */
