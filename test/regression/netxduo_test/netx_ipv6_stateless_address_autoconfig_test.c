/* Test IPv6 ND CACHE APIs. */

#include    "tx_api.h"
#include    "nx_api.h"   
#include    "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && defined(NX_IPV6_STATELESS_AUTOCONFIG_CONTROL) && !defined(NX_DISABLE_ICMPV6_ROUTER_SOLICITATION)
 
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"  
#include    "nx_icmpv6.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;  
static NX_PACKET_POOL          pool_0;
#ifdef NX_ENABLE_DUAL_PACKET_POOL
static NX_PACKET_POOL          auxiliary_pool;
#endif
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;  
static ULONG                   rs_counter;
static ULONG                   address_expired;

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);       
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
static VOID    ip_address_change_notify(NX_IP *ip_ptr, UINT operation, UINT if_index, UINT address_index, ULONG *address);
#endif /* NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY */
                                               
/* RA packet.  */
/* Two prefixes, 3ffe:0501:ffff:0100:: and 3ffe:0501:ffff:0101:: */
static char pkt1[] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 
0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00, 
0x00, 0x00, 0x00, 0x58, 0x3a, 0xff, 0xfe, 0x80, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0xff, 0x02, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0x00, 
0xa3, 0xd5, 0x40, 0x00, 0x07, 0x0d, 0x00, 0x00, 
0x75, 0x35, 0x00, 0x00, 0x03, 0xed, 0x01, 0x01, 
0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x04, 
0x40, 0xc0, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 
0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xfe, 
0x05, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x04, 
0x40, 0xc0, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 
0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xfe, 
0x05, 0x01, 0xff, 0xff, 0x01, 0x01, 0x00, 0x00, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/* One prefix 3ffe:0501:ffff:0100. */
static const unsigned char pkt2[110] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, /* 33...... */
0x00, 0x00, 0xa0, 0xa0, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x38, 0x3a, 0xff, 0xfe, 0x80, /* ...8:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0xa0, 0xa0, 0xfe, 0x80, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x86, 0x00, /* "..3DV.. */
0x7f, 0xd1, 0x40, 0x00, 0x07, 0x08, 0x00, 0x00, /* ..@..... */
0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x0f, 0x14, 0x40, 0x03, 0x04, /* .....@.. */
0x40, 0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, /* @....... */
0x09, 0x60, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xfe, /* .`....?. */
0x05, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_stateless_address_autoconfig_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    /* Initialize the value.  */
    error_counter = 0;
    rs_counter = 0;
    address_expired = 0;

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

#ifdef NX_ENABLE_DUAL_PACKET_POOL  
    /* Create a auxiliary pool.  */
    status = nx_packet_pool_create(&auxiliary_pool, "NetX Main Auxiliary Pool", 256, pointer, 256*16);
    pointer = pointer + 256*16;

    if(status)
        error_counter++;
#endif

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
UINT                i, packet_counter_0;  
#ifdef NX_ENABLE_DUAL_PACKET_POOL    
UINT                packet_counter_1; 
NX_PACKET          *tmp_auxiliary_packet[16];
#endif
UINT                address_index;
NXD_ADDRESS         ipv6_address;
ULONG               prefix_length;
UINT                interface_index;    
NX_PACKET          *tmp_packet[16];   
NX_PACKET          *my_packet;

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Stateless Address Autoconfig Test...................."); 

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                     

#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
    /* Set address change notify. */
    nxd_ipv6_address_change_notify(&ip_0, ip_address_change_notify);
#endif /* NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY */

    /* Disable the Stateless Address Autoconfig feature.  */
    status = nxd_ipv6_stateless_address_autoconfig_disable(&ip_0, 0);
                        
    /* Check the status.  */
    if(status)
        error_counter++;     

    /* Disable the Stateless Address Autoconfig feature again.  */
    status = nxd_ipv6_stateless_address_autoconfig_disable(&ip_0, 0);
                        
    /* Check the status.  */
    if(status)
        error_counter++; 

    /* Set the linklocal address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, &address_index); 

    /* Check the status.  */
    if(status)
        error_counter++;  

    /* Sleep 5 seconds for linklocal address DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Get the linklocal address.  */
    status = nxd_ipv6_address_get(&ip_0, address_index, &ipv6_address, &prefix_length, &interface_index);
                       
    /* Check the status.  */
    if((status) || (prefix_length != 10) || (interface_index != 0))
        error_counter++;  

    /* Set the callback function to process the RS packet.  */
    advanced_packet_process_callback = my_packet_process;    
                                                          
    packet_counter_0 = pool_0.nx_packet_pool_available;

    /* Loop to allocate the all packets from pool_0.  */
    for (i = 0; i < packet_counter_0; i++)
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &tmp_packet[i], NX_UDP_PACKET, TX_WAIT_FOREVER);   

        /* Check the status.  */
        if (status)
            error_counter++;   
    }
             
#ifdef NX_ENABLE_DUAL_PACKET_POOL      
    packet_counter_1 = auxiliary_pool.nx_packet_pool_available;

    /* Loop to allocate the all packets from auxiliary_pool.  */
    for (i = 0; i < packet_counter_1; i++)
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&auxiliary_pool, &tmp_auxiliary_packet[i], NX_UDP_PACKET, TX_WAIT_FOREVER);   

        /* Check the status.  */
        if (status)
            error_counter++;   
    }
#endif

    /* Enable the Stateless Address Autoconfig feature.  */
    status = nxd_ipv6_stateless_address_autoconfig_enable(&ip_0, 0);
                     
    /* Check the status.  */
    if(status)
        error_counter++;  
                                    
    /* Enable the Stateless Address Autoconfig feature again.  */
    status = nxd_ipv6_stateless_address_autoconfig_enable(&ip_0, 0);
                     
    /* Check the status.  */
    if(status != NX_ALREADY_ENABLED)
        error_counter++;  

    /* Sleep 5 seconds for NetX sending RS message.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Check the error.  */
    if(rs_counter != 0)   
        error_counter++; 

    /* Disable the Stateless Address Autoconfig feature.  */
    status = nxd_ipv6_stateless_address_autoconfig_disable(&ip_0, 0);
                        
    /* Check the status.  */
    if(status)
        error_counter++;   

    /* Loop to release the all packets for pool_0.  */
    for (i = 0; i < packet_counter_0; i++)
    {

        /* Allocate a packet.  */
        status =  nx_packet_release(tmp_packet[i]);   

        /* Check the status.  */
        if (status)
            error_counter++;   
    }
             
#ifdef NX_ENABLE_DUAL_PACKET_POOL                              
    /* Loop to release the all packets for auxiliary_pool.  */
    for (i = 0; i < packet_counter_1; i++)
    {
                                
        /* Allocate a packet.  */
        status =  nx_packet_release(tmp_auxiliary_packet[i]);   

        /* Check the status.  */
        if (status)
            error_counter++;   
    }
#endif
                 
    /* Enable the Stateless Address Autoconfig feature.  */
    status = nxd_ipv6_stateless_address_autoconfig_enable(&ip_0, 0);
                     
    /* Check the status.  */
    if(status)
        error_counter++; 

    /* Sleep 5 seconds for Stateless Address Autoconfig.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
                           
    /* Sleep 5 seconds for linklocal address DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Get the Stateless address.  */ 
    status = nxd_ipv6_address_get(&ip_0, 1, &ipv6_address, &prefix_length, &interface_index);
                       
    /* Check the status.  */
    if((status) || (prefix_length != 64) || (interface_index != 0))
        error_counter++;   

    /* Get the Stateless address.  */ 
    status = nxd_ipv6_address_get(&ip_0, 2, &ipv6_address, &prefix_length, &interface_index);
                       
    /* Check the status.  */
    if((status) || (prefix_length != 64) || (interface_index != 0))
        error_counter++;  

    /* Send the RA packet.  */  
    status = nx_packet_allocate(&pool_0, &my_packet, NX_ICMP_PACKET, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
        error_counter ++;

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt2[14], sizeof(pkt2) - 14);
    my_packet -> nx_packet_length = sizeof(pkt2) - 14;
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + sizeof(pkt2) - 14;

    /* Directly receive the RA packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, my_packet);     
                           
    /* Sleep 5 seconds for linklocal address DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Get the Stateless address. No new addresses are generated. */ 
    status = nxd_ipv6_address_get(&ip_0, 3, &ipv6_address, &prefix_length, &interface_index);
    
    if (status == NX_SUCCESS)
        error_counter++;

#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
    /* Sleep 40 seconds and let prefix timeout. */
    tx_thread_sleep(40 * NX_IP_PERIODIC_RATE);

    /* Get the Stateless address.  */ 
    status = nxd_ipv6_address_get(&ip_0, 1, &ipv6_address, &prefix_length, &interface_index);
    
    if (status == NX_SUCCESS)
        error_counter++;

    /* Get the Stateless address.  */ 
    status = nxd_ipv6_address_get(&ip_0, 2, &ipv6_address, &prefix_length, &interface_index);
    
    if (status == NX_SUCCESS)
        error_counter++;
    
    /* Check whether two addresses are expired. */
    if (address_expired != 2)
        error_counter++;
#endif /* NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY */

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


#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
static VOID    ip_address_change_notify(NX_IP *ip_ptr, UINT operation, UINT if_index, 
                                        UINT address_index, ULONG *address)
{
    if (operation == NX_IPV6_ADDRESS_LIFETIME_EXPIRED)
    {
        address_expired++;

        /* Check prefix. */
        if ((address[0] != 0x3ffe0501) ||
            ((address[1] != 0xffff0100) && (address[1] !=0xffff0101)))
        {
            error_counter++;
        }

    }
}
#endif /* NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY */

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{                 

UINT                       status;
NX_ICMPV6_HEADER          *header_ptr;    
NX_PACKET                 *my_packet;

    /* Clean the callback function.  */
    advanced_packet_process_callback = NX_NULL;

    /* Drop the packet. */
    *operation_ptr = NX_RAMDRIVER_OP_DROP;  
    
    /* Points to the ICMP message header.  */
    header_ptr =  (NX_ICMPV6_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_IPV6_HEADER));

    /* Determine the message type and call the appropriate handler.  */
    if (header_ptr -> nx_icmpv6_header_type == NX_ICMPV6_ROUTER_SOLICITATION_TYPE)
    {

        /* Update the RS counter.  */
        rs_counter ++;

        /* Send the RA packet.  */  
        status = nx_packet_allocate(&pool_0, &my_packet, NX_ICMP_PACKET, NX_WAIT_FOREVER);

        /* Check status */
        if(status)
            error_counter ++;

        /* Fill in the packet with data. Skip the MAC header.  */
        memcpy(my_packet -> nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
        my_packet -> nx_packet_length = sizeof(pkt1) - 14;
        my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + sizeof(pkt1) - 14;

        /* Directly receive the RA packet.  */
        _nx_ip_packet_deferred_receive(&ip_0, my_packet);     
    }
                                     
    return NX_TRUE;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_stateless_address_autoconfig_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Stateless Address Autoconfig Test....................N/A\n");   
    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */
