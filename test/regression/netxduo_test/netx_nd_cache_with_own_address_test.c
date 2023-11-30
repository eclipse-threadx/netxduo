/* Test IPv6 ND CACHE APIs. */

#include    "tx_api.h"
#include    "nx_api.h"

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_IPV6_DAD)
#include    "nx_ip.h"
#include    "nx_ipv6.h" 

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;        

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_nd_cache_with_own_address_test_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

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

    if(status)
        error_counter++;         
                                              
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 

    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;                       

    /* Enable ICMPv6 */
    status = nxd_icmp_enable(&ip_0); 

    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT                status;   
NXD_ADDRESS         dest_address;
CHAR                dest_mac[6]; 
NXD_ADDRESS         ipv6_address;   
ULONG               physical_msw;
ULONG               physical_lsw;
UINT                interface_index;
UINT                address_index;

    /* Print out test information banner.  */
    printf("NetX Test:   ND Cache With Own Address Test............................"); 

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                    
                        
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

    /* Set the Destination address and mac address.  */ 
    dest_address.nxd_ip_version = NX_IP_VERSION_V6;
    dest_address.nxd_ip_address.v6[0] = 0xfe800000;
    dest_address.nxd_ip_address.v6[1] = 0x00000000;
    dest_address.nxd_ip_address.v6[2] = 0x021122ff;
    dest_address.nxd_ip_address.v6[3] = 0xfe334457;

    dest_mac[0] = 0x00;  
    dest_mac[1] = 0x11;
    dest_mac[2] = 0x22;
    dest_mac[3] = 0x33;
    dest_mac[4] = 0x44;
    dest_mac[5] = 0x57;

    /* Set the ND CACHE entry.  */
    status = nxd_nd_cache_entry_set(&ip_0, &dest_address.nxd_ip_address.v6[0], 0, &dest_mac[0]); 
           
    /* Check status.  */
    if(status)
        error_counter++;         
                
    /* Find the hardware address and interface index by ipv6 address.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &dest_address, &physical_msw, &physical_lsw, &interface_index);
              
    /* Check status.  */
    if(status)
        error_counter++;

    /* Match the mac address and interface index.  */
    if ((interface_index != 0) ||
        (physical_msw != 0x00000011) ||
        (physical_lsw != 0x22334457))
        error_counter ++; 
                           
    /* Find the ipv6 address and interface index by hardware address.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0x00000011, 0x22334457, &interface_index);
              
    /* Check status.  */
    if(status)
        error_counter++;

    /* Match the mac address and interface index.  */
    if ((interface_index != 0) ||
        (ipv6_address.nxd_ip_address.v6[0] != dest_address.nxd_ip_address.v6[0]) ||
        (ipv6_address.nxd_ip_address.v6[1] != dest_address.nxd_ip_address.v6[1]) ||
        (ipv6_address.nxd_ip_address.v6[2] != dest_address.nxd_ip_address.v6[2]) ||
        (ipv6_address.nxd_ip_address.v6[3] != dest_address.nxd_ip_address.v6[3]))
        error_counter ++;         

    /* Delete the linklocal address.  */
    nxd_ipv6_address_delete(&ip_0, address_index);

    /* Set the physical address.  */
    physical_msw = 0x00000011;
    physical_lsw = 0x22334457;

    /* Set the interface capability.  */
    status = nx_ip_interface_physical_address_set(&ip_0, 0, physical_msw, physical_lsw, NX_TRUE);
    
    /* Check the status.  */
    if (status)
        error_counter++;
                             
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
                                                                           
    /* The linklocal address is same as nd cache address, the ND entry should be invalid.   */

    /* Find the hardware address and interface index by ipv6 address.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &dest_address, &physical_msw, &physical_lsw, &interface_index);
              
    /* Check status.  */
    if(status == NX_SUCCESS)
        error_counter++;

    /* Find the ipv6 address and interface index by hardware address.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0x00000011, 0x22334456, &interface_index);
              
    /* Check status.  */
    if(status == NX_SUCCESS)
        error_counter++;                                                

    /* Check the error counter.  */
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

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_nd_cache_with_own_address_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ND Cache With Own Address Test............................N/A\n");   
    test_control_return(3);        
}
#endif /* FEATURE_NX_IPV6 */
