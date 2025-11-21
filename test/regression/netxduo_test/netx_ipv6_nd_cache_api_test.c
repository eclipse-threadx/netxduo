/* Test IPv6 ND CACHE APIs. */

#include    "tx_api.h"
#include    "nx_api.h"

extern void    test_control_return(UINT status);
#define MAX_TEST_INTERFACES 2

#if defined(FEATURE_NX_IPV6) && (NX_MAX_PHYSICAL_INTERFACES >= MAX_TEST_INTERFACES)
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
                                               
static NXD_ADDRESS             ipv6_address_0;
static NXD_ADDRESS             ipv6_address_1;

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_nd_cache_api_test_application_define(void *first_unused_memory)
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

    ipv6_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_0.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_0.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_0.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_0.nxd_ip_address.v6[3] = 0x01020304;

    status += nxd_ipv6_address_set(&ip_0, 0,&ipv6_address_0, 64, NX_NULL); 

    if(status)
        error_counter++;    

    status += nx_ip_interface_attach(&ip_0,"Second Interface",IP_ADDRESS(2,2,3,4),0xFFFFFF00UL,  _nx_ram_network_driver_512);

    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20020000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x01020304;

    status += nxd_ipv6_address_set(&ip_0, 1, &ipv6_address_1, 64, NX_NULL); 
                                              
    /* Enable IPv6 */
    status += nxd_ipv6_enable(&ip_0); 

    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT                status;   
NXD_ADDRESS         dest_address[4];
CHAR                dest_mac[4][6];
NXD_ADDRESS         ipv6_address;   
NXD_ADDRESS         invalid_address;
ULONG               physical_msw;
ULONG               physical_lsw;
UINT                interface_index;

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 ND Cache API Test...................................."); 

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Set the Destination address and mac address.  */ 
    dest_address[0].nxd_ip_version = NX_IP_VERSION_V6;
    dest_address[0].nxd_ip_address.v6[0] = 0x20010000;
    dest_address[0].nxd_ip_address.v6[1] = 0x00000000;
    dest_address[0].nxd_ip_address.v6[2] = 0x00000000;
    dest_address[0].nxd_ip_address.v6[3] = 0x01020305;

    dest_mac[0][0] = 0x11;  
    dest_mac[0][1] = 0x22;
    dest_mac[0][2] = 0x33;
    dest_mac[0][3] = 0x44;
    dest_mac[0][4] = 0x55;
    dest_mac[0][5] = 0x69;

    /* Set the ND CACHE entry.  */
    status = nxd_nd_cache_entry_set(&ip_0, &dest_address[0].nxd_ip_address.v6[0], 0, &dest_mac[0][0]); 
           
    /* Check status.  */
    if(status)
        error_counter++;

    /* Set the Destination address and mac address.  */ 
    dest_address[1].nxd_ip_version = NX_IP_VERSION_V6;
    dest_address[1].nxd_ip_address.v6[0] = 0x20010000;
    dest_address[1].nxd_ip_address.v6[1] = 0x00000000;
    dest_address[1].nxd_ip_address.v6[2] = 0x00000000;
    dest_address[1].nxd_ip_address.v6[3] = 0x01020306;

    dest_mac[1][0] = 0x11;  
    dest_mac[1][1] = 0x22;
    dest_mac[1][2] = 0x33;
    dest_mac[1][3] = 0x44;
    dest_mac[1][4] = 0x55;
    dest_mac[1][5] = 0x70;

    /* Set the ND CACHE entry.  */
    status = nxd_nd_cache_entry_set(&ip_0, &dest_address[1].nxd_ip_address.v6[0], 0, &dest_mac[1][0]); 
                      
    /* Check status.  */
    if(status)
        error_counter++;
                           
    /* Set the Destination address and mac address.  */ 
    dest_address[2].nxd_ip_version = NX_IP_VERSION_V6;
    dest_address[2].nxd_ip_address.v6[0] = 0x20020000;
    dest_address[2].nxd_ip_address.v6[1] = 0x00000000;
    dest_address[2].nxd_ip_address.v6[2] = 0x00000000;
    dest_address[2].nxd_ip_address.v6[3] = 0x01020305;

    dest_mac[2][0] = 0x11;  
    dest_mac[2][1] = 0x22;
    dest_mac[2][2] = 0x33;
    dest_mac[2][3] = 0x44;
    dest_mac[2][4] = 0x66;
    dest_mac[2][5] = 0x69;

    /* Set the ND CACHE entry.  */
    status = nxd_nd_cache_entry_set(&ip_0, &dest_address[2].nxd_ip_address.v6[0], 1, &dest_mac[2][0]); 
           
    /* Check status.  */
    if(status)
        error_counter++;

    /* Set the Destination address and mac address.  */ 
    dest_address[3].nxd_ip_version = NX_IP_VERSION_V6;
    dest_address[3].nxd_ip_address.v6[0] = 0x20020000;
    dest_address[3].nxd_ip_address.v6[1] = 0x00000000;
    dest_address[3].nxd_ip_address.v6[2] = 0x00000000;
    dest_address[3].nxd_ip_address.v6[3] = 0x01020306;

    dest_mac[3][0] = 0x11;  
    dest_mac[3][1] = 0x22;
    dest_mac[3][2] = 0x33;
    dest_mac[3][3] = 0x44;
    dest_mac[3][4] = 0x66;
    dest_mac[3][5] = 0x70;

    /* Set the ND CACHE entry.  */
    status = nxd_nd_cache_entry_set(&ip_0, &dest_address[3].nxd_ip_address.v6[0], 1, &dest_mac[3][0]); 
                      
    /* Check status.  */
    if(status)
        error_counter++;

    /* Find the hardware address and interface index by ipv6 address.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &dest_address[0], &physical_msw, &physical_lsw, &interface_index);
              
    /* Check status.  */
    if(status)
        error_counter++;

    /* Match the mac address and interface index.  */
    if ((interface_index != 0) ||
        (physical_msw != 0x00001122) ||
        (physical_lsw != 0x33445569))
        error_counter ++; 

    /* Find the hardware address and interface index by ipv6 address.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &dest_address[3], &physical_msw, &physical_lsw, &interface_index);
              
    /* Check status.  */
    if(status)
        error_counter++;

    /* Match the mac address and interface index.  */
    if ((interface_index != 1) ||
        (physical_msw != 0x00001122) ||
        (physical_lsw != 0x33446670))
        error_counter ++;
                             
    /* Find the ipv6 address and interface index by hardware address.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0x00001122, 0x33445570, &interface_index);
              
    /* Check status.  */
    if(status)
        error_counter++;

    /* Match the mac address and interface index.  */
    if ((interface_index != 0) ||
        (ipv6_address.nxd_ip_address.v6[0] != dest_address[1].nxd_ip_address.v6[0]) ||
        (ipv6_address.nxd_ip_address.v6[1] != dest_address[1].nxd_ip_address.v6[1]) ||
        (ipv6_address.nxd_ip_address.v6[2] != dest_address[1].nxd_ip_address.v6[2]) ||
        (ipv6_address.nxd_ip_address.v6[3] != dest_address[1].nxd_ip_address.v6[3]))
        error_counter ++; 
                             
    /* Find the ipv6 address and interface index by hardware address.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0x00001122, 0x33446669, &interface_index);
              
    /* Check status.  */
    if(status)
        error_counter++;

    /* Match the mac address and interface index.  */
    if ((interface_index != 1) ||
        (ipv6_address.nxd_ip_address.v6[0] != dest_address[2].nxd_ip_address.v6[0]) ||
        (ipv6_address.nxd_ip_address.v6[1] != dest_address[2].nxd_ip_address.v6[1]) ||
        (ipv6_address.nxd_ip_address.v6[2] != dest_address[2].nxd_ip_address.v6[2]) ||
        (ipv6_address.nxd_ip_address.v6[3] != dest_address[2].nxd_ip_address.v6[3]))
        error_counter ++; 
                         
    /* Set an invalid address.  */ 
    invalid_address.nxd_ip_version = NX_IP_VERSION_V6;
    invalid_address.nxd_ip_address.v6[0] = 0x30000000;
    invalid_address.nxd_ip_address.v6[1] = 0x00000000;
    invalid_address.nxd_ip_address.v6[2] = 0x00000000;
    invalid_address.nxd_ip_address.v6[3] = 0x11111111;                                                             

    /* Delete the ND Cache entry with invalid address.  */
    status = nxd_nd_cache_entry_delete(&ip_0, &invalid_address.nxd_ip_address.v6[0]);
           
    /* Check status.  */
    if(status != NX_ENTRY_NOT_FOUND)
        error_counter++;

    /* Delete the ND Cache entry.  */
    status = nxd_nd_cache_entry_delete(&ip_0, &dest_address[0].nxd_ip_address.v6[0]);
           
    /* Check status.  */
    if(status)
        error_counter++;                                    

    /* Find the destination address 0.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &dest_address[0], &physical_msw, &physical_lsw, &interface_index);
              
    /* Check status.  */
    if(status == NX_SUCCESS)
        error_counter++;

    /* Invalidate the all address.  */
    status = nxd_nd_cache_invalidate(&ip_0);

    /* Check status.  */  
    if(status)
        error_counter++;

    /* Find the mac address 0 by destination address 0.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &dest_address[0], &physical_msw, &physical_lsw, &interface_index);
              
    /* Check status.  */
    if(status == NX_SUCCESS)
        error_counter++;    

    /* Find the mac address 1 by destination address 1.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &dest_address[1], &physical_msw, &physical_lsw, &interface_index);
              
    /* Check status.  */
    if(status == NX_SUCCESS)
        error_counter++;
    
    /* Find the mac address 2 by destination address 2.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &dest_address[2], &physical_msw, &physical_lsw, &interface_index);
              
    /* Check status.  */
    if(status == NX_SUCCESS)
        error_counter++;
    
    /* Find the mac address 3 by destination address 3.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &dest_address[3], &physical_msw, &physical_lsw, &interface_index);
              
    /* Check status.  */
    if(status == NX_SUCCESS)
        error_counter++;
                            
    /* Find the ipv6 address 0 by hardware address 0.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0x00001122, 0x33445569, &interface_index);
                          
    /* Check status.  */
    if(status == NX_SUCCESS)
        error_counter++;
                         
    /* Find the ipv6 address 1 by hardware address 1.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0x00001122, 0x33445570, &interface_index);
                          
    /* Check status.  */
    if(status == NX_SUCCESS)
        error_counter++;
     
    /* Find the ipv6 address 2 by hardware address 2.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0x00001122, 0x33446669, &interface_index);
                          
    /* Check status.  */
    if(status == NX_SUCCESS)
        error_counter++;
     
    /* Find the ipv6 address 3 by hardware address 3.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0x00001122, 0x33446670, &interface_index);
                          
    /* Check status.  */
    if(status == NX_SUCCESS)
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

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_nd_cache_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 ND Cache API Test....................................N/A\n");   
    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */
