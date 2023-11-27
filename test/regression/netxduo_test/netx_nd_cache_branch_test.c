/* This NetX test concentrates on the code coverage for ND functions,
 * _nx_nd_cache_delete_internal.c
 * _nx_nd_cache_find_entry.c
 * _nx_nd_cache_find_entry_by_mac_addr.c
 */

#include "tx_api.h"
#include "nx_api.h"
extern void    test_control_return(UINT status);
#ifdef FEATURE_NX_IPV6
#include "tx_thread.h" 
#include "nx_icmp.h"
#include "nx_icmpv6.h" 

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;



/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nd_cache_branch_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ICMP processing for IP instance.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check ICMP enable status.  */
    if (status)
        error_counter++;

    /* Enable IPv6 processing for IP instance.  */
    status = nxd_ipv6_enable(&ip_0);

    /* Check IPv6 enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{


ULONG       address_1[4];
ND_CACHE_ENTRY  *cache_entry;

    /* Print out some test information banners.  */
    printf("NetX Test:   ND CACHE Branch Test......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }




    /* Hit false condition of while (table_size && i < NX_IPV6_DESTINATION_TABLE_SIZE) in _nx_nd_cache_delete_internal . */
    ip_0.nx_ipv6_destination_table_size = NX_IPV6_DESTINATION_TABLE_SIZE + 1;
    _nx_nd_cache_delete_internal(&ip_0, &ip_0.nx_ipv6_nd_cache[0]);
    ip_0.nx_ipv6_destination_table_size = 0;


    /* Hit false condition of (ip_0.nx_ipv6_nd_cache[index].nx_nd_cache_interface_ptr) in _nx_nd_cache_find_entry . */
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_nd_status = ND_CACHE_STATE_CREATED;
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_interface_ptr = NX_NULL;
    address_1[0] = 0x00000000;
    address_1[1] = 0x00000000;
    address_1[2] = 0x00000000;
    address_1[3] = 0x00000000;
    _nx_nd_cache_find_entry(&ip_0, address_1, &cache_entry);
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_nd_status = ND_CACHE_STATE_INVALID;


    /* Hit condition of if ((mac_msw == physical_msw) && (mac_lsw == physical_lsw)) in _nx_nd_cache_find_entry_by_mac_addr. */
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_nd_status = ND_CACHE_STATE_CREATED;
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_interface_ptr = &ip_0.nx_ip_interface[0];
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_mac_addr[0] = 0x00;
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_mac_addr[1] = 0x11;
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_mac_addr[2] = 0x22;
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_mac_addr[3] = 0x33;
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_mac_addr[4] = 0x44;
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_mac_addr[5] = 0x56;
    _nx_nd_cache_find_entry_by_mac_addr(&ip_0, 0x0000, 0x22334456, &cache_entry);
    _nx_nd_cache_find_entry_by_mac_addr(&ip_0, 0x0011, 0x22334456, &cache_entry);
    memset(&ip_0.nx_ipv6_nd_cache[0], 0, sizeof(ip_0.nx_ipv6_nd_cache[0]));


    /* Hit false condition of (i < NX_IPV6_DESTINATION_TABLE_SIZE) in _nx_invalidate_destination_entry. */
    ip_0.nx_ipv6_destination_table_size = NX_IPV6_DESTINATION_TABLE_SIZE + 1;
    address_1[0] = 0x90010001;
    address_1[1] = 0x00000002;
    address_1[2] = 0x00000003;
    address_1[3] = 0x00000004;
    _nx_invalidate_destination_entry(&ip_0, address_1);
    ip_0.nx_ipv6_destination_table_size = 0;


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

#else    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nd_cache_branch_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   ND CACHE Branch Test......................................N/A\n");
    
    test_control_return(3);
}
#endif

