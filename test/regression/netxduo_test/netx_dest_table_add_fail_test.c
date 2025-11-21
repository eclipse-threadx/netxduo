/* This NetX test concentrates on the failure of adding destination table.  */

#include   "nx_api.h"
#include   "nx_ip.h"

extern void    test_control_return(UINT status);
#ifdef FEATURE_NX_IPV6
#include   "nx_icmpv6.h"
#include   "nx_nd_cache.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static NXD_ADDRESS             global_address_0; 


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dest_table_add_fail_test_application_define(void *first_unused_memory)
#endif
{

CHAR   *pointer;
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check status.  */
    if (status)
        error_counter++;
    
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;
    
    /* Set ipv6 global address for IP instance 0.  */
    global_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_0.nxd_ip_address.v6[0] = 0x20010000;
    global_address_0.nxd_ip_address.v6[1] = 0x00000000;
    global_address_0.nxd_ip_address.v6[2] = 0x00000000;
    global_address_0.nxd_ip_address.v6[3] = 0x10000001;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &global_address_0, 64, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;       

    /* Enable ICMPv6 processing for IP instances0 .  */
    status = nxd_icmp_enable(&ip_0);      

    /* Check ICMPv6 enable status.  */
    if(status)
        error_counter++;
}                 


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT            status;     
UINT            i;
ND_CACHE_ENTRY *nd_cache_entry;
NX_IPV6_DESTINATION_ENTRY
               *dest_entry;
NXD_ADDRESS     dest_ip;      
CHAR            mac_address[6];
ULONG           next_hop;

    
    /* Print out test information banner.  */
    printf("NetX Test:   Dest Table Add Fail Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                          

    /* Added ND Cache entry until full.  */
    for (i = 0; i < NX_IPV6_NEIGHBOR_CACHE_SIZE; i++)
    {

        /* Set unique MAC address. */
        mac_address[0] = 0x00;                
        mac_address[1] = 0x11;
        mac_address[2] = 0x22;
        mac_address[3] = 0x33;
        mac_address[4] = 0x44;
        mac_address[5] = i + 1;

        /* Set unique ipv6 address.  */
        dest_ip.nxd_ip_version = NX_IP_VERSION_V6;
        dest_ip.nxd_ip_address.v6[0] = 0x20010000;
        dest_ip.nxd_ip_address.v6[1] = 0x00000000;
        dest_ip.nxd_ip_address.v6[2] = 0x00000000;
        dest_ip.nxd_ip_address.v6[3] = i + 1;      

        /* Call the function to added nd cache entry.  */
        status = _nx_nd_cache_add(&ip_0, dest_ip.nxd_ip_address.v6, &ip_0.nx_ip_interface[0], mac_address, 
                                  NX_FALSE, ND_CACHE_STATE_CREATED, &(ip_0.nx_ipv6_address[0]), &nd_cache_entry);

        /* Check status.  */
        if (status)           
        {

            printf("ERROR!\n");
            test_control_return(1);
        }           
    }

    /* Set unique MAC address. */
    mac_address[0] = 0x00;                
    mac_address[1] = 0x11;
    mac_address[2] = 0x22;
    mac_address[3] = 0x33;
    mac_address[4] = 0x44;
    mac_address[5] = i + 1;

    /* Set unique ipv6 address.  */
    dest_ip.nxd_ip_version = NX_IP_VERSION_V6;
    dest_ip.nxd_ip_address.v6[0] = 0x20010000;
    dest_ip.nxd_ip_address.v6[1] = 0x00000000;
    dest_ip.nxd_ip_address.v6[2] = 0x00000000;
    dest_ip.nxd_ip_address.v6[3] = i + 1;      

    /* Call the function to added nd cache entry.  */
    status = _nx_nd_cache_add(&ip_0, dest_ip.nxd_ip_address.v6, &ip_0.nx_ip_interface[0], mac_address, 
                              NX_FALSE, ND_CACHE_STATE_CREATED, &(ip_0.nx_ipv6_address[0]), &nd_cache_entry);

    /* Check status.  */
    if (status != NX_NOT_SUCCESSFUL)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Add destination table entry. */
    status = _nx_icmpv6_dest_table_add(&ip_0, dest_ip.nxd_ip_address.v6, &dest_entry,
                                       &next_hop, 0, 0, &(ip_0.nx_ipv6_address[0]));

    /* Check status.  */
    if (status != NX_NOT_SUCCESSFUL)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Now delete one nd cache entry. */
    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_nd_status = ND_CACHE_STATE_INVALID;

    /* Add destination table entry. */
    status = _nx_icmpv6_dest_table_add(&ip_0, dest_ip.nxd_ip_address.v6, &dest_entry,
                                       &next_hop, 0, 0, &(ip_0.nx_ipv6_address[0]));

    /* Check status.  */
    if (status != NX_SUCCESS)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}         
#else    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dest_table_add_fail_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   Dest Table Add Fail Test..................................N/A\n");
    
    test_control_return(3);
}
#endif
