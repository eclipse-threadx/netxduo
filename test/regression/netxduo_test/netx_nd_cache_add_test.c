/* This NetX test concentrates on the ICMP ping operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"        

extern void    test_control_return(UINT status);
#ifdef FEATURE_NX_IPV6
#include   "nx_nd_cache.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static NXD_ADDRESS             global_address_0; 
static NXD_ADDRESS             global_address_1;  


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nd_cache_add_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 
    status += nxd_ipv6_enable(&ip_1);

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMPv6 processing for IP instances0 .  */
    status = nxd_icmp_enable(&ip_0);      
    status += nxd_icmp_enable(&ip_1);   

    /* Check ICMPv6 enable status.  */
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

    /* Set ipv6 global address for IP instance 1.  */
    global_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_1.nxd_ip_address.v6[0] = 0x20010000;
    global_address_1.nxd_ip_address.v6[1] = 0x00000000;
    global_address_1.nxd_ip_address.v6[2] = 0x00000000;
    global_address_1.nxd_ip_address.v6[3] = 0x10000002;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_1, 0, &global_address_1, 64, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;   
}                 


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT            status;     
UINT            i;
NX_PACKET       *my_packet;     
ND_CACHE_ENTRY  *nd_cache_entry;
NXD_ADDRESS     dest_ip;      
CHAR            mac_address[6];

    
    /* Print out test information banner.  */
    printf("NetX Test:   ND Cache Add Test.........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                          
                          
    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);     

    /* Ping an IP address that does exist.  One entry status is ND_CACHE_STATE_REACHABLE, one entry status is ND_CACHE_STATE_DELAY.  */
    status = nxd_icmp_ping(&ip_0, &global_address_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    /* Added the same ND Cache entry.  */
    mac_address[0] = 0x00;                
    mac_address[1] = 0x11;
    mac_address[2] = 0x22;
    mac_address[3] = 0x33;
    mac_address[4] = 0x44;
    mac_address[5] = 0x57;

    /* Call the function to added the same entry.  */
    status = _nx_nd_cache_add(&ip_0, &global_address_1.nxd_ip_address.v6[0], &ip_0.nx_ip_interface[0], &mac_address[0], 0, ND_CACHE_STATE_CREATED, &ip_0.nx_ipv6_address[0], &nd_cache_entry);

    /* Check status.  */
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           


    /* Added the same ND Cache entry with different first short.  */
    mac_address[0] = 0x11;                
    mac_address[1] = 0x11;
    mac_address[2] = 0x22;
    mac_address[3] = 0x33;
    mac_address[4] = 0x44;
    mac_address[5] = 0x57;

    /* Call the function to added the same entry.  */
    status = _nx_nd_cache_add(&ip_0, &global_address_1.nxd_ip_address.v6[0], &ip_0.nx_ip_interface[0], &mac_address[0], 0, ND_CACHE_STATE_REACHABLE, &ip_0.nx_ipv6_address[0], &nd_cache_entry);

    /* Check status.  */
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           


    /* Added the same ND Cache entry with different second short.  */
    mac_address[0] = 0x11;                
    mac_address[1] = 0x11;
    mac_address[2] = 0x33;
    mac_address[3] = 0x33;
    mac_address[4] = 0x44;
    mac_address[5] = 0x57;

    /* Call the function to added the same entry.  */
    status = _nx_nd_cache_add(&ip_0, &global_address_1.nxd_ip_address.v6[0], &ip_0.nx_ip_interface[0], &mac_address[0], 0, ND_CACHE_STATE_REACHABLE, &ip_0.nx_ipv6_address[0], &nd_cache_entry);

    /* Check status.  */
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           


    /* Added the same ND Cache entry with different third short.  */
    mac_address[0] = 0x11;                
    mac_address[1] = 0x11;
    mac_address[2] = 0x33;
    mac_address[3] = 0x33;
    mac_address[4] = 0x44;
    mac_address[5] = 0x44;

    /* Call the function to added the same entry.  */
    status = _nx_nd_cache_add(&ip_0, &global_address_1.nxd_ip_address.v6[0], &ip_0.nx_ip_interface[0], &mac_address[0], 0, ND_CACHE_STATE_REACHABLE, &ip_0.nx_ipv6_address[0], &nd_cache_entry);

    /* Check status.  */
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           


    /* Set ipv6 global address for IP instance 1.  */
    dest_ip.nxd_ip_version = NX_IP_VERSION_V6;
    dest_ip.nxd_ip_address.v6[0] = 0x20010000;
    dest_ip.nxd_ip_address.v6[1] = 0x00000000;
    dest_ip.nxd_ip_address.v6[2] = 0x00000000;
    dest_ip.nxd_ip_address.v6[3] = 0x10000003;      

    /* Added the same ND Cache entry.  */
    mac_address[0] = 0x00;                
    mac_address[1] = 0x11;
    mac_address[2] = 0x22;
    mac_address[3] = 0x33;
    mac_address[4] = 0x44;
    mac_address[5] = 0x58;

    /* Loop to added the ND CACHE ENTRY.  */
    for (i = 0; i < NX_IPV6_NEIGHBOR_CACHE_SIZE - 1; i ++)
    {         

        /* Update the IP address and mac address.  */
        dest_ip.nxd_ip_address.v6[3] += 1;       
        mac_address[5] += 1;        

        /* Call the function to added the same entry.  */
        status = _nx_nd_cache_add(&ip_0, &dest_ip.nxd_ip_address.v6[0], &ip_0.nx_ip_interface[0], &mac_address[0], 0, ND_CACHE_STATE_CREATED, &ip_0.nx_ipv6_address[0], &nd_cache_entry);

        /* Check status.  */
        if (status)           
        {

            printf("ERROR!\n");
            test_control_return(1);
        }    
    }         

    /* Set the status to stale. */
    ip_0.nx_ipv6_nd_cache[NX_IPV6_NEIGHBOR_CACHE_SIZE - 1].nx_nd_cache_nd_status = ND_CACHE_STATE_STALE;
    ip_0.nx_ipv6_nd_cache[NX_IPV6_NEIGHBOR_CACHE_SIZE - 1].nx_nd_cache_timer_tick = 10;
    ip_0.nx_ipv6_nd_cache[NX_IPV6_NEIGHBOR_CACHE_SIZE - 2].nx_nd_cache_nd_status = ND_CACHE_STATE_STALE;
    ip_0.nx_ipv6_nd_cache[NX_IPV6_NEIGHBOR_CACHE_SIZE - 2].nx_nd_cache_timer_tick = 20;

    /* Update the IP address and mac address.  */
    dest_ip.nxd_ip_address.v6[3] += 1;       
    mac_address[5] += 1;        

    /* Call the function to added the new entry. the entry status is ND_CACHE_STATE_REACHABLE can be replaced when disable the NX_DISABLE_IPV6_PURGE_UNUSED_CACHE_ENTRIES.  */
    status = _nx_nd_cache_add(&ip_0, &dest_ip.nxd_ip_address.v6[0], &ip_0.nx_ip_interface[0], &mac_address[0], 0, ND_CACHE_STATE_CREATED, &ip_0.nx_ipv6_address[0], &nd_cache_entry);
           
#ifndef NX_DISABLE_IPV6_PURGE_UNUSED_CACHE_ENTRIES
    /* Check status.  */
    if (status)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
#else 
    /* Check status.  */
    if (status != NX_NOT_SUCCESSFUL)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
#endif

    /* Loop to mark all the ND CACHE ENTRY as static.  */
    for (i = 0; i < NX_IPV6_NEIGHBOR_CACHE_SIZE; i++)
    {
        ip_0.nx_ipv6_nd_cache[i].nx_nd_cache_is_static = NX_TRUE;
    }

    /* Update the IP address and mac address.  */
    dest_ip.nxd_ip_address.v6[3] += 1;       
    mac_address[5] += 1;        

    /* Call the function to added the new entry. the entry status is ND_CACHE_STATE_REACHABLE can be replaced when disable the NX_DISABLE_IPV6_PURGE_UNUSED_CACHE_ENTRIES.  */
    status = _nx_nd_cache_add(&ip_0, &dest_ip.nxd_ip_address.v6[0], &ip_0.nx_ip_interface[0], &mac_address[0], 0, ND_CACHE_STATE_CREATED, &ip_0.nx_ipv6_address[0], &nd_cache_entry);

    /* Check status.  */
    if (status != NX_NOT_SUCCESSFUL)           
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

#ifndef NX_DISABLE_IPV6_PURGE_UNUSED_CACHE_ENTRIES
    /* Cover branch in nx_nd_cache_add_entry.c
     212         [ +  - ]:          8 :             if (ip_ptr -> nx_ipv6_nd_cache[index].nx_nd_cache_timer_tick < timer_ticks_left) */
    /* Invalidate all ND caches. */
    nxd_nd_cache_invalidate(&ip_0);

    /* Set ipv6 global address for IP instance 1.  */
    dest_ip.nxd_ip_version = NX_IP_VERSION_V6;
    dest_ip.nxd_ip_address.v6[0] = 0x20010000;
    dest_ip.nxd_ip_address.v6[1] = 0x00000000;
    dest_ip.nxd_ip_address.v6[2] = 0x00000000;
    dest_ip.nxd_ip_address.v6[3] = 0x10000003;      

    /* Added the same ND Cache entry.  */
    mac_address[0] = 0x00;                
    mac_address[1] = 0x11;
    mac_address[2] = 0x22;
    mac_address[3] = 0x33;
    mac_address[4] = 0x44;
    mac_address[5] = 0x58;

    /* Loop to added the ND CACHE ENTRY.  */
    for (i = 0; i < NX_IPV6_NEIGHBOR_CACHE_SIZE; i++)
    {         

        /* Update the IP address and mac address.  */
        dest_ip.nxd_ip_address.v6[3] += 1;       
        mac_address[5] += 1;        

        /* Call the function to added the same entry.  */
        status = _nx_nd_cache_add(&ip_0, &dest_ip.nxd_ip_address.v6[0], &ip_0.nx_ip_interface[0], &mac_address[0], 0, ND_CACHE_STATE_REACHABLE, &ip_0.nx_ipv6_address[0], &nd_cache_entry);

        /* Check status.  */
        if (status)           
        {

            printf("ERROR!\n");
            test_control_return(1);
        }    
    }         

    ip_0.nx_ipv6_nd_cache[0].nx_nd_cache_timer_tick -= 1;
    ip_0.nx_ipv6_nd_cache[1].nx_nd_cache_timer_tick -= 2;

    dest_ip.nxd_ip_address.v6[3] += 1;       
    mac_address[5] += 1;        
    status = _nx_nd_cache_add(&ip_0, &dest_ip.nxd_ip_address.v6[0], &ip_0.nx_ip_interface[0], &mac_address[0], 0, ND_CACHE_STATE_CREATED, &ip_0.nx_ipv6_address[0], &nd_cache_entry);
    if (status)           
    {
        printf("ERROR!\n");
        test_control_return(1);
    }  
#endif /* NX_DISABLE_IPV6_PURGE_UNUSED_CACHE_ENTRIES */

    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}         
#else    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nd_cache_add_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   ND Cache Add Test.........................................N/A\n");
    
    test_control_return(3);
}
#endif
