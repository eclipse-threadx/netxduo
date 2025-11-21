/* Test IPv4 default router set/get APIs. */

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

static NXD_ADDRESS                    ipv6_address_1;
static NXD_ADDRESS                    ipv6_router_address;

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_default_router_api_test_application_define(void *first_unused_memory)
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

    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x01020304;

    status += nxd_ipv6_address_set(&ip_0, 0,&ipv6_address_1, 64, NX_NULL); 

    if(status)
        error_counter++;

#ifndef NX_DISABLE_ERROR_CHECKING

    /* Attempt to set default router on interface 1. Since Interface 1 has no drivers attached yet, this call shall fail. */
    ipv6_router_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_router_address.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_router_address.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_router_address.nxd_ip_address.v6[2] = 100;
    ipv6_router_address.nxd_ip_address.v6[3] = 0x01020305;
    status = nxd_ipv6_default_router_add(&ip_0, &ipv6_router_address, 100, 1);
    if(status != NX_INVALID_INTERFACE) 
        error_counter++;

#endif /* NX_DISABLE_ERROR_CHECKING */

    status = nx_ip_interface_attach(&ip_0,"Second Interface",IP_ADDRESS(2,2,3,4),0xFFFFFF00UL,  _nx_ram_network_driver_512);

    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20020000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x01020304;

    status += nxd_ipv6_address_set(&ip_0, 1, &ipv6_address_1, 64, NX_NULL); 


    /* Enable IPv6 */
    status += nxd_ipv6_enable(&ip_0);

    /* Enable ICMP for IP Instance 0.  */
    status += nxd_icmp_enable(&ip_0);


    /* Check status.  */
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);


    /* Check TCP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT       i, j;
UINT       status;
ULONG      router_lifetime;
ULONG      prefix_length;
ULONG      configuration_method;
UINT       entries;

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Default Router API Test..............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    for(i = 0; i < MAX_TEST_INTERFACES; i++)
    {
        /* Attempt to get a default router before routers are configured. */
        memset(&ipv6_router_address, 0, sizeof(ipv6_router_address));
        router_lifetime = 0;
        prefix_length = 0;
        status = nxd_ipv6_default_router_get(&ip_0, i, &ipv6_router_address, &router_lifetime, &prefix_length);
        if(status != NX_NOT_FOUND)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }    

        /* Attempt to get default router entries.  */
        status = nxd_ipv6_default_router_number_of_entries_get(&ip_0, i, &entries);
        if(entries !=0)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Fill the interface with different routers. */  
    status = 0;
    for(i = 0; i < NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE; i++)
    {
        ipv6_router_address.nxd_ip_version = NX_IP_VERSION_V6;
        ipv6_router_address.nxd_ip_address.v6[0] = 0x20010000 + 0x10000 * (i % MAX_TEST_INTERFACES);
        ipv6_router_address.nxd_ip_address.v6[1] = 0x00000000;
        ipv6_router_address.nxd_ip_address.v6[2] = i;
        ipv6_router_address.nxd_ip_address.v6[3] = 0x01020305;

        status += nxd_ipv6_default_router_add(&ip_0, &ipv6_router_address, 100, i % MAX_TEST_INTERFACES);
    } 

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);        
    }

    /* Check router entry for each interface. */ 
    for(i = 0; i < MAX_TEST_INTERFACES; i++)
    {
        status = nxd_ipv6_default_router_number_of_entries_get(&ip_0, i, &entries);

        /* Check entries. */
        if(entries != ((NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE + MAX_TEST_INTERFACES - i - 1) / MAX_TEST_INTERFACES))
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        /* Check router entry for this interface. */
        for(j = 0; j < entries; j++)
        {
            status = nxd_ipv6_default_router_entry_get(&ip_0, i, j, &ipv6_router_address, &router_lifetime, &prefix_length, &configuration_method);
            if(status != NX_SUCCESS)
            {
                error_counter++;
            }
            if(prefix_length != 64)
                error_counter++;
            if (configuration_method != NX_IPV6_ROUTE_TYPE_STATIC)
                error_counter++;

            if(ipv6_router_address.nxd_ip_version != NX_IP_VERSION_V6)
            {
                error_counter++;
            }
            if((ipv6_router_address.nxd_ip_address.v6[0] != 0x20010000 + 0x10000 * (i % MAX_TEST_INTERFACES)) ||
               (ipv6_router_address.nxd_ip_address.v6[1] != 0x00000000) ||
               (ipv6_router_address.nxd_ip_address.v6[2] != (j * MAX_TEST_INTERFACES + i)) ||        
               (ipv6_router_address.nxd_ip_address.v6[3] != 0x01020305))
            {
                error_counter++;
            }            
            if(error_counter)
            {
                printf("ERROR!\n");
                test_control_return(1);
            }
        }
    }

    /* Delete a not existing router. */
    ipv6_router_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_router_address.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_router_address.nxd_ip_address.v6[1] = 0;
    ipv6_router_address.nxd_ip_address.v6[2] = 0;
    ipv6_router_address.nxd_ip_address.v6[3] = 1;
    status = nxd_ipv6_default_router_delete(&ip_0, &ipv6_router_address);

    if(status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);        
    }

    /* Delete all routers. */   
    status = 0;
    for(i = 0; i < NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE; i++)
    {
        ipv6_router_address.nxd_ip_version = NX_IP_VERSION_V6;
        ipv6_router_address.nxd_ip_address.v6[0] = 0x20010000 + 0x10000 * (i % MAX_TEST_INTERFACES);
        ipv6_router_address.nxd_ip_address.v6[1] = 0x00000000;
        ipv6_router_address.nxd_ip_address.v6[2] = i;
        ipv6_router_address.nxd_ip_address.v6[3] = 0x01020305;

        status += nxd_ipv6_default_router_delete(&ip_0, &ipv6_router_address);
    }    

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);        
    }

    /* Fill the IPv6 default router table. */
    status = 0;
    for(i = 0; i < NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE; i++)
    {
        ipv6_router_address.nxd_ip_version = NX_IP_VERSION_V6;
        if(i == 0)
            /* Set the first default router to be link local. */
            ipv6_router_address.nxd_ip_address.v6[0] = 0xFE800000;
        else
            ipv6_router_address.nxd_ip_address.v6[0] = 0x20010000 + 0x10000 * (i % MAX_TEST_INTERFACES);
        ipv6_router_address.nxd_ip_address.v6[1] = 0x00000000;
        ipv6_router_address.nxd_ip_address.v6[2] = i + 1;
        ipv6_router_address.nxd_ip_address.v6[3] = 0x01020305;

        status += nxd_ipv6_default_router_add(&ip_0, &ipv6_router_address, 100, i % MAX_TEST_INTERFACES);
    }

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);        
    }


    /* Read back the default routers. */
    for(i = 0; i < MAX_TEST_INTERFACES; i++)
    {
        memset(&ipv6_router_address, 0, sizeof(ipv6_router_address));
        router_lifetime = 0;
        prefix_length = 0;
        status = nxd_ipv6_default_router_get(&ip_0, i, &ipv6_router_address, &router_lifetime, &prefix_length);
        if(status != NX_SUCCESS)
        {
            error_counter++;
        }
        if(i == 0)
        {
            if(prefix_length != 10)
                error_counter++;
        }
        else if(prefix_length != 64)
            error_counter++;
        
        if(ipv6_router_address.nxd_ip_version != NX_IP_VERSION_V6)
        {
            error_counter++;
        }
        if(i == 0)
        {
            if(ipv6_router_address.nxd_ip_address.v6[0] != 0xFE800000)
                error_counter++;
            if(prefix_length != 10)
                error_counter++;
            
        }
        else 
        {
            if(ipv6_router_address.nxd_ip_address.v6[0] != 0x20010000 + 0x10000 * (i % MAX_TEST_INTERFACES))
                error_counter++;
            if(prefix_length != 64)
                error_counter++;
        }
        if((ipv6_router_address.nxd_ip_address.v6[1] != 0x00000000) ||
           (ipv6_router_address.nxd_ip_address.v6[2] != (i + 1)) ||        
           (ipv6_router_address.nxd_ip_address.v6[3] != 0x01020305))
        {
            error_counter++;
        }            
        if(error_counter)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }
   
    /* Now delete the 1st entry. */
    ipv6_router_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_router_address.nxd_ip_address.v6[0] = 0xFE800000;
    ipv6_router_address.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_router_address.nxd_ip_address.v6[2] = 1;
    ipv6_router_address.nxd_ip_address.v6[3] = 0x01020305;    
    status = nxd_ipv6_default_router_delete(&ip_0, &ipv6_router_address);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Read back the router address. The 2nd entry should be returned. */
    memset(&ipv6_router_address, 0, sizeof(ipv6_router_address));
    router_lifetime = 0;
    prefix_length = 0;

    status = nxd_ipv6_default_router_get(&ip_0, 0, &ipv6_router_address, &router_lifetime, &prefix_length);
    if((status != NX_SUCCESS) || (prefix_length != 64))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    if(ipv6_router_address.nxd_ip_version != NX_IP_VERSION_V6)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }            
    if((ipv6_router_address.nxd_ip_address.v6[0] != 0x20010000) ||
       (ipv6_router_address.nxd_ip_address.v6[1] != 0x00000000) ||
       (ipv6_router_address.nxd_ip_address.v6[2] != (MAX_TEST_INTERFACES + 1)) ||
       (ipv6_router_address.nxd_ip_address.v6[3] != 0x01020305))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Now add another router.  It should be stored at the 1st slot. */
    ipv6_router_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_router_address.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_router_address.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_router_address.nxd_ip_address.v6[2] = 0x00010001;       
    ipv6_router_address.nxd_ip_address.v6[3] = 0x01020305;
    status = nxd_ipv6_default_router_add(&ip_0, &ipv6_router_address, 100, 0);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Read back the default routers. */
    /* In this case the 1st entry (updated) should be returned. */
    memset(&ipv6_router_address, 0, sizeof(ipv6_router_address));
    router_lifetime = 0;
    prefix_length = 0;
    status = nxd_ipv6_default_router_get(&ip_0, 0, &ipv6_router_address, &router_lifetime, &prefix_length);
    if((status != NX_SUCCESS) || (prefix_length != 64))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    if(ipv6_router_address.nxd_ip_version != NX_IP_VERSION_V6)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }            
    if((ipv6_router_address.nxd_ip_address.v6[0] != 0x20010000) ||
       (ipv6_router_address.nxd_ip_address.v6[1] != 0x00000000) ||
       (ipv6_router_address.nxd_ip_address.v6[2] != 0x00010001) ||        
       (ipv6_router_address.nxd_ip_address.v6[3] != 0x01020305))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Delete the last entry. */
    ipv6_router_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_router_address.nxd_ip_address.v6[0] = 0x20010000 + 0x10000 * ((NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE - 1) % MAX_TEST_INTERFACES);
    ipv6_router_address.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_router_address.nxd_ip_address.v6[2] = NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE; 
    ipv6_router_address.nxd_ip_address.v6[3] = 0x01020305;
    status = nxd_ipv6_default_router_delete(&ip_0, &ipv6_router_address);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Add another entry.  This one should take the last spot in the IPv6 default router table */
    ipv6_router_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_router_address.nxd_ip_address.v6[0] = 0x20020000;
    ipv6_router_address.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_router_address.nxd_ip_address.v6[2] = NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE;
    ipv6_router_address.nxd_ip_address.v6[3] = 0x01020305;
    status = nxd_ipv6_default_router_add(&ip_0, &ipv6_router_address, 100, 1);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }            


    /* Make sure the last entry is correctly set. */
    i = NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE - 1;
    if((ip_0.nx_ipv6_default_router_table[i].nx_ipv6_default_router_entry_flag == 0) ||
       (ip_0.nx_ipv6_default_router_table[i].nx_ipv6_default_router_entry_router_address[0] !=  0x20020000) ||
       (ip_0.nx_ipv6_default_router_table[i].nx_ipv6_default_router_entry_router_address[1] !=  0x00000000) ||
       (ip_0.nx_ipv6_default_router_table[i].nx_ipv6_default_router_entry_router_address[2] !=  (i + 1)) |
       (ip_0.nx_ipv6_default_router_table[i].nx_ipv6_default_router_entry_router_address[3] !=  0x01020305))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }            
       

    ipv6_router_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_router_address.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_router_address.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_router_address.nxd_ip_address.v6[2] = NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE; 
    ipv6_router_address.nxd_ip_address.v6[3] = 0x01020305;
    status = nxd_ipv6_default_router_add(&ip_0, &ipv6_router_address, 100, 0);
    if(status != NX_NO_MORE_ENTRIES)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }            
    

    /* All done.  Return Success */
    printf("SUCCESS!\n");
    
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ipv6_default_router_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Default Router API Test..............................N/A\n");
    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */
