/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"      
#include   "nx_ip.h" 
                                       
extern void  test_control_return(UINT status);

#if !defined NX_DISABLE_ERROR_CHECKING && defined FEATURE_NX_IPV6
#include   "nx_nd_cache.h"

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;    
static NX_IP                   invalid_ip;
                                          
/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);  

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nd_cache_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
                                              
    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;                     
}                     

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;    
NXD_ADDRESS ipv6_address;
CHAR        mac_addr[6];
ULONG       physical_msw;
ULONG       physical_lsw;
UINT        interface_index;    

    /* Print out some test information banners.  */
    printf("NetX Test:   ND CACHE NXE API Test.....................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the IPv6 address.  */   
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[0] = 0x20020000;
    ipv6_address.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[3] = 0x01020306;

    /* Set the MAC address.  */
    mac_addr[0] = 0x00;   
    mac_addr[0] = 0x11;
    mac_addr[0] = 0x22;
    mac_addr[0] = 0x33;
    mac_addr[0] = 0x44;
    mac_addr[0] = 0x58;
                         
    /************************************************/   
    /* Tested the nxe_arp_entry_delete api          */
    /************************************************/                 
                   
    /* Delete the entry for NULL IP instance.  */
    status = nxd_nd_cache_entry_delete(NX_NULL, &ipv6_address.nxd_ip_address.v6[0]); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                       
    /* Delete the entry for invalid IP instance.  */
    status = nxd_nd_cache_entry_delete(&invalid_ip, &ipv6_address.nxd_ip_address.v6[0]); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           
                       
    /* Delete the entry with NULL IP address pointer.  */
    status = nxd_nd_cache_entry_delete(&ip_0, NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                       
    /**********************************************/   
    /* Tested the nxde_nd_cache_entry_set api     */
    /**********************************************/                 
                   
    /* Set the ND CACHE entry for NULL IP instance.  */
    status = nxd_nd_cache_entry_set(NX_NULL, &ipv6_address.nxd_ip_address.v6[0], 0, mac_addr); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                   
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;

    /* Set the ND CACHE entry for invalid IP instance.  */
    status = nxd_nd_cache_entry_set(&invalid_ip, &ipv6_address.nxd_ip_address.v6[0], 0, mac_addr); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    
             
    /* Set the ND CACHE entry with NULL ipv6 address pointer.  */
    status = nxd_nd_cache_entry_set(&ip_0, NX_NULL, 0, mac_addr); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
    
    /* Set the ND CACHE entry with NULL mac address pointer.  */
    status = nxd_nd_cache_entry_set(&ip_0, &ipv6_address.nxd_ip_address.v6[0], 0, NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    /* Set the ND CACHE entry with MAX interface index.  */
    status = nxd_nd_cache_entry_set(&ip_0, &ipv6_address.nxd_ip_address.v6[0], NX_MAX_PHYSICAL_INTERFACES, mac_addr); 
                
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                    
            
    /******************************************************/   
    /* Tested the nxde_nd_cache_hardware_address_find api */
    /******************************************************/                 
                   
    /* Find the hardware address for NULL IP instance.  */
    status = nxd_nd_cache_hardware_address_find(NX_NULL, &ipv6_address, &physical_msw, &physical_lsw, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    
                    
    /* Find the hardware address for invalid IP instance.  */
    status = nxd_nd_cache_hardware_address_find(&invalid_ip, &ipv6_address, &physical_msw, &physical_lsw, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                                
    /* Find the hardware address with NULL address pointer.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, NX_NULL, &physical_msw, &physical_lsw, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Find the hardware address for valid IP instance with invalid physical_msw pointer.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &ipv6_address, NX_NULL, &physical_lsw, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                           
    /* Find the hardware address for valid IP instance with invalid physical_msw pointer.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &ipv6_address, &physical_msw, NX_NULL, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                            
    /* Find the hardware address for valid IP instance with NULL interface index pointer.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &ipv6_address, &physical_msw, &physical_lsw, NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    /* Set the IPv6 address with invalid version.  */   
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V4;                    
                          
    /* Find the hardware address with invalid address version.  */
    status = nxd_nd_cache_hardware_address_find(&ip_0, &ipv6_address, &physical_msw, &physical_lsw, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                         
                         
    /*******************************************/   
    /* Tested the nxde_nd_cache_invalidate api */
    /*******************************************/                 
                   
    /* Delete the ND Cache entries for NULL IP instance.  */
    status = nxd_nd_cache_invalidate(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Set the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    
                    
    /* Delete the ND Cache entries for invalid IP instance.  */ 
    status = nxd_nd_cache_invalidate(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                                                            
                     
    /************************************************/   
    /* Tested the nxde_nd_cache_ip_address_find api */
    /************************************************/                 
                   
    /* Find the ip address for NULL IP instance.  */
    status = nxd_nd_cache_ip_address_find(NX_NULL, &ipv6_address, 0x0011, 0x22334456, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    
                    
    /* Find the ip address for invalid IP instance.  */
    status = nxd_nd_cache_ip_address_find(&invalid_ip, &ipv6_address, 0x0011, 0x22334456, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                          
    /* Find the ip address with NULL ip address pointer.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, NX_NULL, 0x0011, 0x22334456, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                           
                                                                       
    /* Find the ip address with NULL interface index pointer.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0x0011, 0x22334456, NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                                                       
    /* Find the ip address with invalid physcial address.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0, 0, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                     
                                                       
    /* Find the ip address with valid physcial address.  */
    status = nxd_nd_cache_ip_address_find(&ip_0, &ipv6_address, 0, 1, &interface_index); 
                
    /* Check for error.  */
    if (status != NX_ENTRY_NOT_FOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                     

    /* Output success.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}                             
#else                 
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nd_cache_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ND CACHE NXE API Test.....................................N/A\n"); 

    test_control_return(3);  
}      
#endif
