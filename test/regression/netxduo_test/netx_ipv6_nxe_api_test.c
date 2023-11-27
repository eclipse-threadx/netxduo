/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"      
#include   "nx_ip.h"
                                       
extern void  test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__) && defined(FEATURE_NX_IPV6)
#include    "nx_ipv6.h"

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;  
static NX_IP                   ip_0;      
static NX_IP                   invalid_ip;
                                          
/* Define the counters used in the demo application...  */

static ULONG                   error_counter;    
static CHAR                    *pointer;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);   

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256, pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;                     
}                     

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;              
ULONG       prefix_length;
UINT        interface_index; 
UINT        address_index;
ULONG       router_lifetime;
ULONG       configuration_method;
UINT        num_entries;
NXD_ADDRESS ip_address;
NXD_ADDRESS router_addr;   
#ifdef NX_ENABLE_IPV6_MULTICAST
NXD_ADDRESS group_address;
#endif


    /* Print out some test information banners.  */
    printf("NetX Test:   IPv6 NXE API Test.........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                               

#ifdef NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY
    /**************************************************/   
    /* Tested the nxde_ipv6_address_change_notify api */
    /**************************************************/  

    /* Set the IPV6 address change notify function for NULL IP instance.  */
    status = nxd_ipv6_address_change_notify(NX_NULL, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                                     
    /* Set the IPv6 address change notify function for invalid IP instance.  */
    status = nxd_ipv6_address_change_notify(&invalid_ip, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
#endif
                    
    /************************************************/   
    /* Tested the nxde_ipv6_address_delete api      */
    /************************************************/  

    /* Delete the IPv6 address with NULL IP instance.  */
    status = nxd_ipv6_address_delete(NX_NULL, 0);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Delete the IPv6 address with invalid IP instance.  */
    status = nxd_ipv6_address_delete(&invalid_ip, 0);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                          
    /* Delete the IPv6 address with invalid address index.  */
    status = nxd_ipv6_address_delete(&ip_0, NX_MAX_IPV6_ADDRESSES);
                  
    /* Check for error.  */
    if (status != NX_NO_INTERFACE_ADDRESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             

    /************************************************/   
    /* Tested the nxde_ipv6_address_get api         */
    /************************************************/  

    /* Get the IPv6 address with NULL IP instance.  */
    status = nxd_ipv6_address_get(NX_NULL, 0, &ip_address, &prefix_length, &interface_index);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Get the IPv6 address with invalid IP instance.  */
    status = nxd_ipv6_address_get(&invalid_ip, 0, &ip_address, &prefix_length, &interface_index);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                          
    /* Get the IP address with NULL address pointer.  */
    status = nxd_ipv6_address_get(&ip_0, 0, NX_NULL, &prefix_length, &interface_index);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                       
    /* Get the IPv6 address with NULL prefix length pointer.  */
    status = nxd_ipv6_address_get(&ip_0, 0, &ip_address, NX_NULL, &interface_index);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             

    /* Get the IPv6 address with NULL interface index pointer.  */
    status = nxd_ipv6_address_get(&ip_0, 0, &ip_address, &prefix_length, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          

    /* Get the IPv6 address with invalid address index.  */
    status = nxd_ipv6_address_get(&ip_0, (NX_MAX_IPV6_ADDRESSES + NX_LOOPBACK_IPV6_ENABLED), &ip_address, &prefix_length, &interface_index);
                  
    /* Check for error.  */
    if (status != NX_NO_INTERFACE_ADDRESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                   
    /************************************************/   
    /* Tested the nxde_ipv6_address_set api         */
    /************************************************/  

    /* Set the IPv6 address.  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    ip_address.nxd_ip_address.v6[0] = 0x20010000;  
    ip_address.nxd_ip_address.v6[1] = 0x00000000;
    ip_address.nxd_ip_address.v6[2] = 0x00000000;
    ip_address.nxd_ip_address.v6[3] = 0x00001234;

    /* Set the IPv6 address with NULL IP instance.  */
    status = nxd_ipv6_address_set(NX_NULL, 0, &ip_address, 64, &address_index);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Set the IPv6 address with invalid IP instance.  */
    status = nxd_ipv6_address_set(&invalid_ip, 0, &ip_address, 64, &address_index);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                                          
    /* Set the IPv6 address with invalid version.  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V4;

    /* Set the IP address with invalid address version.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &ip_address, 64, &address_index);
                  
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    /* Reset the IPv6 address version.  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V6;  
                                                  
    /* Set the IP address with invalid interface index.  */
    status = nxd_ipv6_address_set(&ip_0, NX_MAX_PHYSICAL_INTERFACES, &ip_address, 64, &address_index);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Reset the IPv6 address.  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V6;  
    ip_address.nxd_ip_address.v6[0] = 0x00000000;  
    ip_address.nxd_ip_address.v6[1] = 0x00000000;
    ip_address.nxd_ip_address.v6[2] = 0x00000000;
    ip_address.nxd_ip_address.v6[3] = 0x00000000;

    /* Set the IPv6 address with NULL prefix length pointer.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &ip_address, 64, &address_index);
                  
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             
           
    /************************************************/   
    /* Tested the nxde_ipv6_default_router_add api  */
    /************************************************/  

    /* Set the router IPv6 address.  */
    router_addr.nxd_ip_version = NX_IP_VERSION_V6;
    router_addr.nxd_ip_address.v6[0] = 0x20010000;  
    router_addr.nxd_ip_address.v6[1] = 0x00000000;
    router_addr.nxd_ip_address.v6[2] = 0x00000000;
    router_addr.nxd_ip_address.v6[3] = 0x00000001;

    /* Add the default router address with NULL IP instance.  */
    status = nxd_ipv6_default_router_add(NX_NULL, &router_addr, 1000, 0);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Add the default router address with invalid IP instance.  */
    status = nxd_ipv6_default_router_add(&invalid_ip, &router_addr, 1000, 0);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                               
                              
    /* Add the default router address with NULL router address pointer.  */
    status = nxd_ipv6_default_router_add(&ip_0, NX_NULL, 1000, 0);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                     
    /* Set the IPv6 address with invalid address version.  */
    router_addr.nxd_ip_version = NX_IP_VERSION_V4;  

    /* Add the default router address with invalid address version.  */
    status = nxd_ipv6_default_router_add(&ip_0, &router_addr, 1000, 0);
                  
    /* Check for error.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               

    /* Reset the IPv6 address version.  */
    router_addr.nxd_ip_version = NX_IP_VERSION_V6;  
                                                  
    /* Add the default router address with invalid interface index.  */
    status = nxd_ipv6_default_router_add(&ip_0, &router_addr, 1000, NX_MAX_PHYSICAL_INTERFACES);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                                            
    /* Add the default router address with invalid interface index.  */
    status = nxd_ipv6_default_router_add(&ip_0, &router_addr, 1000, 1);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
        
    /***************************************************/   
    /* Tested the nxde_ipv6_default_router_delete api  */
    /***************************************************/  

    /* Set the router IPv6 address.  */
    router_addr.nxd_ip_version = NX_IP_VERSION_V6;
    router_addr.nxd_ip_address.v6[0] = 0x20010000;  
    router_addr.nxd_ip_address.v6[1] = 0x00000000;
    router_addr.nxd_ip_address.v6[2] = 0x00000000;
    router_addr.nxd_ip_address.v6[3] = 0x00000001;

    /* Delete the default router address with NULL IP instance.  */
    status = nxd_ipv6_default_router_delete(NX_NULL, &router_addr);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Delete the default router address with invalid IP instance.  */
    status = nxd_ipv6_default_router_delete(&invalid_ip, &router_addr);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                               
                              
    /* Delete the default router address with NULL router address pointer.  */
    status = nxd_ipv6_default_router_delete(&ip_0, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                     
    /* Set the IPv6 address with invalid address version.  */
    router_addr.nxd_ip_version = NX_IP_VERSION_V4;  

    /* Delete the default router address with invalid address version.  */
    status = nxd_ipv6_default_router_delete(&ip_0, &router_addr);
                  
    /* Check for error.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               
              
    /*****************************************************/   
    /* Tested the nxde_ipv6_default_router_entry_get api */
    /*****************************************************/        

    /* Get the default router address with NULL IP instance.  */
    status = nxd_ipv6_default_router_entry_get(NX_NULL, 0, 0, &router_addr, &router_lifetime, &prefix_length, &configuration_method);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Get the default router address with invalid IP instance.  */
    status = nxd_ipv6_default_router_entry_get(&invalid_ip, 0, 0, &router_addr, &router_lifetime, &prefix_length, &configuration_method);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                               
                              
    /* Get the default router address with invalid interface index.  */
    status = nxd_ipv6_default_router_entry_get(&ip_0, NX_MAX_PHYSICAL_INTERFACES, 0, &router_addr, &router_lifetime, &prefix_length, &configuration_method);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                     

    /* Get the default router address with invalid entry index.  */
    status = nxd_ipv6_default_router_entry_get(&ip_0, 0, NX_IPV6_DEFAULT_ROUTER_TABLE_SIZE, &router_addr, &router_lifetime, &prefix_length, &configuration_method);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
      
    /*****************************************************/   
    /* Tested the nxde_ipv6_default_router_get api       */
    /*****************************************************/        

    /* Get the default router address with NULL IP instance.  */
    status = nxd_ipv6_default_router_get(NX_NULL, 0, &router_addr, &router_lifetime, &prefix_length);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Get the default router address with invalid IP instance.  */
    status = nxd_ipv6_default_router_get(&invalid_ip, 0, &router_addr, &router_lifetime, &prefix_length);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                       

    /* Get the default router address with NULL router address pointer.  */
    status = nxd_ipv6_default_router_get(&ip_0, 0, NX_NULL, &router_lifetime, &prefix_length);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    /* Get the default router address with NULL router lifetime pointer.  */
    status = nxd_ipv6_default_router_get(&ip_0, 0, &router_addr, NX_NULL, &prefix_length);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                        
         
    /* Get the default router address with NULL prefix length.  */
    status = nxd_ipv6_default_router_get(&ip_0, 0, &router_addr, &router_lifetime, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Get the default router address with invalid interface index.  */
    status = nxd_ipv6_default_router_get(&ip_0, NX_MAX_PHYSICAL_INTERFACES, &router_addr, &router_lifetime, &prefix_length);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                          
       
    /*****************************************************************/   
    /* Tested the nxde_ipv6_default_router_number_of_entries_get api */
    /*****************************************************************/        

    /* Get the default router number with NULL IP instance.  */
    status = nxd_ipv6_default_router_number_of_entries_get(NX_NULL, 0, &num_entries);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Get the default router number with invalid IP instance.  */
    status = nxd_ipv6_default_router_number_of_entries_get(&invalid_ip, 0, &num_entries);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                       

    /* Get the default router number with NULL num entries pointer.  */
    status = nxd_ipv6_default_router_number_of_entries_get(&ip_0, 0, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Get the default router address with invalid interface index.  */
    status = nxd_ipv6_default_router_number_of_entries_get(&ip_0, NX_MAX_PHYSICAL_INTERFACES, &num_entries);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                    
    /************************************************/   
    /* Tested the nxde_ipv6_disable api              */
    /************************************************/                 
                   
    /* Disable the IPv6 feature with NULL IP instance.  */
    status = nxd_ipv6_disable(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
             
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   

    /* Disable the IPv6 feature with invalid IP instance.  */
    status = nxd_ipv6_disable(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /************************************************/   
    /* Tested the nxde_ipv6_enable api              */
    /************************************************/                 
                   
    /* Enable the IPv6 feature with NULL IP instance.  */
    status = nxd_ipv6_enable(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
             
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   

    /* Enable the IPv6 feature with invalid IP instance.  */
    status = nxd_ipv6_enable(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

#ifdef NX_ENABLE_IPV6_MULTICAST
    /*************************************************************/   
    /* Tested the nxde_ipv6_multicast_interface_join api         */
    /*************************************************************/                 
                                  
    /* Set the IPv6 Multicast group address.  */
    group_address.nxd_ip_version = NX_IP_VERSION_V6;
    group_address.nxd_ip_address.v6[0] = 0xFF020000;
    group_address.nxd_ip_address.v6[1] = 0x00000000;
    group_address.nxd_ip_address.v6[2] = 0x00000000;
    group_address.nxd_ip_address.v6[3] = 0x000000FB;

    /* Join the IPv6 multicast group with NULL IP instance.  */
    status = nxd_ipv6_multicast_interface_join(NX_NULL, &group_address, 0); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Join the IPv6 multicast group with invalid IP instance.  */ 
    status = nxd_ipv6_multicast_interface_join(&invalid_ip, &group_address, 0); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                              

    /* Join the IPv6 multicast group with NULL group address pointer.  */   
    status = nxd_ipv6_multicast_interface_join(&ip_0, NX_NULL, 0); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Set the invalid multicast address.  */
    group_address.nxd_ip_version = NX_IP_VERSION_V6;
    group_address.nxd_ip_address.v6[0] = 0x20010000;
    group_address.nxd_ip_address.v6[1] = 0x00000000;
    group_address.nxd_ip_address.v6[2] = 0x00000000;
    group_address.nxd_ip_address.v6[3] = 0x00001234;
                                       
    /* Join the IPv6 multicast group with invalid multicast address.  */   
    status = nxd_ipv6_multicast_interface_join(&ip_0, &group_address, 0); 

    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                               
    /* Reset the IPv6 Multicast group address.  */
    group_address.nxd_ip_version = NX_IP_VERSION_V6;
    group_address.nxd_ip_address.v6[0] = 0xFF020000;
    group_address.nxd_ip_address.v6[1] = 0x00000000;
    group_address.nxd_ip_address.v6[2] = 0x00000000;
    group_address.nxd_ip_address.v6[3] = 0x000000FB;

    /* Join the IPv6 multicast group with invalid interface index.  */   
    status = nxd_ipv6_multicast_interface_join(&ip_0, &group_address, NX_MAX_PHYSICAL_INTERFACES); 

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Join the IPv6 multicast group with invalid interface index.  */   
    status = nxd_ipv6_multicast_interface_join(&ip_0, &group_address, 1); 

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
         
    /*************************************************************/   
    /* Tested the nxde_ipv6_multicast_interface_leave api         */
    /*************************************************************/                 
                                  
    /* Set the IPv6 Multicast group address.  */
    group_address.nxd_ip_version = NX_IP_VERSION_V6;
    group_address.nxd_ip_address.v6[0] = 0xFF020000;
    group_address.nxd_ip_address.v6[1] = 0x00000000;
    group_address.nxd_ip_address.v6[2] = 0x00000000;
    group_address.nxd_ip_address.v6[3] = 0x000000FB;

    /* Leave the IPv6 multicast group with NULL IP instance.  */
    status = nxd_ipv6_multicast_interface_leave(NX_NULL, &group_address, 0); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Leave the IPv6 multicast group with invalid IP instance.  */ 
    status = nxd_ipv6_multicast_interface_leave(&invalid_ip, &group_address, 0); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                              

    /* Leave the IPv6 multicast group with NULL group address pointer.  */   
    status = nxd_ipv6_multicast_interface_leave(&ip_0, NX_NULL, 0); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Set the invalid multicast address.  */
    group_address.nxd_ip_version = NX_IP_VERSION_V6;
    group_address.nxd_ip_address.v6[0] = 0x20010000;
    group_address.nxd_ip_address.v6[1] = 0x00000000;
    group_address.nxd_ip_address.v6[2] = 0x00000000;
    group_address.nxd_ip_address.v6[3] = 0x00001234;
                                       
    /* Leave the IPv6 multicast group with invalid multicast address.  */   
    status = nxd_ipv6_multicast_interface_leave(&ip_0, &group_address, 0); 

    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                               
    /* Reset the IPv6 Multicast group address.  */
    group_address.nxd_ip_version = NX_IP_VERSION_V6;
    group_address.nxd_ip_address.v6[0] = 0xFF020000;
    group_address.nxd_ip_address.v6[1] = 0x00000000;
    group_address.nxd_ip_address.v6[2] = 0x00000000;
    group_address.nxd_ip_address.v6[3] = 0x000000FB;

    /* Leave the IPv6 multicast group with invalid interface index.  */   
    status = nxd_ipv6_multicast_interface_leave(&ip_0, &group_address, NX_MAX_PHYSICAL_INTERFACES); 

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    
#endif
           
#ifdef NX_IPV6_STATELESS_AUTOCONFIG_CONTROL
    /*****************************************************************/   
    /* Tested the nxde_ipv6_stateless_address_autoconfig_disable api */
    /*****************************************************************/                 
                   
    /* Disable the IPv6 stateless address autoconfig feature with NULL IP instance.  */
    status = nxd_ipv6_stateless_address_autoconfig_disable(NX_NULL, 0); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
             
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   

    /* Disable the IPv6 stateless address autoconfig feature with invalid IP instance.  */
    status = nxd_ipv6_stateless_address_autoconfig_disable(&invalid_ip, 0); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                 
    /* Disable the IPv6 stateless address autoconfig feature with invalid interface index.  */
    status = nxd_ipv6_stateless_address_autoconfig_disable(&ip_0, NX_MAX_PHYSICAL_INTERFACES); 
                
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /*****************************************************************/   
    /* Tested the nxde_ipv6_stateless_address_autoconfig_enable api */
    /*****************************************************************/                 
                   
    /* Enable the IPv6 stateless address autoconfig feature with NULL IP instance.  */
    status = nxd_ipv6_stateless_address_autoconfig_enable(NX_NULL, 0); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
             
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   

    /* Enable the IPv6 stateless address autoconfig feature with invalid IP instance.  */
    status = nxd_ipv6_stateless_address_autoconfig_enable(&invalid_ip, 0); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                 
    /* Enable the IPv6 stateless address autoconfig feature with invalid interface index.  */
    status = nxd_ipv6_stateless_address_autoconfig_enable(&ip_0, NX_MAX_PHYSICAL_INTERFACES); 
                
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Output success.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}       
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 NXE API Test.........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
