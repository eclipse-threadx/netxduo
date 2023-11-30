/* This NetX test concentrates on the basic UDP operation.  */


#include   "nx_igmp.h"
#include   "tx_api.h"
#include   "nx_api.h"      
#include   "nx_ip.h"   
                                       
extern void  test_control_return(UINT status);

#if !defined NX_DISABLE_ERROR_CHECKING && defined __PRODUCT_NETXDUO__ && !defined(NX_DISABLE_IPV4)

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
void    netx_igmp_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

CHAR        *pointer;
UINT        status;  
    
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
ULONG       igmp_reports_sent; 
ULONG       igmp_queries_received;
ULONG       igmp_checksum_errors;
ULONG       current_groups_joined;
                   

    /* Print out some test information banners.  */
    printf("NetX Test:   IGMP NXE API Test.........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                         
    /************************************************/   
    /* Tested the nxe_igmp_enable api               */
    /************************************************/                 
                   
    /* Enable the IGMP feature for NULL IP instance.  */
    status = nx_icmp_enable(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
             
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   

    /* Enable the IGMP feature for invalid IP instance.  */
    status = nx_igmp_enable(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
              
    /* Enable the IGMP feature for valid IP instance.  */
    status = nx_igmp_enable(&ip_0); 
                
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                
    /* Enable the IGMP feature again for valid IP instance .  */
    status = nx_igmp_enable(&ip_0); 
                
    /* Check for error.  */
    if (status != NX_ALREADY_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                        
    /************************************************/   
    /* Tested the nxe_igmp_info_get api             */
    /************************************************/                 
                   
    /* Get the IGMP information for NULL IP instance.  */
    status = nx_igmp_info_get(NX_NULL, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Get the IGMP information for invalid IP instance.  */ 
    status = nx_igmp_info_get(&invalid_ip, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                     
    /* Disable the IGMP feature.  */
    ip_0.nx_ip_igmp_packet_receive = NX_NULL;   
                  
    /* Get the IGMP information for invalid IP instance.  */   
    status = nx_igmp_info_get(&ip_0, &igmp_reports_sent, &igmp_queries_received, &igmp_checksum_errors, &current_groups_joined); 

    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               
      
    /************************************************/   
    /* Tested the nxe_igmp_loopback_disable api     */
    /************************************************/                 
                   
    /* Disable the IGMP loopback for NULL IP instance.  */
    status = nx_igmp_loopback_disable(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Disable the IGMP loopback for invalid IP instance.  */ 
    status = nx_igmp_loopback_disable(&invalid_ip); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                     
    /* Disable the IGMP feature.  */
    ip_0.nx_ip_igmp_packet_receive = NX_NULL;   
                  
    /* Disable the IGMP loopback for invalid IP instance.  */   
    status = nx_igmp_loopback_disable(&ip_0); 

    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /************************************************/   
    /* Tested the nxe_igmp_loopback_enable api     */
    /************************************************/                 
                   
    /* Enable the IGMP loopback for NULL IP instance.  */
    status = nx_igmp_loopback_enable(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Enable the IGMP loopback for invalid IP instance.  */ 
    status = nx_igmp_loopback_enable(&invalid_ip); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                     
    /* Disable the IGMP feature.  */
    ip_0.nx_ip_igmp_packet_receive = NX_NULL;   
                  
    /* Enable the IGMP loopback for invalid IP instance.  */   
    status = nx_igmp_loopback_enable(&ip_0); 

    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
            
    /***************************************************/   
    /* Tested the nxe_igmp_multicast_interface_join api */
    /***************************************************/                 
    
    /* Reset the igmp packet receive function.  */
    ip_0.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;

    /* Join the ICMP group for NULL IP instance.  */
    status = nx_igmp_multicast_interface_join(NX_NULL, IP_ADDRESS(224,0,0,251), 0); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Join the ICMP group for invalid IP instance.  */ 
    status = nx_igmp_multicast_interface_join(&invalid_ip, IP_ADDRESS(224,0,0,251), 0); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                              
    /* Join the ICMP group with invalid IP address.  */   
    status = nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(1, 2, 3, 4), NX_MAX_PHYSICAL_INTERFACES); 

    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable the IGMP feature.  */
    ip_0.nx_ip_igmp_packet_receive = NX_NULL;   
                  
    /* Join the ICMP group with IGMP feature disable.  */   
    status = nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,251), 0); 

    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /* Reset the igmp packet receive function.  */
    ip_0.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;
                
    /* Join the ICMP group with MAX interface index.  */   
    status = nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,251), NX_MAX_PHYSICAL_INTERFACES); 

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Join the ICMP group with invalid interface.  */   
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_FALSE;
    status = nx_igmp_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,251), 0); 
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_TRUE;

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /*************************************************************/   
    /* Tested the nxe_igmp_multicast_interface_join_internal api */
    /* by nxe_ipv4_multicast_interface_join api                  */
    /*************************************************************/                 
    
    /* Reset the igmp packet receive function.  */
    ip_0.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;

    /* Join the ICMP group for NULL IP instance.  */
    status = nx_ipv4_multicast_interface_join(NX_NULL, IP_ADDRESS(224,0,0,251), 0); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Join the ICMP group with invalid interface.  */   
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_FALSE;
    status = nx_ipv4_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,251), 0); 
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_TRUE;

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Join the ICMP group for invalid IP instance.  */ 
    status = nx_ipv4_multicast_interface_join(&invalid_ip, IP_ADDRESS(224,0,0,251), 0); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                              
    /* Join the ICMP group with invalid IP address.  */   
    status = nx_ipv4_multicast_interface_join(&ip_0, IP_ADDRESS(1, 2, 3, 4), NX_MAX_PHYSICAL_INTERFACES); 

    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Join the ICMP group with MAX interface index.  */   
    status = nx_ipv4_multicast_interface_join(&ip_0, IP_ADDRESS(224,0,0,251), NX_MAX_PHYSICAL_INTERFACES); 

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
            
    /*****************************************************/   
    /* Tested the nxe_igmp_multicast_interface_leave api */
    /*****************************************************/                 
    
    /* Reset the igmp packet receive function.  */
    ip_0.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;

    /* Leave the ICMP group for NULL IP instance.  */
    status = nx_igmp_multicast_interface_leave(NX_NULL, IP_ADDRESS(224,0,0,251), 0); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Leave the ICMP group for invalid IP instance.  */ 
    status = nx_igmp_multicast_interface_leave(&invalid_ip, IP_ADDRESS(224,0,0,251), 0); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                              
    /* Leave the ICMP group with invalid IP address.  */   
    status = nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(1, 2, 3, 4), NX_MAX_PHYSICAL_INTERFACES); 

    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable the IGMP feature.  */
    ip_0.nx_ip_igmp_packet_receive = NX_NULL;   
                  
    /* Join the ICMP group with IGMP feature disable.  */   
    status = nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,251), 0); 

    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /* Reset the igmp packet receive function.  */
    ip_0.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;
                
    /* Leave the ICMP group with MAX interface index.  */   
    status = nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,251), NX_MAX_PHYSICAL_INTERFACES); 

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Leave the IGMP group with invalid interface.  */   
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_FALSE;
    status = nx_igmp_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,251), 0); 
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_TRUE;

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /**************************************************************/   
    /* Tested the nxe_igmp_multicast_interface_leave_internal api */
    /* by nxe_ipv4_multicast_interface_leave api                  */
    /**************************************************************/                 
    
    /* Reset the igmp packet receive function.  */
    ip_0.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;

    /* Leave the multicast for NULL IP instance.  */
    status = nx_ipv4_multicast_interface_leave(NX_NULL, IP_ADDRESS(224,0,0,251), 0); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Leave the multicast for invalid IP instance.  */ 
    status = nx_ipv4_multicast_interface_leave(&invalid_ip, IP_ADDRESS(224,0,0,251), 0); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                              
    /* Leave the multicast with invalid IP address.  */   
    status = nx_ipv4_multicast_interface_leave(&ip_0, IP_ADDRESS(1, 2, 3, 4), NX_MAX_PHYSICAL_INTERFACES); 

    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                        
                
    /* Leave the multicast group with MAX interface index.  */   
    status = nx_ipv4_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,251), NX_MAX_PHYSICAL_INTERFACES); 

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Leave the IGMP group with invalid interface.  */   
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_FALSE;
    status = nx_ipv4_multicast_interface_leave(&ip_0, IP_ADDRESS(224,0,0,251), 0); 
    ip_0.nx_ip_interface[0].nx_interface_valid = NX_TRUE;

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /***************************************************/   
    /* Tested the nxe_igmp_multicast_join api          */
    /***************************************************/                 
    
    /* Reset the igmp packet receive function.  */
    ip_0.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;

    /* Join the ICMP group for NULL IP instance.  */
    status = nx_igmp_multicast_join(NX_NULL, IP_ADDRESS(224,0,0,251)); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Join the ICMP group for invalid IP instance.  */ 
    status = nx_igmp_multicast_join(&invalid_ip, IP_ADDRESS(224,0,0,251)); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                              
    /* Join the ICMP group with invalid IP address.  */   
    status = nx_igmp_multicast_join(&ip_0, IP_ADDRESS(1, 2, 3, 4)); 

    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable the IGMP feature.  */
    ip_0.nx_ip_igmp_packet_receive = NX_NULL;   
                  
    /* Join the ICMP group with IGMP feature disable.  */   
    status = nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224,0,0,251)); 

    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /* Set the IP instance ID and igmp packet receive function.  */     
    invalid_ip.nx_ip_id  = NX_IP_ID;
    invalid_ip.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;
                
    /* Join the ICMP group with invalid interface index.  */   
    status = nx_igmp_multicast_join(&invalid_ip, IP_ADDRESS(224,0,0,251)); 

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
         
    /***************************************************/   
    /* Tested the nxe_igmp_multicast_leave api          */
    /***************************************************/                 
    
    /* Reset the igmp packet receive function.  */
    ip_0.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;

    /* Join the ICMP group for NULL IP instance.  */
    status = nx_igmp_multicast_leave(NX_NULL, IP_ADDRESS(224,0,0,251)); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Join the ICMP group for invalid IP instance.  */ 
    status = nx_igmp_multicast_leave(&invalid_ip, IP_ADDRESS(224,0,0,251)); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                              
    /* Join the ICMP group with invalid IP address.  */   
    status = nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(1, 2, 3, 4)); 

    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable the IGMP feature.  */
    ip_0.nx_ip_igmp_packet_receive = NX_NULL;   
                  
    /* Join the ICMP group with IGMP feature disable.  */   
    status = nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224,0,0,251)); 

    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /* Set the IP instance ID and igmp packet receive function.  */     
    invalid_ip.nx_ip_id  = NX_IP_ID;
    invalid_ip.nx_ip_igmp_packet_receive = _nx_igmp_packet_receive;
                
    /* Join the ICMP group with invalid interface index.  */   
    status = nx_igmp_multicast_leave(&invalid_ip, IP_ADDRESS(224,0,0,251)); 

    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
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
void    netx_igmp_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IGMP NXE API Test.........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
