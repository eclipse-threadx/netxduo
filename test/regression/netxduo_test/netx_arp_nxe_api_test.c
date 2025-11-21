/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"      
#include   "nx_ip.h"
                                       
extern void  test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;    
static NX_IP                   invalid_ip;
static UCHAR                   cache_memory[1024];
                                          
/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    responder_handler(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);  

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_nxe_api_test_application_define(void *first_unused_memory)
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
ULONG       ip_address;
ULONG       physical_msw;
ULONG       physical_lsw;
ULONG       arp_requests_sent;  
ULONG       arp_requests_received;
ULONG       arp_responses_sent;
ULONG       arp_responses_received;
ULONG       arp_dynamic_entries;
ULONG       arp_static_entries;
ULONG       arp_aged_entries;
ULONG       arp_invalid_messages;


    /* Print out some test information banners.  */
    printf("NetX Test:   ARP NXE API Test..........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                         
    /************************************************/   
    /* Tested the nxe_arp_enable api                */
    /************************************************/                 
                   
    /* Enable the ARP feature for NULL IP instance.  */
    status = nx_arp_enable(NX_NULL, cache_memory, 1024); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Enable the ARP feature for invalid IP instance.  */
    status = nx_arp_enable(&invalid_ip, cache_memory, 1024); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
       
    /* Enable the ARP feature for IP instance with invalid cache.  */
    status = nx_arp_enable(&ip_0, NX_NULL, 1024); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
           
    /* Enable the ARP feature for IP instance with invalid cache size.  */
    status = nx_arp_enable(&ip_0, cache_memory, 2); 
                
    /* Check for error.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Enable the ARP feature for valid IP instance.  */
    status = nx_arp_enable(&ip_0, cache_memory, 1024); 
                
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      
           
    /* Enable the ARP feature again.  */
    status = nx_arp_enable(&ip_0, cache_memory, 1024); 
                
    /* Check for error.  */
    if (status != NX_ALREADY_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /************************************************/   
    /* Tested the nxe_arp_entry_delete api          */
    /************************************************/                 
                   
    /* Delete the entry for NULL IP instance.  */
    status = nx_arp_entry_delete(NX_NULL, IP_ADDRESS(1, 2, 3, 4)); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                       
    /* Delete the entry for invalid IP instance.  */
    status = nx_arp_entry_delete(&invalid_ip, IP_ADDRESS(1, 2, 3, 4)); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }              

    /* Delete the entry with invalid IP address.  */
    status = nx_arp_entry_delete(&ip_0, NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
         
    /************************************************/   
    /* Tested the nxe_arp_gratuitous_send api       */
    /************************************************/                 
                   
    /* Call the gratuitous send for NULL IP instance.  */
    status = nx_arp_gratuitous_send(NX_NULL, responder_handler); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                 
    /* Call the gratuitous send for invalid IP instance.  */
    status = nx_arp_gratuitous_send(&invalid_ip, responder_handler); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Set the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_IP_ID;      
             
    /* Call the gratuitous send for invalid IP instance.  */
    status = nx_arp_gratuitous_send(&invalid_ip, responder_handler); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Disable the ARP feature.  */
    ip_0.nx_ip_arp_allocate = NX_NULL;     
             
    /* Call the gratuitous send for valid IP instance without ARP feature.  */
    status = nx_arp_gratuitous_send(&ip_0, responder_handler); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /************************************************/   
    /* Tested the nxe_arp_hardware_address_find api */
    /************************************************/                 
                   
    /* Find the hardware address for NULL IP instance.  */
    status = nx_arp_hardware_address_find(NX_NULL, IP_ADDRESS(1, 2, 3, 4), &physical_msw, &physical_lsw); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    
                    
    /* Find the hardware address for invalid IP instance.  */
    status = nx_arp_hardware_address_find(&invalid_ip, IP_ADDRESS(1, 2, 3, 4), &physical_msw, &physical_lsw); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                          
    /* Find the hardware address for valid IP instance with invalid physical_msw pointer.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 4), NX_NULL, &physical_lsw); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                           
    /* Find the hardware address for valid IP instance with invalid physical_msw pointer.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 4), &physical_msw, NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                            
    /* Find the hardware address for valid IP instance with NULL IP address.  */
    status = nx_arp_hardware_address_find(&ip_0, NX_NULL, &physical_msw, &physical_lsw); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                
    /* Disable the ARP feature.  */
    ip_0.nx_ip_arp_allocate = NX_NULL;     
                                                       
    /* Find the hardware address for valid IP instance without ARP feature.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 4), &physical_msw, &physical_lsw); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                            
    /************************************************/   
    /* Tested the nxe_arp_info_get api              */
    /************************************************/                 
                   
    /* Get the ARP information for NULL IP instance.  */
    status = nx_arp_info_get(NX_NULL, &arp_requests_sent, &arp_requests_received, &arp_responses_sent, &arp_responses_received, &arp_dynamic_entries, &arp_static_entries, &arp_aged_entries, &arp_invalid_messages); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Get the ARP information for invalid IP instance.  */
    status = nx_arp_info_get(&invalid_ip, &arp_requests_sent, &arp_requests_received, &arp_responses_sent, &arp_responses_received, &arp_dynamic_entries, &arp_static_entries, &arp_aged_entries, &arp_invalid_messages); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                     
    /* Disable the ARP feature.  */
    ip_0.nx_ip_arp_allocate = NX_NULL;   
                  
    /* Get the ARP information for invalid IP instance.  */
    status = nx_arp_info_get(&ip_0, &arp_requests_sent, &arp_requests_received, &arp_responses_sent, &arp_responses_received, &arp_dynamic_entries, &arp_static_entries, &arp_aged_entries, &arp_invalid_messages); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                   
    /************************************************/   
    /* Tested the nxe_arp_ip_address_find api       */
    /************************************************/                 
                   
    /* Find the ip address for NULL IP instance.  */
    status = nx_arp_ip_address_find(NX_NULL, &ip_address, 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    
                    
    /* Find the ip address for invalid IP instance.  */
    status = nx_arp_ip_address_find(&invalid_ip, &ip_address, 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                          
    /* Find the ip address for valid IP instance with invalid ip address pointer.  */
    status = nx_arp_ip_address_find(&ip_0, NX_NULL, 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                           
               
    /* Find the ip address for valid IP instance with NULL physical address.  */
    status = nx_arp_ip_address_find(&ip_0, &ip_address, 0, 0); 
                
    /* Check for error.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Disable the ARP feature.  */
    ip_0.nx_ip_arp_allocate = NX_NULL;     
                                                       
    /* Find the ip address for valid IP instance without ARP feature.  */
    status = nx_arp_ip_address_find(&ip_0, &ip_address, 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                   
    /*****************************************************/   
    /* Tested the nxe_arp_dynamic_entries_invalidate api */
    /*****************************************************/                 
                   
    /* Delete the dynamic entries for NULL IP instance.  */
    status = nx_arp_dynamic_entries_invalidate(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Set the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    
                    
    /* Delete the dynamic entries for invalid IP instance.  */ 
    status = nx_arp_dynamic_entries_invalidate(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                                                            
                
    /* Disable the ARP feature.  */
    ip_0.nx_ip_arp_allocate = NX_NULL;     
                                                       
    /* Delete the dynamic entries for valid IP instance without ARP feature.  */
    status = nx_arp_dynamic_entries_invalidate(&ip_0); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                 
    /************************************************/   
    /* Tested the nxe_arp_dynamic_entry_set api     */
    /************************************************/                 
                   
    /* Create the dynamic entry for NULL IP instance.  */
    status = nx_arp_dynamic_entry_set(NX_NULL, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                   
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;

    /* Create the dynamic entry for invalid IP instance.  */
    status = nx_arp_dynamic_entry_set(&invalid_ip, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    

    /* Create the dynamic entry with invalid IP address.  */
    status = nx_arp_dynamic_entry_set(&ip_0, NX_NULL, 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                           

    /* Create the dynamic entry with multicast IP address.  */
    status = nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(224,0,0,251), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create the dynamic entry with directed broadcast IP address.  */
    status = nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(255, 255, 255, 255), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable the ARP feature.  */
    ip_0.nx_ip_arp_allocate = NX_NULL;     
                                                       
    /* Create the dynamic entry for valid IP instance without ARP feature.  */
    status = nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /************************************************/   
    /* Tested the nxe_arp_static_entries_delete api */
    /************************************************/                 
                   
    /* Delete the static entries for NULL IP instance.  */
    status = nx_arp_static_entries_delete(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    
                    
    /* Delete the static entries for invalid IP instance.  */ 
    status = nx_arp_static_entries_delete(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                                                            
                
    /* Disable the ARP feature.  */
    ip_0.nx_ip_arp_allocate = NX_NULL;     
                                                       
    /* Delete the static entries for valid IP instance without ARP feature.  */
    status = nx_arp_static_entries_delete(&ip_0); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /************************************************/   
    /* Tested the nxe_arp_static_entry_create api   */
    /************************************************/                 
                   
    /* Create the static entry for NULL IP instance.  */
    status = nx_arp_static_entry_create(NX_NULL, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                   
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;

    /* Create the static entry for invalid IP instance.  */
    status = nx_arp_static_entry_create(&invalid_ip, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    

    /* Create the static entry with invalid IP address.  */
    status = nx_arp_static_entry_create(&ip_0, NX_NULL, 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                           

    /* Create the static entry with multicast IP address.  */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(224,0,0,251), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create the static entry with directed broadcast IP address.  */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(255, 255, 255, 255), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create the static entry with invalid IP address.  */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, 4), 0, 0); 
                
    /* Check for error.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Disable the ARP feature.  */
    ip_0.nx_ip_arp_allocate = NX_NULL;     
                                                       
    /* Create the static entry for valid IP instance without ARP feature.  */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /************************************************/   
    /* Tested the nxe_arp_static_entry_delete api   */
    /************************************************/                 
                   
    /* Delete the static entry for NULL IP instance.  */
    status = nx_arp_static_entry_delete(NX_NULL, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                  
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;

    /* Delete the static entry for invalid IP instance.  */
    status = nx_arp_static_entry_delete(&invalid_ip, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                           
    /* Delete the static entry for valid IP address.  */
    status = nx_arp_static_entry_delete(&ip_0, NX_NULL, 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                        
                       
    /* Delete the static entry for valid physical address.  */
    status = nx_arp_static_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, 4), 0, 0); 
                
    /* Check for error.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    /* Disable the ARP feature.  */
    ip_0.nx_ip_arp_allocate = NX_NULL;     
                                                       
    /* Delete the static entry for valid IP instance without ARP feature.  */
    status = nx_arp_static_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Output success.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}   

static void    responder_handler(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP NXE API Test..........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
