/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"      
#include   "nx_ip.h"
#include   "tx_thread.h"
                                       
extern void  test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;  
static NX_PACKET_POOL          invalid_pool;
static NX_IP                   ip_0;      
static NX_IP                   ip_1;    
static NX_IP                   invalid_ip;
                                          
/* Define the counters used in the demo application...  */

static ULONG                   error_counter;    
static CHAR                    *pointer;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);   
static VOID    link_status_change_notify(NX_IP *ip_ptr, UINT interface_index, UINT link_up);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_nxe_api_test_application_define(void *first_unused_memory)
#endif
{
UINT         status;

    
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

    /* Check for IP create errors.  */
    if (status)
        error_counter++;                     

    /* Create an IP instance in ISR with invalid IP address.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 0", IP_ADDRESS(255, 255, 255, 255), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256, pointer + 2048, 2048, 1);

    /* Check for IP create errors.  */
    if (status != NX_IP_ADDRESS_ERROR)
        error_counter++;                     

    /* Create an IP instance in ISR with corruptted memory.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256, pointer + 1, 2048, 1);

    /* Check for IP create errors.  */
    if (status != NX_PTR_ERROR)
        error_counter++;                     


    /* Create an IP instance in ISR with corruptted memory.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256, pointer + 1, 2048, 1);

    /* Check for IP create errors.  */
    if (status != NX_PTR_ERROR)
        error_counter++;                     

    /* Create an IP instance in ISR with corruptted memory.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256, pointer - 1, 2048, 1);

    /* Check for IP create errors.  */
    if (status != NX_PTR_ERROR)
        error_counter++;                     

    pointer =  pointer + 2048;

}                     

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_address;
ULONG       network_mask;  
ULONG       return_value_ptr;  
ULONG       ip_total_packets_sent;
ULONG       ip_total_bytes_sent;
ULONG       ip_total_packets_received;
ULONG       ip_total_bytes_received;
ULONG       ip_invalid_packets;
ULONG       ip_receive_packets_dropped;
ULONG       ip_receive_checksum_errors;
ULONG       ip_send_packets_dropped;
ULONG       ip_total_fragments_sent;
ULONG       ip_total_fragments_received;  
#ifdef NX_ENABLE_INTERFACE_CAPABILITY 
ULONG       interface_capability_flag;
#endif                     
CHAR        *interface_name;
ULONG       mtu_size;
ULONG       physical_address_msw;
ULONG       physical_address_lsw;
ULONG       actual_status;   
#ifdef __PRODUCT_NETXDUO__
NXD_ADDRESS dest_address;
ULONG       start_offset_ptr;
ULONG       payload_length_ptr;
#endif

    /* Print out some test information banners.  */
    printf("NetX Test:   IP NXE API Test...........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                               

    /************************************************/   
    /* Tested the nxe_ip_address_change_notify api  */
    /************************************************/  

    /* Set the IP address change notify function for NULL IP instance.  */
    status = nx_ip_address_change_notify(NX_NULL, NX_NULL, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                                     
    /* Set the IP address change notify function for invalid IP instance.  */
    status = nx_ip_address_change_notify(&invalid_ip, NX_NULL, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                    
    /************************************************/   
    /* Tested the nxe_ip_address_get api            */
    /************************************************/  

    /* Get the IP address for NULL IP instance.  */
    status = nx_ip_address_get(NX_NULL, &ip_address, &network_mask);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Get the IP address for invalid IP instance.  */
    status = nx_ip_address_get(&invalid_ip, &ip_address, &network_mask);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                          
    /* Get the IP address with NULL address pointer.  */
    status = nx_ip_address_get(&ip_0, NX_NULL, &network_mask);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                       
    /* Get the IP address with NULL network mask pointer.  */
    status = nx_ip_address_get(&ip_0, &ip_address, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                          
    /************************************************/   
    /* Tested the nxe_ip_address_set api            */
    /************************************************/  

    /* Set the IP address for NULL IP instance.  */
    status = nx_ip_address_set(NX_NULL, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Set the IP address for invalid IP instance.  */
    status = nx_ip_address_set(&invalid_ip, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                          
    /* Set the IP address with loopback address.  */
    status = nx_ip_address_set(&ip_0, IP_ADDRESS(255, 255, 255, 255), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                          
    /* Set the IP address with Class C address.  */
    status = nx_ip_address_set(&ip_0, IP_ADDRESS(192, 0, 0, 1), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                        
    /************************************************/   
    /* Tested the nxe_ip_create api                 */
    /************************************************/  

#ifndef NX_DISABLE_ERROR_CHECKING
    status = _nxe_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256, pointer, 2048, 1, 0);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING */

    /* Create the IP instance with NULL IP instance.  */
    status = nx_ip_create(NX_NULL, "NetX IP Instance test", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256, pointer, 2048, 1);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Create the IP instance with NULL pool.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance test", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, NX_NULL, _nx_ram_network_driver_256, pointer, 2048, 1);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Clear the ID for invalid pool.  */
    invalid_pool.nx_packet_pool_id  = NX_NULL;   
                                              
    /* Create the IP instance with invalid pool.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance test", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &invalid_pool, _nx_ram_network_driver_256, pointer, 2048, 1);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                                                 
    /* Create the IP instance with NULL driver.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance test", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, NX_NULL, pointer, 2048, 1);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                                                 
    /* Create the IP instance with NULL memory pointer.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance test", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256, NX_NULL, 2048, 1);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                                               
    /* Create the IP instance with small memory size.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance test", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256, pointer, TX_MINIMUM_STACK - 1, 1);
                  
    /* Check for error.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                                               
    /* Create the IP instance with small memory size.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance test", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256, pointer, 2048, TX_MAX_PRIORITIES);
                  
    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create the IP instance with same IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance test", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256, pointer, 2048, 1);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create the IP instance with invalid address.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance test", IP_ADDRESS(255, 255, 255, 255), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256, pointer, 2048, 1);
                  
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                             
    /************************************************/   
    /* Tested the nxe_ip_delete api                 */
    /************************************************/  

    /* Delete the IP instance for NULL IP instance.  */
    status = nx_ip_delete(NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Delete the IP instance for invalid IP instance.  */
    status = nx_ip_delete(&invalid_ip);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                               
    /************************************************/   
    /* Tested the nxe_ip_driver_direct_command api  */
    /************************************************/  

    /* Set the command for NULL IP instance.  */
    status = nx_ip_driver_direct_command(NX_NULL, NX_LINK_GET_STATUS, &return_value_ptr);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
          
    /* Set the command for invalid IP instance.  */
    status = nx_ip_driver_direct_command(&invalid_ip, NX_LINK_GET_STATUS, &return_value_ptr);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                   
    /* Set the command with NULL return value pointer.  */
    status = nx_ip_driver_direct_command(&ip_0, NX_LINK_GET_STATUS, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                             
    /*********************************************************/   
    /* Tested the nxe_ip_driver_interface_direct_command api */
    /*********************************************************/  

    /* Set the command for NULL IP instance.  */
    status = nx_ip_driver_interface_direct_command(NX_NULL, NX_LINK_GET_STATUS, 0, &return_value_ptr);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
          
    /* Set the command for invalid IP instance.  */
    status = nx_ip_driver_interface_direct_command(&invalid_ip, NX_LINK_GET_STATUS, 0, &return_value_ptr);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                   
    /* Set the command with NULL return value pointer.  */
    status = nx_ip_driver_interface_direct_command(&ip_0, NX_LINK_GET_STATUS, 0, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                 
    /* Set the command with error interface index.  */
    status = nx_ip_driver_interface_direct_command(&ip_0, NX_LINK_GET_STATUS, NX_MAX_PHYSICAL_INTERFACES, &return_value_ptr);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                  
    /************************************************/   
    /* Tested the nxe_ip_forwarding_disable api     */
    /************************************************/  

    /* Disable forward feature for NULL IP instance.  */
    status = nx_ip_forwarding_disable(NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Disable forward feature for invalid IP instance.  */
    status = nx_ip_forwarding_disable(&invalid_ip);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                      
                        
    /************************************************/   
    /* Tested the nxe_ip_forwarding_enable api     */
    /************************************************/  

    /* Enable forward feature for NULL IP instance.  */
    status = nx_ip_forwarding_enable(NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Enable forward feature for invalid IP instance.  */
    status = nx_ip_forwarding_enable(&invalid_ip);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          
                    
    /************************************************/   
    /* Tested the nxe_ip_fragment_disable api     */
    /************************************************/  

    /* Disable fragment feature for NULL IP instance.  */
    status = nx_ip_fragment_disable(NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Disable fragment feature for invalid IP instance.  */
    status = nx_ip_fragment_disable(&invalid_ip);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                      
                        
    /************************************************/   
    /* Tested the nxe_ip_fragment_enable api     */
    /************************************************/  

    /* Enable fragment feature for NULL IP instance.  */
    status = nx_ip_forwarding_enable(NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Enable fragment feature for invalid IP instance.  */
    status = nx_ip_fragment_enable(&invalid_ip);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     
                   
    /************************************************/   
    /* Tested the nxe_ip_gateway_address_clear api  */
    /************************************************/  

    /* Clear the gateway address for NULL IP instance.  */
    status = nx_ip_gateway_address_clear(NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Clear the gateway address for invalid IP instance.  */
    status = nx_ip_gateway_address_clear(&invalid_ip);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /************************************************/   
    /* Tested the nxe_ip_gateway_address_get api    */
    /************************************************/  

    /* Get the gateway address for NULL IP instance.  */
    status = nx_ip_gateway_address_get(NX_NULL, &ip_address);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Get the gateway address for invalid IP instance.  */
    status = nx_ip_gateway_address_get(&invalid_ip, &ip_address);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                        
    /* Get the gateway address with NULL ip address pointer.  */
    status = nx_ip_gateway_address_get(&ip_0, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
         
    /************************************************/   
    /* Tested the nxe_ip_gateway_address_set api    */
    /************************************************/  

    /* Set the gateway address for NULL IP instance.  */
    status = nx_ip_gateway_address_set(NX_NULL, IP_ADDRESS(1, 2, 3, 1));
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Set the gateway address for invalid IP instance.  */
    status = nx_ip_gateway_address_set(&invalid_ip, IP_ADDRESS(1, 2, 3, 1));
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                

    /* Set the gateway address with NULL address.  */
    status = nx_ip_gateway_address_set(&ip_0, NX_NULL);

    /* Check the status.  */
    if (status != NX_IP_ADDRESS_ERROR)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }                        
                 
    /************************************************/   
    /* Tested the nxe_ip_info_get api               */
    /************************************************/  
    
    /* Get IP info with NULL IP instance.  */
    status =  nx_ip_info_get(NX_NULL, &ip_total_packets_sent, 
                                    &ip_total_bytes_sent,
                                    &ip_total_packets_received,
                                    &ip_total_bytes_received,
                                    &ip_invalid_packets,
                                    &ip_receive_packets_dropped,
                                    &ip_receive_checksum_errors,
                                    &ip_send_packets_dropped,
                                    &ip_total_fragments_sent,
                                    &ip_total_fragments_received);     
                               
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   
                         
    /* Get IP info with invalid IP instance.  */
    status =  nx_ip_info_get(&invalid_ip, &ip_total_packets_sent, 
                                    &ip_total_bytes_sent,
                                    &ip_total_packets_received,
                                    &ip_total_bytes_received,
                                    &ip_invalid_packets,
                                    &ip_receive_packets_dropped,
                                    &ip_receive_checksum_errors,
                                    &ip_send_packets_dropped,
                                    &ip_total_fragments_sent,
                                    &ip_total_fragments_received);    
                                   
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                   
    /************************************************/   
    /* Tested the nxe_ip_interface_address_get api  */
    /************************************************/  

    /* Get the interface IP address for NULL IP instance.  */
    status = nx_ip_interface_address_get(NX_NULL, 0, &ip_address, &network_mask);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Get the interface IP address for invalid IP instance.  */
    status = nx_ip_interface_address_get(&invalid_ip, 0, &ip_address, &network_mask);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                          
    /* Get the interface IP address with NULL address pointer.  */
    status = nx_ip_interface_address_get(&ip_0, 0, NX_NULL, &network_mask);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                       
    /* Get the interface IP address with NULL network mask pointer.  */
    status = nx_ip_interface_address_get(&ip_0, 0, &ip_address, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    /* Get the interface IP address with MAX interface index.  */
    status = nx_ip_interface_address_get(&ip_0, NX_MAX_PHYSICAL_INTERFACES, &ip_address, &network_mask);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Get the interface IP address with invalid interface index.  */
    status = nx_ip_interface_address_get(&ip_0, 1, &ip_address, &network_mask);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /**************************************************************/   
    /* Tested the nxe_ip_interface_address_mapping_configure api  */
    /**************************************************************/  

    /* Configure the interface mapping for NULL IP instance.  */
    status = nx_ip_interface_address_mapping_configure(NX_NULL, 0, NX_FALSE);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Configure the interface mapping for invalid IP instance.  */
    status = nx_ip_interface_address_mapping_configure(&invalid_ip, 0, NX_FALSE);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                    

    /* Configure the interface mapping with MAX interface index.  */
    status = nx_ip_interface_address_mapping_configure(&ip_0, NX_MAX_PHYSICAL_INTERFACES, NX_FALSE);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                                  
    /************************************************/   
    /* Tested the nxe_ip_interface_address_set api  */
    /************************************************/  
                          
    /* Set the IP address with Class B address.  */
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(128, 0, 0, 1), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                          
    /* Set the IP address with Class C address.  */
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(192, 0, 0, 1), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Set the interface IP address for NULL IP instance.  */
    status = nx_ip_interface_address_set(NX_NULL, 0, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Set the interface IP address for invalid IP instance.  */
    status = nx_ip_interface_address_set(&invalid_ip, 0, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                          
    /* Set the interface IP address with NULL address pointer.  */
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(255, 255, 255, 255), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                      

    /* Set the interface IP address with MAX interface index.  */
    status = nx_ip_interface_address_set(&ip_0, NX_MAX_PHYSICAL_INTERFACES, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Set the interface IP address with invalid interface index.  */
    status = nx_ip_interface_address_set(&ip_0, 1, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  


 #if (NX_MAX_PHYSICAL_INTERFACES >= 2)
    /************************************************/   
    /* Tested the nxe_ip_interface_attach api       */
    /************************************************/  
    
    /* Attach the interface for NULL IP instance.  */
    status = nx_ip_interface_attach(NX_NULL, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_256);
                    
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
             
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Attach the interface for invalid IP instance.  */                                                 
    status = nx_ip_interface_attach(&invalid_ip, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_256);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                            
    /* Attach the interface for NULL dirver.  */                                                 
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                
                            
    /* Attach the interface for NULL name.  */                                                 
    status = nx_ip_interface_attach(&ip_0, NX_NULL, IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_256);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                

    /* Attach the interface for invalid IP address.  */                                                 
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(255, 255, 255, 255), 0xFFFFFF00UL, _nx_ram_network_driver_256);
                  
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                

    /* Attach the interface for valid IP address.  */                                                 
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(192, 0, 0, 2), 0xFFFFFF00UL, _nx_ram_network_driver_256);
                  
    /* Check for error.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                
    nx_ip_interface_detach(&ip_0, 1);
#endif



#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    /**************************************************/   
    /* Tested the nxe_ip_interface_capability_get api */
    /**************************************************/  

    /* Get the interface capability for NULL IP instance.  */
    status = nx_ip_interface_capability_get(NX_NULL, 0, &interface_capability_flag);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Get the interface capability for invalid IP instance.  */
    status = nx_ip_interface_capability_get(&invalid_ip, 0, &interface_capability_flag);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Get the interface capability with MAX interface index.  */
    status = nx_ip_interface_capability_get(&ip_0, NX_MAX_PHYSICAL_INTERFACES, &interface_capability_flag);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                      
                          
    /* Get the interface capability with NULL interface capability pointer.  */
    status = nx_ip_interface_capability_get(&ip_0, 0, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /**************************************************/   
    /* Tested the nxe_ip_interface_capability_set api */
    /**************************************************/  

    /* Set the interface capability for NULL IP instance.  */
    status = nx_ip_interface_capability_set(NX_NULL, 0, NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Set the interface capability for invalid IP instance.  */
    status = nx_ip_interface_capability_set(&invalid_ip, 0, NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Set the interface capability with MAX interface index.  */
    status = nx_ip_interface_capability_set(&ip_0, NX_MAX_PHYSICAL_INTERFACES, NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                                  
#endif
                  
    /************************************************/   
    /* Tested the nxe_ip_interface_detach api       */
    /************************************************/  
    
    /* Detach the interface for NULL IP instance.  */
    status = nx_ip_interface_detach(NX_NULL, 0);
                    
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
             
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Detach the interface for invalid IP instance.  */                                                 
    status = nx_ip_interface_detach(&invalid_ip, 0);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                    

    /* Detach the interface with MAX interface index.  */                                                 
    status = nx_ip_interface_detach(&ip_0, NX_MAX_PHYSICAL_INTERFACES);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    

    /************************************************/   
    /* Tested the nxe_ip_interface_info_get api     */
    /************************************************/  
                             
    /* Get the interface info for NULL IP instance.  */
    status = nx_ip_interface_info_get(NX_NULL, 0, &interface_name, &ip_address, &network_mask, &mtu_size, &physical_address_msw, &physical_address_lsw);

    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                                
    /* Get the interface info for NULL IP instance.  */
    status = nx_ip_interface_info_get(&invalid_ip, 0, &interface_name, &ip_address, &network_mask, &mtu_size, &physical_address_msw, &physical_address_lsw);

    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                               
    /* Get the interface info with MAX interface index.  */
    status = nx_ip_interface_info_get(&ip_0, NX_MAX_PHYSICAL_INTERFACES, &interface_name, &ip_address, &network_mask, &mtu_size, &physical_address_msw, &physical_address_lsw);

    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    
    /*******************************************/   
    /* Tested the nxe_ip_interface_mtu_set api */
    /*******************************************/  

    /* Set the interface mtu for NULL IP instance.  */
    status = nx_ip_interface_mtu_set(NX_NULL, 0, 512);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Set the interface mtu for invalid IP instance.  */
    status = nx_ip_interface_mtu_set(&invalid_ip, 0, 512);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Set the interface mtu with MAX interface index.  */
    status = nx_ip_interface_mtu_set(&ip_0, NX_MAX_PHYSICAL_INTERFACES, 512);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
            
    /********************************************************/   
    /* Tested the nxe_ip_interface_physical_address_get api */
    /********************************************************/  

    /* Get the interface physical address for NULL IP instance.  */
    status = nx_ip_interface_physical_address_get(NX_NULL, 0, &physical_address_msw, &physical_address_lsw);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Get the interface physical address for invalid IP instance.  */
    status = nx_ip_interface_physical_address_get(&invalid_ip, 0, &physical_address_msw, &physical_address_lsw);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            
                               
    /* Get the interface physical address with NULL physical pointer.  */
    status = nx_ip_interface_physical_address_get(&ip_0, 0, NX_NULL, &physical_address_lsw);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                               
    /* Get the interface physical address with NULL physical pointer.  */
    status = nx_ip_interface_physical_address_get(&ip_0, 0, &physical_address_msw, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get the interface physical address with MAX interface index.  */
    status = nx_ip_interface_physical_address_get(&ip_0, NX_MAX_PHYSICAL_INTERFACES, &physical_address_msw, &physical_address_lsw);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                      
             
         
    /********************************************************/   
    /* Tested the nxe_ip_interface_physical_address_set api */
    /********************************************************/  

    /* Set the interface physical address for NULL IP instance.  */
    status = nx_ip_interface_physical_address_set(NX_NULL, 0, 0x0011, 0x0022334457, NX_TRUE);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Set the interface physical address for invalid IP instance.  */
    status = nx_ip_interface_physical_address_set(&invalid_ip, 0, 0x0011, 0x0022334457, NX_TRUE);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                           

    /* Set the interface physical address with MAX interface index.  */
    status = nx_ip_interface_physical_address_set(&ip_0, NX_MAX_PHYSICAL_INTERFACES, 0x0011, 0x0022334457, NX_TRUE);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                      
      
    /************************************************/   
    /* Tested the nxe_ip_interface_status_check api */
    /************************************************/  

    /* Check the interface status for NULL IP instance.  */
    status = nx_ip_interface_status_check(NX_NULL, 0, NX_IP_RARP_COMPLETE, &actual_status, NX_NO_WAIT);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Check the interface status for invalid IP instance.  */
    status = nx_ip_interface_status_check(&invalid_ip, 0, NX_IP_RARP_COMPLETE, &actual_status, NX_NO_WAIT);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                           
                          
    /* Check the interface status with NULL actual status pointer.  */
    status = nx_ip_interface_status_check(&ip_0, 0, NX_IP_RARP_COMPLETE, NX_NULL, NX_NO_WAIT);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Check the interface status with MAX interface index.  */
    status = nx_ip_interface_status_check(&ip_0, NX_MAX_PHYSICAL_INTERFACES, NX_IP_RARP_COMPLETE, &actual_status, NX_NO_WAIT);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                    
             
    /* Check the interface status with invalid interface index.  */
    status = nx_ip_interface_status_check(&ip_0, 1, NX_IP_RARP_COMPLETE, &actual_status, NX_NO_WAIT);
                  
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
               
    /* Check the interface status with invalid need status.  */
    status = nx_ip_interface_status_check(&ip_0, 0, 0x8000, &actual_status, NX_NO_WAIT);
                  
    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
           
#ifdef __PRODUCT_NETXDUO__

    /************************************************/   
    /* Tested the nxe_ip_max_payload_size_find api  */
    /************************************************/  

    /* Set the dest address.  */
    dest_address.nxd_ip_version = NX_IP_VERSION_V4;
    dest_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);

    /* Find the max payload size for NULL IP instance.  */
    status = nx_ip_max_payload_size_find(NX_NULL, &dest_address, 0, 80, 80, NX_PROTOCOL_TCP, &start_offset_ptr, &payload_length_ptr);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL; 
                    
    /* Find the max payload size for invalid IP instance.  */
    status = nx_ip_max_payload_size_find(&invalid_ip, &dest_address, 0, 80, 80, NX_PROTOCOL_TCP, &start_offset_ptr, &payload_length_ptr);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                                               

    /* Find the max payload size with NULL dest address.  */
    status = nx_ip_max_payload_size_find(&ip_0, NX_NULL, 0, 80, 80, NX_PROTOCOL_TCP, &start_offset_ptr, &payload_length_ptr);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                         
    /* Set the dest address.  */
    dest_address.nxd_ip_version = 0x80;
    dest_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);

    /* Find the max payload size with invalid dest address.  */
    status = nx_ip_max_payload_size_find(&ip_0, &dest_address, 0, 80, 80, NX_PROTOCOL_TCP, &start_offset_ptr, &payload_length_ptr);
                  
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                         
    /* Set the dest address.  */
    dest_address.nxd_ip_version = NX_IP_VERSION_V4;
    dest_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);

    /* Find the max payload size with invalid protocol.  */
    status = nx_ip_max_payload_size_find(&ip_0, &dest_address, 0, 80, 80, NX_PROTOCOL_ICMP, &start_offset_ptr, &payload_length_ptr);
                  
    /* Check for error.  */
    if (status != NX_NOT_SUPPORTED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
#endif
             
#ifdef NX_ENABLE_DUAL_PACKET_POOL
    /************************************************/   
    /* Tested the nxe_ip_auxiliary_packet_pool_set api  */
    /************************************************/  

    /* Set the auxiliary packet pool for NULL IP instance.  */
    status = nx_ip_auxiliary_packet_pool_set(NX_NULL, &pool_0);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL; 
                    
    /* Set the auxiliary packet pool for invalid IP instance.  */
    status = nx_ip_auxiliary_packet_pool_set(&invalid_ip, &pool_0);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                                               

    /* Set the auxiliary packet pool with NULL pool.  */
    status = nx_ip_auxiliary_packet_pool_set(&ip_0, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                                   
    /* Clear the ID for invalid pool.  */
    invalid_pool.nx_packet_pool_id  = NX_NULL; 

    /* Set the auxiliary packet pool with invalid pool.  */
    status = nx_ip_auxiliary_packet_pool_set(&ip_0, &invalid_pool);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
#endif /* NX_ENABLE_DUAL_PACKET_POOL */
                                             
#ifdef NX_ENABLE_IP_STATIC_ROUTING
    /************************************************/   
    /* Tested the nxe_ip_static_route_add api       */
    /************************************************/  

    /* Add the static route for NULL IP instance.  */
    status = nx_ip_static_route_add(NX_NULL, IP_ADDRESS(1, 2, 3, 10), IP_ADDRESS(255, 255, 255,0 ), IP_ADDRESS(1, 2, 3, 1));
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL; 
                    
    /* Add the static route for invalid IP instance.  */
    status = nx_ip_static_route_add(&invalid_ip, IP_ADDRESS(1, 2, 3, 10), IP_ADDRESS(255, 255, 255, 0), IP_ADDRESS(1, 2, 3, 1));
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                                                            
         
    /************************************************/   
    /* Tested the nxe_ip_static_route_delete api    */
    /************************************************/  

    /* Delete the static route for NULL IP instance.  */
    status = nx_ip_static_route_delete(NX_NULL, IP_ADDRESS(1, 2, 3, 10), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL; 
                    
    /* Delete the static route for invalid IP instance.  */
    status = nx_ip_static_route_delete(&invalid_ip, IP_ADDRESS(1, 2, 3, 10), IP_ADDRESS(255, 255, 255, 0));
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                      
#endif
                  
    /************************************************/   
    /* Tested the nxe_ip_status_check api           */
    /************************************************/  

    /* Check the status for NULL IP instance.  */
    status = nx_ip_status_check(NX_NULL, NX_IP_RARP_COMPLETE, &actual_status, NX_NO_WAIT);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
              
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     
                           
    /* Check the status for invalid IP instance.  */
    status = nx_ip_status_check(&invalid_ip, NX_IP_RARP_COMPLETE, &actual_status, NX_NO_WAIT);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                           
                          
    /* Check the status with NULL actual status pointer.  */
    status = nx_ip_status_check(&ip_0, NX_IP_RARP_COMPLETE, NX_NULL, NX_NO_WAIT);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                   
               
    /* Check the status with invalid need status.  */
    status = nx_ip_status_check(&ip_0, 0x8000, &actual_status, NX_NO_WAIT);
                  
    /* Check for error.  */
    if (status != NX_OPTION_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                 
    /******************************************************/   
    /* Tested the nx_ip_link_status_change_notify_set api */
    /******************************************************/  

    /* Set link status change notify will NULL IP. */
    status = nx_ip_link_status_change_notify_set(NX_NULL, link_status_change_notify);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set link status change notify will NULL callback function pointer. */
    status = nx_ip_link_status_change_notify_set(&ip_0, NX_NULL);
                  
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Output success.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}       


static VOID    link_status_change_notify(NX_IP *ip_ptr, UINT interface_index, UINT link_up)
{
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP NXE API Test...........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
