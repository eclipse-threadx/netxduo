/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"      
#include   "nx_ip.h"
#ifdef FEATURE_NX_IPV6
#include   "nx_ipv6.h"
#include   "nx_icmpv6.h"
#endif /* FEATURE_NX_IPV6 */
                                       
extern void  test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING) && !defined(NX_DISABLE_IPV4)     

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
#ifdef FEATURE_NX_IPV6
static void    icmpv6_ra_flag_callback(NX_IP *ip_ptr, UINT ra_flag);
#endif 

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

CHAR        *pointer;
UINT        status;  
#ifdef FEATURE_NX_IPV6
NXD_ADDRESS ipv6_address;
#endif

    
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
    
#ifdef FEATURE_NX_IPV6
    /* Set ipv6 version and address.  */
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[3] = 0x10000001;   

    /* Set interfaces' address */
    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address, 64, NX_NULL);   

    /* Check for IP create errors.  */
    if (status)
        error_counter++;  
#endif
}                     

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;  
NX_PACKET   *my_packet = NX_NULL;
ULONG       pings_sent;   
ULONG       ping_timeouts;
ULONG       ping_threads_suspended;
ULONG       ping_responses_received;
ULONG       icmp_checksum_errors;
ULONG       icmp_unhandled_messages;   
#ifdef FEATURE_NX_IPV6 
NXD_ADDRESS ip_address;
#endif                          

    /* Print out some test information banners.  */
    printf("NetX Test:   ICMP NXE API Test.........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                         
    /************************************************/   
    /* Tested the nxe_icmp_enable api               */
    /************************************************/                 
                   
    /* Enable the ICMP feature for NULL IP instance.  */
    status = nx_icmp_enable(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
             
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   

    /* Enable the ICMP feature for invalid IP instance.  */
    status = nx_icmp_enable(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
              
    /* Enable the ICMP feature for valid IP instance.  */
    status = nx_icmp_enable(&ip_0); 
                
    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                
    /* Enable the ICMP feature again for valid IP instance .  */
    status = nx_icmp_enable(&ip_0); 
                
    /* Check for error.  */
    if (status != NX_ALREADY_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                        
    /************************************************/   
    /* Tested the nxe_icmp_info_get api             */
    /************************************************/                 
                   
    /* Get the ICMP information for NULL IP instance.  */
    status = nx_icmp_info_get(NX_NULL, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Get the ICMP information for invalid IP instance.  */ 
    status = nx_icmp_info_get(&invalid_ip, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages); 

    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                     
    /* Disable the ICMP feature.  */
    ip_0.nx_ip_icmp_packet_receive = NX_NULL;   
                  
    /* Get the ICMP information for invalid IP instance.  */   
    status = nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages); 

    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /************************************************/   
    /* Tested the nxe_icmp_ping api                 */
    /************************************************/                 
                                                            
    /* Send the ping information for NULL IP instance.  */
    status = nx_icmp_ping(NX_NULL, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                         

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   
                                                 
    /* Send the ping information for invalid IP instance.  */
    status = nx_icmp_ping(&invalid_ip, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             
                                                          
    /* Send the ping information for valid IP instance with NULL packet pointer.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, NX_NULL, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        
                        
                                                          
    /* Send the ping information for valid IP instance with invalid address.  */
    status = nx_icmp_ping(&ip_0, NX_NULL, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        
                
    /* Disable the ICMP feature.  */
    ip_0.nx_ip_icmp_packet_receive = NX_NULL;   
                                                  
    /* Send the ping information for valid IP instance with disable ICMP feature.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

#ifdef FEATURE_NX_IPV6            
                                
    /************************************************/   
    /* Tested the nxde_icmp_enable api              */
    /************************************************/                 
                   
    /* Enable the ICMPv6 feature for NULL IP instance.  */
    status = nxd_icmp_enable(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
             
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   

    /* Enable the ICMPv6 feature for invalid IP instance.  */
    status = nxd_icmp_enable(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                               

    /************************************************/   
    /* Tested the nxde_icmp_ping api                */
    /************************************************/      

    /* Set the address.  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
                                                            
    /* Send the ping information for NULL IP instance.  */
    status = nxd_icmp_ping(NX_NULL, &ip_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                         

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   
                                                 
    /* Send the ping information for invalid IP instance.  */
    status = nxd_icmp_ping(&invalid_ip, &ip_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             
                                                          
    /* Send the ping information for valid IP instance with NULL packet pointer.  */
    status = nxd_icmp_ping(&ip_0, &ip_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, NX_NULL, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        
                                                         
    /* Send the ping information for valid IP instance with invalid address.  */
    status = nxd_icmp_ping(&ip_0, NX_NULL, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Set the wrong address version.  */
    ip_address.nxd_ip_version = 0x80;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
                                                          
    /* Send the ping information for valid IP instance with invalid address.  */
    status = nxd_icmp_ping(&ip_0, &ip_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        
                       
    /* Set the address .  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
                                      
    /* Disable the ICMPv4 feature.  */
    ip_0.nx_ip_icmpv4_packet_process  = NX_NULL;  
                                                          
    /* Send the ping information, valid IP instance, valid address and disable ICMPv4 feature.  */
    status = nxd_icmp_ping(&ip_0, &ip_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                       
    /* Set the address .  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    ip_address.nxd_ip_address.v6[0] = 0x20010000; 
    ip_address.nxd_ip_address.v6[1] = 0x00000000;
    ip_address.nxd_ip_address.v6[2] = 0x00000000;
    ip_address.nxd_ip_address.v6[3] = 0x00000001;
                                      
    /* Disable the ICMPv6 feature.  */
    ip_0.nx_ip_icmpv6_packet_process   = NX_NULL;  
                                                          
    /* Send the ping information, valid IP instance, valid address and disable ICMPv6 feature.  */
    status = nxd_icmp_ping(&ip_0, &ip_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        
    ip_0.nx_ip_icmpv6_packet_process   = _nx_icmpv6_packet_process;  

    /* Disable the IPv6 feature.  */
    ip_0.nx_ipv6_packet_receive   = NX_NULL;  

    /* Send the ping information, valid IP instance, valid address and disable ICMPv6 feature.  */
    status = nxd_icmp_ping(&ip_0, &ip_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        
    ip_0.nx_ipv6_packet_receive   = _nx_ipv6_packet_receive;

    /************************************************/   
    /* Tested the nxde_icmp_source_ping api         */
    /************************************************/      

    /* Set the address.  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
                                                            
    /* Send the ping information for NULL IP instance.  */
    status = nxd_icmp_source_ping(NX_NULL, &ip_address, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                         

    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;   
                                                 
    /* Send the ping information for invalid IP instance.  */
    status = nxd_icmp_source_ping(&invalid_ip, &ip_address, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             
                                                          
    /* Send the ping information for valid IP instance with NULL packet pointer.  */
    status = nxd_icmp_source_ping(&ip_0, &ip_address, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, NX_NULL, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        
                                                         
    /* Send the ping information for valid IP instance with invalid address.  */
    status = nxd_icmp_source_ping(&ip_0, NX_NULL, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      

    /* Set the wrong address version.  */
    ip_address.nxd_ip_version = 0x80;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
                                                          
    /* Send the ping information for valid IP instance with invalid address.  */
    status = nxd_icmp_source_ping(&ip_0, &ip_address, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        
                       
    /* Set the address .  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V4;
    ip_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
                                                                                                        
    /* Send the ping information, valid IP instance, valid address and valid interface index.  */
    status = nxd_icmp_source_ping(&ip_0, &ip_address, NX_MAX_IP_INTERFACES, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Disable the ICMPv4 feature.  */
    ip_0.nx_ip_icmpv4_packet_process  = NX_NULL;  
                                                          
    /* Send the ping information, valid IP instance, valid address and disable ICMPv4 feature.  */
    status = nxd_icmp_source_ping(&ip_0, &ip_address, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   
                       
    /* Set the address .  */
    ip_address.nxd_ip_version = NX_IP_VERSION_V6;
    ip_address.nxd_ip_address.v6[0] = 0x20010000; 
    ip_address.nxd_ip_address.v6[1] = 0x00000000;
    ip_address.nxd_ip_address.v6[2] = 0x00000000;
    ip_address.nxd_ip_address.v6[3] = 0x00000001;
                                                                       
    /* Send the ping information, valid IP instance, valid address and invalid address index.  */
    status = nxd_icmp_source_ping(&ip_0, &ip_address, NX_MAX_IPV6_ADDRESSES + NX_LOOPBACK_IPV6_ENABLED, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                                                                       
    /* Send the ping information, valid IP instance, valid address and invalid address attached interface.  */
    ip_0.nx_ipv6_address[0].nxd_ipv6_address_attached = NX_NULL;
    status = nxd_icmp_source_ping(&ip_0, &ip_address, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
    ip_0.nx_ipv6_address[0].nxd_ipv6_address_attached = &ip_0.nx_ip_interface[0];
                                                                       
    /* Send the ping information, valid IP instance, valid address and invalid address state.  */
    ip_0.nx_ipv6_address[0].nxd_ipv6_address_valid = NX_FALSE;
    status = nxd_icmp_source_ping(&ip_0, &ip_address, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_INVALID_INTERFACE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
    ip_0.nx_ipv6_address[0].nxd_ipv6_address_valid = NX_TRUE;

    /* Disable the ICMPv6 feature.  */
    ip_0.nx_ip_icmpv6_packet_process   = NX_NULL;  
                                                          
    /* Send the ping information, valid IP instance, valid address and disable ICMPv6 feature.  */
    status = nxd_icmp_source_ping(&ip_0, &ip_address, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                 
    ip_0.nx_ip_icmpv6_packet_process   = _nx_icmpv6_packet_process;  

    /* Disable the IPv6 feature.  */
    ip_0.nx_ipv6_packet_receive   = NX_NULL;  
                                                          
    /* Send the ping information, valid IP instance, valid address and disable ICMPv6 feature.  */
    status = nxd_icmp_source_ping(&ip_0, &ip_address, 0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                 
    ip_0.nx_ipv6_packet_receive   = _nx_ipv6_packet_receive;  
          
    /***************************************************/   
    /* Tested the nxde_icmpv6_ra_flag_callback_set api */
    /***************************************************/      
                                                                                                                          
    /* Send the ra callback function for NULL IP instance.  */
    status = nxd_icmpv6_ra_flag_callback_set(NX_NULL, icmpv6_ra_flag_callback); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                       
                                                                                                                          
    /* Send the ra callback function for invalid IP instance.  */
    status = nxd_icmpv6_ra_flag_callback_set(&invalid_ip, icmpv6_ra_flag_callback); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    
#endif        

    /* Output success.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}      
               
#ifdef FEATURE_NX_IPV6
static void    icmpv6_ra_flag_callback(NX_IP *ip_ptr, UINT ra_flag)
{
}
#endif
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP NXE API Test.........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
