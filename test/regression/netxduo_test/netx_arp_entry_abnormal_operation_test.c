/* This NetX test concentrates on the ARP dynamic/static entry abnormal operation.  */

#include   "tx_api.h"
#include   "nx_api.h"  
#include   "nx_ip.h"
                                
extern void    test_control_return(UINT status);
                                
#if defined (__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES >= 2) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048    
#define     NX_ETHERNET_IP          0x0800
#define     NX_ETHERNET_ARP         0x0806
#define     NX_ETHERNET_RARP        0x8035
#define     NX_ETHERNET_IPV6        0x86DD

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static UINT                    arp_receive;
static UINT                    icmp_receive;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);  
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_entry_abnormal_operation_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
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
                                  

    /* Attach new interface.  */
    status += nx_ip_interface_attach(&ip_0,"Second Interface",IP_ADDRESS(2,2,3,4),0xFFFFFF00UL,  _nx_ram_network_driver_256);
    if (status)
        error_counter++;     

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;         

    /* Enable ICMP processing.  */
    status =  nx_icmp_enable(&ip_0);

    /* Check ICMP enable status.  */
    if (status)
        error_counter++;
}                  


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
ULONG       ip_address;
ULONG       physical_msw;
ULONG       physical_lsw;


    /* Print out some test information banners.  */
    printf("NetX Test:   ARP Entry Abnormal Operation Test.........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the callback function to detect the packet. */
    advanced_packet_process_callback = my_packet_process;

    /* Clear the arp receive and icmp receive falg.  */
    arp_receive = NX_FALSE;                               
    icmp_receive = NX_FALSE;

    /* Ping an IP address that does exist, but the peer IP instance disable the ARP feature.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(2, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
                                       
    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Check the arp receive and icmp receive flag.  */
    if ((arp_receive != NX_TRUE) || (icmp_receive != NX_FALSE)) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_dynamic_active_count != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
                       
#ifndef NX_DISABLE_ARP_INFO
    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_static_entries != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif  

    /* Clear the arp receive and icmp receive falg.  */
    arp_receive = NX_FALSE;                               
    icmp_receive = NX_FALSE;
                                    
    /* Set a dynamic ARP entry with the same IP address.  */
    status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(2, 2, 3, 5), 0x0011, 0x22334467);    

    /* Determine if the timeout error occurred.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                 
    /* Check the arp receive and icmp receive flag.  */
    if ((arp_receive != NX_FALSE) || (icmp_receive != NX_TRUE)) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_dynamic_active_count != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
           
#ifndef NX_DISABLE_ARP_INFO
    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_static_entries != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif  

    /* Clear the arp receive and icmp receive falg.  */
    arp_receive = NX_FALSE;                               
    icmp_receive = NX_FALSE;

    /* Ping an IP address that does exist, but the peer IP instance disable the ARP feature.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(2, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 50);
                                       
    /* Determine if the timeout error occurred.  */ 
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                       
    /* Check the arp receive and icmp receive flag.  */
    if ((arp_receive != NX_FALSE) || (icmp_receive != NX_TRUE)) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_dynamic_active_count != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                  

#ifndef NX_DISABLE_ARP_INFO
    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_static_entries != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif  
                       
    /* Clear the arp receive and icmp receive falg.  */
    arp_receive = NX_FALSE;                               
    icmp_receive = NX_FALSE;

    /* Setup multiple static ARP entries.  */
    status =   nx_arp_static_entry_create(&ip_0, IP_ADDRESS(2, 2, 3, 5), 0x0011, 0x22334467);

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Check the arp receive and icmp receive flag.  */
    if ((arp_receive != NX_FALSE) || (icmp_receive != NX_FALSE)) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_dynamic_active_count != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
#ifndef NX_DISABLE_ARP_INFO
    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_static_entries != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Find the IP address.  */
    status = nx_arp_ip_address_find(&ip_0, &ip_address, 0x0011, 0x22334467);
    if ((status) || (ip_address != IP_ADDRESS(2, 2, 3, 5)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(2, 2, 3, 5), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x0011) || (physical_lsw != 0x22334467))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                        
                             
                       
    /* Clear the arp receive and icmp receive falg.  */
    arp_receive = NX_FALSE;                               
    icmp_receive = NX_FALSE;

    /* Ping an IP address that does exist, but the peer IP instance disable the ARP feature.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(2, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
                                       
    /* Determine if the timeout error occurred.  */ 
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                  
    /* Check the arp receive and icmp receive flag.  */
    if ((arp_receive != NX_FALSE) || (icmp_receive != NX_TRUE)) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_dynamic_active_count != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
#ifndef NX_DISABLE_ARP_INFO
    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_static_entries != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Set a dynamic ARP entry.  */
    status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(2, 2, 3, 5), 0x0011, 0x22334467);    

#ifdef __PRODUCT_NETXDUO__
    /* Determine if the timeout error occurred.  */
    if (status == NX_SUCCESS)
#else
    if (status)
#endif
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
        
    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_dynamic_active_count != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
#ifndef NX_DISABLE_ARP_INFO
    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_static_entries != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif 

    /* Detach the second interface.  */
    status = nx_ip_interface_detach(&ip_0, 1);
                     
    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_dynamic_active_count != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
#ifndef NX_DISABLE_ARP_INFO
    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_static_entries != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif        
             
    /* Attach interface again.  */
    status = nx_ip_interface_attach(&ip_0,"Second Interface",IP_ADDRESS(2,2,3,4),0xFFFFFF00UL,  _nx_ram_network_driver_256);
    if (status)              
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Set the callback function to detect the packet. */
    advanced_packet_process_callback = my_packet_process;

    /* Clear the arp receive and icmp receive falg.  */
    arp_receive = NX_FALSE;                               
    icmp_receive = NX_FALSE;

    /* Ping an IP address that does exist, but the peer IP instance disable the ARP feature.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(2, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
                                       
    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Check the arp receive and icmp receive flag.  */
    if ((arp_receive != NX_TRUE) || (icmp_receive != NX_FALSE)) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_dynamic_active_count != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          

#ifndef NX_DISABLE_ARP_INFO
    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_static_entries != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
                         
    /* Clear the arp receive and icmp receive falg.  */
    arp_receive = NX_FALSE;                               
    icmp_receive = NX_FALSE;

    /* Setup multiple static ARP entries.  */
    status =   nx_arp_static_entry_create(&ip_0, IP_ADDRESS(2, 2, 3, 5), 0x0011, 0x22334467);

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }            

    /* Check the arp receive and icmp receive flag.  */
    if ((arp_receive != NX_FALSE) || (icmp_receive != NX_TRUE)) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_dynamic_active_count != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
#ifndef NX_DISABLE_ARP_INFO
    /* Check the dynamic entry count.  */
    if (ip_0.nx_ip_arp_static_entries != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    printf("SUCCESS!\n");
    test_control_return(0);
}   
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{                           
    
#ifdef __PRODUCT_NETXDUO__
NX_IPV4_HEADER   *ip_header_ptr;
#else
NX_IP_HEADER     *ip_header_ptr;
#endif   
ULONG            protocol; 

    /* For this test case, only ARP and ICMP packet will be send.  */
               
    /* Check the packet length.  */
    if (packet_ptr -> nx_packet_length >= 28)
    {

#if defined(__PRODUCT_NETXDUO__)
        ip_header_ptr = (NX_IPV4_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);

#else
        ip_header_ptr = (NX_IP_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);
#endif

        /* Get IP header. */
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
        protocol = (ip_header_ptr -> nx_ip_header_word_2 >> 16) & 0xFF;

        /* Is ICMP packet? */
        if(protocol == 1)
        {

            /* Set the flag.  */
            icmp_receive = NX_TRUE;
        }  
        else
        {

            /* Set the flag.  */
            arp_receive = NX_TRUE;
        }
    }  

    /* Release the packet.  */
    nx_packet_release(packet_ptr);

    return NX_FALSE;
}        
#else  
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_entry_abnormal_operation_test_application_define(void *first_unused_memory)
#endif
{      

    /* Print out some test information banners.  */
    printf("NetX Test:   ARP Entry Abnormal Operation Test.........................N/A\n");
    
    test_control_return(3);
}
#endif
