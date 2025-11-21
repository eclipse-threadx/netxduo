/* This NetX test concentrates on the ICMP Clean up operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"   
#ifdef FEATURE_NX_IPV6                 
#include   "nx_icmpv6.h"   
#endif

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048  

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0; 
static TX_THREAD               ntest_1;   
static TX_THREAD               ntest_2;
static TX_THREAD               ntest_3; 
#ifdef FEATURE_NX_IPV6   
static TX_THREAD               ntest_4;  
#endif 
static TX_THREAD               ntest_5;  


static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;     


/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);  
static void    ntest_1_entry(ULONG thread_input);   
static void    ntest_2_entry(ULONG thread_input);
static void    ntest_3_entry(ULONG thread_input);  
#ifdef FEATURE_NX_IPV6             
static void    ntest_4_entry(ULONG thread_input); 
#endif
static void    ntest_5_entry(ULONG thread_input); 
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_cleanup_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;  
#ifdef FEATURE_NX_IPV6 
NXD_ADDRESS global_address;
#endif

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;
                                        
    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;
                                            
    /* Create the main thread.  */
    tx_thread_create(&ntest_2, "thread 2", ntest_2_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_3, "thread 3", ntest_3_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;      
                            
#ifdef FEATURE_NX_IPV6          
    /* Create the main thread.  */
    tx_thread_create(&ntest_4, "thread 4", ntest_4_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;  
#endif
                                            
    /* Create the main thread.  */
    tx_thread_create(&ntest_5, "thread 5", ntest_5_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
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
                                   
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for IP instances.  */
    status =  nx_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6        
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMPv6 processing for IP instances0 .  */
    status =  nxd_icmp_enable(&ip_0);   

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;
    
    /* Set ipv6 global address for IP instance 0.  */
    global_address.nxd_ip_version = NX_IP_VERSION_V6;
    global_address.nxd_ip_address.v6[0] = 0x20010000;
    global_address.nxd_ip_address.v6[1] = 0x00000000;
    global_address.nxd_ip_address.v6[2] = 0x00000000;
    global_address.nxd_ip_address.v6[3] = 0x10000001;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &global_address, 64, NX_NULL);    

    /* Check status.  */
    if(status)
        error_counter++;
#endif

    /* Resume the test thread.  */   
    tx_thread_resume(&ntest_0);   
}
                     

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;

    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Cleanup Test.........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                             
          
#ifdef FEATURE_NX_IPV6  
    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);     
#endif

    tx_thread_resume(&ntest_1);   
    tx_thread_resume(&ntest_2);
    tx_thread_resume(&ntest_3);  
#ifdef FEATURE_NX_IPV6  
    tx_thread_resume(&ntest_4);
#endif
    tx_thread_resume(&ntest_5);

    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 0)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an unknown IP address. This will timeout after 1 second.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 7), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          
}
      

/* Define the test threads.  */

static void    ntest_1_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
                      
    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 1)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an unknown IP address. This will timeout after 5 seconds.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 7), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 5 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_WAIT_ABORTED) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
         
    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 0)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}                

/* Define the test threads.  */

static void    ntest_2_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
                    
    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 2)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an unknown IP address. This will timeout after 4 seconds.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 7), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 4 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 1)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Abort thread 1. */
    tx_thread_wait_abort(&ntest_1);
}

/* Define the test threads.  */

static void    ntest_3_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;

    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 3)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an unknown IP address. This will timeout after 3 seconds.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 7), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 3 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
             
    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 2)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
}
                  
#ifdef FEATURE_NX_IPV6        
/* Define the test threads.  */

static void    ntest_4_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet; 
NXD_ADDRESS dest_address;

    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 4)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set destination address.  */
    dest_address.nxd_ip_version = NX_IP_VERSION_V6;
    dest_address.nxd_ip_address.v6[0] = 0x20010000;
    dest_address.nxd_ip_address.v6[1] = 0x00000000;
    dest_address.nxd_ip_address.v6[2] = 0x00000000;
    dest_address.nxd_ip_address.v6[3] = 0x10000002;     

    /* Ping an unknown IP address. This will timeout after 2 seconds.  */
    status =  nxd_icmp_ping(&ip_0, &dest_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 2 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
             
    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 3)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
}
#endif

/* Define the test threads.  */

static void    ntest_5_entry(ULONG thread_input)
{
               
#ifdef FEATURE_NX_IPV6   
    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 5)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      
#else    
    /* Check the ICMP ping suspended count.  */
    if (ip_0.nx_ip_icmp_ping_suspended_count != 4)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }      
#endif
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_cleanup_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Cleanup Test.........................................N/A\n"); 

    test_control_return(3);  
}      
#endif