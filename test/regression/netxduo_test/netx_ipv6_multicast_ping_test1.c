/* This NetX test concentrates on the basic multicast ICMPv6 operation.  
 * Two nodes (A and B) with link local addresses. 
 * Let node A finish DAD first. 
 * Let node A ping all node multicast address. 
 * Since the state of address for node B is still tentative, B would not respond A.
 * Let node B finish DAD. 
 * Let node A ping all node multicast address. 
 * Check the return status of ping from A. */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status); 
#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_IPV6_DAD)

#define     DEMO_STACK_SIZE     2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0; 
static NX_IP                   ip_1; 


/* Define the counters used in the test application...  */

static ULONG                   error_counter;   

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);

extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_multicast_ping_test1_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
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

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;
}
                     

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NXD_ADDRESS multicast_address; 
NX_PACKET   *my_packet;  
ULONG       pings_sent;
ULONG       ping_timeouts;
ULONG       ping_threads_suspended;
ULONG       ping_responses_received;
ULONG       icmp_checksum_errors;
ULONG       icmp_unhandled_messages;            

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Multicast Ping Test 1................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;       
                     
    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);  

    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_1, 0, NX_NULL, 10, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;   

    /* Set the group address .  */ 
    multicast_address.nxd_ip_version = NX_IP_VERSION_V6;
    multicast_address.nxd_ip_address.v6[0] = 0xff020000;
    multicast_address.nxd_ip_address.v6[1] = 0x00000000;
    multicast_address.nxd_ip_address.v6[2] = 0x00000000;
    multicast_address.nxd_ip_address.v6[3] = 0x00000001;    

    /* Ping multicast address before DAD of IP_1 is done. */
    status =  nxd_icmp_ping(&ip_0, &multicast_address, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
                   
    /* Check status.  */
    if(status == NX_SUCCESS)              
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         
                     
    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);  
             
    /* Now ping an Multicast address that does exist.  */
    /* The reply packet contains checksum 0. */
    status =  nxd_icmp_ping(&ip_0, &multicast_address, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
                   
    /* Check status.  */
    if(status)              
    {

        printf("ERROR!\n");
        test_control_return(1);
    }         

    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_multicast_ping_test1_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   IPv6 Multicast Ping Test 1................................N/A\n");
    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */
