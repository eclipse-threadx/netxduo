/* This NetX test concentrates on the ARP dynamic entry operation.  */

#include   "tx_api.h"
#include   "nx_api.h"   
#include   "nx_system.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;  
static CHAR                    *pointer;     
static CHAR                    set_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req); 
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);            


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_dynamic_entry_test2_application_define(void *first_unused_memory)
#endif
{

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

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
                                    
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */   
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}                                     


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;   
ULONG       pings_sent;
ULONG       ping_timeouts;
ULONG       ping_threads_suspended;
ULONG       ping_responses_received;
ULONG       icmp_checksum_errors;
ULONG       icmp_unhandled_messages;   

    /* Print out some test information banners.  */
    printf("NetX Test:   ARP Dynamic Entry Processing Test2........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                

    /* Check the packet count.  */
    if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                              
    /* Ping an IP address that does exist, but the peer IP instance disable the ARP feature. This will timeout after 100 ticks.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                    
                  
    /* Check the packet count, one ping packet should be exi.  */
    if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total - 1)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Clear the all dynamic entries.  */
    status =  nx_arp_dynamic_entries_invalidate(&ip_0);
                
    /* Check the status and packet count.  */
    if ((status) || (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Set packet process to detect the ARP message and set the dynamic entry, the ping operation should be correct.  */
    advanced_packet_process_callback = my_packet_process;  

    /* Update the counter.  */
    set_counter = 0;

    /* Now ping an IP address that does exist.  */
    /* The reply packet contains checksum 0. */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, 2 * NX_IP_PERIODIC_RATE);

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 1) || (pings_sent != 2) || (ping_responses_received != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28 /* data only */) ||
        (ping_threads_suspended) || (icmp_checksum_errors) || (icmp_unhandled_messages))
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                
    /* Determine if the test was successful.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {

        printf("SUCCESS!\n");
        test_control_return(0);
    }
}                

static UINT   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

UINT        status;

    /* Update the counter.  */
    set_counter ++;

    /* Check the arp counter.  */
    if (set_counter == 1)
    {                                          

        /* Set a dynamic ARP entry for IP instance0, the ping will be sent.  */
        status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0x0011, 0x22334457);
        if (status)
        {
            error_counter++;
        }       

        /* Enable ARP and supply ARP cache memory for IP Instance 0.  */   
        status = nx_arp_enable(&ip_1, (void *) pointer, 1024);
        pointer = pointer + 1024;    
        if (status)            
        {
            error_counter++;
        }       

        /* Set a dynamic ARP entry for IP instance0, the ping will be response.  */
        status =  nx_arp_dynamic_entry_set(&ip_1, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456);
        if (status)
        {
            error_counter++;
        }      
    }             

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_dynamic_entry_test2_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Dynamic Entry Processing Test2........................N/A\n"); 

    test_control_return(3);  
}      
#endif  
