/* This NetX test concentrates on the ARP dynamic entry operation.  */

#include   "tx_api.h"
#include   "nx_api.h"   

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;      
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;  


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);        


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_queue_depth_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;    
CHAR    *pointer;     

    
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
                                    
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */   
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nx_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}                                     


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;   
UINT        i;
NX_PACKET   *my_packet;  

    /* Print out some test information banners.  */
    printf("NetX Test:   ARP Queue Depth Test......................................");

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
                              
    /* Loop to send the ICMP ping to test the ARP queue depth.  */
    for (i = 0; i < NX_ARP_MAX_QUEUE_DEPTH + 3; i ++)
    {

        /* Ping an IP address that does exist, but the peer IP instance disable the ARP feature. This will timeout after 100 ticks.  */
        status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 10);

        /* Determine if the timeout error occurred.  */
        if ((status != NX_NO_RESPONSE) || (my_packet))
        {

            printf("ERROR!\n");
            test_control_return(1);
        }                                    

        /* Check the count.  */
        if (i < NX_ARP_MAX_QUEUE_DEPTH)
        {

            /* Check the packet count, one ping packet should be exi.  */
            if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total - i - 1)  
            {

                printf("ERROR!\n");
                test_control_return(1);
            }  
        }
        else
        {   

            /* Check the packet count, one ping packet should be exi.  */
            if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total - NX_ARP_MAX_QUEUE_DEPTH)  
            {

                printf("ERROR!\n");
                test_control_return(1);
            }  
        }
    }

    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_queue_depth_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Queue Depth Test......................................N/A\n"); 

    test_control_return(3);  
}      
#endif     