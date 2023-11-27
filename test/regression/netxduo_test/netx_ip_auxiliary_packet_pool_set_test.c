/* This NetX test concentrates on the basic TCP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
                             
#if defined __PRODUCT_NETXDUO__  && defined NX_ENABLE_DUAL_PACKET_POOL

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;    
static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          auxiliary_pool_0; 
static NX_PACKET_POOL          auxiliary_pool_1;
static NX_IP                   ip_0;          

/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_auxiliary_packet_pool_set_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;
                                  

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool. 256 * 10= 2560   */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2560);
    pointer = pointer + 2560;

    if (status)
        error_counter++;
                          
    /* Create a auxiliary packet pool 0.  128*10 = 1280 */
    status =  nx_packet_pool_create(&auxiliary_pool_0, "NetX Auxiliary Packet Pool 0", 128, pointer, 1280);
    pointer = pointer + 1280;

    if (status)
        error_counter++;    

    /* Create a auxiliary packet pool 1.  512*10 = 5120 */
    status =  nx_packet_pool_create(&auxiliary_pool_1, "NetX Auxiliary Packet Pool 1", 512, pointer, 5120);
    pointer = pointer + 5120;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;  

    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;

    /* Print out some test information banners.  */
    printf("NetX Test:   IP Auxiliary Packet Pool Set Test.........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                 
    /* Set the auxiliary packet pool 0 for IP instance 0.  */
    status = nx_ip_auxiliary_packet_pool_set(&ip_0, &auxiliary_pool_0);

    /* Check the status.  */
    if(status != NX_SUCCESS)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the default packet pool and auxiliary packet pool.  */
    if ((ip_0.nx_ip_default_packet_pool != &pool_0) ||
        (ip_0.nx_ip_auxiliary_packet_pool != &auxiliary_pool_0))  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                             
    /* Set the auxiliary packet pool 1 for IP instance 1.  */
    status = nx_ip_auxiliary_packet_pool_set(&ip_0, &auxiliary_pool_1);
           
    /* Check the status.  */
    if(status != NX_SUCCESS)  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the default packet pool and auxiliary packet pool.  */
    if ((ip_0.nx_ip_default_packet_pool != &auxiliary_pool_1) ||
        (ip_0.nx_ip_auxiliary_packet_pool != &auxiliary_pool_0))  
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
                              
#else

extern void    test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_auxiliary_packet_pool_set_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Auxiliary Packet Pool Set Test.........................N/A\n");
    test_control_return(3);
}
#endif
