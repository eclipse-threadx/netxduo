/* This NetX test concentrates on the basic IP static operation: static route add/delete/find  */

#include   "tx_api.h"
#include   "nx_api.h"
                      
extern void    test_control_return(UINT status);  

#if defined(NX_ENABLE_INTERFACE_CAPABILITY) && !defined(NX_DISABLE_IPV4) 
#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;


static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;         


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
void           _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_capability_test_application_define(void *first_unused_memory)
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

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check the status.  */
    if (status)
        error_counter++;
}
                   

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{
UINT    status;
ULONG   interface_capability_flag;

    printf("NetX Test:   IP Interface Capability test..............................");

    /* Check for earlier error.  */
    if (error_counter)
    {            
        printf("ERROR!\n");
        test_control_return(1);
    }    

    /* Set the interface capability.  */
    status = nx_ip_interface_capability_set(&ip_0, 0, NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM);
    
    /* Check the status.  */
    if (status)
        error_counter++;
    
    /* Get the interface capability.  */
    status = nx_ip_interface_capability_get(&ip_0, 0, &interface_capability_flag);
    
    /* Check the status.  */
    if ((status) || (interface_capability_flag != NX_INTERFACE_CAPABILITY_IPV4_TX_CHECKSUM))
        error_counter++;
    
    /* Check status.  */
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

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ip_interface_capability_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Interface Capability test..............................N/A\n");   
    test_control_return(3); 
}
#endif /* NX_ENABLE_INTERFACE_CAPABILITY  */
    
