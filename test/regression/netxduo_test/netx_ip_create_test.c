/* This NetX test concentrates on the IP Delete operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h" 
#include   "nx_system.h"
#include   "nx_packet.h"
                     

#define     DEMO_STACK_SIZE         2048     

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;  
static CHAR                    *pointer;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);  
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_create_test_application_define(void *first_unused_memory)
#endif
{
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;        
}           


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
CHAR        id;
    

    /* Print out test information banner.  */
    printf("NetX Test:   IP Create Operation Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Store the ID.  */
    id = _nx_version_id[0];

    /* Clear the ID.  */
    _nx_version_id[0] = 0;
       
    /* Clear the system value.  */
    _nx_system_build_options_1 = 0;
    _nx_system_build_options_2 = 0;  
    _nx_system_build_options_3 = 0;
    _nx_system_build_options_4 = 0;   
    _nx_system_build_options_5 = 0;

    /* Set the pool ID.  */
    pool_0.nx_packet_pool_id = NX_PACKET_POOL_ID;

    /* Create IP instances with NX_NULL ID before NetX initialize.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          pointer, 2048, 1);
             
    /* Check the status.  */
    if (status != NX_NOT_IMPLEMENTED)
        error_counter++;
                             
    /* Reset the ID.  */
    _nx_version_id[0] = id;
                               
    /* Initialize the NetX system.  */
    nx_system_initialize();
                                 
    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;   

    /* Create IP instances.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 9), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
                         
    /* Check status.  */
    if (status)              
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                

    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}      