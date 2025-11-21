/* This NetX test concentrates on the basic UDP operation.  */

#include   "nx_rarp.h"
#include   "tx_api.h"
#include   "nx_api.h"      
#include   "nx_ip.h"
                                       
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

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rarp_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
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
}                     

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       rarp_requests_sent;  
ULONG       rarp_responses_received;
ULONG       rarp_invalid_messages;


    /* Print out some test information banners.  */
    printf("NetX Test:   RARP NXE API Test.........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                   
    /************************************************/   
    /* Tested the nxe_rarp_disable api              */
    /************************************************/                 
                   
    /* Enable the RARP feature for NULL IP instance.  */
    status = nx_rarp_disable(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;     

    /* Disable the RARP feature for invalid IP instance.  */
    status = nx_rarp_disable(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                          

    /************************************************/   
    /* Tested the nxe_rarp_enable api               */
    /************************************************/                 
                   
    /* Enable the RARP feature for NULL IP instance.  */
    status = nx_rarp_enable(NX_NULL); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                           
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;  

    /* Enable the RARP feature for invalid IP instance.  */
    status = nx_rarp_enable(&invalid_ip); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                
                            
    /***********************************************/   
    /* Tested the nxe_rarp_info_get api              */
    /************************************************/                 
                   
    /* Get the RARP information for NULL IP instance.  */
    status = nx_rarp_info_get(NX_NULL, &rarp_requests_sent, &rarp_responses_received, &rarp_invalid_messages); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                            
    /* Clear the ID for invalid IP instance.  */
    invalid_ip.nx_ip_id = NX_NULL;    

    /* Get the RARP information for invalid IP instance.  */
    status = nx_rarp_info_get(&invalid_ip,  &rarp_requests_sent, &rarp_responses_received, &rarp_invalid_messages); 
                
    /* Check for error.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                     
    /* Disable the RARP feature.  */
    ip_0.nx_ip_rarp_queue_process = NX_NULL; 
    ip_0.nx_ip_rarp_responses_received  = NX_NULL;    
                  
    /* Get the RARP information for invalid IP instance.  */
    status = nx_rarp_info_get(&ip_0,  &rarp_requests_sent, &rarp_responses_received, &rarp_invalid_messages); 
                
    /* Check for error.  */
    if (status != NX_NOT_ENABLED)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                  

    /* Output success.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}       
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_rarp_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RARP NXE API Test.........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
