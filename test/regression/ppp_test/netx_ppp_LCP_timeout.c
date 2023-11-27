/* This demo tests the nx_ppp_restart() function.  The PPP_1 instance is never started.  
   So PPP_0 fails to complete the LCP protocol. After so many attempts at the LCP 
   protocol, the PPP_0 should go into a FAILED state and call the link down callback.
   NetX PPP has a restart function which reinitializes the PPP instance so it can 
   restart the PPP protocol again.

   This test runs until the second link down event occurs. This is considered a successful 
   outcome because it verifies the NetX PPP properly resets the LCP state, removes packets on 
   the receive queue, resets the buffer markers, and clears authentication status. 

*/

#include "tx_api.h"
#include "nx_api.h"
#include "nx_ppp.h"

extern void         test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

/* Define demo stack size.   */

#define DEMO_STACK_SIZE     2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_PPP                  ppp_0;
static NX_PPP                  ppp_1;


/* Define the counters used in the demo application...  */

static ULONG                   ppp_0_link_up_counter;
static ULONG                   ppp_0_link_down_counter;
static ULONG                   error_counter = 0;       

/* Define thread prototypes.  */                                  
static void         thread_0_entry(ULONG thread_input);
static void         link_up_callback(NX_PPP *ppp_ptr); 
static void         link_down_callback(NX_PPP *ppp_ptr);    
static void         ppp_0_serial_byte_output(UCHAR byte);   
static void         invalid_packet_handler(NX_PACKET *packet_ptr);


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_LCP_timeout_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the thread 0.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NX_PPP_MIN_PACKET_PAYLOAD, pointer, 2048);
    pointer = pointer + 2048;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, 
                          &pool_0, nx_ppp_driver, pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create the PPP instance.  */
    status =  nx_ppp_create(&ppp_0, "PPP0", &ip_0, pointer, 2048, 1, &pool_0, invalid_packet_handler, ppp_0_serial_byte_output);
    pointer =  pointer + 2048;

    /* Check for PPP create error.   */
    if (status)
        error_counter++;

    /* Define IP address. This PPP instance is effectively the server since it has both IP addresses. */
    status =  nx_ppp_ip_address_assign(&ppp_0, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(1, 2, 3, 5));
    
    /* Check for PPP IP address assign error.   */
    if (status)
        error_counter++;

    /* Register the link up/down callbacks.  */
    status =  nx_ppp_link_up_notify(&ppp_0, link_up_callback);
    status += nx_ppp_link_down_notify(&ppp_0, link_down_callback);

    /* Check for PPP link up/down callback registration error(s).   */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    nx_udp_enable(&ip_0);
}         


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_status;


    /* Print out test information banner.  */
    printf("NetX Test:   PPP LCP Timeout/Restart Test..............................");

    if (error_counter)
    {
        printf("ERROR\n");
        test_control_return(1);
    }

    do
    {
    
        /* Wait for the link to come up.  */
        status =  nx_ip_status_check(&ip_0, NX_IP_LINK_ENABLED, &ip_status, NX_IP_PERIODIC_RATE);

        if (ppp_0_link_down_counter > 1)
        {
            /* Deleting the PPP_0 instance. Test is complete.  */
            status = NX_SUCCESS;
            break;
        }
    } while (status != NX_SUCCESS);


    /* Check status.  */
    if ((status) || (error_counter) || (ppp_0_link_down_counter != 2))
    {       
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    nx_ppp_delete(&ppp_0);
    test_control_return(0);

}
    

/* Define serial output routines.  Normally these routines would
   map to physical UART routines and the nx_ppp_byte_receive call
   would be made from a UART receive interrupt.  */

static void    ppp_0_serial_byte_output(UCHAR byte)
{

    /* Just feed the PPP 1 input routine.  */
    nx_ppp_byte_receive(&ppp_1, byte);
}


static void invalid_packet_handler(NX_PACKET *packet_ptr)
{

    error_counter++;
    nx_packet_release(packet_ptr);
}


static void link_up_callback(NX_PPP *ppp_ptr)
{

    /* Just increment the link up counter.  */
    ppp_0_link_up_counter++;
}


static void link_down_callback(NX_PPP *ppp_ptr)
{

    /* Just increment the link down counter.  */
    ppp_0_link_down_counter++;

    if (ppp_ptr -> nx_ppp_protocol_retry_counter != NX_PPP_MAX_LCP_PROTOCOL_RETRIES)
    {
        /* Error with retry counter */
        error_counter++;
    }
    else if (ppp_ptr -> nx_ppp_lcp_state != NX_PPP_LCP_FAILED_STATE)
    {

        /* Error: the PPP is not in the LCP failed state */
        error_counter++;
    }
          
    /* Restart the PPP instance.  */    
    nx_ppp_restart(ppp_ptr);

    return;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_LCP_timeout_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   PPP LCP Timeout/Restart Test..............................N/A\n"); 

    test_control_return(3);  
}      
#endif



