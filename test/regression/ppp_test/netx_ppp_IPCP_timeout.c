/* This demo tests the nx_ppp_restart() function.  To simulate a link down in the middle of the IPCP
   negotiation, the thread_0/PPP_0 promotes the PPP 1 instance to LCP complete, and its IPCP state to STARTED.
   Then the PPP0 instance is suspended as part of simulating link down.  

   PPP_1 should go into a FAILED state after the max number of retries, and call the link down callback.
   NetX PPP has a restart function which reinitializes the PPP instance so it can restart the PPP
   protocol using nx_ppp_restart().

   The process is started again, PPP 0 is resumed, and thread 0 promotes the PPP 1 instance ahead
   to the LCP complete state, and ICP start state.  After the second link down event, the test is complete.    

   This test verifies that the NetX PPP properly clears and restarts a PPP instance, including resetting 
   the PPP state to restart the  IPCP negotiation.
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
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;

static NX_IP                   ip_0;
static NX_IP                   ip_1;

static NX_PPP                  ppp_0;
static NX_PPP                  ppp_1;


/* Define the counters used in the demo application...  */

static ULONG                   ppp_0_link_up_counter;
static ULONG                   ppp_0_link_down_counter;
static ULONG                   ppp_1_link_up_counter;
static ULONG                   ppp_1_link_down_counter;
static ULONG                   error_counter = 0;       
static UINT                    suspend_thread = NX_TRUE;

/* Define thread prototypes.  */                                  
static void         thread_0_entry(ULONG thread_input);
static void         thread_1_entry(ULONG thread_input); 
static void         link_up_callback(NX_PPP *ppp_ptr); 
static void         link_down_callback(NX_PPP *ppp_ptr);    
static void         ppp_0_serial_byte_output(UCHAR byte);   
static void         ppp_1_serial_byte_output(UCHAR byte);
static void         invalid_packet_handler(NX_PACKET *packet_ptr); 



/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_IPCP_timeout_test_application_define(void *first_unused_memory)
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
                                          
    /* Create the thread 1.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1024, pointer, 8192);
    pointer = pointer + 8192;
    status +=  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool",  NX_PPP_MIN_PACKET_PAYLOAD, pointer, 4096);
    pointer = pointer + 4096;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;


    /* Create the first PPP instance.  */
    status =  nx_ppp_create(&ppp_0, "PPP0", &ip_0, pointer, 2048, 1, &pool_0, invalid_packet_handler, ppp_0_serial_byte_output);
    pointer =  pointer + 2048;

    /* Check for PPP create error.   */
    if (status)
        error_counter++;

    /* Define the IP addresses. This PPP instance is effectively the server since it has both IP addresses. */
    status =  nx_ppp_ip_address_assign(&ppp_0, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(1, 2, 3, 5));
    
    /* Check for PPP IP address assign error.   */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFF000UL, &pool_0, nx_ppp_driver,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;
                                
    /* Check for IP create error.   */
    if (status)
        error_counter++;

    /* Register the link up/down callbacks.  */
    status =  nx_ppp_link_up_notify(&ppp_0, link_up_callback);
    status += nx_ppp_link_down_notify(&ppp_0, link_down_callback);

    /* Check for PPP link up/down callback registration error(s).   */
    if (status)
        error_counter++;

    /* Create the next PPP instance.  */
    status =  nx_ppp_create(&ppp_1, "PPP1", &ip_1, pointer, 2048, 1, &pool_1, invalid_packet_handler, ppp_1_serial_byte_output);
    pointer =  pointer + 2048;

    /* Check for PPP create error.   */
    if (status)
        error_counter++;

    /* Define IP address. This PPP instance is effectively the client since it doesn't have any IP addresses. */
    status =  nx_ppp_ip_address_assign(&ppp_1, IP_ADDRESS(0, 0, 0, 0), IP_ADDRESS(0, 0, 0, 0));

    /* Check for PPP IP address assign error.   */
    if (status)
        error_counter++;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(0, 0, 0, 0), 0xFFFFF000UL, &pool_1, nx_ppp_driver,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;
                    
    /* Check for IP create error.   */
    if (status)
        error_counter++;

    /* Register the link up/down callbacks.  */
    status =  nx_ppp_link_up_notify(&ppp_1, link_up_callback);
    status += nx_ppp_link_down_notify(&ppp_1, link_down_callback);

    /* Check for PPP link up/down callback registration error(s).   */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    nx_udp_enable(&ip_0);
    nx_udp_enable(&ip_1);

    /* Enable ICMP traffic.  */
    nx_icmp_enable(&ip_0);
    nx_icmp_enable(&ip_1);

}         


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_status;

    /* Print out test information banner.  */
    printf("NetX Test:   PPP IPCP Timeout/Restart Test.............................");

    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    do
    {

        if (suspend_thread)
        {

            if (ppp_1.nx_ppp_lcp_state >= 2)
            {

                suspend_thread = NX_FALSE;

                /* PPP_1 is in the LCP completed state. Suspend PPP_0 thread so PPP_1 will not be able
                   to complete the IPCP protocol. */
                tx_thread_suspend(&(ppp_0.nx_ppp_thread));
    
                ppp_1.nx_ppp_timeout =  NX_PPP_PROTOCOL_TIMEOUT;
                ppp_1.nx_ppp_lcp_state =  NX_PPP_LCP_COMPLETED_STATE;
                ppp_1.nx_ppp_ipcp_state =  NX_PPP_IPCP_START_STATE;

            }

        }

        /* Determine if the two or more restarts have occurred */
        if (ppp_1_link_down_counter >= 2)
        {
            break;
        }

        /* Wait for the link to come up (this should not happen if we are
           testing the link down callback.  */
        status =  nx_ip_status_check(&ip_0, NX_IP_LINK_ENABLED, &ip_status, NX_IP_PERIODIC_RATE/2);

    } while (status != NX_SUCCESS) ;

    /* Determine if the test completed successfully. */
    if ((error_counter == 0)  && (ppp_0_link_down_counter == 0) && (ppp_1_link_down_counter >= 2))
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
    else
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

}
    

static void    thread_1_entry(ULONG thread_input)
{


UINT        status;
ULONG       ip_status;

    tx_thread_sleep(20);
    do
    {

        /* If this is the second restart, the test is complete. */
        if (ppp_1_link_down_counter > 1)
        {

            return;
        }
    
        /* Wait for the link to come up.  */
        status =  nx_ip_status_check(&ip_1, NX_IP_LINK_ENABLED, &ip_status, NX_IP_PERIODIC_RATE/2);

    } while (status != NX_SUCCESS);

}
          
/* Define serial output routines.  Normally these routines would
   map to physical UART routines and the nx_ppp_byte_receive call
   would be made from a UART receive interrupt.  */

static void    ppp_0_serial_byte_output(UCHAR byte)
{

    /* Just feed the PPP 1 input routine.  */
    nx_ppp_byte_receive(&ppp_1, byte);
}

static void    ppp_1_serial_byte_output(UCHAR byte)
{

    /* Just feed the PPP 0 input routine.  */
    nx_ppp_byte_receive(&ppp_0, byte);
}


static void invalid_packet_handler(NX_PACKET *packet_ptr)
{

    error_counter++;
    nx_packet_release(packet_ptr);
}


static void link_up_callback(NX_PPP *ppp_ptr)
{

    /* Just increment the link up counter.  */
    if (ppp_ptr == &ppp_0)
        ppp_0_link_up_counter++;
    else
        ppp_1_link_up_counter++;
}


static void link_down_callback(NX_PPP *ppp_ptr)
{

    /* Just increment the link down counter.  */
    if (ppp_ptr == &ppp_0)
        ppp_0_link_down_counter++;
    else
        ppp_1_link_down_counter++;

    if (ppp_ptr -> nx_ppp_ipcp_state != NX_PPP_IPCP_FAILED_STATE)
    {
        /* Error test should only restart from the IPCP FAILED state */
        error_counter++;
        return;
    }

    /* If this is the second restart, the test is complete. */
    if (ppp_1_link_down_counter > 1)
    {
        /* Success. Restart test is complete */
        return;
    }

    /* Restart PPP 1.  */    
    nx_ppp_restart(ppp_ptr);

    if (ppp_1_link_down_counter == 1)
    {
        /* First restart. Wait for second restart to verify first restart succeeds */
        suspend_thread = NX_TRUE;
    }

    return;

}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_IPCP_timeout_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   PPP IPCP Timeout/Restart Test.............................N/A\n"); 

    test_control_return(3);  
}      
#endif


