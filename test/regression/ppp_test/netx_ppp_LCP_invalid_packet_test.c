/* This demo tests the invalid LCP packet.

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
void    netx_ppp_LCP_invalid_packet_test_application_define(void *first_unused_memory)
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

static char invalid_lcp_data_0[] = {0xc0, 0x21, 0x01, 0x1e, 0x00, 0x00};
static char invalid_lcp_data_1[] = {0xc0, 0x21, 0x00, 0x00, 0x00, 0x00, 0x02, 0x16};
extern void  _nx_ppp_receive_packet_process(NX_PPP *ppp_ptr, NX_PACKET *packet_ptr);

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *invalid_packet;
UINT        i = 0;
UCHAR       *data_ptr;
UINT        data_size;


    /* Print out test information banner.  */
    printf("NetX Test:   PPP LCP Invalid Packet Test...............................");

    if (error_counter)
    {
        printf("ERROR\n");
        test_control_return(1);
    }

    for (i = 0; i < 2; i++)
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &invalid_packet, NX_IP_PACKET, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
            error_counter++;

        if (i == 0)
        {

            /* Invalid NX_PPP_LCP_CONFIGURE_REQUEST.  */
            data_ptr = invalid_lcp_data_0;
            data_size = sizeof(invalid_lcp_data_0);
        }
        else
        {

            /* Invalid unsupported code ID.  */
            data_ptr = invalid_lcp_data_1;
            data_size = sizeof(invalid_lcp_data_1);
        }

        /* Write invalid data into the packet payload.  */
        nx_packet_data_append(invalid_packet, data_ptr, data_size, &pool_0, TX_WAIT_FOREVER);

        /* Call PPP packet process function.  */
        _nx_ppp_receive_packet_process(&ppp_0, invalid_packet);
    }

    if (ppp_0.nx_ppp_lcp_frames_received != 0)
    {
        error_counter++;
    }

    /* Check status.  */
    if (error_counter)
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

    return;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_LCP_invalid_packet_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   PPP LCP Invalid Packet Test...............................N/A\n"); 

    test_control_return(3);  
}      
#endif



