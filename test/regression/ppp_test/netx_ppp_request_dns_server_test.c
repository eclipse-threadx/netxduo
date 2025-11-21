/* This tests the use of requesting and processing primary and secondary DNS servers 
   as part of the IPCP handshake.  */

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
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_PPP                  ppp_0;
static NX_PPP                  ppp_1;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter = 0; 
static UINT                    thread_1_alive = NX_TRUE;
static ULONG                   dns_address = 0 ;
static ULONG                   secondary_dns_address = 0;

/* Define thread prototypes.  */                        
static void         thread_0_entry(ULONG thread_input);
static void         thread_1_entry(ULONG thread_input); 
static void         ppp_0_serial_byte_output(UCHAR byte);   
static void         ppp_1_serial_byte_output(UCHAR byte);
static void         invalid_packet_handler(NX_PACKET *packet_ptr); 


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_request_dns_server_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NX_PPP_MIN_PACKET_PAYLOAD, pointer, 2048);
    pointer = pointer + 2048;

    /* Check for pool creation error.  */
    if (status)
    {
        error_counter++;
    }        

    /* Create the first PPP instance.  */
    status =  nx_ppp_create(&ppp_0, "PPP 0", &ip_0, pointer, 2048, 1, &pool_0, invalid_packet_handler, ppp_0_serial_byte_output);
    pointer =  pointer + 2048;

    /* Check for PPP create error.   */
    if (status)
    {
        error_counter++;
    }        

    /* Define IP address. This PPP instance is effectively the server since it has both IP addresses. */
    status =  nx_ppp_ip_address_assign(&ppp_0, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(1, 2, 3, 5));
    
    /* Check for PPP IP address assign error.   */
    if (status)
    {
        error_counter++;
    }        

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFF000UL, &pool_0, nx_ppp_driver,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create error.   */
    if (status)
    {
        error_counter++;
    }        
  
    /* Create the next PPP instance.  */
    status =  nx_ppp_create(&ppp_1, "PPP 1", &ip_1, pointer, 2048, 1, &pool_0, invalid_packet_handler, ppp_1_serial_byte_output);
    pointer =  pointer + 2048;

    /* Check for PPP create error.   */
    if (status)
    {
        error_counter++;
    }        

    /* Define IP address. This PPP instance is effectively the client since it doesn't have any IP addresses. */
    status =  nx_ppp_ip_address_assign(&ppp_1, IP_ADDRESS(0, 0, 0, 0), IP_ADDRESS(0, 0, 0, 0));

    /* Check for PPP IP address assign error.   */
    if (status)
    {
        error_counter++;
    }        

    /* Create another IP instance.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(0, 0, 0, 0), 0xFFFFF000UL, &pool_0, nx_ppp_driver,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create error.   */
    if (status)
    {
        error_counter++;
    }        

    /* Enable UDP traffic.  */
    nx_udp_enable(&ip_0);
    nx_udp_enable(&ip_1);

    /* Set up the PPP0 primary address. */
    status = nx_ppp_dns_address_set(&ppp_0, IP_ADDRESS(1,2,3,89));

    /* Set the PPP0 secondary DNS server */
    status += nx_ppp_secondary_dns_address_set(&ppp_0, IP_ADDRESS(1,2,3,88));

    /* Set PP1 primary DNS. Note that PPP_0 will overwrite this with its own primary DNS. */
    status += nx_ppp_dns_address_set(&ppp_1, IP_ADDRESS(1,2,3,79));

    if (status)
    {
        error_counter++;
    }        
}         


/* Define the test threads.  */

void    thread_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_status;

      
             
    printf("NetX Test:   PPP Request DNS Server Test...............................");

    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for the link to come up.  */
    do
    {
    
        status =  nx_ip_status_check(&ip_0, NX_IP_LINK_ENABLED, &ip_status, 20 * NX_IP_PERIODIC_RATE);
    }while(status != NX_SUCCESS);

    /* Wait for the other thread to finish. */
    while(thread_1_alive)
    {
    
        tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);
    }     

    if (!secondary_dns_address || !dns_address || error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);

    }

    printf("SUCCESS!\n");
    test_control_return(0);
 
    return;
}
    

void    thread_1_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_status;


    /* Wait for the link to come up.  */
    do
    {
    
        status =  nx_ip_status_check(&ip_1, NX_IP_LINK_ENABLED, &ip_status, 20 * NX_IP_PERIODIC_RATE);
    }while(status != NX_SUCCESS);
          

    status = nx_ppp_dns_address_get(&ppp_1, &dns_address);
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }
    
    status = nx_ppp_secondary_dns_address_get(&ppp_1, &secondary_dns_address);
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    thread_1_alive = NX_FALSE;

    return;

}
          
/* Define serial output routines.  Normally these routines would
   map to physical UART routines and the nx_ppp_byte_receive call
   would be made from a UART receive interrupt.  */

void    ppp_0_serial_byte_output(UCHAR byte)
{

    /* Just feed the PPP 1 input routine.  */
    nx_ppp_byte_receive(&ppp_1, byte);
}

void    ppp_1_serial_byte_output(UCHAR byte)
{

    /* Just feed the PPP 0 input routine.  */
    nx_ppp_byte_receive(&ppp_0, byte);
}


void invalid_packet_handler(NX_PACKET *packet_ptr)
{
    /* Print out the non-PPP byte. In Windows, the string "CLIENT" will
       be sent before Windows PPP starts. Once CLIENT is received, we need
       to send "CLIENTSERVER" to establish communication. It's also possible
       to receive modem commands here that might need some response to 
       continue.  */
    nx_packet_release(packet_ptr);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_request_dns_server_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   PPP Request DNS Server Test...............................N/A\n"); 

    test_control_return(3);  
}      
#endif

