/* This test should be done with the PACKET CHAIN option enabled.  It tests that the PPP instance can 
   handle receiving chained packets, including when the data, CRC checksum and PPP frame closing sequence
   occur on or around the packet buffer boundary.  It should run to completion.
 */
#include "tx_api.h"
#include "nx_api.h"
#include "nx_ppp.h"
                  
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_PACKET_CHAIN) && !defined(NX_DISABLE_IPV4)

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

static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;


/* Define the counters used in the demo application...  */

static ULONG                   thread_0_counter = 0;
static ULONG                   thread_1_counter = 0;
static ULONG                   ppp_0_link_up_counter;
static ULONG                   ppp_0_link_down_counter;
static ULONG                   ppp_1_link_up_counter;
static ULONG                   ppp_1_link_down_counter;
static UINT                    error_counter = 0;
static UINT                    ppp_boundary_test_complete = NX_FALSE;

/* Define thread prototypes.  */
static void         thread_0_entry(ULONG thread_input);
static void         thread_1_entry(ULONG thread_input);      
static void         ppp_0_serial_byte_output(UCHAR byte);
static void         ppp_1_serial_byte_output(UCHAR byte);
static void         invalid_packet_handler(NX_PACKET *packet_ptr);
static void         link_up_callback(NX_PPP *ppp_ptr);
static void         link_down_callback(NX_PPP *ppp_ptr);



/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_check_boundary_test_application_define(void *first_unused_memory)
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
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1024, pointer, 8192);
    pointer = pointer + 8192;
    status +=  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool",  500, pointer, 8192);
    pointer = pointer + 8192;

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


UCHAR message[] = 
"12345678901234567890123456789012345678901234567890"
"12345678901234567890123456789012345678901234567890"

"12345678901234567890123456789012345678901234567890"
"12345678901234567890123456789012345678901234567890"

"12345678901234567890123456789012345678901234567890"
"12345678901234567890123456789012345678901234567890"

"12345678901234567890123456789012345678901234567890"
"12345678901234567890123456789012345678901234567890"

"12345678901234567890123456789012345678901234567890"
"12345678901234567890123456789012345678901234567890"

"12345678901234567890123456789012345678901234567890"
"12345678901234567890123456789012345678901234567890"
;

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_status;
NX_PACKET   *my_packet;
UINT        length;
UINT        total;
UINT        counter;

      
    /* Print out test information banner.  */
    printf("NetX Test:   PPP Check Packet Boundary Test............................");
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for address resolved.  */
    nx_ip_status_check(&ip_0, NX_IP_ADDRESS_RESOLVED, &ip_status, NX_WAIT_FOREVER);

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Disable checksum logic for this socket.  */
    nx_udp_socket_checksum_disable(&socket_0);

    /* Set the value.  */
    length = 10;
    total = strlen((const char *)message);
    counter = total - length;

    /* Increase the size of message till we hit a boundary error (e.g. packet payload area exceeded). */
    while(length <= total)
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_1, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            break;
        }

        /* Write ABCs into the packet payload!  */
        status = nx_packet_data_append(my_packet, &message[0], length, &pool_1, NX_WAIT_FOREVER);
                              
        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            break;
        }

        /* Send the UDP packet.  */
        status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            break;
        }

        /* Increment thread 0's counter.  */
        thread_0_counter++;
        tx_thread_sleep(NX_IP_PERIODIC_RATE/10);

        length++;
    }

    /* Let ppp_1 receive packets.  */
    while (ppp_boundary_test_complete == NX_FALSE)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    /* Delete ppp_0.  */
    nx_ppp_delete(&ppp_0);

    /* Check status.  */
    if (error_counter || (thread_0_counter != counter + 1) || (thread_0_counter != thread_1_counter) || (length != total + 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {

        /* Output successful.  */
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}
    

static void    thread_1_entry(ULONG thread_input)
{

UINT        status;  
ULONG       ip_status;
NX_PACKET   *my_packet;


    /* Wait for address resolved.  */
    nx_ip_status_check(&ip_1, NX_IP_ADDRESS_RESOLVED, &ip_status, NX_WAIT_FOREVER);

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, 0x89, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
        error_counter++;

    while(1)
    {

        /* Receive a UDP packet.  */
        status =  nx_udp_socket_receive(&socket_1, &my_packet, NX_IP_PERIODIC_RATE);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            break;
        }

        thread_1_counter++;

        if (thread_1_counter == 590)
            thread_1_counter = 590;

        /* Release the packet.  */
        nx_packet_release(my_packet);
    }

    nx_ppp_delete(&ppp_1);
    ppp_boundary_test_complete = NX_TRUE;

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
    /* Print out the non-PPP byte. In Windows, the string "CLIENT" will
       be sent before Windows PPP starts. Once CLIENT is received, we need
       to send "CLIENTSERVER" to establish communication. It's also possible
       to receive modem commands here that might need some response to 
       continue.  */
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
        
    /* Restart the PPP instance.  */    
    nx_ppp_restart(ppp_ptr);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ppp_check_boundary_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   PPP Check Packet Boundary Test............................N/A\n");

    test_control_return(3);         
}
#endif
