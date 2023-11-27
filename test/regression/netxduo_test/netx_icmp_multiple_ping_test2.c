/* This NetX test concentrates on the ICMP ping operation.  */
/*
  thread 0 send ICMP Echo Request to the existent IP address IP_ADDRESS(1, 2, 3, 5),
  thread 1 send ICMP Echo Request to the existent IP address IP_ADDRESS(1, 2, 3, 5),
  Delay the first ICMP Echo Reply in driver, let thread 1 first receive the ICMP Echo Reply before thread 0 receive the ICMP Echo Reply.
*/

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;   
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static UINT                    icmp_request_counter;
static UINT                    icmp_reply_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);   
static void    ntest_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_multiple_ping_test2_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    error_counter = 0;
    icmp_request_counter = 0;
    icmp_reply_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
                                        
    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;


    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Multiple Ping Test2..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                        

    /* Let driver delay the echo reply for 1 second. */
    advanced_packet_process_callback = packet_process;

    /* Ping an IP address.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 3 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status) || (my_packet -> nx_packet_length != 28) ||
        (memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the error counter.  */
    if ((error_counter) || (icmp_request_counter != 2) || (icmp_reply_counter != 2))
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


/* Define the test threads.  */

static void    ntest_1_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;

    /* Now ping an IP address that does exist.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, 2 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status) || (my_packet -> nx_packet_length != 28) ||
        (memcmp(my_packet -> nx_packet_prepend_ptr, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
}


static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    /* Packet length: 20(IP) + 8(ICMP) + 28(data). */
    if ((ip_ptr == &ip_0) &&
        (packet_ptr -> nx_packet_length == 56) && 
        (*(packet_ptr -> nx_packet_prepend_ptr + 20) == NX_ICMP_ECHO_REQUEST_TYPE))
    {

        /* Updated the icmp_request_counter.  */
        icmp_request_counter ++;
    }

    /* Packet length: 20(IP) + 8(ICMP) + 28(data). */
    if ((ip_ptr == &ip_1) &&
        (packet_ptr -> nx_packet_length == 56) && 
        (*(packet_ptr -> nx_packet_prepend_ptr + 20) == NX_ICMP_ECHO_REPLY_TYPE))
    {

        /* Updated the icmp_request_counter.  */
        icmp_reply_counter ++;

        /* Delay the first ICMP Echo Reply.  */
        if (icmp_reply_counter == 1)
        {

            /* Delay 1 second. */
            *operation_ptr = NX_RAMDRIVER_OP_DELAY;
            *delay_ptr = NX_IP_PERIODIC_RATE;
        }
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_multiple_ping_test2_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Multiple Ping Test2..................................N/A\n"); 

    test_control_return(3);  
}      
#endif