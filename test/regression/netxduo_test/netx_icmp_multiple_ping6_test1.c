/* This NetX test concentrates on the ICMPv6 ping operation.  */
/*
  thread 0 send ICMPv6 Echo Request to the existent IP address IP_ADDRESS(1, 2, 3, 5),
  thread 1 send ICMPv6 Echo Request to the nonexistent IP address IP_ADDRESS(1, 2, 3, 7),
  Delay the ICMPv6 Echo Reply in driver, let thread 0 receive the ICMPv6 Echo Reply after thread 1 send ICMPv6 Echo Request.
*/

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);
#ifdef FEATURE_NX_IPV6

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;  
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static NXD_ADDRESS             global_address_0; 
static NXD_ADDRESS             global_address_1;  
static NXD_ADDRESS             destination_address;
static UINT                    icmpv6_request_counter;
static UINT                    icmpv6_reply_counter;


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
void    netx_icmp_multiple_ping6_test1_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;  

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    error_counter = 0;
    icmpv6_request_counter = 0;
    icmpv6_reply_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;
                                 
    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
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
    
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 
    status += nxd_ipv6_enable(&ip_1);

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMPv6 processing for IP instances0 .  */
    status = nxd_icmp_enable(&ip_0);      
    status += nxd_icmp_enable(&ip_1);   

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;
    
    /* Set ipv6 global address for IP instance 0.  */
    global_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_0.nxd_ip_address.v6[0] = 0x20010000;
    global_address_0.nxd_ip_address.v6[1] = 0x00000000;
    global_address_0.nxd_ip_address.v6[2] = 0x00000000;
    global_address_0.nxd_ip_address.v6[3] = 0x10000001;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &global_address_0, 64, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;       

    /* Set ipv6 global address for IP instance 1.  */
    global_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_1.nxd_ip_address.v6[0] = 0x20010000;
    global_address_1.nxd_ip_address.v6[1] = 0x00000000;
    global_address_1.nxd_ip_address.v6[2] = 0x00000000;
    global_address_1.nxd_ip_address.v6[3] = 0x10000002;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_1, 0, &global_address_1, 64, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;   

    /* Resume test thread.  */
    tx_thread_resume(&ntest_0);    
}                 


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;  


    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Multiple Ping6 Test1.................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                          
    
    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);            
    tx_thread_resume(&ntest_1);

    /* Let driver delay the echo reply for 1 second. */
    advanced_packet_process_callback = packet_process;

    /* Set ipv6 destination address.  */
    destination_address.nxd_ip_version = NX_IP_VERSION_V6;
    destination_address.nxd_ip_address.v6[0] = 0x20010000;
    destination_address.nxd_ip_address.v6[1] = 0x00000000;
    destination_address.nxd_ip_address.v6[2] = 0x00000000;
    destination_address.nxd_ip_address.v6[3] = 0x10000002;  

    /* Now ping an IP address that does exist.  */
    /* The reply packet contains checksum 0. */
    status =  nxd_icmp_ping(&ip_0, &destination_address, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 3 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status) || (my_packet -> nx_packet_length != 28) ||
        (memcmp(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let thread 1 run.  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    /* Check the error counter.  */
    if ((error_counter) || (icmpv6_request_counter != 1) || (icmpv6_reply_counter != 1))
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


    /* Set ipv6 destination address.  */
    destination_address.nxd_ip_version = NX_IP_VERSION_V6;
    destination_address.nxd_ip_address.v6[0] = 0x20010000;
    destination_address.nxd_ip_address.v6[1] = 0x00000000;
    destination_address.nxd_ip_address.v6[2] = 0x00000000;
    destination_address.nxd_ip_address.v6[3] = 0x10000003; 

    /* Ping an unknown IP address. This will timeout after 100 ticks.  */
    status =  nxd_icmp_ping(&ip_0, &destination_address, "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, 2 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if (status == NX_SUCCESS)
    {
        error_counter++;
    }
}

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    /* Packet length: 40(IPv6) + 8(ICMPv6) + 28(data). */
    if ((ip_ptr == &ip_0) &&
        (packet_ptr -> nx_packet_length == 76) && 
        (*(packet_ptr -> nx_packet_prepend_ptr + 40) == NX_ICMPV6_ECHO_REQUEST_TYPE))
    {

        /* Updated the icmpv6_request_counter.  */
        icmpv6_request_counter ++;
    }

    /* Packet length: 40(IPv6) + 8(ICMPv6) + 28(data). */
    if ((ip_ptr == &ip_1) &&
        (packet_ptr -> nx_packet_length == 76) && 
        (*(packet_ptr -> nx_packet_prepend_ptr + 40) == NX_ICMPV6_ECHO_REPLY_TYPE))
    {

        /* Updated the icmpv6_request_counter.  */
        icmpv6_reply_counter ++;

        /* Delay the first ICMPv6 Echo Reply.  */
        if (icmpv6_reply_counter == 1)
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
void    netx_icmp_multiple_ping6_test1_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Multiple Ping6 Test1.................................N/A\n");
    
    test_control_return(3);
}
#endif
