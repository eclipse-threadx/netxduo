/* This NetX test concentrates on ICMP Time Exceeded Message for IP fragmentation.  */
/* Requirement: __PRODUCT_NETXDUO__ is defined, NX_DISABLE_ICMPV4_ERROR_MESSAGE is not defined. NX_DISABLE_FRAGMENTATION is not defined. */
/* Test sequence:
 * 1. ip_0 send ICMP Ping with 600 bytes to ip_2. It is fragmented into three packets.  
 * 2. Delay 5 seconds for second fragmentation packet of ip_0 to update the timeout of fragmentation to let ip_1 fragmentation timeout first. 
 * 3. Delay NX_IP_TIME_TO_LIVE + 4 seconds for third fragmentation  of ip_0, send the third fragmentation before ip_0 fragmentation timeout, after ip_1 fragmentation timeout.
 * 4. ip_1 send ICMP Ping with 600 bytes to ip_2. It is fragmented into three packets. 
 * 5. Discard the third fragmentation packet of ip_1 to let ip_1 fragmentation timeout. 
 * 6. Check if ip_1 instance get the fragmentation time exceeded message from ip_2 instance. 
 * 7. Check if ip_1 instance get the response from ip_2 instance.              
 * 7. Check if ip_0 instance get the response from ip_2 instance.
 */


#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_icmp.h"
#include   "nx_system.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);
#if defined (__PRODUCT_NETXDUO__) && !defined (NX_DISABLE_ICMPV4_ERROR_MESSAGE) && !defined (NX_DISABLE_FRAGMENTATION) && !defined(NX_DISABLE_IPV4)
#define    DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;        
static TX_THREAD               thread_1;       
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;  
static NX_IP                   ip_2;
                                           

/* Define the counters used in the demo application...  */

static ULONG    error_counter;  
static ULONG    ip_0_packet_counter;  
static ULONG    ip_1_packet_counter;
static UCHAR    time_exceeded_message;  
static UCHAR    icmp_ping_timeout;    
static UCHAR    icmp_ping_received;  
static CHAR     msg[600];                        

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);    
static void    thread_1_entry(ULONG thread_input); 
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_time_exceeded_message_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    ip_0_packet_counter = 0;  
    ip_1_packet_counter = 0; 
    time_exceeded_message = NX_FALSE;
    icmp_ping_received = NX_FALSE;    
    icmp_ping_timeout = NX_FALSE;
    memset(msg, '1', sizeof(msg));

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
                                             
    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*20);
    pointer = pointer + 1536*20;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;    

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_2, "NetX IP Instance 2", IP_ADDRESS(1, 2, 3, 6), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;    

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_2, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP traffic.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);  
    status += nx_icmp_enable(&ip_2);

    /* Check for ICMP enable errors.  */
    if (status)
        error_counter++;


    /* Enable IP fragmentation logic on both IP instances.  */
    status =  nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1); 
    status += nx_ip_fragment_enable(&ip_2);

    /* Check for IP fragment enable errors.  */
    if (status)
        error_counter++;
}
               

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;

    /* Print out some test information banners.  */
    printf("NetX Test:   IP Fragmentation Time Exceeded Message Test...............");
                  
    /* Set the callback function.  */
    advanced_packet_process_callback = my_packet_process;

    /* Ping an IP address that does exist. Set the timeout as NX_IP_TIME_TO_LIVE + 1 + 5. delay the second fragmentation.   */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 6), msg, 600, &my_packet, (NX_IP_TIME_TO_LIVE + 1 + 5) * NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status == NX_SUCCESS)
    {             

        /* Update the flag.  */
        icmp_ping_received = NX_TRUE;

        /* Release the packet.  */
        nx_packet_release(my_packet);
    }    

    /* Check status.  */
    if ((error_counter) || (time_exceeded_message != NX_TRUE) || 
        (icmp_ping_timeout != NX_TRUE) || (icmp_ping_received != NX_TRUE))
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

static void    thread_1_entry(ULONG thread_input)
{

UINT        status;  
NX_PACKET   *my_packet;

    /* Ping an IP address that does exist. Set the timeout as NX_IP_TIME_TO_LIVE + 1.   */
    status = nx_icmp_ping(&ip_1, IP_ADDRESS(1, 2, 3, 6), msg, 600, &my_packet, (NX_IP_TIME_TO_LIVE + 1) * NX_IP_PERIODIC_RATE);

    /* Check the status, should not get the response.  */
    if (status == NX_NO_RESPONSE)
    {            
        icmp_ping_timeout = NX_TRUE;
    }    
}

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
NX_ICMPV4_ERROR *icmpv4_error;

    /* Return if it is not an IP packet. */
    if (packet_ptr -> nx_packet_length <= 28)
        return NX_TRUE;

    /* Check the IP instance.  */
    if (ip_ptr == &ip_0)
    {

        /* Update the fragmentation packet counter.  */
        ip_0_packet_counter ++;
 
        /* Delay the second fragmentation packet.  */
        if (ip_0_packet_counter == 2)
        {
                                 
            /* Set the discard operation.  */
            *operation_ptr = NX_RAMDRIVER_OP_DELAY;

            /* Delay the second fragmentation ping, the timeout of ip_0 fragmentation should be updated. .  */
            *delay_ptr = 5 * NX_IP_PERIODIC_RATE;
        } 
        /* Delay the second fragmentation packet.  */
        if (ip_0_packet_counter == 3)
        {
                                 
            /* Set the discard operation.  */
            *operation_ptr = NX_RAMDRIVER_OP_DELAY;
                                                                                     
            /* Delay the third fragmentation ping, send the third fragmentation ping after ip_1 fragmentation timeout, before ip_0 fragmentation timeout.  */
            *delay_ptr = (NX_IP_TIME_TO_LIVE + 4) * NX_IP_PERIODIC_RATE;
        }
    }  
    /* Check the IP instance.  */
    else if (ip_ptr == &ip_1)
    {

        /* Update the fragmentation packet counter.  */
        ip_1_packet_counter ++;
                             
        /* Discard the third fragmentation packet.  */
        if (ip_1_packet_counter == 3)
        {

            /* Set the discard operation.  */
            *operation_ptr = NX_RAMDRIVER_OP_DROP;
        }      
    }
    else
    {

        /* Set the ICMP Error Message header.  */
        icmpv4_error = (NX_ICMPV4_ERROR*)(packet_ptr -> nx_packet_prepend_ptr + 20);
                                         
        /* Check if it is a fragmentation time exceeded message.  */  
        if ((icmpv4_error -> nx_icmpv4_error_header.nx_icmpv4_header_type == NX_ICMP_TIME_EXCEEDED_TYPE) &&
            (icmpv4_error -> nx_icmpv4_error_header.nx_icmpv4_header_code == NX_ICMP_FRT_EXCEEDED_CODE))
            time_exceeded_message = NX_TRUE;
    }


    return NX_TRUE;
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_time_exceeded_message_test_application_define(void *first_unused_memory)
#endif
{
    
    printf("NetX Test:   IP Fragmentation Time Exceeded Message Test...............N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_FRAGMENTATION  */
