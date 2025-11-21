/* This NetX test concentrates on basic IPv6 fragmentation.  */
/* Test sequence:
 * 1. ip_0 allocate one packets.     
 * 1. ip_0 add the Hop-by-Hop Option, 2 bytes(next header, option length) + 128 bytes(option length).
 * 1. ip_0 append the data 1000 bytes.     
 * 2. ip_0 discard the packets excpet the header packet, packet length also is 2 + 128 + 1000.
 * 3. ip_0 call nxd_ip_raw_packet_send to send the packet with Hop-by-Hop Option.  
 * 4. ip_0 call nx_ipv6_fragment_process to fragment packet and send the fragmentation packets. 
 * 5. check if the driver receive fragmentation packet form ip_0.
 Test pointer:
 * 1. in _nx_ipv6_packet_copy failure since the next packet of source packet is NX_NULL, cover the following code.
        if ((source_pkt == NX_NULL) || (dest_pkt == NX_NULL))
            return(NX_NOT_SUCCESSFUL);
 * 2. in nx_ipv6_fragment_process failure since _nx_ipv6_packet_copy failure, cover the following code: 
        // For the first packet, the prepend pointer is already at the begining of the IP header.
        if (_nx_ipv6_packet_copy(source_packet, first_fragment, fragment_size))
            break;
*/


#include   "tx_api.h"
#include   "nx_api.h"
#if !defined(NX_DISABLE_FRAGMENTATION) && defined(FEATURE_NX_IPV6)  
#include   "nx_ipv6.h"
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

static NXD_ADDRESS             ipv6_address_0;
static NXD_ADDRESS             ipv6_address_1;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   fragmentation_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);     
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

static CHAR     msg[1500]={'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void  netx_ipv6_fragmentation_error_test2_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    fragmentation_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 128, pointer, 128*60);
    pointer = pointer + 128*60;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    status = nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    if (status)
        error_counter++;

    /* Enable IP fragmentation logic on both IP instances.  */
    status =  nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);
    if (status)
        error_counter++;
    
    /* Enable IP raw feature on both IP instances.  */
    status =  nx_ip_raw_packet_enable(&ip_0);
    status += nx_ip_raw_packet_enable(&ip_1);
    if (status)
        error_counter++;

    status = nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);
    if (status)
        error_counter++; 

    /* Set ipv6 version and address.  */
    ipv6_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_0.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_0.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_0.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_0.nxd_ip_address.v6[3] = 0x10000001;

    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x10000002;   

    /* Set interfaces' address */
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_1, 64, NX_NULL);

    if(status)
        error_counter++;

}                   


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
UCHAR       data;
NX_PACKET   *my_packet;


    /* Print out some test information banners.  */
    printf("NetX Test:   IPv6 Fragmentation Error Test2............................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* DAD */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Set the callback function.  */
    advanced_packet_process_callback = my_packet_process;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_IPv6_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Added Hop-by-Hop Options header to let the unfragmentable size exceed one packet.  */

    /* Added the Next header.  */
    data = 23;
    status = nx_packet_data_append(my_packet, &data, 1, &pool_0, NX_IP_PERIODIC_RATE);

    /* Added the Hdr Ext Len.  */
    data = 16;
    status += nx_packet_data_append(my_packet, &data, 1, &pool_0, NX_IP_PERIODIC_RATE);

    /* Added the Options.  */
    status += nx_packet_data_append(my_packet, msg, 16 * 8, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    status = nx_packet_data_append(my_packet, msg, 1000, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Discard the packets except the header packet.  */
    my_packet -> nx_packet_next = NX_NULL;
    my_packet -> nx_packet_last = NX_NULL;

    /* Send the raw packet for Hop-by-Hop Option.  */
    status = nxd_ip_raw_packet_send(&ip_0, my_packet, &ipv6_address_1, NX_PROTOCOL_NEXT_HEADER_HOP_BY_HOP, 255, NX_IP_NORMAL);
    
    /* Check for error.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check for error.  */
    if((error_counter) || (fragmentation_counter))
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

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    /* Check if receive IPv6 fragmentation packet from ip_0, except NA and NS(IPv6(40) + NS/NA(32)). */
    if ((ip_ptr == &ip_0) && (packet_ptr -> nx_packet_length > 72))
    {

        /* Updated the packet_counter.  */
        fragmentation_counter ++;
    }

    return NX_TRUE;
}

#else             
extern void    test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ipv6_fragmentation_error_test2_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   IPv6 Fragmentation Error Test2............................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_FRAGMENTATION  */
