/* This NetX test concentrates on the ICMP ping6 operation use second interface.  */

#include   "tx_api.h"
#include   "nx_api.h"
extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && (NX_MAX_PHYSICAL_INTERFACES > 1)
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"
#include    "nx_nd_cache.h"
#include    "nx_icmpv6.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     1


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */
static ULONG                   error_counter;

static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;
static NXD_ADDRESS             ipv6_address_3;
static NXD_ADDRESS             ipv6_address_4;
static NXD_ADDRESS             ipv6_address_5;
static NXD_ADDRESS             ip0_lla_1;
static NXD_ADDRESS             ip0_lla_2;
static NXD_ADDRESS             ip1_lla_1;
static NXD_ADDRESS             ip1_lla_2;
#ifndef NX_DISABLE_LOOPBACK_INTERFACE
static NXD_ADDRESS             loopback_addr;
#endif /* NX_DISABLE_LOOPBACK_INTERFACE */
#ifdef NX_DISABLE_FRAGMENTATION
static char                    long_msg[700] = ""; 
#endif

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
#if !defined(NX_DISABLE_IPV6_DAD) || defined(NX_DISABLE_FRAGMENTATION)
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
#endif
extern UINT    (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UINT    check_checksum(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
#if (NX_IPV6_NEIGHBOR_CACHE_SIZE==8) && defined(NX_DISABLE_IPV6_PURGE_UNUSED_CACHE_ENTRIES)
static UINT    packet_process_filter(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
#endif


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_interface2_ping6_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1024, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Set the second interface.  */
    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_512);
    status += nx_ip_interface_attach(&ip_1, "Second Interface", IP_ADDRESS(2, 2, 3, 5), 0xFFFFFF00UL, _nx_ram_network_driver_512);
    if (status)
        error_counter++;

    /* Set ipv6 version and address.  */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x10000001;

    ipv6_address_2.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_2.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_2.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_2.nxd_ip_address.v6[3] = 0x10000002;

    ipv6_address_3.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_3.nxd_ip_address.v6[0] = 0x30010000;
    ipv6_address_3.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_3.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_3.nxd_ip_address.v6[3] = 0x20000003;

    ipv6_address_4.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_4.nxd_ip_address.v6[0] = 0x30010000;
    ipv6_address_4.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_4.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_4.nxd_ip_address.v6[3] = 0x20000004;

    ipv6_address_5.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_5.nxd_ip_address.v6[0] = 0x30010000;
    ipv6_address_5.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_5.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_5.nxd_ip_address.v6[3] = 0x10000005;

    ip0_lla_1.nxd_ip_version = NX_IP_VERSION_V6;
    ip0_lla_1.nxd_ip_address.v6[0] = 0xfe800000;
    ip0_lla_1.nxd_ip_address.v6[1] = 0x0;
    ip0_lla_1.nxd_ip_address.v6[2] = 0x0;
    ip0_lla_1.nxd_ip_address.v6[3] = 0x1;

    ip0_lla_2.nxd_ip_version = NX_IP_VERSION_V6;
    ip0_lla_2.nxd_ip_address.v6[0] = 0xfe800000;
    ip0_lla_2.nxd_ip_address.v6[1] = 0x0;
    ip0_lla_2.nxd_ip_address.v6[2] = 0x0;
    ip0_lla_2.nxd_ip_address.v6[3] = 0x2;

    ip1_lla_1.nxd_ip_version = NX_IP_VERSION_V6;
    ip1_lla_1.nxd_ip_address.v6[0] = 0xfe800000;
    ip1_lla_1.nxd_ip_address.v6[1] = 0x1;
    ip1_lla_1.nxd_ip_address.v6[2] = 0x0;
    ip1_lla_1.nxd_ip_address.v6[3] = 0x1;

    ip1_lla_2.nxd_ip_version = NX_IP_VERSION_V6;
    ip1_lla_2.nxd_ip_address.v6[0] = 0xfe800000;
    ip1_lla_2.nxd_ip_address.v6[1] = 0x1;
    ip1_lla_2.nxd_ip_address.v6[2] = 0x0;
    ip1_lla_2.nxd_ip_address.v6[3] = 0x2;
    
#ifndef NX_DISABLE_LOOPBACK_INTERFACE
    loopback_addr.nxd_ip_version = NX_IP_VERSION_V6;
    loopback_addr.nxd_ip_address.v6[0] = 0x0;
    loopback_addr.nxd_ip_address.v6[1] = 0x0;
    loopback_addr.nxd_ip_address.v6[2] = 0x0;
    loopback_addr.nxd_ip_address.v6[3] = 0x1;
#endif /* NX_DISABLE_LOOPBACK_INTERFACE */

    /* Check ipv6 address set status.  */
    if(status)
        error_counter++;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    status = nxd_ipv6_enable(&ip_1);

    /* Enable ICMP processing for both IP instances.  */
    status =  nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
#if !defined(NX_DISABLE_IPV6_DAD) || defined(NX_DISABLE_FRAGMENTATION)
TX_INTERRUPT_SAVE_AREA
#endif
UINT             status = 0;
NX_PACKET       *my_packet;
ULONG            pings_sent;
ULONG            ping_timeouts;
ULONG            ping_threads_suspended;
ULONG            ping_responses_received;
ULONG            icmp_checksum_errors;
ULONG            icmp_unhandled_messages;
NX_IPV6_HEADER  *ipv6_header;
UINT             addr_index_1;
UINT             addr_index_2;
ULONG            return_value;

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Interface2 Ping6 Test................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_2, 64, NX_NULL);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_LOOPBACK_INTERFACE
    /* Now ping loopback address.  */
    status = nxd_icmp_ping(&ip_0, &loopback_addr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet. */
    nx_packet_release(my_packet);
#endif /* NX_DISABLE_LOOPBACK_INTERFACE */

    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Configure mapping needed and test again. */
    nx_ip_interface_address_mapping_configure(&ip_0, 0, NX_FALSE);
    nx_ip_interface_address_mapping_configure(&ip_1, 0, NX_FALSE);

    /* Now ping local address.  */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet. */
    nx_packet_release(my_packet);

    /* Now ping an IP address that does exist.  */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_2, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet. */
    nx_packet_release(my_packet);

    nx_ip_interface_address_mapping_configure(&ip_0, 0, NX_TRUE);
    nx_ip_interface_address_mapping_configure(&ip_1, 0, NX_TRUE);

    /* Delete the global addresses and assign link local addresses. */
    status = nxd_ipv6_address_delete(&ip_0, 0);
    status += nxd_ipv6_address_delete(&ip_1, 0);
    if(status)
        error_counter++;

    /* Set interfaces' address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_2, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_0, 1, &ipv6_address_3, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 1, &ipv6_address_4, 64, NX_NULL);
    if(status)
        error_counter++;

    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Ping an unknown IP address. This will timeout after 100 ticks.  */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_5, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Now setup address 5. */
    status = nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_5, 64, NX_NULL);
    if(status)
        error_counter++;

    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Ping address 5. */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_5, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet. */
    nx_packet_release(my_packet);

    /* Now ping local address.  */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet. */
    nx_packet_release(my_packet);

    /* Now ping peer's address.  */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_2, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet. */
    nx_packet_release(my_packet);

    /* Now ping an IP address that does exist.  */
    /* The checksum of echo reply should not be 0xFFFF. */
    packet_process_callback = check_checksum;
    status = nxd_icmp_ping(&ip_0, &ipv6_address_4, "zzzNzFzHbJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    packet_process_callback = NX_NULL;

    /* Get ICMP information.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);

#ifndef NX_DISABLE_ICMP_INFO
#ifndef NX_DISABLE_LOOPBACK_INTERFACE
    if ((ping_timeouts != 1) || (pings_sent != 8) || (ping_responses_received != 7))
#else
    if ((ping_timeouts != 1) || (pings_sent != 7) || (ping_responses_received != 6))
#endif /* NX_DISABLE_LOOPBACK_INTERFACE */
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28) ||
        (ping_threads_suspended) || (icmp_checksum_errors) || (icmp_unhandled_messages) || error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Make sure the packet is received via the 2nd address on IP 0. */
    ipv6_header = (NX_IPV6_HEADER*)(my_packet -> nx_packet_ip_header);

    if(!CHECK_IPV6_ADDRESSES_SAME(ipv6_header -> nx_ip_header_destination_ip, ipv6_address_3.nxd_ip_address.v6))
    {
        printf("ERROR!\n");
        test_control_return(1);    
    }

    /* Release the packet. */
    nx_packet_release(my_packet);



    /* Set interfaces' address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &ip0_lla_1, 10, &addr_index_1);
    status += nxd_ipv6_address_set(&ip_1, 0, &ip1_lla_1, 10, NX_NULL);
    status += nxd_ipv6_address_set(&ip_0, 1, &ip0_lla_2, 10, &addr_index_2);
    status += nxd_ipv6_address_set(&ip_1, 1, &ip1_lla_2, 10, NX_NULL);

    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
#ifndef NX_DISABLE_IPV6_DAD
    /* Disable interrupts.  */
    TX_DISABLE

    /* Hook link driver to check packets. */
    packet_process_callback = packet_process;

    /* Send ICMPv6 packet before address is valid. */
    nxd_icmp_interface_ping(&ip_0, &ip1_lla_2, addr_index_2, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_NO_WAIT);

    packet_process_callback = NX_NULL;

    /* Restore previous interrupt posture.  */
    TX_RESTORE

    /* Check whether ICMPv6 echo request is sent out. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
        
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Send a ping to ip1_lla_2, via ip0_lla_2.*/
    status = nxd_icmp_interface_ping(&ip_0, &ip1_lla_2, addr_index_2, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, TX_TIMER_TICKS_PER_SECOND);
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Verify that we receive the ping response via addr_3 */
    ipv6_header = (NX_IPV6_HEADER*)(my_packet -> nx_packet_ip_header);
    if(!CHECK_IPV6_ADDRESSES_SAME(ipv6_header -> nx_ip_header_destination_ip, ip0_lla_2.nxd_ip_address.v6))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet. */
    nx_packet_release(my_packet);

    /* Set link status from up to down. */
    nx_ip_driver_interface_direct_command(&ip_0, NX_LINK_DISABLE, 0, &return_value);
    nx_ip_driver_interface_direct_command(&ip_0, NX_LINK_DISABLE, 1, &return_value);

    /* Send a ping to ip1_lla_2.*/
    status = nxd_icmp_ping(&ip_0, &ip1_lla_2, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, TX_TIMER_TICKS_PER_SECOND);
    if(status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set link status from down to up. */
    nx_ip_driver_interface_direct_command(&ip_0, NX_LINK_ENABLE, 0, &return_value);
    nx_ip_driver_interface_direct_command(&ip_0, NX_LINK_ENABLE, 1, &return_value);
    
#ifdef NX_DISABLE_FRAGMENTATION

    /* Disable interrupts.  */
    TX_DISABLE

    /* Hook link driver to check packets. */
    packet_process_callback = packet_process;

    /* Send ICMPv6 packet larger than MTU. */
    nxd_icmp_interface_ping(&ip_0, &ip1_lla_2, addr_index_2, long_msg, 600, &my_packet, NX_NO_WAIT);

    packet_process_callback = NX_NULL;

    /* Restore previous interrupt posture.  */
    TX_RESTORE

    /* Check whether ICMPv6 echo request is sent out. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_FRAGMENTATION */

#if 0
#if (NX_IPV6_DESTINATION_TABLE_SIZE==8) 
    /* Seven destination tables are used. Ping needs two more destination tables. Ping should not success. */
    status = nxd_icmp_interface_ping(&ip_0, &ip1_lla_1, addr_index_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);
    if(status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

#if (NX_IPV6_NEIGHBOR_CACHE_SIZE==8) && defined(NX_DISABLE_IPV6_PURGE_UNUSED_CACHE_ENTRIES) && (NX_IPV6_DESTINATION_TABLE_SIZE>8) 
    /* Seven nd caches are used. nd cache of ip0_lla_2 is poluted. Ping needs two more destination tables. Ping should not success. */
    packet_process_callback = packet_process_filter;
    status = nxd_icmp_interface_ping(&ip_0, &ip1_lla_1, addr_index_2, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);
    if(status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
#endif

    printf("SUCCESS!\n");
    test_control_return(0);


}


static UINT    check_checksum(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_IPV6_HEADER   *ip_header_ptr;
ULONG            protocol;
NX_ICMPV6_HEADER *icmp_header_ptr;

    /* Ignore packet that is not ICMP. */
    if(packet_ptr -> nx_packet_length < (sizeof(NX_IPV6_HEADER) + sizeof(NX_ICMPV6_HEADER)))
        return NX_TRUE;

    ip_header_ptr = (NX_IPV6_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);

    /* Get IP header. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);
    protocol = (ip_header_ptr -> nx_ip_header_word_1 >> 8) & 0xFF;
    if(protocol == NX_PROTOCOL_ICMPV6)
    {

        /* Get ICMP header. */
        icmp_header_ptr = (NX_ICMPV6_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_IPV6_HEADER));
        if((icmp_header_ptr -> nx_icmpv6_header_checksum) == 0xFFFF)
            error_counter++;
    }
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);
}


#if !defined(NX_DISABLE_IPV6_DAD) || defined(NX_DISABLE_FRAGMENTATION)
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

    /* In this case, ICMPv6 echo request is sent out. */
    error_counter++;
    return NX_TRUE;
}
#endif

#if (NX_IPV6_NEIGHBOR_CACHE_SIZE==8) && defined(NX_DISABLE_IPV6_PURGE_UNUSED_CACHE_ENTRIES)
static UINT    packet_process_filter(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
UINT i;

    /* Continue process only when echo request is received. */
    if (packet_ptr -> nx_packet_length != 76)
        return NX_TRUE;

    /* Modify ND CACHE for lla_0. */
    for (i = 0; i < NX_IPV6_NEIGHBOR_CACHE_SIZE; i++)
    {
        if (CHECK_IPV6_ADDRESSES_SAME(ip_0.nx_ipv6_nd_cache[i].nx_nd_cache_dest_ip, ip0_lla_2.nxd_ip_address.v6))
        {
            ip_0.nx_ipv6_nd_cache[i].nx_nd_cache_dest_ip[3] = 9; 
            break;
        }
    }

    /* Modify destination table for lla_0. */
    for (i = 0; i < NX_IPV6_DESTINATION_TABLE_SIZE; i++)
    {

        /* Skip invalid entries. */
        if (!ip_0.nx_ipv6_destination_table[i].nx_ipv6_destination_entry_valid)
            continue;

        if(CHECK_IPV6_ADDRESSES_SAME(ip_0.nx_ipv6_destination_table[i].nx_ipv6_destination_entry_destination_address, ip0_lla_2.nxd_ip_address.v6))
        {
            ip_0.nx_ipv6_destination_table[i].nx_ipv6_destination_entry_destination_address[3] = 9;
            break;
        }
    }

    packet_process_callback = NX_NULL;
    return NX_TRUE;
}
#endif

#else 

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmp_interface2_ping6_test_application_define(void *first_unused_memory)
#endif
{   

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Interface2 Ping6 Test................................N/A\n");

    test_control_return(3);

}
#endif /* FEATURE_NX_IPV6 */
