/* This NetX test concentrates on the code coverage for ICMPv6 functions,
 * _nx_icmpv6_DAD_failure.c
 * _nx_icmpv6_dest_table_find.c
 */
                   
#include "tx_api.h"
#include "nx_api.h"
extern void    test_control_return(UINT status);

#if defined(FEATURE_NX_IPV6) && !defined(NX_ENABLE_INTERFACE_CAPABILITY)
#include "tx_thread.h"
#include "nx_icmp.h"
#include "nx_icmpv6.h" 

#define     DEMO_STACK_SIZE         2048

#define     ASSERT_THREAD_COUNT     10


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0; 
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
#ifndef NX_DISABLE_ASSERT
static TX_THREAD               thread_for_assert[ASSERT_THREAD_COUNT];
static UCHAR                   stack_for_assert[ASSERT_THREAD_COUNT][DEMO_STACK_SIZE];
#endif

/* NS packet with invalid option type 0. */
static unsigned char pkt1[86] = {
0x33, 0x33, 0xff, 0x00, 0x01, 0x00, 0x00, 0x11, /* 33...... */
0x22, 0x33, 0x44, 0x56, 0x86, 0xdd, 0x60, 0x00, /* "3DV..`. */
0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, /* ... :... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x87, 0x00, /* ........ */
0xae, 0x68, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, /* .h...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x00, 0x01, /* "..3DV.. */
0x00, 0x11, 0x22, 0x33, 0x44, 0x56              /* .."3DV */
};

/* NS packet with different SLLA. */
static unsigned char pkt2[86] = {
0x33, 0x33, 0xff, 0x33, 0x44, 0x56, 0x00, 0x00, /* 33.3DV.. */
0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, /* ... :... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0xff, 0x33, 0x44, 0x56, 0x87, 0x00, /* ...3DV.. */
0x2d, 0xd9, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, /* -....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x01, 0x01, /* "..3DV.. */
0x00, 0x00, 0x00, 0x00, 0xa0, 0xa0              /* ...... */
};
static unsigned char pkt3[86] = {
0x33, 0x33, 0xff, 0x33, 0x44, 0x56, 0x00, 0x00, /* 33.3DV.. */
0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, /* ... :... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0xff, 0x33, 0x44, 0x56, 0x87, 0x00, /* ...3DV.. */
0x2d, 0x39, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, /* -9...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, /* ........ */
0x22, 0xff, 0xfe, 0x33, 0x44, 0x56, 0x01, 0x01, /* "..3DV.. */
0x00, 0xa0, 0x00, 0x00, 0xa0, 0xa0              /* ...... */
};


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
#ifndef NX_DISABLE_ASSERT
static VOID    thread_for_assert_entry_0(ULONG thread_input);
static VOID    thread_for_assert_entry_1(ULONG thread_input);
static VOID    thread_for_assert_entry_2(ULONG thread_input);
static VOID    thread_for_assert_entry_3(ULONG thread_input);
static VOID    thread_for_assert_entry_4(ULONG thread_input);
static VOID    thread_for_assert_entry_5(ULONG thread_input);
static VOID    thread_for_assert_entry_6(ULONG thread_input);
static VOID    thread_for_assert_entry_7(ULONG thread_input);
static VOID    thread_for_assert_entry_8(ULONG thread_input);
static VOID    thread_for_assert_entry_9(ULONG thread_input);
static VOID  (*thread_for_assert_entry[])(ULONG) = 
{
    thread_for_assert_entry_0,
    thread_for_assert_entry_1,
    thread_for_assert_entry_2,
    thread_for_assert_entry_3,
    thread_for_assert_entry_4,
    thread_for_assert_entry_5,
    thread_for_assert_entry_6,
    thread_for_assert_entry_7,
    thread_for_assert_entry_8,
    thread_for_assert_entry_9,
};
#endif

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmpv6_branch_test_application_define(void *first_unused_memory)
#endif
{

CHAR       *pointer;
UINT        status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ICMP processing for IP instance.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check ICMP enable status.  */
    if (status)
        error_counter++;

    /* Enable IPv6 processing for IP instance.  */
    status = nxd_ipv6_enable(&ip_0);

    /* Check IPv6 enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

ULONG       destination_address[4];
ULONG       next_hop[4];
NX_IPV6_DESTINATION_ENTRY 
           *dest_entry_ptr;
#ifndef NX_DISABLE_IPV6_DAD
NXD_ADDRESS ipv6_address;
#endif
NX_PACKET  *packet_ptr;
NX_IPV6_HEADER 
           *ip_header_ptr;
ND_CACHE_ENTRY
            nd_entry;
UINT        i;

    /* Print out some test information banners.  */
    printf("NetX Test:   ICMPv6 Branch Test........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }



#ifndef NX_DISABLE_IPV6_DAD
    /* Hit condition of if (address_ptr -> nxd_ipv6_address_next == ipv6_address) in _nx_icmpv6_DAD_failure().  */
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address.nxd_ip_address.v6[1] = 0x00000009;
    ipv6_address.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[3] = 0x00010003;
    nxd_ipv6_address_set(&ip_0, 0, &ipv6_address, 64, NX_NULL);

    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address.nxd_ip_address.v6[1] = 0x00000009;
    ipv6_address.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[3] = 0x00010004;
    nxd_ipv6_address_set(&ip_0, 0, &ipv6_address, 64, NX_NULL); 

    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address.nxd_ip_address.v6[1] = 0x00000009;
    ipv6_address.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address.nxd_ip_address.v6[3] = 0x00010005;
    nxd_ipv6_address_set(&ip_0, 0, &ipv6_address, 64, NX_NULL);
    
    _nx_icmpv6_DAD_failure(&ip_0, &ip_0.nx_ipv6_address[2]);
    _nx_icmpv6_DAD_failure(&ip_0, &ip_0.nx_ipv6_address[1]);

    nxd_ipv6_address_delete(&ip_0, 0);
    nxd_ipv6_address_delete(&ip_0, 1);
    nxd_ipv6_address_delete(&ip_0, 2);
#endif



    /* Test _nx_icmpv6_dest_table_find.  */
    /* Hit false condition of (i < NX_IPV6_DESTINATION_TABLE_SIZE). */
    ip_0.nx_ipv6_destination_table_size = 1;
    if (_nx_icmpv6_dest_table_find(&ip_0, destination_address, &dest_entry_ptr, 0, 0) == NX_SUCCESS)
    {
        error_counter++;
    }

    /* Recover*/
    ip_0.nx_ipv6_destination_table_size = 0;

#ifndef NX_DISABLE_ASSERT
    for (i = 0; i < ASSERT_THREAD_COUNT; i++)
    {

        /* Create the assert thread.  */
        tx_thread_create(&thread_for_assert[i], "Assert Test thread", thread_for_assert_entry[i], 0,  
                stack_for_assert[i], DEMO_STACK_SIZE, 
                5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

        /* Let test thread run.  */
        tx_thread_sleep(NX_IP_PERIODIC_RATE);

        /* Terminate the test thread.  */
        tx_thread_terminate(&thread_for_assert[i]);
        tx_thread_delete(&thread_for_assert[i]);
    }
#endif
    for (i = 0; i < NX_IPV6_DESTINATION_TABLE_SIZE; i++)
    {
        ip_0.nx_ipv6_destination_table[i].nx_ipv6_destination_entry_valid = NX_FALSE;
    }

    /* Test _nx_icmpv6_send_queued_packets(). */
    /* Cover the false branch of 'if (status == NX_SUCCESS)'. */
    destination_address[0] = 0xfe800000;
    destination_address[1] = 0;
    destination_address[2] = 0;
    destination_address[3] = 1;
    next_hop[0] = 0;
    next_hop[1] = 0;
    next_hop[2] = 0;
    next_hop[3] = 0;
    nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);
    if (nx_packet_allocate(&pool_0, &packet_ptr, NX_IPv6_PACKET, 0))
    {
        error_counter++;
    }
    ip_header_ptr = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    packet_ptr -> nx_packet_append_ptr += sizeof(NX_IPV6_HEADER);
    packet_ptr -> nx_packet_length += sizeof(NX_IPV6_HEADER);
    COPY_IPV6_ADDRESS(destination_address, ip_header_ptr -> nx_ip_header_destination_ip);
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header_ptr -> nx_ip_header_destination_ip);
    nd_entry.nx_nd_cache_packet_waiting_head = packet_ptr;
    nd_entry.nx_nd_cache_interface_ptr = &(ip_0.nx_ip_interface[0]);
    packet_ptr -> nx_packet_queue_next = NX_NULL;
    packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr = &(ip_0.nx_ipv6_address[0]);
    _nx_icmpv6_send_queued_packets(&ip_0, &nd_entry);

    /* Test _nx_icmpv6_send_queued_packets(). */
    /* Cover the false branch of 'if (!CHECK_UNSPECIFIED_ADDRESS(&(next_hop_address[0])))'. */
    destination_address[0] = 0xfe800000;
    destination_address[1] = 0;
    destination_address[2] = 0;
    destination_address[3] = 1;
    next_hop[0] = 0;
    next_hop[1] = 0;
    next_hop[2] = 0;
    next_hop[3] = 0;
    nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);
    _nx_icmpv6_dest_table_add(&ip_0, destination_address, &dest_entry_ptr, next_hop, 0, 0, &ip_0.nx_ipv6_address[0]);
    if (nx_packet_allocate(&pool_0, &packet_ptr, NX_IPv6_PACKET, 0))
    {
        error_counter++;
    }
    ip_header_ptr = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    packet_ptr -> nx_packet_append_ptr += sizeof(NX_IPV6_HEADER);
    packet_ptr -> nx_packet_length += sizeof(NX_IPV6_HEADER);
    COPY_IPV6_ADDRESS(destination_address, ip_header_ptr -> nx_ip_header_destination_ip);
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header_ptr -> nx_ip_header_destination_ip);
    nd_entry.nx_nd_cache_packet_waiting_head = packet_ptr;
    nd_entry.nx_nd_cache_interface_ptr = &(ip_0.nx_ip_interface[0]);
    packet_ptr -> nx_packet_queue_next = NX_NULL;
    packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr = &(ip_0.nx_ipv6_address[0]);
    _nx_icmpv6_send_queued_packets(&ip_0, &nd_entry);

    /* Cover the false branch of 'if ((next_hop_dest_entry_ptr -> nx_ipv6_destination_entry_path_mtu > 0) &&'. */
    destination_address[0] = 0xfe800000;
    destination_address[1] = 0;
    destination_address[2] = 0;
    destination_address[3] = 3;
    ip_0.nx_ip_interface[0].nx_interface_ip_mtu_size = 0;
    _nx_icmpv6_dest_table_add(&ip_0, destination_address, &dest_entry_ptr, next_hop, 0, 0, &ip_0.nx_ipv6_address[0]);
    ip_0.nx_ip_interface[0].nx_interface_ip_mtu_size = 256;
    destination_address[0] = 0xfe800000;
    destination_address[1] = 0;
    destination_address[2] = 0;
    destination_address[3] = 2;
    next_hop[0] = 0xfe800000;
    next_hop[1] = 0;
    next_hop[2] = 0;
    next_hop[3] = 3;
    _nx_icmpv6_dest_table_add(&ip_0, destination_address, &dest_entry_ptr, next_hop, 256, 0, &ip_0.nx_ipv6_address[0]);
    if (nx_packet_allocate(&pool_0, &packet_ptr, NX_IPv6_PACKET, 0))
    {
        error_counter++;
    }
    ip_header_ptr = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    packet_ptr -> nx_packet_append_ptr += sizeof(NX_IPV6_HEADER);
    packet_ptr -> nx_packet_length += sizeof(NX_IPV6_HEADER);
    COPY_IPV6_ADDRESS(destination_address, ip_header_ptr -> nx_ip_header_destination_ip);
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header_ptr -> nx_ip_header_destination_ip);
    nd_entry.nx_nd_cache_packet_waiting_head = packet_ptr;
    nd_entry.nx_nd_cache_interface_ptr = &(ip_0.nx_ip_interface[0]);
    packet_ptr -> nx_packet_queue_next = NX_NULL;
    packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr = &(ip_0.nx_ipv6_address[0]);
    _nx_icmpv6_send_queued_packets(&ip_0, &nd_entry);

    /* Cover the false branch of 'if (status == NX_SUCCESS)'. */
    destination_address[0] = 0xfe800000;
    destination_address[1] = 0;
    destination_address[2] = 0;
    destination_address[3] = 5;
    next_hop[0] = 0xfe800000;
    next_hop[1] = 0;
    next_hop[2] = 0;
    next_hop[3] = 6;
    _nx_icmpv6_dest_table_add(&ip_0, destination_address, &dest_entry_ptr, next_hop, 256, 0, &ip_0.nx_ipv6_address[0]);
    if (nx_packet_allocate(&pool_0, &packet_ptr, NX_IPv6_PACKET, 0))
    {
        error_counter++;
    }
    ip_header_ptr = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    packet_ptr -> nx_packet_append_ptr += sizeof(NX_IPV6_HEADER);
    packet_ptr -> nx_packet_length += sizeof(NX_IPV6_HEADER);
    COPY_IPV6_ADDRESS(destination_address, ip_header_ptr -> nx_ip_header_destination_ip);
    NX_IPV6_ADDRESS_CHANGE_ENDIAN(ip_header_ptr -> nx_ip_header_destination_ip);
    nd_entry.nx_nd_cache_packet_waiting_head = packet_ptr;
    nd_entry.nx_nd_cache_interface_ptr = &(ip_0.nx_ip_interface[0]);
    packet_ptr -> nx_packet_queue_next = NX_NULL;
    packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr = &(ip_0.nx_ipv6_address[0]);
    _nx_icmpv6_send_queued_packets(&ip_0, &nd_entry);



#ifndef NX_DISABLE_ICMPV6_ERROR_MESSAGE
    /* Test _nx_icmpv6_send_error_message(). */
    /* Cover the true banch of 'if ((pkt_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr == NX_NULL) ||' */
    destination_address[0] = 0xfe800000;
    destination_address[1] = 0;
    destination_address[2] = 0;
    destination_address[3] = 1;
    if (nx_packet_allocate(&pool_0, &packet_ptr, NX_IPv6_PACKET, 0))
    {
        error_counter++;
    }
    ip_header_ptr = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_prepend_ptr;
    packet_ptr -> nx_packet_ip_header = packet_ptr -> nx_packet_prepend_ptr;
    packet_ptr -> nx_packet_append_ptr += sizeof(NX_IPV6_HEADER);
    packet_ptr -> nx_packet_length += sizeof(NX_IPV6_HEADER);
    packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr = NX_NULL;
    COPY_IPV6_ADDRESS(destination_address, ip_header_ptr -> nx_ip_header_destination_ip);
    COPY_IPV6_ADDRESS(destination_address, ip_header_ptr -> nx_ip_header_source_ip);
    _nx_icmpv6_send_error_message(&ip_0, packet_ptr, 0, 0);
#endif


    /* Test _nx_icmpv6_process_ns(). */
    /* Cover the false branch of '(option_ptr -> nx_icmpv6_option_type == ICMPV6_OPTION_TYPE_SRC_LINK_ADDR)'. */
    /* Inject NS packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt1[14], sizeof(pkt1) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt1) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Directly receive the NS packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Test _nx_icmpv6_process_ns(). */
    /* Cover the false branch of '(mac_msw != new_msw)'. */
    /* Inject NS packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt2[14], sizeof(pkt2) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt2) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Set address state to valid. */
    ip_0.nx_ipv6_address[0].nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_VALID;

    /* Directly receive the NS packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     

    /* Inject NS packet. */
    nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, &pkt3[14], sizeof(pkt3) - 14);
    packet_ptr -> nx_packet_length = sizeof(pkt3) - 14;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Set address state to valid. */
    ip_0.nx_ipv6_address[0].nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_VALID;

    /* Directly receive the NS packet.  */
    _nx_ip_packet_deferred_receive(&ip_0, packet_ptr);     


    /* Check status.  */
    if (error_counter) 
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

#ifndef NX_DISABLE_ASSERT
static VOID    thread_for_assert_entry_0(ULONG thread_input)
{

    /* Test _nx_icmpv6_dest_table_add().  */
    /* Hit NX_ASSERT((destination_address != NX_NULL) && (dest_entry_ptr != NX_NULL) && (next_hop != NX_NULL));  */
    _nx_icmpv6_dest_table_add(&ip_0, NX_NULL, NX_NULL, NX_NULL, 0, 0, NX_NULL);
}

static VOID    thread_for_assert_entry_1(ULONG thread_input)
{
ULONG destination_address[4] = {0};

    /* Test _nx_icmpv6_dest_table_add().  */
    /* Hit NX_ASSERT((destination_address != NX_NULL) && (dest_entry_ptr != NX_NULL) && (next_hop != NX_NULL));  */
    _nx_icmpv6_dest_table_add(&ip_0, destination_address, NX_NULL, NX_NULL, 0, 0, NX_NULL);
}

static VOID    thread_for_assert_entry_2(ULONG thread_input)
{
ULONG destination_address[4] = {0};
NX_IPV6_DESTINATION_ENTRY *dest_entry;

    /* Test _nx_icmpv6_dest_table_add().  */
    /* Hit NX_ASSERT((destination_address != NX_NULL) && (dest_entry_ptr != NX_NULL) && (next_hop != NX_NULL));  */
    _nx_icmpv6_dest_table_add(&ip_0, destination_address, &dest_entry, NX_NULL, 0, 0, NX_NULL);
}

static VOID    thread_for_assert_entry_3(ULONG thread_input)
{
ULONG destination_address[4] = {0};
NX_IPV6_DESTINATION_ENTRY *dest_entry;
ULONG next_hop;
UINT i;

    /* Test _nx_icmpv6_dest_table_add().  */
    /* Hit NX_ASSERT(i < NX_IPV6_DESTINATION_TABLE_SIZE); */
    for (i = 0; i < NX_IPV6_DESTINATION_TABLE_SIZE; i++)
    {
        ip_0.nx_ipv6_destination_table[i].nx_ipv6_destination_entry_valid = NX_TRUE;
    }
    _nx_icmpv6_dest_table_add(&ip_0, destination_address, &dest_entry, &next_hop, 0, 0, NX_NULL);
}

static VOID    thread_for_assert_entry_4(ULONG thread_input)
{

    /* Test _nx_icmpv6_dest_table_find().  */
    /* Hit NX_ASSERT((destination_address != NX_NULL) && (dest_entry_ptr != NULL));  */
    _nx_icmpv6_dest_table_find(&ip_0, NX_NULL, NX_NULL, 0, 0);
}

static VOID    thread_for_assert_entry_5(ULONG thread_input)
{
ULONG destination_address[4];

    /* Test _nx_icmpv6_dest_table_find().  */
    /* Hit NX_ASSERT((destination_address != NX_NULL) && (dest_entry_ptr != NULL));  */
    _nx_icmpv6_dest_table_find(&ip_0, destination_address, NX_NULL, 0, 0);
}

static VOID    thread_for_assert_entry_6(ULONG thread_input)
{
ULONG destination_address[4];
NXD_IPV6_ADDRESS ipv6_address;

    /* Test _nx_icmpv6_send_ns().  */
    /* Hit NX_ASSERT(driver_request.nx_ip_driver_interface != NX_NULL);  */
    ipv6_address.nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_TENTATIVE;
    ipv6_address.nxd_ipv6_address_attached = NX_NULL;
    _nx_icmpv6_send_ns(&ip_0, destination_address, NX_FALSE, &ipv6_address, NX_FALSE, NX_NULL);
}

static VOID    thread_for_assert_entry_7(ULONG thread_input)
{
ULONG destination_address[4];
NXD_IPV6_ADDRESS ipv6_address;
NX_INTERFACE nx_interface;

    /* Test _nx_icmpv6_send_ns().  */
    /* Hit NX_ASSERT(outgoing_address -> nxd_ipv6_address_attached -> nx_interface_link_driver_entry != NX_NULL); */
    ipv6_address.nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_TENTATIVE;
    ipv6_address.nxd_ipv6_address_attached = &nx_interface;
    nx_interface.nx_interface_link_driver_entry = NX_NULL;
    _nx_icmpv6_send_ns(&ip_0, destination_address, NX_FALSE, &ipv6_address, NX_FALSE, NX_NULL);
}

static VOID    thread_for_assert_entry_8(ULONG thread_input)
{

    /* Test _nx_icmpv6_send_queued_packets().  */
    /* Hit NX_ASSERT(nd_entry != NX_NULL);  */
    _nx_icmpv6_send_queued_packets(&ip_0, NX_NULL);
}

static VOID    thread_for_assert_entry_9(ULONG thread_input)
{
ND_CACHE_ENTRY nd_entry;

    /* Test _nx_icmpv6_send_queued_packets().  */
    /* Hit NX_ASSERT(nd_entry -> nx_nd_cache_packet_waiting_head != NX_NULL);  */
    nd_entry.nx_nd_cache_packet_waiting_head = NX_NULL;
    _nx_icmpv6_send_queued_packets(&ip_0, &nd_entry);
}
#endif

#else    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmpv6_branch_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 Branch Test........................................N/A\n");
    
    test_control_return(3);
}
#endif

