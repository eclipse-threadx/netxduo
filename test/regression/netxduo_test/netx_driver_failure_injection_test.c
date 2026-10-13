/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation 
 * Copyright (c) 2026 Eclipse ThreadX contributors
 * 
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 * 
 * SPDX-License-Identifier: MIT
 **************************************************************************/

// Portions of this file were generated with AI assistance.

/* This NetX test concentrates on the three failures the gap inventory groups
   as driver-alloc-failure: a driver that refuses a multicast join, an
   auxiliary packet pool that cannot satisfy an allocation the stack then
   retries against the default pool, and an inbound IP packet filter that
   consumes a packet.

   None of these is a protocol case. Each needs something underneath the
   stack to say no, which is why they sit with the driver work rather than
   with a subsystem batch.

   No new driver is needed for any of them. The RAM driver already refuses a
   multicast join once its eight-entry table is full, and the other two are
   driven by what the test hands the stack: an auxiliary pool it has emptied,
   and a filter it has installed. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_arp.h"
#include   "nx_igmp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048

/* The auxiliary pool has to be emptied for this test to work, and how many
   packets a block holds is not something the test can compute: NX_PACKET
   alignment and header padding are per-configuration, and v4_packet_pad_build
   sets NX_PACKET_ALIGNMENT to 64. So the block is sized generously and
   drained in a loop rather than sized for one packet and allocated once.

   Sizing it for exactly one packet is what the first version did, and
   nx_packet_pool_create refused the block outright wherever alignment pushed
   one packet past it. */
#define     AUX_PACKET_SIZE         256
#define     AUX_POOL_BYTES          4096
#define     AUX_MAX_HELD            64

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          auxiliary_pool;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
#ifdef NX_ENABLE_IP_PACKET_FILTER
static NX_UDP_SOCKET           sender_socket;
static NX_UDP_SOCKET           receiver_socket;
#endif

static ULONG                   error_counter;
static ULONG                   filter_in_calls;

/* When NX_TRUE the inbound filter consumes the packet. */
static UINT                    filter_consumes;

static void    thread_0_entry(ULONG thread_input);
#ifdef NX_ENABLE_IP_PACKET_FILTER
static UINT    inbound_filter(VOID *ip_header_ptr, UINT direction);
#endif

extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_driver_failure_injection_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    pointer =  (CHAR *) first_unused_memory;

    error_counter =   0;
    filter_in_calls = 0;
    filter_consumes = NX_FALSE;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 16384);
    pointer = pointer + 16384;
    if (status)
        error_counter++;

    /* A pool of its own, not the default one. The branches this test is here
       for compare the two pointers, so they are only reachable when the two
       pools are genuinely different objects. */
    status =  nx_packet_pool_create(&auxiliary_pool, "NetX Auxiliary Pool", AUX_PACKET_SIZE, pointer,
                                    AUX_POOL_BYTES);
    pointer = pointer + AUX_POOL_BYTES;
    if (status)
        error_counter++;

    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0,
                          _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer =  pointer + 2048;

    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0,
                           _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    status =  nx_igmp_enable(&ip_0);
    if (status)
        error_counter++;

    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    status =  nxd_ipv6_enable(&ip_0);
    if (status)
        error_counter++;
#endif

    status = nx_ip_auxiliary_packet_pool_set(&ip_0, &auxiliary_pool);
#ifdef NX_ENABLE_DUAL_PACKET_POOL
    if (status != NX_SUCCESS)
        error_counter++;
#else
    if (status != NX_NOT_SUPPORTED)
        error_counter++;
#endif
}


static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;
#ifdef NX_ENABLE_DUAL_PACKET_POOL
NX_PACKET  *held[AUX_MAX_HELD];
UINT        held_count;
#endif
#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)
NXD_ADDRESS group_address;
UINT        i;
UINT        joins;
#endif

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   Driver Failure Injection Test............................");

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

#ifdef NX_ENABLE_DUAL_PACKET_POOL

    /* 1. Empty the auxiliary pool, so the stack's first allocation fails and
          it falls back to the default pool. That fallback is guarded by the
          two pools being different objects, which is the branch outcome the
          inventory records as uncovered.

          Drained in a loop because the packet count is a property of the
          configuration's alignment and padding, not of this test. */
    held_count = 0;
    while (held_count < AUX_MAX_HELD)
    {
        if (nx_packet_allocate(&auxiliary_pool, &held[held_count], NX_PHYSICAL_HEADER, NX_NO_WAIT))
            break;

        held_count++;
    }

    /* A pool that gave nothing, or one this test could not empty, makes every
       assertion below vacuous. */
    if (held_count == 0)
        error_counter++;
    if (held_count == AUX_MAX_HELD)
        error_counter++;
    if (auxiliary_pool.nx_packet_pool_available != 0)
        error_counter++;

    /* An ARP request for an address nothing will answer. */
    _nx_arp_packet_send(&ip_0, IP_ADDRESS(1, 2, 3, 99), &(ip_0.nx_ip_interface[0]));

    /* An ARP probe, as duplicate address detection sends. */
    status = _nx_arp_probe_send(&ip_0, 0, IP_ADDRESS(1, 2, 3, 4));
    if (status)
        error_counter++;

    /* An IGMP report, which allocates the same way. */
    status = nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224, 0, 0, 10));
    if (status)
        error_counter++;

    status = _nx_igmp_interface_report_send(&ip_0, IP_ADDRESS(224, 0, 0, 10), 0, NX_TRUE);
    if (status)
        error_counter++;

    status = nx_igmp_multicast_leave(&ip_0, IP_ADDRESS(224, 0, 0, 10));
    if (status)
        error_counter++;

    /* The auxiliary pool is still empty: every one of those went to the
       default pool, which is the point. */
    if (auxiliary_pool.nx_packet_pool_available != 0)
        error_counter++;

    while (held_count > 0)
    {
        held_count--;
        nx_packet_release(held[held_count]);
    }

#endif /* NX_ENABLE_DUAL_PACKET_POOL */

#ifdef NX_ENABLE_IP_PACKET_FILTER

    /* 2. An inbound filter that consumes the packet, which is the arm of
          _nx_ip_packet_receive that drops it before any protocol sees it.

          It has to be a real IP datagram: an ARP frame never reaches
          _nx_ip_packet_receive, so filtering one would prove nothing. A UDP
          datagram from ip_1 to a socket bound on ip_0 is one, and whether it
          arrives is the assertion. */
    status =  nx_udp_socket_create(&ip_0, &receiver_socket, "Receiver",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    status += nx_udp_socket_create(&ip_1, &sender_socket, "Sender",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status)
        error_counter++;

    status =  nx_udp_socket_bind(&receiver_socket, 0x89, NX_WAIT_FOREVER);
    status += nx_udp_socket_bind(&sender_socket, 0x88, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Install the filter first and let it pass one datagram through. Both
       outcomes of the one test in _nx_ip_packet_receive are wanted, and the
       passing one is only reachable with a filter installed -- sending with
       no filter at all skips the test rather than taking its other arm. */
    ip_0.nx_ip_packet_filter = inbound_filter;
    filter_consumes = NX_FALSE;

    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        nx_packet_data_append(packet_ptr, "unfiltered", 10, &pool_0, NX_WAIT_FOREVER);

        if (nx_udp_socket_send(&sender_socket, packet_ptr, IP_ADDRESS(1, 2, 3, 4), 0x89))
        {
            error_counter++;
            nx_packet_release(packet_ptr);
        }
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* It passed the filter, so it must have arrived. */
    if (nx_udp_socket_receive(&receiver_socket, &packet_ptr, NX_IP_PERIODIC_RATE))
        error_counter++;
    else
        nx_packet_release(packet_ptr);

    if (filter_in_calls == 0)
        error_counter++;

    /* Now the same datagram with the filter consuming it. */
    filter_consumes = NX_TRUE;

    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        nx_packet_data_append(packet_ptr, "filtered", 8, &pool_0, NX_WAIT_FOREVER);

        if (nx_udp_socket_send(&sender_socket, packet_ptr, IP_ADDRESS(1, 2, 3, 4), 0x89))
        {
            error_counter++;
            nx_packet_release(packet_ptr);
        }
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    filter_consumes = NX_FALSE;
    ip_0.nx_ip_packet_filter = NX_NULL;

    if (filter_in_calls == 0)
        error_counter++;

    /* The filtered datagram must not have arrived. */
    if (nx_udp_socket_receive(&receiver_socket, &packet_ptr, NX_IP_PERIODIC_RATE) != NX_NO_PACKET)
    {
        error_counter++;
        nx_packet_release(packet_ptr);
    }

    status =  nx_udp_socket_unbind(&receiver_socket);
    status += nx_udp_socket_unbind(&sender_socket);
    status += nx_udp_socket_delete(&receiver_socket);
    status += nx_udp_socket_delete(&sender_socket);
    if (status)
        error_counter++;

#endif /* NX_ENABLE_IP_PACKET_FILTER */

#if defined(NX_ENABLE_IPV6_MULTICAST) && defined(FEATURE_NX_IPV6)

    /* 3. A driver that refuses the join. The RAM driver's multicast table
          holds eight addresses, so the ninth distinct join is refused and
          nxd_ipv6_multicast_interface_join reports NX_OVERFLOW.

          The loop runs past eight deliberately: the exact number of entries
          already taken by the instance's own solicited-node addresses is not
          something this test should assume, so it joins until one is refused
          and asserts that one was. */
    group_address.nxd_ip_version = NX_IP_VERSION_V6;
    group_address.nxd_ip_address.v6[0] = 0xFF020000;
    group_address.nxd_ip_address.v6[1] = 0;
    group_address.nxd_ip_address.v6[2] = 0;

    joins = 0;
    status = NX_SUCCESS;
    for (i = 0; i < 16; i++)
    {
        group_address.nxd_ip_address.v6[3] = 0x00010000 + i;

        status = nxd_ipv6_multicast_interface_join(&ip_0, &group_address, 0);
        if (status != NX_SUCCESS)
            break;

        joins++;
    }

    if (status != NX_OVERFLOW)
        error_counter++;
    if (joins == 0)
        error_counter++;

    /* Give back what was taken, so the refusal above is the only one. */
    for (i = 0; i < joins; i++)
    {
        group_address.nxd_ip_address.v6[3] = 0x00010000 + i;
        if (nxd_ipv6_multicast_interface_leave(&ip_0, &group_address, 0))
            error_counter++;
    }

#endif /* NX_ENABLE_IPV6_MULTICAST && FEATURE_NX_IPV6 */

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


#ifdef NX_ENABLE_IP_PACKET_FILTER
static UINT    inbound_filter(VOID *ip_header_ptr, UINT direction)
{
    NX_PARAMETER_NOT_USED(ip_header_ptr);

    if (direction == NX_IP_PACKET_IN)
    {
        filter_in_calls++;

        if (filter_consumes == NX_TRUE)
            return(NX_NOT_SUCCESSFUL);
    }

    return(NX_SUCCESS);
}
#endif /* NX_ENABLE_IP_PACKET_FILTER */

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_driver_failure_injection_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Driver Failure Injection Test............................N/A\n");
    test_control_return(3);
}

#endif
