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

/* This NetX test concentrates on the caller check of the error-checking
   shells whose service is compiled only under a feature macro.
   netx_caller_check_test covers the shells every configuration compiles, and
   none of these.

   Two macros are involved, and each rejects a different set of callers:

     NX_INIT_AND_THREADS_CALLER_CHECKING  an ISR, or the timer thread.
                                          Initialization is accepted.
     NX_THREADS_ONLY_CALLER_CHECKING      an ISR or initialization, no
                                          current thread, or the timer thread.

   So every arm is driven from the context that takes it, and three of the
   four are real: initialization is test_application_define, which runs
   inside tx_application_define, and the timer thread is a timer's expiration
   function. Only an ISR and an absent current thread are forged, the way
   netx_caller_check_test forges them, with interrupts disabled across the
   forgery. That is safe because every call made under it returns at the
   caller check, before anything that would disable interrupts itself -- an
   interrupt control call made with no current thread ends the Linux thread
   that made it. The NX_INIT_AND_THREADS shells are therefore never called
   with the current thread forged away: they accept that caller and would run
   the service. */

#include   "tx_api.h"
#include   "tx_initialize.h"
#include   "tx_thread.h"
#include   "tx_timer.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING)

#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
#define TEST_EXTENDED_NOTIFY
#endif
#if defined(FEATURE_NX_IPV6) && defined(NX_ENABLE_IPV6_ADDRESS_CHANGE_NOTIFY)
#define TEST_ADDRESS_CHANGE_NOTIFY
#endif
#if defined(FEATURE_NX_IPV6) && defined(NX_ENABLE_IPV6_MULTICAST)
#define TEST_IPV6_MULTICAST
#endif
#if defined(FEATURE_NX_IPV6) && defined(NX_IPV6_STATELESS_AUTOCONFIG_CONTROL)
#define TEST_STATELESS_AUTOCONFIG
#endif
#ifdef NX_ENABLE_DUAL_PACKET_POOL
#define TEST_DUAL_PACKET_POOL
#endif
#ifdef NX_ENABLE_INTERFACE_CAPABILITY
#define TEST_INTERFACE_CAPABILITY
#endif
#ifdef NX_ENABLE_IP_RAW_PACKET_FILTER
#define TEST_RAW_PACKET_FILTER
#endif
#if !defined(NX_DISABLE_IPV4) && defined(NX_ENABLE_IP_STATIC_ROUTING)
#define TEST_STATIC_ROUTING
#endif
#ifdef NX_ENABLE_TCP_QUEUE_DEPTH_UPDATE_NOTIFY
#define TEST_QUEUE_DEPTH_NOTIFY
#endif

#endif /* !NX_DISABLE_ERROR_CHECKING */

#if defined(TEST_EXTENDED_NOTIFY) || defined(TEST_ADDRESS_CHANGE_NOTIFY) || \
    defined(TEST_IPV6_MULTICAST) || defined(TEST_STATELESS_AUTOCONFIG) || \
    defined(TEST_DUAL_PACKET_POOL) || defined(TEST_INTERFACE_CAPABILITY) || \
    defined(TEST_RAW_PACKET_FILTER) || defined(TEST_STATIC_ROUTING) || \
    defined(TEST_QUEUE_DEPTH_NOTIFY)

#define     DEMO_STACK_SIZE         2048

/* Inside 1.2.3.0/24, the network of the only interface, as a static route's
   next hop has to be. */
#define     ROUTE_NETWORK           IP_ADDRESS(10, 0, 0, 0)
#define     ROUTE_MASK              0xFF000000UL
#define     ROUTE_NEXT_HOP          IP_ADDRESS(1, 2, 3, 1)

static TX_THREAD               thread_0;
static TX_TIMER                timer_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           tcp_socket;

#ifdef TEST_IPV6_MULTICAST
static NXD_ADDRESS             group_address;
#endif

static ULONG                   error_counter;

/* Written by the timer's expiration function and read by thread 0. */
static volatile UINT           timer_done;
static volatile UINT           timer_failures;

static void    thread_0_entry(ULONG thread_input);
static void    timer_0_entry(ULONG timer_input);
static UINT    init_and_threads_calls(void);
static UINT    threads_only_calls(void);

#if defined(TEST_EXTENDED_NOTIFY) || defined(TEST_QUEUE_DEPTH_NOTIFY)
static VOID    tcp_notify(NX_TCP_SOCKET *socket_ptr);
#endif
#ifdef TEST_ADDRESS_CHANGE_NOTIFY
static VOID    address_change_notify(NX_IP *ip_ptr, UINT status, UINT interface_index,
                                     UINT address_index, ULONG *ip_address);
#endif
#ifdef TEST_RAW_PACKET_FILTER
static UINT    raw_packet_filter(NX_IP *ip_ptr, ULONG protocol, NX_PACKET *packet_ptr);
#endif

extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_gated_caller_check_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;
#ifdef TEST_INTERFACE_CAPABILITY
ULONG   capability;
#endif

    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 16384);
    pointer = pointer + 16384;
    if (status)
        error_counter++;

    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0,
                          _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status =  nx_tcp_enable(&ip_0);
    if (status)
        error_counter++;

    status =  nx_tcp_socket_create(&ip_0, &tcp_socket, "TCP Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;

#ifdef TEST_IPV6_MULTICAST
    group_address.nxd_ip_version = NX_IP_VERSION_V6;
    group_address.nxd_ip_address.v6[0] = 0xFF020000;
    group_address.nxd_ip_address.v6[1] = 0;
    group_address.nxd_ip_address.v6[2] = 0;
    group_address.nxd_ip_address.v6[3] = 0x00010003;
#endif

    /* 1. Initialization. The NX_INIT_AND_THREADS shells accept this caller
          and run the service, so each must return the service's own status;
          the NX_THREADS_ONLY shells refuse it. Under CTEST this function runs
          inside tx_application_define, so the system state is
          TX_INITIALIZE_IN_PROGRESS and is not forged.  */
    if (TX_THREAD_GET_SYSTEM_STATE() < TX_INITIALIZE_IN_PROGRESS)
        error_counter++;

#ifdef TEST_EXTENDED_NOTIFY
    if (nx_tcp_socket_establish_notify(&tcp_socket, tcp_notify) != NX_SUCCESS)
        error_counter++;
    if (nx_tcp_socket_disconnect_complete_notify(&tcp_socket, tcp_notify) != NX_SUCCESS)
        error_counter++;
    if (nx_tcp_socket_timed_wait_callback(&tcp_socket, tcp_notify) != NX_SUCCESS)
        error_counter++;
#endif
#ifdef TEST_STATELESS_AUTOCONFIG
    if (nxd_ipv6_stateless_address_autoconfig_disable(&ip_0, 0) != NX_SUCCESS)
        error_counter++;
    if (nxd_ipv6_stateless_address_autoconfig_enable(&ip_0, 0) != NX_SUCCESS)
        error_counter++;
#endif
#ifdef TEST_DUAL_PACKET_POOL
    if (nx_ip_auxiliary_packet_pool_set(&ip_0, &pool_0) != NX_SUCCESS)
        error_counter++;
#endif
#ifdef TEST_INTERFACE_CAPABILITY
    if (nx_ip_interface_capability_get(&ip_0, 0, &capability) != NX_SUCCESS)
        error_counter++;
    else if (nx_ip_interface_capability_set(&ip_0, 0, capability) != NX_SUCCESS)
        error_counter++;
#endif
#ifdef TEST_RAW_PACKET_FILTER
    if (nx_ip_raw_packet_filter_set(&ip_0, raw_packet_filter) != NX_SUCCESS)
        error_counter++;
#endif
#ifdef TEST_STATIC_ROUTING
    if (nx_ip_static_route_add(&ip_0, ROUTE_NETWORK, ROUTE_MASK, ROUTE_NEXT_HOP) != NX_SUCCESS)
        error_counter++;
    if (nx_ip_static_route_delete(&ip_0, ROUTE_NETWORK, ROUTE_MASK) != NX_SUCCESS)
        error_counter++;
#endif

    error_counter += threads_only_calls();
}


/* Every call is made with arguments that pass each check ahead of the caller
   check, so that it is the caller check which answers. Each returns how many
   calls it answered with anything but NX_CALLER_ERROR.  */
static UINT    init_and_threads_calls(void)
{

UINT    failures = 0;
#ifdef TEST_INTERFACE_CAPABILITY
ULONG   capability;
#endif

#ifdef TEST_EXTENDED_NOTIFY
    if (nx_tcp_socket_establish_notify(&tcp_socket, tcp_notify) != NX_CALLER_ERROR)
        failures++;
    if (nx_tcp_socket_disconnect_complete_notify(&tcp_socket, tcp_notify) != NX_CALLER_ERROR)
        failures++;
    if (nx_tcp_socket_timed_wait_callback(&tcp_socket, tcp_notify) != NX_CALLER_ERROR)
        failures++;
#endif
#ifdef TEST_STATELESS_AUTOCONFIG
    if (nxd_ipv6_stateless_address_autoconfig_disable(&ip_0, 0) != NX_CALLER_ERROR)
        failures++;
    if (nxd_ipv6_stateless_address_autoconfig_enable(&ip_0, 0) != NX_CALLER_ERROR)
        failures++;
#endif
#ifdef TEST_DUAL_PACKET_POOL
    if (nx_ip_auxiliary_packet_pool_set(&ip_0, &pool_0) != NX_CALLER_ERROR)
        failures++;
#endif
#ifdef TEST_INTERFACE_CAPABILITY
    if (nx_ip_interface_capability_get(&ip_0, 0, &capability) != NX_CALLER_ERROR)
        failures++;
    if (nx_ip_interface_capability_set(&ip_0, 0, 0) != NX_CALLER_ERROR)
        failures++;
#endif
#ifdef TEST_RAW_PACKET_FILTER
    if (nx_ip_raw_packet_filter_set(&ip_0, raw_packet_filter) != NX_CALLER_ERROR)
        failures++;
#endif
#ifdef TEST_STATIC_ROUTING
    if (nx_ip_static_route_add(&ip_0, ROUTE_NETWORK, ROUTE_MASK, ROUTE_NEXT_HOP) != NX_CALLER_ERROR)
        failures++;
    if (nx_ip_static_route_delete(&ip_0, ROUTE_NETWORK, ROUTE_MASK) != NX_CALLER_ERROR)
        failures++;
#endif

    return(failures);
}


static UINT    threads_only_calls(void)
{

UINT    failures = 0;

#ifdef TEST_ADDRESS_CHANGE_NOTIFY
    if (nxd_ipv6_address_change_notify(&ip_0, address_change_notify) != NX_CALLER_ERROR)
        failures++;
#endif
#ifdef TEST_IPV6_MULTICAST
    if (nxd_ipv6_multicast_interface_join(&ip_0, &group_address, 0) != NX_CALLER_ERROR)
        failures++;
    if (nxd_ipv6_multicast_interface_leave(&ip_0, &group_address, 0) != NX_CALLER_ERROR)
        failures++;
#endif
#ifdef TEST_QUEUE_DEPTH_NOTIFY
    if (nx_tcp_socket_queue_depth_notify_set(&tcp_socket, tcp_notify) != NX_CALLER_ERROR)
        failures++;
#endif

    return(failures);
}


static void    timer_0_entry(ULONG timer_input)
{

    NX_PARAMETER_NOT_USED(timer_input);

    /* Not forged: an expiration function runs in the timer thread.  */
    if (_tx_thread_current_ptr != &_tx_timer_thread)
        timer_failures++;

    timer_failures += init_and_threads_calls();
    timer_failures += threads_only_calls();
    timer_done = NX_TRUE;
}


static void    thread_0_entry(ULONG thread_input)
{

TX_INTERRUPT_SAVE_AREA
ULONG       old_state;
TX_THREAD  *old_thread;
UINT        failures;
UINT        i;

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   Gated Caller Check Test..................................");

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* 2. An ISR, forged. Both macros refuse it.  */
    TX_DISABLE
    old_state = _tx_thread_system_state;
    _tx_thread_system_state = 1;

    failures =  init_and_threads_calls();
    failures += threads_only_calls();

    _tx_thread_system_state = old_state;
    TX_RESTORE

    error_counter += failures;

    /* 3. No current thread, forged. Only NX_THREADS_ONLY refuses it.  */
    TX_DISABLE
    old_thread = _tx_thread_current_ptr;
    _tx_thread_current_ptr = TX_NULL;

    failures = threads_only_calls();

    _tx_thread_current_ptr = old_thread;
    TX_RESTORE

    error_counter += failures;

    /* 4. The timer thread. Both macros refuse it.  */
    timer_done = NX_FALSE;
    timer_failures = 0;
    if (tx_timer_create(&timer_0, "Caller check timer", timer_0_entry, 0, 1, 0, TX_AUTO_ACTIVATE))
        error_counter++;

    for (i = 0; (i < 10 * NX_IP_PERIODIC_RATE) && !timer_done; i++)
        tx_thread_sleep(1);

    if (!timer_done)
        error_counter++;
    error_counter += timer_failures;

    tx_timer_delete(&timer_0);

    /* 5. A thread, which both macros accept. This is the control for the
          NX_THREADS_ONLY shells: the same arguments succeed here, so the
          refusals above came from the caller and not from the arguments.
          Initialization is the NX_INIT_AND_THREADS shells' control, in 1.  */
#ifdef TEST_ADDRESS_CHANGE_NOTIFY
    if (nxd_ipv6_address_change_notify(&ip_0, address_change_notify) != NX_SUCCESS)
        error_counter++;
#endif
#ifdef TEST_IPV6_MULTICAST
    if (nxd_ipv6_multicast_interface_join(&ip_0, &group_address, 0) != NX_SUCCESS)
        error_counter++;
    if (nxd_ipv6_multicast_interface_leave(&ip_0, &group_address, 0) != NX_SUCCESS)
        error_counter++;
#endif
#ifdef TEST_QUEUE_DEPTH_NOTIFY
    if (nx_tcp_socket_queue_depth_notify_set(&tcp_socket, tcp_notify) != NX_SUCCESS)
        error_counter++;
#endif

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

#if defined(TEST_EXTENDED_NOTIFY) || defined(TEST_QUEUE_DEPTH_NOTIFY)
static VOID    tcp_notify(NX_TCP_SOCKET *socket_ptr)
{
    NX_PARAMETER_NOT_USED(socket_ptr);
}
#endif

#ifdef TEST_ADDRESS_CHANGE_NOTIFY
static VOID    address_change_notify(NX_IP *ip_ptr, UINT status, UINT interface_index,
                                     UINT address_index, ULONG *ip_address)
{
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(status);
    NX_PARAMETER_NOT_USED(interface_index);
    NX_PARAMETER_NOT_USED(address_index);
    NX_PARAMETER_NOT_USED(ip_address);
}
#endif

#ifdef TEST_RAW_PACKET_FILTER
static UINT    raw_packet_filter(NX_IP *ip_ptr, ULONG protocol, NX_PACKET *packet_ptr)
{
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(protocol);
    NX_PARAMETER_NOT_USED(packet_ptr);

    return(NX_SUCCESS);
}
#endif

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_gated_caller_check_test_application_define(void *first_unused_memory)
#endif
{

    NX_PARAMETER_NOT_USED(first_unused_memory);

    printf("NetX Test:   Gated Caller Check Test..................................N/A\n");

    test_control_return(3);
}
#endif
