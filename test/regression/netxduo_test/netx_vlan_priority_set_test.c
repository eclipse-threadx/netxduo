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

/* This NetX test concentrates on the VLAN priority setters -- the three
   nx_*_vlan_priority_set entry points and their nxe_* error-checking shells,
   which between them are four of the files the gap inventory records as
   having no covered line at all.

   It does not go N/A outside NX_ENABLE_VLAN, and that is the point of it.
   Each setter has a second arm that returns NX_NOT_SUPPORTED when VLAN is
   compiled out, and that arm is only reachable from a configuration without
   the feature. So the test asserts the refusal there and the behaviour here,
   and runs everywhere either way. */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#ifdef NX_ENABLE_VLAN
#include   "nx_link.h"
#endif

#define     DEMO_STACK_SIZE         2048
#define     VLAN_TAG                0x2064
#define     SERVER_PORT             0x89
#define     CLIENT_PORT             0x88

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_UDP_SOCKET           udp_socket;

static ULONG                   error_counter;

static void    thread_0_entry(ULONG thread_input);

extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_vlan_priority_set_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

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

    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    status += nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);
    if (status)
        error_counter++;
}


static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   VLAN Priority Set Test...................................");

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;

    status =  nx_udp_socket_create(&ip_0, &udp_socket, "UDP Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status)
        error_counter++;

    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

#ifdef NX_ENABLE_VLAN

    /* 1. The parameter-checking arms of the nxe_* shells. They sit inside the
          same #ifdef as everything else in those files -- which is why they
          are asserted here and not before the #ifdef: with VLAN compiled out
          there is no pointer check to reach, only the single
          NX_NOT_SUPPORTED return the #else arm below drives. */
    if (nx_tcp_socket_vlan_priority_set(NX_NULL, 0) != NX_PTR_ERROR)
        error_counter++;
    if (nx_udp_socket_vlan_priority_set(NX_NULL, 0) != NX_PTR_ERROR)
        error_counter++;
    if (nx_packet_vlan_priority_set(NX_NULL, 0) != NX_PTR_ERROR)
        error_counter++;

    if (nx_tcp_socket_vlan_priority_set(&client_socket, NX_VLAN_PRIORITY_MAX + 1) != NX_INVALID_PARAMETERS)
        error_counter++;
    if (nx_udp_socket_vlan_priority_set(&udp_socket, NX_VLAN_PRIORITY_MAX + 1) != NX_INVALID_PARAMETERS)
        error_counter++;
    if (packet_ptr &&
        (nx_packet_vlan_priority_set(packet_ptr, NX_VLAN_PRIORITY_MAX + 1) != NX_INVALID_PARAMETERS))
        error_counter++;

    /* 2. A valid priority, which is recorded on the socket and the packet. */
    if (nx_tcp_socket_vlan_priority_set(&client_socket, NX_VLAN_PRIORITY_MAX))
        error_counter++;
    if (client_socket.nx_tcp_socket_vlan_priority != NX_VLAN_PRIORITY_MAX)
        error_counter++;

    if (nx_udp_socket_vlan_priority_set(&udp_socket, 3))
        error_counter++;
    if (udp_socket.nx_udp_socket_vlan_priority != 3)
        error_counter++;

    if (packet_ptr)
    {
        if (nx_packet_vlan_priority_set(packet_ptr, 5))
            error_counter++;
        if (packet_ptr -> nx_packet_vlan_priority != 5)
            error_counter++;
    }

    /* 3. A datagram actually sent with that priority, so the priority is
          read back out of the socket on the send path rather than only
          written into it. */
    if (nx_link_vlan_set(&ip_0, 0, VLAN_TAG))
        error_counter++;
    if (nx_link_vlan_set(&ip_1, 0, VLAN_TAG))
        error_counter++;

    if (nx_udp_socket_bind(&udp_socket, CLIENT_PORT, NX_WAIT_FOREVER))
        error_counter++;

    if (packet_ptr)
    {
        nx_packet_data_append(packet_ptr, "priority", 8, &pool_0, NX_WAIT_FOREVER);

        status = nx_udp_socket_send(&udp_socket, packet_ptr, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT);
        if (status)
        {
            error_counter++;
            nx_packet_release(packet_ptr);
        }

        /* Consumed by the send either way. */
        packet_ptr = NX_NULL;
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    if (nx_udp_socket_unbind(&udp_socket))
        error_counter++;

#else

    /* The whole of each nxe_* shell is compiled out here, so every call
       returns NX_NOT_SUPPORTED whatever it is passed -- a null pointer and an
       out-of-range priority included. That is the arm this configuration
       exists to cover, and asserting a pointer error here would assert
       behaviour the build does not contain. */
    if (nx_tcp_socket_vlan_priority_set(&client_socket, NX_VLAN_PRIORITY_MAX) != NX_NOT_SUPPORTED)
        error_counter++;
    if (nx_udp_socket_vlan_priority_set(&udp_socket, 3) != NX_NOT_SUPPORTED)
        error_counter++;
    if (packet_ptr && (nx_packet_vlan_priority_set(packet_ptr, 5) != NX_NOT_SUPPORTED))
        error_counter++;

    if (nx_tcp_socket_vlan_priority_set(NX_NULL, 0) != NX_NOT_SUPPORTED)
        error_counter++;
    if (nx_udp_socket_vlan_priority_set(NX_NULL, 0) != NX_NOT_SUPPORTED)
        error_counter++;
    if (nx_packet_vlan_priority_set(NX_NULL, 0) != NX_NOT_SUPPORTED)
        error_counter++;

#endif /* NX_ENABLE_VLAN */

    if (packet_ptr)
        nx_packet_release(packet_ptr);

    if (nx_udp_socket_delete(&udp_socket))
        error_counter++;
    if (nx_tcp_socket_delete(&client_socket))
        error_counter++;

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

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_vlan_priority_set_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   VLAN Priority Set Test...................................N/A\n");
    test_control_return(3);
}

#endif
