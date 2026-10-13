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

/* This NetX test concentrates on the UDP half of the TCP/IP offload
   interface: bind, send, receive and unbind over both IPv4 and IPv6, a bind
   the driver refuses, and a send the driver fails.

   It also installs an IP packet filter and an extended IP packet filter,
   because _nxd_udp_socket_send builds a throwaway IP header before the
   offload send purely so a filter can see one, and that header-build is
   compiled only when both NX_ENABLE_TCPIP_OFFLOAD and
   NX_ENABLE_IP_PACKET_FILTER are set. Without a filter installed the whole
   block is skipped and the send proves nothing about it. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcpip_offload_driver.h"

extern void    test_control_return(UINT status);

#if defined(NX_ENABLE_TCPIP_OFFLOAD) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048
#define     SERVER_PORT             0x89
#define     CLIENT_PORT             0x88

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_UDP_SOCKET           client_socket;
static NX_UDP_SOCKET           server_socket;

static ULONG                   error_counter;
static ULONG                   filter_calls;
static ULONG                   filter_extended_calls;

/* When NX_TRUE the filter consumes the datagram instead of passing it, which
   is the arm that returns early and releases the packet. */
static UINT                    filter_consumes;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             ipv6_address_0;
static NXD_ADDRESS             ipv6_address_1;
#endif

static void    thread_0_entry(ULONG thread_input);
#ifdef NX_ENABLE_IP_PACKET_FILTER
static UINT    my_packet_filter(VOID *ip_header_ptr, UINT direction);
static UINT    my_packet_filter_extended(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT direction);
#endif /* NX_ENABLE_IP_PACKET_FILTER */
static UINT    exchange(NXD_ADDRESS *destination);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcpip_offload_udp_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    pointer =  (CHAR *) first_unused_memory;

    error_counter =         0;
    filter_calls =          0;
    filter_extended_calls = 0;
    filter_consumes =       NX_FALSE;

    nx_tcpip_offload_driver_reset();

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
                          nx_tcpip_offload_driver, pointer, 2048, 1);
    pointer =  pointer + 2048;

    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0,
                           nx_tcpip_offload_driver, pointer, 2048, 1);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    status =  nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    if (status)
        error_counter++;

    /* Set here rather than in the thread because duplicate address detection
       has to finish before the address can be a source, and doing it at
       define time lets it run while the threads are still starting. */
    ipv6_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_0.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_0.nxd_ip_address.v6[1] = 0;
    ipv6_address_0.nxd_ip_address.v6[2] = 0;
    ipv6_address_0.nxd_ip_address.v6[3] = 1;

    ipv6_address_1 = ipv6_address_0;
    ipv6_address_1.nxd_ip_address.v6[3] = 2;

    status =  nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_1, 64, NX_NULL);
    if (status)
        error_counter++;
#endif
}


/* Sends one datagram from the client to the server and reads it back out,
   returning NX_SUCCESS when the round trip worked. */
static UINT    exchange(NXD_ADDRESS *destination)
{

UINT        status;
NX_PACKET  *packet_ptr;
ULONG       length;
UCHAR       buffer[32];

    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        return(status);

    status = nx_packet_data_append(packet_ptr, "offload udp", 11, &pool_0, NX_WAIT_FOREVER);
    if (status)
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    status = nxd_udp_socket_send(&client_socket, packet_ptr, destination, SERVER_PORT);
    if (status)
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    status = nx_udp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        return(status);

    length = 0;
    nx_packet_data_retrieve(packet_ptr, buffer, &length);
    nx_packet_release(packet_ptr);

    if ((length != 11) || (memcmp(buffer, "offload udp", 11) != 0))
        return(NX_NOT_SUCCESSFUL);

    return(NX_SUCCESS);
}


static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;
NXD_ADDRESS destination;
#ifdef FEATURE_NX_IPV6
ULONG       sends_before;
#endif

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP/IP Offload UDP Test...................................");

    /* Long enough for duplicate address detection on both instances to
       finish, which is what makes the IPv6 address usable as a source. */
    tx_thread_sleep(6 * NX_IP_PERIODIC_RATE);

    if ((ip_0.nx_ip_interface[0].nx_interface_capability_flag &
         NX_INTERFACE_CAPABILITY_TCPIP_OFFLOAD) == 0)
        error_counter++;

    status =  nx_udp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    status += nx_udp_socket_create(&ip_1, &server_socket, "Server Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status)
        error_counter++;

    /* 1. A bind the driver refuses. _nx_udp_socket_bind unwinds it through
          _nx_udp_socket_unbind and reports NX_TCPIP_OFFLOAD_ERROR. */
    nx_tcpip_offload_bind_failure = NX_TRUE;
    status = nx_udp_socket_bind(&client_socket, CLIENT_PORT, NX_IP_PERIODIC_RATE);
    if (status != NX_TCPIP_OFFLOAD_ERROR)
        error_counter++;
    nx_tcpip_offload_bind_failure = NX_FALSE;

    status =  nx_udp_socket_bind(&client_socket, CLIENT_PORT, NX_WAIT_FOREVER);
    status += nx_udp_socket_bind(&server_socket, SERVER_PORT, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_UDP_SOCKET_BIND] == 0)
        error_counter++;

    /* 2. An IPv4 round trip with no filter installed. */
    destination.nxd_ip_version = NX_IP_VERSION_V4;
    destination.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    if (exchange(&destination))
        error_counter++;

#ifdef FEATURE_NX_IPV6

    /* 3. The same over IPv6, asserted as a full round trip.

          It could not be until the union handling in
          _nx_udp_socket_driver_packet_receive was fixed:
          _nx_ipv6_header_add reads
          nx_packet_address.nx_packet_ipv6_address_ptr and the deferred
          receive behind it reads nx_packet_address.nx_packet_interface_ptr,
          two members of one slot the driver writes once. The receive routine
          now saves the interface, resolves the local address, and puts the
          interface back around the call. */
    if (exchange(&ipv6_address_1))
        error_counter++;
#endif /* FEATURE_NX_IPV6 */

#ifdef NX_ENABLE_IP_PACKET_FILTER

    /* 4. IPv4 again with both filters installed and passing, which is what
          runs the IPv4 header-build block that exists only to give a filter
          something to look at. The block is compiled only when the filter
          feature is, and v4_link_cap_build is an offload configuration
          without it, so everything that touches a filter is guarded. */
    ip_0.nx_ip_packet_filter = my_packet_filter;
    ip_0.nx_ip_packet_filter_extended = my_packet_filter_extended;

    if (exchange(&destination))
        error_counter++;

    if ((filter_calls == 0) || (filter_extended_calls == 0))
        error_counter++;
#endif /* NX_ENABLE_IP_PACKET_FILTER */

#ifdef FEATURE_NX_IPV6

    /* 5. The IPv6 arm of that same block. _nx_ipv6_header_add may consume the
          datagram here -- the destination's neighbour entry is not resolved,
          because an offload interface never runs neighbour discovery -- and
          that consumed arm is itself one of the lines this step is here to
          reach. So the send must succeed and the datagram may or may not
          arrive; what is asserted is the send, not the delivery. */
    sends_before = nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_UDP_SOCKET_SEND];

    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        nx_packet_data_append(packet_ptr, "offload udp", 11, &pool_0, NX_WAIT_FOREVER);

        status = nxd_udp_socket_send(&client_socket, packet_ptr, &ipv6_address_1, SERVER_PORT);
        if (status)
            error_counter++;
    }

    /* _nx_ipv6_header_add may consume the datagram in this arm, because an
       offload interface runs no neighbour discovery, so the handler is not
       required to have seen it. The send itself must still report success. */
    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_UDP_SOCKET_SEND] > sends_before + 1)
        error_counter++;

    /* Drain anything that did arrive, so it cannot be mistaken for the
       consumed datagram the next step checks for. */
    if (nx_udp_socket_receive(&server_socket, &packet_ptr, NX_IP_PERIODIC_RATE) == NX_SUCCESS)
        nx_packet_release(packet_ptr);
#endif /* FEATURE_NX_IPV6 */

#ifdef NX_ENABLE_IP_PACKET_FILTER

    /* 6. A filter that consumes the datagram. Both filters take the same arm,
          so each is driven in turn. */
    filter_consumes = NX_TRUE;

    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        nx_packet_data_append(packet_ptr, "consumed", 8, &pool_0, NX_WAIT_FOREVER);

        /* A consumed datagram still reports success: it was handled, not
           rejected. What must not happen is it arriving. */
        status = nxd_udp_socket_send(&client_socket, packet_ptr, &destination, SERVER_PORT);
        if (status)
            error_counter++;
    }

    status = nx_udp_socket_receive(&server_socket, &packet_ptr, NX_IP_PERIODIC_RATE);
    if (status != NX_NO_PACKET)
    {
        error_counter++;
        if (status == NX_SUCCESS)
            nx_packet_release(packet_ptr);
    }

    filter_consumes = NX_FALSE;

    /* Let the extended filter take the consuming arm on its own. */
    ip_0.nx_ip_packet_filter = NX_NULL;
    filter_consumes = NX_TRUE;

    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        nx_packet_data_append(packet_ptr, "consumed", 8, &pool_0, NX_WAIT_FOREVER);
        status = nxd_udp_socket_send(&client_socket, packet_ptr, &destination, SERVER_PORT);
        if (status)
            error_counter++;
    }

    filter_consumes = NX_FALSE;
    ip_0.nx_ip_packet_filter_extended = NX_NULL;
#endif /* NX_ENABLE_IP_PACKET_FILTER */

    /* 7. A send the driver fails, which is the NX_TCPIP_OFFLOAD_ERROR return
          in _nxd_udp_socket_send. */
    nx_tcpip_offload_send_failure = NX_TRUE;
    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        nx_packet_data_append(packet_ptr, "fail", 4, &pool_0, NX_WAIT_FOREVER);
        status = nxd_udp_socket_send(&client_socket, packet_ptr, &destination, SERVER_PORT);
        if (status != NX_TCPIP_OFFLOAD_ERROR)
            error_counter++;
        nx_packet_release(packet_ptr);
    }
    nx_tcpip_offload_send_failure = NX_FALSE;

    /* 8. A datagram to a port nothing is bound to. The engine drops it, which
          is what UDP does, and the send still succeeds. */
    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        nx_packet_data_append(packet_ptr, "nowhere", 7, &pool_0, NX_WAIT_FOREVER);
        status = nxd_udp_socket_send(&client_socket, packet_ptr, &destination, SERVER_PORT + 40);
        if (status)
            error_counter++;
    }

    status =  nx_udp_socket_unbind(&client_socket);
    status += nx_udp_socket_unbind(&server_socket);
    if (status)
        error_counter++;

    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_UDP_SOCKET_UNBIND] == 0)
        error_counter++;
    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_UDP_SOCKET_SEND] == 0)
        error_counter++;

    status =  nx_udp_socket_delete(&client_socket);
    status += nx_udp_socket_delete(&server_socket);
    if (status)
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


#ifdef NX_ENABLE_IP_PACKET_FILTER
static UINT    my_packet_filter(VOID *ip_header_ptr, UINT direction)
{
    NX_PARAMETER_NOT_USED(ip_header_ptr);

    if (direction == NX_IP_PACKET_OUT)
        filter_calls++;

    if (filter_consumes == NX_TRUE)
        return(NX_NOT_SUCCESSFUL);

    return(NX_SUCCESS);
}


static UINT    my_packet_filter_extended(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT direction)
{
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(packet_ptr);

    if (direction == NX_IP_PACKET_OUT)
        filter_extended_calls++;

    if (filter_consumes == NX_TRUE)
        return(NX_NOT_SUCCESSFUL);

    return(NX_SUCCESS);
}
#endif /* NX_ENABLE_IP_PACKET_FILTER */

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcpip_offload_udp_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP/IP Offload UDP Test...................................N/A\n");
    test_control_return(3);
}

#endif
