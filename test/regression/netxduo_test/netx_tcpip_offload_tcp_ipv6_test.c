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

/* This NetX test is the IPv6 half of netx_tcpip_offload_tcp_test: a TCP
   connection established, used and closed entirely through the TCP/IP offload
   handler, over IPv6.

   It exists as its own file because the receive side is where IPv6 offload
   differs. _nx_tcp_socket_driver_packet_receive fabricates an IPv6 header with
   _nx_ipv6_header_add, which reads
   nx_packet_address.nx_packet_ipv6_address_ptr, while the deferred receive
   behind it reads nx_packet_address.nx_packet_interface_ptr -- two members of
   one union that the driver writes once. Until the receive routine learned to
   save the interface and put it back around the call, no driver could satisfy
   both and an IPv6 offload socket could not receive at all. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcpip_offload_driver.h"

extern void    test_control_return(UINT status);

#if defined(NX_ENABLE_TCPIP_OFFLOAD) && defined(FEATURE_NX_IPV6)

#define     DEMO_STACK_SIZE         2048
#define     SERVER_PORT             12
#define     CLIENT_PORT             13

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;

static NXD_ADDRESS             ipv6_address_0;
static NXD_ADDRESS             ipv6_address_1;

static ULONG                   error_counter;
static ULONG                   connections;
static ULONG                   server_receives;
static ULONG                   client_receives;

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    connect_received(NX_TCP_SOCKET *socket_ptr, UINT port);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcpip_offload_tcp_ipv6_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    pointer =  (CHAR *) first_unused_memory;

    error_counter =   0;
    connections =     0;
    server_receives = 0;
    client_receives = 0;

    nx_tcpip_offload_driver_reset();

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
            pointer, DEMO_STACK_SIZE, 4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
            pointer, DEMO_STACK_SIZE, 3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
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

    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    if (status)
        error_counter++;

    status =  nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    if (status)
        error_counter++;

    /* Set at define time so duplicate address detection finishes while the
       threads are still starting. */
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
}


/* The client. */
static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;
ULONG       length;
UCHAR       buffer[32];

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP/IP Offload TCP IPv6 Test..............................");

    /* Long enough for duplicate address detection on both instances. */
    tx_thread_sleep(6 * NX_IP_PERIODIC_RATE);

    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;

    status =  nx_tcp_client_socket_bind(&client_socket, CLIENT_PORT, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    status =  nxd_tcp_client_socket_connect(&client_socket, &ipv6_address_1, SERVER_PORT,
                                            5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    if (client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED)
        error_counter++;

    /* The connection has to be IPv6, or this test is the IPv4 one again. */
    if (client_socket.nx_tcp_socket_connect_ip.nxd_ip_version != NX_IP_VERSION_V6)
        error_counter++;

    /* The engine reports the server side from its own thread, so the
       connection is complete at this end before it is complete at the other.
       Sending before the far end is up gets the datagram refused, which is
       the engine behaving correctly rather than a protocol error -- real
       offload hardware completes a handshake asynchronously too. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_TCP_SERVER_SOCKET_ACCEPT] == 0)
        error_counter++;

    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        nx_packet_data_append(packet_ptr, "offload v6 client", 17, &pool_0, NX_WAIT_FOREVER);

        status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);
        if (status)
        {
            error_counter++;
            nx_packet_release(packet_ptr);
        }
    }

    /* The reply arrives through _nx_tcp_socket_driver_packet_receive's IPv6
       arm, which is the path this test exists for. */
    status = nx_tcp_socket_receive(&client_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
    {
        length = 0;
        nx_packet_data_retrieve(packet_ptr, buffer, &length);
        if ((length != 17) || (memcmp(buffer, "offload v6 server", 17) != 0))
            error_counter++;
        client_receives++;
        nx_packet_release(packet_ptr);
    }

    status =  nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    status =  nx_tcp_client_socket_unbind(&client_socket);
    if (status)
        error_counter++;

    status =  nx_tcp_socket_delete(&client_socket);
    if (status)
        error_counter++;

    tx_thread_sleep(6 * NX_IP_PERIODIC_RATE);

    if ((connections != 1) || (server_receives != 1) || (client_receives != 1))
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


/* The server. */
static void    thread_1_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;
ULONG       length;
UCHAR       buffer[32];

    NX_PARAMETER_NOT_USED(thread_input);

    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;

    status =  nx_tcp_server_socket_listen(&ip_1, SERVER_PORT, &server_socket, 5, connect_received);
    if (status)
        error_counter++;

    status =  nx_tcp_server_socket_accept(&server_socket, 20 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
    {
        length = 0;
        nx_packet_data_retrieve(packet_ptr, buffer, &length);
        if ((length != 17) || (memcmp(buffer, "offload v6 client", 17) != 0))
            error_counter++;
        server_receives++;
        nx_packet_release(packet_ptr);
    }

    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        nx_packet_data_append(packet_ptr, "offload v6 server", 17, &pool_0, NX_WAIT_FOREVER);

        status = nx_tcp_socket_send(&server_socket, packet_ptr, NX_IP_PERIODIC_RATE);
        if (status)
        {
            error_counter++;
            nx_packet_release(packet_ptr);
        }
    }

    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);

    nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);
    nx_tcp_server_socket_unaccept(&server_socket);
    nx_tcp_server_socket_unlisten(&ip_1, SERVER_PORT);
    nx_tcp_socket_delete(&server_socket);
}


static void  connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{
    if ((socket_ptr != &server_socket) || (port != SERVER_PORT))
        error_counter++;

    connections++;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcpip_offload_tcp_ipv6_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP/IP Offload TCP IPv6 Test..............................N/A\n");
    test_control_return(3);
}

#endif
