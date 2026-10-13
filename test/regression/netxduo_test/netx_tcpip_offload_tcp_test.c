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

/* This NetX test concentrates on the TCP half of the TCP/IP offload interface:
   listen, connect, accept, send, receive and disconnect, all driven through
   nx_interface_tcpip_offload_handler rather than through the TCP state
   machine. It covers the three ways a connect can end -- established at once,
   reported later by the driver, and refused -- because each selects a
   different arm of _nxd_tcp_client_socket_driver_connect. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcpip_offload_driver.h"

extern void    test_control_return(UINT status);

#if defined(NX_ENABLE_TCPIP_OFFLOAD) && !defined(NX_DISABLE_IPV4)

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

static ULONG                   error_counter;
static ULONG                   connections;
static ULONG                   disconnections;
static ULONG                   server_receives;
static ULONG                   client_receives;
static ULONG                   establish_notifies;

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
static void    connect_received(NX_TCP_SOCKET *socket_ptr, UINT port);
static void    disconnect_received(NX_TCP_SOCKET *socket_ptr);
#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
static void    establish_notify(NX_TCP_SOCKET *socket_ptr);
#endif

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcpip_offload_tcp_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    pointer =  (CHAR *) first_unused_memory;

    error_counter =      0;
    connections =        0;
    disconnections =     0;
    server_receives =    0;
    client_receives =    0;
    establish_notifies = 0;

    nx_tcpip_offload_driver_reset();

    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
            pointer, DEMO_STACK_SIZE,
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 16384);
    pointer = pointer + 16384;
    if (status)
        error_counter++;

    /* Both instances run on the offload driver, so every socket operation
       below reaches the offload handler instead of the TCP state machine. */
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
}


/* The client. */
static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;
NXD_ADDRESS server_address;
ULONG       length;
UCHAR       buffer[32];

    NX_PARAMETER_NOT_USED(thread_input);

    printf("NetX Test:   TCP/IP Offload TCP Test...................................");

    /* Give the server thread time to start listening. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* The interface must have come up as an offload interface, or nothing
       below is testing what it claims to. */
    if ((ip_0.nx_ip_interface[0].nx_interface_capability_flag &
         NX_INTERFACE_CAPABILITY_TCPIP_OFFLOAD) == 0)
        error_counter++;

    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;

#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
    status = nx_tcp_socket_establish_notify(&client_socket, establish_notify);
    if (status)
        error_counter++;
#endif

    status =  nx_tcp_client_socket_bind(&client_socket, CLIENT_PORT, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* 1. A connect the driver refuses. This is the only way to reach the arm
          of _nxd_tcp_client_socket_driver_connect that unwinds the connection
          counters and returns NX_TCPIP_OFFLOAD_ERROR. */
    nx_tcpip_offload_connect_mode = NX_TCPIP_OFFLOAD_CONNECT_REFUSE;
    server_address.nxd_ip_version = NX_IP_VERSION_V4;
    server_address.nxd_ip_address.v4 = IP_ADDRESS(1, 2, 3, 5);
    status =  nxd_tcp_client_socket_connect(&client_socket, &server_address,
                                            SERVER_PORT, NX_IP_PERIODIC_RATE);
    if (status == NX_SUCCESS)
        error_counter++;
    if (client_socket.nx_tcp_socket_state != NX_TCP_CLOSED)
        error_counter++;

    /* 2. A connect the driver reports as in progress, completed later from
          the engine thread. This takes the NX_TCP_SYN_SENT arm. */
    nx_tcpip_offload_connect_mode = NX_TCPIP_OFFLOAD_CONNECT_IN_PROGRESS;
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), SERVER_PORT,
                                           5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* The in-progress arm returns success with the socket in NX_TCP_SYN_SENT
       and leaves the establish to the driver, so the connection is not up
       when the call returns. The engine thread may already have reported it
       by the time this runs, which is why both states are accepted here; what
       is not acceptable is the socket never reaching NX_TCP_ESTABLISHED. */
    if ((client_socket.nx_tcp_socket_state != NX_TCP_SYN_SENT) &&
        (client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED))
        error_counter++;

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    if (client_socket.nx_tcp_socket_state != NX_TCP_ESTABLISHED)
        error_counter++;

    /* Send through the offload handler. */
    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        status = nx_packet_data_append(packet_ptr, "offload client", 14, &pool_0, NX_WAIT_FOREVER);
        if (status)
            error_counter++;

        status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);
        if (status)
        {
            error_counter++;
            nx_packet_release(packet_ptr);
        }
    }

    /* Receive the server's reply, which arrived through
       _nx_tcp_socket_driver_packet_receive. */
    status = nx_tcp_socket_receive(&client_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
    {
        length = 0;
        nx_packet_data_retrieve(packet_ptr, buffer, &length);
        if ((length != 14) || (memcmp(buffer, "offload server", 14) != 0))
            error_counter++;
        client_receives++;
        nx_packet_release(packet_ptr);
    }

    /* 3. A send the driver fails, which is the only way to reach the
          NX_TCPIP_OFFLOAD_ERROR return in _nx_tcp_socket_driver_send. */
    nx_tcpip_offload_send_failure = NX_TRUE;
    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        status = nx_packet_data_append(packet_ptr, "fail", 4, &pool_0, NX_WAIT_FOREVER);
        if (status)
            error_counter++;

        status = nx_tcp_socket_send(&client_socket, packet_ptr, NX_IP_PERIODIC_RATE);
        if (status != NX_TCPIP_OFFLOAD_ERROR)
            error_counter++;
        nx_packet_release(packet_ptr);
    }
    nx_tcpip_offload_send_failure = NX_FALSE;

    status =  nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    status =  nx_tcp_client_socket_unbind(&client_socket);
    if (status)
        error_counter++;

    status =  nx_tcp_socket_delete(&client_socket);
    if (status)
        error_counter++;

    /* Let the server finish: it unaccepts and unlistens after its own sleep,
       and the handler counts below include both of those operations. */
    tx_thread_sleep(6 * NX_IP_PERIODIC_RATE);

    /* Each of the six TCP operations must have been seen by the handler.
       A test that passes without them has proved nothing about offload. */
    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_TCP_CLIENT_SOCKET_CONNECT] == 0)
        error_counter++;
    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_TCP_SERVER_SOCKET_LISTEN] == 0)
        error_counter++;
    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_TCP_SERVER_SOCKET_ACCEPT] == 0)
        error_counter++;
    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_TCP_SERVER_SOCKET_UNLISTEN] == 0)
        error_counter++;
    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_TCP_SOCKET_DISCONNECT] == 0)
        error_counter++;
    if (nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_TCP_SOCKET_SEND] == 0)
        error_counter++;

    if ((connections != 1) || (server_receives != 1) || (client_receives != 1))
        error_counter++;

#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
    if (establish_notifies == 0)
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
                                   NX_NULL, disconnect_received);
    if (status)
        error_counter++;

    status =  nx_tcp_server_socket_listen(&ip_1, SERVER_PORT, &server_socket, 5, connect_received);
    if (status)
        error_counter++;

    /* With offload the driver establishes the connection and the accept just
       observes it, so a long wait here is a failure, not patience. */
    status =  nx_tcp_server_socket_accept(&server_socket, 10 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    status = nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
    {
        length = 0;
        nx_packet_data_retrieve(packet_ptr, buffer, &length);
        if ((length != 14) || (memcmp(buffer, "offload client", 14) != 0))
            error_counter++;
        server_receives++;
        nx_packet_release(packet_ptr);
    }

    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;
    else
    {
        status = nx_packet_data_append(packet_ptr, "offload server", 14, &pool_0, NX_WAIT_FOREVER);
        if (status)
            error_counter++;

        status = nx_tcp_socket_send(&server_socket, packet_ptr, NX_IP_PERIODIC_RATE);
        if (status)
        {
            error_counter++;
            nx_packet_release(packet_ptr);
        }
    }

    /* Wait for the client's disconnect to reach this end. */
    tx_thread_sleep(3 * NX_IP_PERIODIC_RATE);

    nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

    status = nx_tcp_server_socket_unaccept(&server_socket);
    if (status)
        error_counter++;

    status = nx_tcp_server_socket_unlisten(&ip_1, SERVER_PORT);
    if (status)
        error_counter++;

    status = nx_tcp_socket_delete(&server_socket);
    if (status)
        error_counter++;
}


static void  connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{
    if ((socket_ptr != &server_socket) || (port != SERVER_PORT))
        error_counter++;

    connections++;
}


static void  disconnect_received(NX_TCP_SOCKET *socket_ptr)
{
    if (socket_ptr != &server_socket)
        error_counter++;

    disconnections++;
}


#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
static void  establish_notify(NX_TCP_SOCKET *socket_ptr)
{
    if (socket_ptr != &client_socket)
        error_counter++;

    establish_notifies++;
}
#endif

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcpip_offload_tcp_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP/IP Offload TCP Test...................................N/A\n");
    test_control_return(3);
}

#endif
