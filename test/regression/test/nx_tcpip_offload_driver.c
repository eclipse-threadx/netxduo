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

/* The loopback TCP/IP offload engine described in nx_tcpip_offload_driver.h. */

#include "nx_api.h"
#include "nx_tcpip_offload_driver.h"

#ifdef NX_ENABLE_TCPIP_OFFLOAD

#include "nx_ip.h"
#include "nx_tcp.h"
#include "nx_udp.h"
#include "nx_packet.h"

#define NX_TCPIP_OFFLOAD_MAX_ENDPOINTS 16
#define NX_TCPIP_OFFLOAD_MAX_EVENTS    32
#define NX_TCPIP_OFFLOAD_ENGINE_STACK  4096
#define NX_TCPIP_OFFLOAD_NO_PEER       (-1)

/* One half of a connection, or one bound UDP socket, or one listener. */
typedef struct NX_TCPIP_OFFLOAD_ENDPOINT_STRUCT
{
    UINT          nx_tcpip_offload_in_use;
    UINT          nx_tcpip_offload_is_tcp;
    UINT          nx_tcpip_offload_listening;
    UINT          nx_tcpip_offload_established;
    NX_IP        *nx_tcpip_offload_ip_ptr;
    NX_INTERFACE *nx_tcpip_offload_interface_ptr;
    VOID         *nx_tcpip_offload_socket_ptr;
    UINT          nx_tcpip_offload_local_port;
    UINT          nx_tcpip_offload_remote_port;
    NXD_ADDRESS   nx_tcpip_offload_local_ip;
    NXD_ADDRESS   nx_tcpip_offload_remote_ip;

    /* The other half of an established connection, or NX_TCPIP_OFFLOAD_NO_PEER. */
    INT           nx_tcpip_offload_peer;

    /* On a listener, the client endpoint whose connection the next
       NX_TCPIP_OFFLOAD_TCP_SERVER_SOCKET_ACCEPT will report. */
    INT           nx_tcpip_offload_pending;
} NX_TCPIP_OFFLOAD_ENDPOINT;

/* What the engine thread has been asked to report back into NetX Duo.

   Nothing is reported from the handler itself. The handler runs on the
   caller's thread, and two of the nine operations are invoked with that IP
   instance's nx_ip_protection already held -- nxd_udp_socket_send.c holds it
   across the call. Reporting inline would mean taking the peer's protection
   mutex while holding the sender's, which is an AB-BA deadlock the moment two
   IP instances send to each other at once. The engine thread holds at most one
   protection mutex at a time, so the cycle cannot form. */
#define NX_TCPIP_OFFLOAD_EVENT_ESTABLISH   0
#define NX_TCPIP_OFFLOAD_EVENT_TCP_RECEIVE 1
#define NX_TCPIP_OFFLOAD_EVENT_UDP_RECEIVE 2
#define NX_TCPIP_OFFLOAD_EVENT_TCP_CLOSED  3

typedef struct NX_TCPIP_OFFLOAD_EVENT_STRUCT
{
    UINT        nx_tcpip_offload_event_type;
    INT         nx_tcpip_offload_event_endpoint;
    NX_PACKET  *nx_tcpip_offload_event_packet;
    NXD_ADDRESS nx_tcpip_offload_event_local_ip;
    NXD_ADDRESS nx_tcpip_offload_event_remote_ip;
    UINT        nx_tcpip_offload_event_remote_port;
} NX_TCPIP_OFFLOAD_EVENT;

UINT  nx_tcpip_offload_connect_mode;
UINT  nx_tcpip_offload_send_failure;
UINT  nx_tcpip_offload_bind_failure;
UINT  nx_tcpip_offload_listen_failure;
ULONG nx_tcpip_offload_operations[NX_TCPIP_OFFLOAD_OPERATION_COUNT];

static NX_TCPIP_OFFLOAD_ENDPOINT nx_tcpip_offload_endpoints[NX_TCPIP_OFFLOAD_MAX_ENDPOINTS];
static NX_TCPIP_OFFLOAD_EVENT    nx_tcpip_offload_events[NX_TCPIP_OFFLOAD_MAX_EVENTS];
static UINT                      nx_tcpip_offload_event_head;
static UINT                      nx_tcpip_offload_event_tail;

static TX_MUTEX  nx_tcpip_offload_fabric_mutex;
static TX_THREAD nx_tcpip_offload_engine_thread;
static ULONG     nx_tcpip_offload_engine_stack[NX_TCPIP_OFFLOAD_ENGINE_STACK / sizeof(ULONG)];
static UINT      nx_tcpip_offload_engine_started;

static VOID nx_tcpip_offload_engine_entry(ULONG thread_input);
static UINT nx_tcpip_offload_handler(NX_IP *ip_ptr, NX_INTERFACE *interface_ptr,
                                     VOID *socket_ptr, UINT operation, NX_PACKET *packet_ptr,
                                     NXD_ADDRESS *local_ip, NXD_ADDRESS *remote_ip,
                                     UINT local_port, UINT *remote_port, UINT wait_option);


/* The fabric lock is a leaf: it is never held across a call into NetX Duo, in
   either direction. That is what keeps it out of the lock order above. */
static VOID nx_tcpip_offload_lock(VOID)
{
    tx_mutex_get(&nx_tcpip_offload_fabric_mutex, TX_WAIT_FOREVER);
}

static VOID nx_tcpip_offload_unlock(VOID)
{
    tx_mutex_put(&nx_tcpip_offload_fabric_mutex);
}

/* Appends an event. The caller holds the fabric lock.

   A full queue drops the event rather than blocking, because the producer may
   be holding an IP protection mutex and blocking here would stall the stack it
   is reporting to. The queue is sized well above what any one test enqueues,
   so a drop means a test outgrew the engine and the test's own assertions will
   say so. */
static VOID nx_tcpip_offload_post(UINT type, INT endpoint, NX_PACKET *packet_ptr,
                                  NXD_ADDRESS *local_ip, NXD_ADDRESS *remote_ip,
                                  UINT remote_port)
{
UINT next;

    next = (nx_tcpip_offload_event_head + 1) % NX_TCPIP_OFFLOAD_MAX_EVENTS;
    if (next == nx_tcpip_offload_event_tail)
    {

        /* Queue full. */
        return;
    }

    nx_tcpip_offload_events[nx_tcpip_offload_event_head].nx_tcpip_offload_event_type = type;
    nx_tcpip_offload_events[nx_tcpip_offload_event_head].nx_tcpip_offload_event_endpoint = endpoint;
    nx_tcpip_offload_events[nx_tcpip_offload_event_head].nx_tcpip_offload_event_packet = packet_ptr;
    nx_tcpip_offload_events[nx_tcpip_offload_event_head].nx_tcpip_offload_event_remote_port = remote_port;

    if (local_ip)
    {
        nx_tcpip_offload_events[nx_tcpip_offload_event_head].nx_tcpip_offload_event_local_ip = *local_ip;
    }
    else
    {
        memset(&(nx_tcpip_offload_events[nx_tcpip_offload_event_head].nx_tcpip_offload_event_local_ip),
               0, sizeof(NXD_ADDRESS));
    }

    if (remote_ip)
    {
        nx_tcpip_offload_events[nx_tcpip_offload_event_head].nx_tcpip_offload_event_remote_ip = *remote_ip;
    }
    else
    {
        memset(&(nx_tcpip_offload_events[nx_tcpip_offload_event_head].nx_tcpip_offload_event_remote_ip),
               0, sizeof(NXD_ADDRESS));
    }

    nx_tcpip_offload_event_head = next;
}

/* Allocates an endpoint. The caller holds the fabric lock. */
static INT nx_tcpip_offload_endpoint_allocate(VOID)
{
INT i;

    for (i = 0; i < NX_TCPIP_OFFLOAD_MAX_ENDPOINTS; i++)
    {
        if (nx_tcpip_offload_endpoints[i].nx_tcpip_offload_in_use == NX_FALSE)
        {
            memset(&nx_tcpip_offload_endpoints[i], 0, sizeof(NX_TCPIP_OFFLOAD_ENDPOINT));
            nx_tcpip_offload_endpoints[i].nx_tcpip_offload_in_use = NX_TRUE;
            nx_tcpip_offload_endpoints[i].nx_tcpip_offload_peer = NX_TCPIP_OFFLOAD_NO_PEER;
            nx_tcpip_offload_endpoints[i].nx_tcpip_offload_pending = NX_TCPIP_OFFLOAD_NO_PEER;
            return(i);
        }
    }

    return(NX_TCPIP_OFFLOAD_NO_PEER);
}

/* Finds the endpoint owning a socket. The caller holds the fabric lock. */
static INT nx_tcpip_offload_endpoint_find(VOID *socket_ptr, UINT is_tcp)
{
INT i;

    for (i = 0; i < NX_TCPIP_OFFLOAD_MAX_ENDPOINTS; i++)
    {
        if ((nx_tcpip_offload_endpoints[i].nx_tcpip_offload_in_use == NX_TRUE) &&
            (nx_tcpip_offload_endpoints[i].nx_tcpip_offload_is_tcp == is_tcp) &&
            (nx_tcpip_offload_endpoints[i].nx_tcpip_offload_socket_ptr == socket_ptr))
        {
            return(i);
        }
    }

    return(NX_TCPIP_OFFLOAD_NO_PEER);
}

/* Finds a TCP listener on a port, on any IP instance other than the caller's.

   Matching on the port alone and excluding the client's own IP instance is
   what lets a test put the client on ip_0 and the server on ip_1 without the
   engine having to route anything. The engine is deliberately not an IP
   stack. The caller holds the fabric lock. */
static INT nx_tcpip_offload_listener_find(NX_IP *exclude_ip_ptr, UINT port)
{
INT i;

    for (i = 0; i < NX_TCPIP_OFFLOAD_MAX_ENDPOINTS; i++)
    {
        if ((nx_tcpip_offload_endpoints[i].nx_tcpip_offload_in_use == NX_TRUE) &&
            (nx_tcpip_offload_endpoints[i].nx_tcpip_offload_is_tcp == NX_TRUE) &&
            (nx_tcpip_offload_endpoints[i].nx_tcpip_offload_listening == NX_TRUE) &&
            (nx_tcpip_offload_endpoints[i].nx_tcpip_offload_local_port == port) &&
            (nx_tcpip_offload_endpoints[i].nx_tcpip_offload_ip_ptr != exclude_ip_ptr))
        {
            return(i);
        }
    }

    return(NX_TCPIP_OFFLOAD_NO_PEER);
}

/* Finds a bound UDP endpoint on a port, excluding the sender's IP instance. */
static INT nx_tcpip_offload_udp_find(NX_IP *exclude_ip_ptr, UINT port)
{
INT i;

    for (i = 0; i < NX_TCPIP_OFFLOAD_MAX_ENDPOINTS; i++)
    {
        if ((nx_tcpip_offload_endpoints[i].nx_tcpip_offload_in_use == NX_TRUE) &&
            (nx_tcpip_offload_endpoints[i].nx_tcpip_offload_is_tcp == NX_FALSE) &&
            (nx_tcpip_offload_endpoints[i].nx_tcpip_offload_local_port == port) &&
            (nx_tcpip_offload_endpoints[i].nx_tcpip_offload_ip_ptr != exclude_ip_ptr))
        {
            return(i);
        }
    }

    return(NX_TCPIP_OFFLOAD_NO_PEER);
}


/* The engine thread.

   It polls rather than suspending forever on a semaphore, and the reason is
   recorded here because it looks like a worse design than it is: the ThreadX
   Linux port can lose a futex wake-up on _tx_linux_mutex, which is the defect
   behind the suite's ~0.39% of 1,000-second ctest timeouts. A thread blocked
   on TX_WAIT_FOREVER that misses its wake-up never runs again and takes the
   whole test with it. A one-tick poll cannot miss anything: a lost wake-up
   costs a tick, not the run. */
static VOID nx_tcpip_offload_engine_entry(ULONG thread_input)
{
NX_TCPIP_OFFLOAD_EVENT     event;
NX_TCPIP_OFFLOAD_ENDPOINT *endpoint_ptr;
UINT                       have_event;

    NX_PARAMETER_NOT_USED(thread_input);

    for (;;)
    {
        nx_tcpip_offload_lock();
        if (nx_tcpip_offload_event_tail != nx_tcpip_offload_event_head)
        {
            event = nx_tcpip_offload_events[nx_tcpip_offload_event_tail];
            nx_tcpip_offload_event_tail = (nx_tcpip_offload_event_tail + 1) % NX_TCPIP_OFFLOAD_MAX_EVENTS;
            have_event = NX_TRUE;
        }
        else
        {
            memset(&event, 0, sizeof(event));
            have_event = NX_FALSE;
        }
        nx_tcpip_offload_unlock();

        if (have_event == NX_FALSE)
        {
            tx_thread_sleep(1);
            continue;
        }

        endpoint_ptr = &nx_tcpip_offload_endpoints[event.nx_tcpip_offload_event_endpoint];

        /* The fabric lock is released above and is not held across any call
           below. Each call takes one IP protection mutex of its own. */
        switch (event.nx_tcpip_offload_event_type)
        {

        case NX_TCPIP_OFFLOAD_EVENT_ESTABLISH:

            _nx_tcp_socket_driver_establish((NX_TCP_SOCKET *)endpoint_ptr -> nx_tcpip_offload_socket_ptr,
                                            endpoint_ptr -> nx_tcpip_offload_interface_ptr,
                                            event.nx_tcpip_offload_event_remote_port);
            break;

        case NX_TCPIP_OFFLOAD_EVENT_TCP_RECEIVE:

            _nx_tcp_socket_driver_packet_receive((NX_TCP_SOCKET *)endpoint_ptr -> nx_tcpip_offload_socket_ptr,
                                                 event.nx_tcpip_offload_event_packet);
            break;

        case NX_TCPIP_OFFLOAD_EVENT_UDP_RECEIVE:

            _nx_udp_socket_driver_packet_receive((NX_UDP_SOCKET *)endpoint_ptr -> nx_tcpip_offload_socket_ptr,
                                                 event.nx_tcpip_offload_event_packet,
                                                 &(event.nx_tcpip_offload_event_local_ip),
                                                 &(event.nx_tcpip_offload_event_remote_ip),
                                                 event.nx_tcpip_offload_event_remote_port);
            break;

        case NX_TCPIP_OFFLOAD_EVENT_TCP_CLOSED:

            /* A null packet is how the driver reports a closed connection to
               _nx_tcp_socket_driver_packet_receive. */
            _nx_tcp_socket_driver_packet_receive((NX_TCP_SOCKET *)endpoint_ptr -> nx_tcpip_offload_socket_ptr,
                                                 NX_NULL);
            break;

        default:
            break;
        }
    }
}


/* Hands a packet to the peer's stack.

   The packet is forwarded, not copied. NetX Duo's offload send paths do not
   release it on success, so the driver owns it from the call onward, and both
   receive routines prepend a synthetic TCP/UDP and IP header into the space
   the sending pool already reserved. A packet remembers the pool it came
   from, so the receiving side releasing it into the sender's pool is correct.

   The caller holds the fabric lock. */
static VOID nx_tcpip_offload_deliver(INT peer, NX_PACKET *packet_ptr, UINT type,
                                     NXD_ADDRESS *local_ip, NXD_ADDRESS *remote_ip,
                                     UINT remote_port)
{

    /* The receive routines read nx_packet_ip_interface to build the synthetic
       IP header, so it has to name the interface the packet is arriving on --
       the peer's, not the sender's. */
    packet_ptr -> nx_packet_ip_interface = nx_tcpip_offload_endpoints[peer].nx_tcpip_offload_interface_ptr;

    nx_tcpip_offload_post(type, peer, packet_ptr, local_ip, remote_ip, remote_port);
}


/* The nine operations NX_ENABLE_TCPIP_OFFLOAD defines.

   Every one of them returns without having called into NetX Duo. Anything to
   be reported back is posted to the engine thread -- see the comment on
   NX_TCPIP_OFFLOAD_EVENT_ESTABLISH for why that is not optional. */
static UINT nx_tcpip_offload_handler(NX_IP *ip_ptr, NX_INTERFACE *interface_ptr,
                                     VOID *socket_ptr, UINT operation, NX_PACKET *packet_ptr,
                                     NXD_ADDRESS *local_ip, NXD_ADDRESS *remote_ip,
                                     UINT local_port, UINT *remote_port, UINT wait_option)
{
INT   self;
INT   peer;
UINT  status;

    NX_PARAMETER_NOT_USED(wait_option);

    if (operation < NX_TCPIP_OFFLOAD_OPERATION_COUNT)
    {
        nx_tcpip_offload_operations[operation]++;
    }

    status = NX_SUCCESS;

    nx_tcpip_offload_lock();

    switch (operation)
    {

    case NX_TCPIP_OFFLOAD_TCP_CLIENT_SOCKET_CONNECT:

        if (nx_tcpip_offload_connect_mode == NX_TCPIP_OFFLOAD_CONNECT_REFUSE)
        {
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        peer = nx_tcpip_offload_listener_find(ip_ptr, *remote_port);
        if (peer == NX_TCPIP_OFFLOAD_NO_PEER)
        {

            /* Nothing is listening. Refusing here is what drives the
               NX_TCPIP_OFFLOAD_ERROR arm of the connect path. */
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        self = nx_tcpip_offload_endpoint_allocate();
        if (self == NX_TCPIP_OFFLOAD_NO_PEER)
        {
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_is_tcp = NX_TRUE;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_ip_ptr = ip_ptr;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_interface_ptr = interface_ptr;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_socket_ptr = socket_ptr;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_local_port = local_port;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_remote_port = *remote_port;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_peer = peer;

        if (remote_ip)
        {
            nx_tcpip_offload_endpoints[self].nx_tcpip_offload_remote_ip = *remote_ip;
        }

        /* The client's own address is the interface's, in the family the
           caller asked for. */
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_local_ip.nxd_ip_version =
            nx_tcpip_offload_endpoints[self].nx_tcpip_offload_remote_ip.nxd_ip_version;
#ifndef NX_DISABLE_IPV4
        if (nx_tcpip_offload_endpoints[self].nx_tcpip_offload_local_ip.nxd_ip_version == NX_IP_VERSION_V4)
        {
            nx_tcpip_offload_endpoints[self].nx_tcpip_offload_local_ip.nxd_ip_address.v4 =
                interface_ptr -> nx_interface_ip_address;
        }
#endif /* !NX_DISABLE_IPV4 */
#ifdef FEATURE_NX_IPV6
        if (nx_tcpip_offload_endpoints[self].nx_tcpip_offload_local_ip.nxd_ip_version == NX_IP_VERSION_V6)
        {

            /* The socket's source address has already been selected by the
               time the handler is called, so it is read off the socket rather
               than off the interface, which may carry several. */
            if (((NX_TCP_SOCKET *)socket_ptr) -> nx_tcp_socket_ipv6_addr)
            {
            ULONG *from = ((NX_TCP_SOCKET *)socket_ptr) -> nx_tcp_socket_ipv6_addr -> nxd_ipv6_address;
            ULONG *to = nx_tcpip_offload_endpoints[self].nx_tcpip_offload_local_ip.nxd_ip_address.v6;

                /* Copied word by word rather than with COPY_IPV6_ADDRESS,
                   which is only a macro when NX_IPV6_UTIL_INLINE is set. */
                to[0] = from[0];
                to[1] = from[1];
                to[2] = from[2];
                to[3] = from[3];
            }
        }
#endif /* FEATURE_NX_IPV6 */

        /* Tell the listener who is calling, then wake it. The listener's
           socket is still the one in NX_TCP_LISTEN_STATE: it is
           _nx_tcp_socket_driver_establish that turns it into the connection,
           by asking this handler for the accept details. */
        nx_tcpip_offload_endpoints[peer].nx_tcpip_offload_pending = self;
        nx_tcpip_offload_post(NX_TCPIP_OFFLOAD_EVENT_ESTABLISH, peer, NX_NULL, NX_NULL, NX_NULL, local_port);

        if (nx_tcpip_offload_connect_mode == NX_TCPIP_OFFLOAD_CONNECT_IN_PROGRESS)
        {

            /* Report the connection later, from the engine thread, which is
               what takes _nxd_tcp_client_socket_driver_connect through
               NX_TCP_SYN_SENT instead of straight to NX_TCP_ESTABLISHED. */
            nx_tcpip_offload_post(NX_TCPIP_OFFLOAD_EVENT_ESTABLISH, self, NX_NULL, NX_NULL, NX_NULL,
                                  *remote_port);
            status = NX_IN_PROGRESS;
        }
        else
        {
            nx_tcpip_offload_endpoints[self].nx_tcpip_offload_established = NX_TRUE;
            status = NX_SUCCESS;
        }
        break;

    case NX_TCPIP_OFFLOAD_TCP_SERVER_SOCKET_LISTEN:

        if (nx_tcpip_offload_listen_failure == NX_TRUE)
        {
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        self = nx_tcpip_offload_endpoint_find(socket_ptr, NX_TRUE);
        if (self == NX_TCPIP_OFFLOAD_NO_PEER)
        {
            self = nx_tcpip_offload_endpoint_allocate();
        }

        if (self == NX_TCPIP_OFFLOAD_NO_PEER)
        {
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_is_tcp = NX_TRUE;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_listening = NX_TRUE;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_ip_ptr = ip_ptr;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_interface_ptr = interface_ptr;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_socket_ptr = socket_ptr;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_local_port = local_port;
        break;

    case NX_TCPIP_OFFLOAD_TCP_SERVER_SOCKET_ACCEPT:

        self = nx_tcpip_offload_endpoint_find(socket_ptr, NX_TRUE);
        if ((self == NX_TCPIP_OFFLOAD_NO_PEER) ||
            (nx_tcpip_offload_endpoints[self].nx_tcpip_offload_pending == NX_TCPIP_OFFLOAD_NO_PEER))
        {

            /* _nx_tcp_socket_driver_establish treats a failure here as
               NX_TCPIP_OFFLOAD_ERROR, which is the "should not happen" arm. */
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        peer = nx_tcpip_offload_endpoints[self].nx_tcpip_offload_pending;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_pending = NX_TCPIP_OFFLOAD_NO_PEER;

        /* The listener becomes this connection's server half. */
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_listening = NX_FALSE;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_peer = peer;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_established = NX_TRUE;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_remote_port =
            nx_tcpip_offload_endpoints[peer].nx_tcpip_offload_local_port;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_remote_ip =
            nx_tcpip_offload_endpoints[peer].nx_tcpip_offload_local_ip;
        nx_tcpip_offload_endpoints[peer].nx_tcpip_offload_established = NX_TRUE;

        /* _nx_tcp_socket_driver_establish passes the address out through
           remote_ip and the port through remote_port. */
        if (remote_ip)
        {
            *remote_ip = nx_tcpip_offload_endpoints[self].nx_tcpip_offload_remote_ip;
        }
        if (remote_port)
        {
            *remote_port = nx_tcpip_offload_endpoints[self].nx_tcpip_offload_remote_port;
        }
        break;

    case NX_TCPIP_OFFLOAD_TCP_SERVER_SOCKET_UNLISTEN:

        self = nx_tcpip_offload_endpoint_find(socket_ptr, NX_TRUE);
        if (self != NX_TCPIP_OFFLOAD_NO_PEER)
        {
            nx_tcpip_offload_endpoints[self].nx_tcpip_offload_listening = NX_FALSE;
            if (nx_tcpip_offload_endpoints[self].nx_tcpip_offload_established == NX_FALSE)
            {
                nx_tcpip_offload_endpoints[self].nx_tcpip_offload_in_use = NX_FALSE;
            }
        }
        break;

    case NX_TCPIP_OFFLOAD_TCP_SOCKET_DISCONNECT:

        self = nx_tcpip_offload_endpoint_find(socket_ptr, NX_TRUE);
        if (self == NX_TCPIP_OFFLOAD_NO_PEER)
        {
            break;
        }

        peer = nx_tcpip_offload_endpoints[self].nx_tcpip_offload_peer;
        if ((peer != NX_TCPIP_OFFLOAD_NO_PEER) &&
            (nx_tcpip_offload_endpoints[peer].nx_tcpip_offload_established == NX_TRUE))
        {

            /* Report the close to the far end, which is what takes
               _nx_tcp_socket_driver_packet_receive through its null-packet
               arm into NX_TCP_CLOSE_WAIT and the disconnect callback. */
            nx_tcpip_offload_endpoints[peer].nx_tcpip_offload_peer = NX_TCPIP_OFFLOAD_NO_PEER;
            nx_tcpip_offload_post(NX_TCPIP_OFFLOAD_EVENT_TCP_CLOSED, peer, NX_NULL, NX_NULL, NX_NULL, 0);
        }

        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_in_use = NX_FALSE;
        break;

    case NX_TCPIP_OFFLOAD_TCP_SOCKET_SEND:

        if (nx_tcpip_offload_send_failure == NX_TRUE)
        {
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        self = nx_tcpip_offload_endpoint_find(socket_ptr, NX_TRUE);
        if (self == NX_TCPIP_OFFLOAD_NO_PEER)
        {
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        peer = nx_tcpip_offload_endpoints[self].nx_tcpip_offload_peer;
        if ((peer == NX_TCPIP_OFFLOAD_NO_PEER) ||
            (nx_tcpip_offload_endpoints[peer].nx_tcpip_offload_established == NX_FALSE))
        {
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        nx_tcpip_offload_deliver(peer, packet_ptr, NX_TCPIP_OFFLOAD_EVENT_TCP_RECEIVE,
                                 NX_NULL, NX_NULL, 0);
        break;

    case NX_TCPIP_OFFLOAD_UDP_SOCKET_BIND:

        if (nx_tcpip_offload_bind_failure == NX_TRUE)
        {
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        self = nx_tcpip_offload_endpoint_allocate();
        if (self == NX_TCPIP_OFFLOAD_NO_PEER)
        {
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_is_tcp = NX_FALSE;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_ip_ptr = ip_ptr;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_interface_ptr = interface_ptr;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_socket_ptr = socket_ptr;
        nx_tcpip_offload_endpoints[self].nx_tcpip_offload_local_port = local_port;
        break;

    case NX_TCPIP_OFFLOAD_UDP_SOCKET_UNBIND:

        /* _nx_udp_socket_unbind calls this once per offload interface, so an
           endpoint that is already gone is normal, not an error. */
        self = nx_tcpip_offload_endpoint_find(socket_ptr, NX_FALSE);
        if (self != NX_TCPIP_OFFLOAD_NO_PEER)
        {
            nx_tcpip_offload_endpoints[self].nx_tcpip_offload_in_use = NX_FALSE;
        }
        break;

    case NX_TCPIP_OFFLOAD_UDP_SOCKET_SEND:

        if (nx_tcpip_offload_send_failure == NX_TRUE)
        {
            status = NX_NOT_SUCCESSFUL;
            break;
        }

        peer = nx_tcpip_offload_udp_find(ip_ptr, *remote_port);
        if (peer == NX_TCPIP_OFFLOAD_NO_PEER)
        {

            /* Nothing bound on the far side. The datagram is dropped, which
               is what UDP does, and the send still succeeds. */
            _nx_packet_transmit_release(packet_ptr);
            break;
        }

        /* _nx_udp_socket_driver_packet_receive is told where the datagram
           came from, so the sender's address becomes the receiver's remote
           and the destination becomes its local. */
        nx_tcpip_offload_deliver(peer, packet_ptr, NX_TCPIP_OFFLOAD_EVENT_UDP_RECEIVE,
                                 remote_ip, local_ip, local_port);
        break;

    default:
        status = NX_NOT_SUCCESSFUL;
        break;
    }

    nx_tcpip_offload_unlock();

    return(status);
}


/* The link driver entry point.

   An offload interface still has a link driver: NetX Duo attaches it,
   initialises it and enables it before any socket call reaches the offload
   handler. What makes the interface an offload interface is what this routine
   does during NX_LINK_INTERFACE_ATTACH -- it sets
   NX_INTERFACE_CAPABILITY_TCPIP_OFFLOAD and installs the handler. Both
   nx_ip_interface_attach.c and nx_ip_thread_entry.c read them immediately
   after the attach returns, and add NX_INTERFACE_CAPABILITY_CHECKSUM_ALL on
   the strength of the flag.

   The link commands that carry IP traffic are answered by releasing the
   packet. On an offload interface they should not arrive at all -- the socket
   layer diverts to the handler long before the packet reaches the link -- and
   releasing rather than transmitting keeps a stray one from leaking a packet
   and failing a later allocation for a reason unrelated to the test. */
VOID nx_tcpip_offload_driver(NX_IP_DRIVER *driver_req_ptr)
{
NX_IP        *ip_ptr;
NX_INTERFACE *interface_ptr;
UINT          interface_index;

    ip_ptr = driver_req_ptr -> nx_ip_driver_ptr;
    interface_ptr = driver_req_ptr -> nx_ip_driver_interface;

    driver_req_ptr -> nx_ip_driver_status = NX_SUCCESS;

    switch (driver_req_ptr -> nx_ip_driver_command)
    {

    case NX_LINK_INTERFACE_ATTACH:

        if (nx_tcpip_offload_engine_started == NX_FALSE)
        {
            tx_mutex_create(&nx_tcpip_offload_fabric_mutex, "offload fabric", TX_NO_INHERIT);
            tx_thread_create(&nx_tcpip_offload_engine_thread, "offload engine",
                             nx_tcpip_offload_engine_entry, 0,
                             nx_tcpip_offload_engine_stack, sizeof(nx_tcpip_offload_engine_stack),
                             1, 1, TX_NO_TIME_SLICE, TX_AUTO_START);
            nx_tcpip_offload_engine_started = NX_TRUE;
        }

        /* This is what makes it an offload interface. */
        interface_ptr -> nx_interface_capability_flag |= NX_INTERFACE_CAPABILITY_TCPIP_OFFLOAD;
        interface_ptr -> nx_interface_tcpip_offload_handler = nx_tcpip_offload_handler;
        break;

    case NX_LINK_INITIALIZE:

        interface_index = driver_req_ptr -> nx_ip_driver_interface -> nx_interface_index;

        nx_ip_interface_mtu_set(ip_ptr, interface_index, 1500);

        /* An offload interface resolves nothing itself, so no address mapping
           is needed and no ARP traffic is generated for it. */
        nx_ip_interface_address_mapping_configure(ip_ptr, interface_index, NX_FALSE);
        break;

    case NX_LINK_ENABLE:

        interface_ptr -> nx_interface_link_up = NX_TRUE;
        break;

    case NX_LINK_DISABLE:

        interface_ptr -> nx_interface_link_up = NX_FALSE;
        break;

    case NX_LINK_PACKET_SEND:
    case NX_LINK_PACKET_BROADCAST:
    case NX_LINK_ARP_SEND:
    case NX_LINK_ARP_RESPONSE_SEND:
    case NX_LINK_RARP_SEND:

        nx_packet_transmit_release(driver_req_ptr -> nx_ip_driver_packet);
        break;

    case NX_LINK_UNINITIALIZE:
    case NX_LINK_INTERFACE_DETACH:
    case NX_LINK_MULTICAST_JOIN:
    case NX_LINK_MULTICAST_LEAVE:
    case NX_LINK_GET_STATUS:
    case NX_LINK_DEFERRED_PROCESSING:
        break;

    default:

        driver_req_ptr -> nx_ip_driver_status = NX_UNHANDLED_COMMAND;
        break;
    }
}


VOID nx_tcpip_offload_driver_reset(VOID)
{
UINT i;

    /* The engine thread may be between its dequeue and its call into NetX
       Duo. Taking the fabric lock is enough to keep it out of the tables
       while they are cleared; the event it already holds names an endpoint
       that is about to become free, which the engine tolerates because a
       freed endpoint's socket pointer is only read, never followed into. */
    if (nx_tcpip_offload_engine_started == NX_TRUE)
    {
        nx_tcpip_offload_lock();
    }

    for (i = 0; i < NX_TCPIP_OFFLOAD_MAX_ENDPOINTS; i++)
    {
        memset(&nx_tcpip_offload_endpoints[i], 0, sizeof(NX_TCPIP_OFFLOAD_ENDPOINT));
        nx_tcpip_offload_endpoints[i].nx_tcpip_offload_peer = NX_TCPIP_OFFLOAD_NO_PEER;
        nx_tcpip_offload_endpoints[i].nx_tcpip_offload_pending = NX_TCPIP_OFFLOAD_NO_PEER;
    }

    nx_tcpip_offload_event_head = 0;
    nx_tcpip_offload_event_tail = 0;

    nx_tcpip_offload_connect_mode = NX_TCPIP_OFFLOAD_CONNECT_IMMEDIATE;
    nx_tcpip_offload_send_failure = NX_FALSE;
    nx_tcpip_offload_bind_failure = NX_FALSE;
    nx_tcpip_offload_listen_failure = NX_FALSE;

    for (i = 0; i < NX_TCPIP_OFFLOAD_OPERATION_COUNT; i++)
    {
        nx_tcpip_offload_operations[i] = 0;
    }

    if (nx_tcpip_offload_engine_started == NX_TRUE)
    {
        nx_tcpip_offload_unlock();
    }
}

#endif /* NX_ENABLE_TCPIP_OFFLOAD */
