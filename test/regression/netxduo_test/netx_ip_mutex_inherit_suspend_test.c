/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* This NetX test checks how NetX services suspend the calling thread when the
   IP protection mutex has priority inheritance.

   A NetX service that suspends the caller releases the IP mutex just before
   the thread suspends. If the IP thread waits for the mutex at that point,
   the caller runs at the IP thread's priority, and tx_mutex_put() restores
   the caller's own priority. ThreadX moves only a TX_READY thread between
   the ready lists. A caller already marked as suspended stays on the ready
   list of the inherited priority, and the suspension then removes it from
   the wrong list. The scheduler keeps running the "suspended" thread and
   never runs the IP thread again.

   The test enables priority inheritance on the IP mutex. A victim thread then
   calls each service while the IP thread waits for the mutex the victim owns:
     - nx_tcp_client_socket_connect() (_nx_tcp_socket_thread_suspend),
     - nx_udp_socket_bind() of a port in use,
     - nx_icmp_ping(),
     - nxd_icmp_ping() to an IPv6 address.
   After every call the test checks the ThreadX ready lists.

   How the IP thread is made to wait at the right time:
     1. The holder thread owns the IP mutex and starts the victim, which
        blocks on the mutex inside the service.
     2. The holder releases the mutex. The victim owns it now, but does not
        run yet: it has a lower priority than the holder.
     3. The holder wakes the IP thread. The IP thread blocks on the mutex,
        and the victim inherits its priority. The victim then runs inside
        the service at the IP thread's priority.  */

#include   "tx_api.h"
#include   "tx_thread.h"
#include   "nx_api.h"
#include   "nx_ip.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048
#define     IP_THREAD_PRIORITY      1
#define     HOLDER_PRIORITY         2
#define     VICTIM_PRIORITY         3
#define     ARMED_ROUNDS            3
#define     MAX_ATTEMPTS            10
#define     UDP_TEST_PORT           0x88
#define     TCP_TEST_PORT           12


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               holder_thread;
static TX_THREAD               victim_thread;
static TX_SEMAPHORE            victim_go;
static TX_SEMAPHORE            victim_done;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;
static NX_UDP_SOCKET           udp_blocker;
static NX_UDP_SOCKET           udp_victim;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             ipv6_address_0;
static NXD_ADDRESS             ipv6_address_1;
#endif /* FEATURE_NX_IPV6 */


/* Define the counters and the victim's job.  */

static ULONG                   error_counter;
static UINT                    (*victim_action)(VOID);
static UINT                    victim_status;
static NX_PACKET              *ping_response;


/* Define thread prototypes.  */

static void    holder_entry(ULONG thread_input);
static void    victim_entry(ULONG thread_input);
static UINT    ready_list_check(VOID);
static UINT    arm_and_run(UINT (*action)(VOID));
static UINT    tcp_connect_action(VOID);
static UINT    udp_bind_action(VOID);
static UINT    ping_action(VOID);
#ifdef FEATURE_NX_IPV6
static UINT    ping6_action(VOID);
#endif /* FEATURE_NX_IPV6 */
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_mutex_inherit_suspend_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the holder and the victim threads.  */
    status =  tx_thread_create(&holder_thread, "holder", holder_entry, 0,
                               pointer, DEMO_STACK_SIZE,
                               HOLDER_PRIORITY, HOLDER_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    status += tx_thread_create(&victim_thread, "victim", victim_entry, 0,
                               pointer, DEMO_STACK_SIZE,
                               VICTIM_PRIORITY, VICTIM_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
    status += tx_semaphore_create(&victim_go, "victim go", 0);
    status += tx_semaphore_create(&victim_done, "victim done", 0);
    if (status)
        error_counter++;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;
    if (status)
        error_counter++;

    /* Create two IP instances.  */
    status =  nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                           pointer, 2048, IP_THREAD_PRIORITY);
    pointer =  pointer + 2048;
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                           pointer, 2048, IP_THREAD_PRIORITY);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Give the IP mutex of ip_0 priority inheritance, as tx_mutex_create()
       with TX_INHERIT does. Nothing has obtained the mutex yet.  */
    if ((ip_0.nx_ip_protection.tx_mutex_owner != TX_NULL) || (ip_0.nx_ip_protection.tx_mutex_ownership_count != 0))
        error_counter++;
    ip_0.nx_ip_protection.tx_mutex_inherit =  TX_TRUE;

    /* Enable ARP and supply ARP cache memory.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP, UDP and TCP.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);
    status += nx_udp_enable(&ip_0);
    status += nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 and ICMPv6.  */
    status =  nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    status += nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);
    if (status)
        error_counter++;

    /* Set the IPv6 global addresses.  */
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
    status =  nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_1, 64, NX_NULL);
    if (status)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */
}


/* Check the ThreadX ready lists: every thread on a ready list is ready and
   has the list's priority, every ring closes, and every ready thread is on
   the list of its priority.  */

static UINT    ready_list_check(VOID)
{

TX_INTERRUPT_SAVE_AREA
TX_THREAD   *thread_ptr;
TX_THREAD   *head_ptr;
TX_THREAD   *next_ptr;
UINT         priority;
ULONG        count;
ULONG        i;
UINT         found;
UINT         status =  NX_SUCCESS;


    TX_DISABLE

    for (priority = 0; priority < TX_MAX_PRIORITIES; priority++)
    {

        head_ptr =  _tx_thread_priority_list[priority];
        if (head_ptr == TX_NULL)
            continue;

        next_ptr =  head_ptr;
        count =  0;
        do
        {
            if ((next_ptr -> tx_thread_state != TX_READY) || (next_ptr -> tx_thread_priority != priority))
                status =  NX_NOT_SUCCESSFUL;
            next_ptr =  next_ptr -> tx_thread_ready_next;
            count++;
        } while ((next_ptr != head_ptr) && (count <= _tx_thread_created_count));

        if (next_ptr != head_ptr)
            status =  NX_NOT_SUCCESSFUL;
    }

    thread_ptr =  _tx_thread_created_ptr;
    for (i = 0; i < _tx_thread_created_count; i++)
    {

        if (thread_ptr -> tx_thread_state == TX_READY)
        {

            found =  NX_FALSE;
            head_ptr =  _tx_thread_priority_list[thread_ptr -> tx_thread_priority];
            next_ptr =  head_ptr;
            count =  0;
            while ((next_ptr != TX_NULL) && (count <= _tx_thread_created_count))
            {
                if (next_ptr == thread_ptr)
                {
                    found =  NX_TRUE;
                    break;
                }
                next_ptr =  next_ptr -> tx_thread_ready_next;
                count++;
                if (next_ptr == head_ptr)
                    break;
            }

            if (found == NX_FALSE)
                status =  NX_NOT_SUCCESSFUL;
        }

        thread_ptr =  thread_ptr -> tx_thread_created_next;
    }

    TX_RESTORE

    return(status);
}


/* Let the victim run ACTION while the IP thread waits for the IP mutex the
   victim owns. Return NX_TRUE if that situation was set up.  */

static UINT    arm_and_run(UINT (*action)(VOID))
{

UINT    i;
UINT    armed;


    victim_action =  action;

    /* Own the IP mutex, then start the victim. It blocks on the mutex inside
       the service while this thread sleeps.  */
    tx_mutex_get(&(ip_0.nx_ip_protection), TX_WAIT_FOREVER);
    tx_semaphore_put(&victim_go);
    for (i = 0; (i < 100) && (victim_thread.tx_thread_state != TX_MUTEX_SUSP); i++)
    {
        tx_thread_sleep(1);
    }
    if (victim_thread.tx_thread_state != TX_MUTEX_SUSP)
        error_counter++;

    /* Release the mutex. The victim owns it now, unless the IP thread waited
       too. The victim does not run yet: its priority is lower.  */
    tx_mutex_put(&(ip_0.nx_ip_protection));

    /* Wake the IP thread. It blocks on the mutex, and the victim inherits the
       IP thread's priority inside the service.  */
    armed =  ((ip_0.nx_ip_protection.tx_mutex_owner == &victim_thread) &&
              (victim_thread.tx_thread_state == TX_READY) &&
              (victim_thread.tx_thread_priority == VICTIM_PRIORITY) &&
              (ip_0.nx_ip_thread.tx_thread_state == TX_EVENT_FLAG));
    if (armed)
        tx_event_flags_set(&(ip_0.nx_ip_events), NX_IP_RECEIVE_EVENT, TX_OR);

    /* Wait for the victim.  */
    if (tx_semaphore_get(&victim_done, 10 * NX_IP_PERIODIC_RATE) != TX_SUCCESS)
        error_counter++;

    if (ready_list_check() != NX_SUCCESS)
        error_counter++;

    return(armed);
}


static UINT    tcp_connect_action(VOID)
{
    return(nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), TCP_TEST_PORT, 5 * NX_IP_PERIODIC_RATE));
}


static UINT    udp_bind_action(VOID)
{
    return(nx_udp_socket_bind(&udp_victim, UDP_TEST_PORT, NX_IP_PERIODIC_RATE / 10));
}


static UINT    ping_action(VOID)
{
    ping_response =  NX_NULL;
    return(nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGH", 8, &ping_response, 5 * NX_IP_PERIODIC_RATE));
}


#ifdef FEATURE_NX_IPV6
static UINT    ping6_action(VOID)
{
    ping_response =  NX_NULL;
    return(nxd_icmp_ping(&ip_0, &ipv6_address_1, "ABCDEFGH", 8, &ping_response, 5 * NX_IP_PERIODIC_RATE));
}
#endif /* FEATURE_NX_IPV6 */


/* Define the test threads.  */

static void    victim_entry(ULONG thread_input)
{

    NX_PARAMETER_NOT_USED(thread_input);

    for (;;)
    {

        tx_semaphore_get(&victim_go, TX_WAIT_FOREVER);

        victim_status =  victim_action();

        /* With the defect the service returns at once, without waiting, and
           the ready lists are broken. Stop here: the IP thread cannot run.  */
        if (ready_list_check() != NX_SUCCESS)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }

        tx_semaphore_put(&victim_done);
    }
}


static void    holder_entry(ULONG thread_input)
{

UINT        status;
UINT        attempt;
UINT        armed_rounds;
NX_PACKET  *packet_ptr;


    NX_PARAMETER_NOT_USED(thread_input);

    /* Print out some test information banners.  */
    printf("NetX Test:   IP Mutex Inherit Suspend Test.............................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Resolve the peer's addresses before the test.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGH", 8, &packet_ptr, NX_IP_PERIODIC_RATE);
    if (status == NX_SUCCESS)
        nx_packet_release(packet_ptr);
    else
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* Wait for Duplicate Address Detection.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
    status =  nxd_icmp_ping(&ip_0, &ipv6_address_1, "ABCDEFGH", 8, &packet_ptr, NX_IP_PERIODIC_RATE);
    if (status == NX_SUCCESS)
        nx_packet_release(packet_ptr);
    else
        error_counter++;
#endif /* FEATURE_NX_IPV6 */

    /* TCP connect: _nx_tcp_socket_thread_suspend().  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                                   NX_IP_TIME_TO_LIVE, 200, NX_NULL, NX_NULL);
    status += nx_tcp_server_socket_listen(&ip_1, TCP_TEST_PORT, &server_socket, 5, NX_NULL);
    status += nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY,
                                   NX_IP_TIME_TO_LIVE, 200, NX_NULL, NX_NULL);
    if (status)
        error_counter++;

    armed_rounds =  0;
    for (attempt = 0; (attempt < MAX_ATTEMPTS) && (armed_rounds < ARMED_ROUNDS) && (error_counter == 0); attempt++)
    {

        if (nx_tcp_client_socket_bind(&client_socket, NX_ANY_PORT, NX_NO_WAIT))
            error_counter++;

        /* NetX answers the SYN only after accept.  */
        if (nx_tcp_server_socket_accept(&server_socket, NX_NO_WAIT) != NX_IN_PROGRESS)
            error_counter++;

        armed_rounds +=  arm_and_run(tcp_connect_action);
        if (victim_status != NX_SUCCESS)
            error_counter++;

        if (nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE))
            error_counter++;

        /* Reset the connection and listen again.  */
        nx_tcp_socket_disconnect(&client_socket, NX_NO_WAIT);
        nx_tcp_client_socket_unbind(&client_socket);
        nx_tcp_socket_disconnect(&server_socket, NX_NO_WAIT);
        nx_tcp_server_socket_unaccept(&server_socket);
        if (nx_tcp_server_socket_relisten(&ip_1, TCP_TEST_PORT, &server_socket))
            error_counter++;
    }
    if (armed_rounds < ARMED_ROUNDS)
        error_counter++;

    /* UDP bind of a port in use: nx_udp_socket_bind().  */
    status =  nx_udp_socket_create(&ip_0, &udp_blocker, "UDP Blocker", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    status += nx_udp_socket_bind(&udp_blocker, UDP_TEST_PORT, NX_NO_WAIT);
    status += nx_udp_socket_create(&ip_0, &udp_victim, "UDP Victim", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status)
        error_counter++;

    armed_rounds =  0;
    for (attempt = 0; (attempt < MAX_ATTEMPTS) && (armed_rounds < ARMED_ROUNDS) && (error_counter == 0); attempt++)
    {

        armed_rounds +=  arm_and_run(udp_bind_action);
        if (victim_status != NX_PORT_UNAVAILABLE)
            error_counter++;
    }
    if (armed_rounds < ARMED_ROUNDS)
        error_counter++;

    /* ICMP ping: nx_icmp_interface_ping().  */
    armed_rounds =  0;
    for (attempt = 0; (attempt < MAX_ATTEMPTS) && (armed_rounds < ARMED_ROUNDS) && (error_counter == 0); attempt++)
    {

        armed_rounds +=  arm_and_run(ping_action);
        if ((victim_status != NX_SUCCESS) || (ping_response == NX_NULL))
            error_counter++;
        else
            nx_packet_release(ping_response);
    }
    if (armed_rounds < ARMED_ROUNDS)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* ICMPv6 ping: nx_icmp_interface_ping6().  */
    armed_rounds =  0;
    for (attempt = 0; (attempt < MAX_ATTEMPTS) && (armed_rounds < ARMED_ROUNDS) && (error_counter == 0); attempt++)
    {

        armed_rounds +=  arm_and_run(ping6_action);
        if ((victim_status != NX_SUCCESS) || (ping_response == NX_NULL))
            error_counter++;
        else
            nx_packet_release(ping_response);
    }
    if (armed_rounds < ARMED_ROUNDS)
        error_counter++;
#endif /* FEATURE_NX_IPV6 */

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_mutex_inherit_suspend_test_application_define(void *first_unused_memory)
#endif
{

    NX_PARAMETER_NOT_USED(first_unused_memory);

    /* Print out test information banner.  */
    printf("NetX Test:   IP Mutex Inherit Suspend Test.............................N/A\n");

    test_control_return(3);
}
#endif /* !NX_DISABLE_IPV4 */
