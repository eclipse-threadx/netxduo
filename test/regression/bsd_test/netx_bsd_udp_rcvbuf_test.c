/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* This NetX test concentrates on SO_RCVBUF of BSD UDP sockets: the option sets the
   depth of the BSD receive queue, in bytes of the BSD packet pool's payload size.  */
#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nxd_bsd.h"
#define     DEMO_STACK_SIZE         4096
#define     POOL_PACKET_COUNT       64
#define     SERVER_PORT             12345
#define     CLIENT_PORT             54321


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_UDP_SOCKET           client_socket;
static TX_SEMAPHORE            sema_send;
static TX_SEMAPHORE            sema_sent;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
#define BSD_THREAD_PRIORITY    2

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Number of datagrams the client sends in the current round, and the round number.
   A count of 0 ends the client thread.  */
static UINT                    send_count;
static UCHAR                   send_round;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_udp_rcvbuf_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the client thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    status =  tx_semaphore_create(&sema_send, "send", 0);
    status += tx_semaphore_create(&sema_sent, "sent", 0);
    if (status)
        error_counter++;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, (256 + sizeof(NX_PACKET)) * POOL_PACKET_COUNT);
    pointer = pointer + (256 + sizeof(NX_PACKET)) * POOL_PACKET_COUNT;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable udp and tcp processing for IP instance 0, udp for IP instance 1.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);
    status += nx_tcp_enable(&ip_0);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check BSD init and udp enable status.  */
    if (status)
        error_counter++;
}


/* Let the client send count datagrams to the server socket in one burst, and wait
   until it is done.  */
static void send_burst(UINT count, UCHAR round)
{

    send_count = count;
    send_round = round;
    tx_semaphore_put(&sema_send);

    if (tx_semaphore_get(&sema_sent, 5 * NX_IP_PERIODIC_RATE))
        error_counter++;
}


/* Read every queued datagram without blocking. Each one must be the next datagram
   of the round, starting with the first one, and the count must match.  */
static void drain_and_check(int sockfd, UINT expected_count, UCHAR round)
{

int     ret;
UINT    received = 0;
char    buf[16];


    while (1)
    {
        ret = recv(sockfd, buf, sizeof(buf), 0);
        if (ret < 0)
        {
            if (errno != EWOULDBLOCK)
                error_counter++;
            break;
        }

        if ((ret != 2) || ((UCHAR)buf[0] != round) || ((UCHAR)buf[1] != (UCHAR)received))
            error_counter++;

        received++;
    }

    if (received != expected_count)
        error_counter++;
}


static int get_rcvbuf(int sockfd)
{

int     value = -1;
int     length = sizeof(value);


    if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &value, &length) < 0)
        error_counter++;

    if (length != (int)sizeof(value))
        error_counter++;

    return value;
}


static void set_rcvbuf(int sockfd, int value)
{

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) < 0)
        error_counter++;
}


static void test_udp_rcvbuf(void)
{

int                 sockfd;
int                 tcp_sockfd;
struct sockaddr_in  local_addr;
int                 ret;
int                 value;
int                 length;
short               short_value = 1;
int                 payload = (int)pool_0.nx_packet_pool_payload_size;
int                 default_size = NX_BSD_SOCKET_QUEUE_MAX * payload;


    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        error_counter++;

    /* A new socket reports the default queue depth.  */
    if (get_rcvbuf(sockfd) != default_size)
        error_counter++;

    /* Invalid arguments are rejected and change nothing.  */
    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &short_value, sizeof(short_value));
    if ((ret >= 0) || (errno != EINVAL))
        error_counter++;

    value = -1;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value));
    if ((ret >= 0) || (errno != EINVAL))
        error_counter++;

    length = sizeof(short_value);
    ret = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &value, &length);
    if ((ret >= 0) || (errno != EINVAL))
        error_counter++;

    if (get_rcvbuf(sockfd) != default_size)
        error_counter++;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(SERVER_PORT);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if (ret < 0)
        error_counter++;

    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0)
        error_counter++;

    /* Warm up: resolves ARP, so that no datagram of a burst waits in the ARP queue.  */
    send_burst(1, 0);
    drain_and_check(sockfd, 1, 0);

    /* Default depth: the datagrams beyond NX_BSD_SOCKET_QUEUE_MAX are dropped.  */
    send_burst(2 * NX_BSD_SOCKET_QUEUE_MAX + 2, 1);
    drain_and_check(sockfd, NX_BSD_SOCKET_QUEUE_MAX, 1);

    /* Doubling the reported size doubles the depth.  */
    set_rcvbuf(sockfd, 2 * get_rcvbuf(sockfd));
    if (get_rcvbuf(sockfd) != 2 * default_size)
        error_counter++;

    send_burst(2 * NX_BSD_SOCKET_QUEUE_MAX + 2, 2);
    drain_and_check(sockfd, 2 * NX_BSD_SOCKET_QUEUE_MAX, 2);

    /* The size is rounded down to whole packets.  */
    set_rcvbuf(sockfd, 3 * payload + payload / 2);
    if (get_rcvbuf(sockfd) != 3 * payload)
        error_counter++;

    send_burst(6, 3);
    drain_and_check(sockfd, 3, 3);

    /* A size below one packet keeps one datagram, and so does zero.  */
    set_rcvbuf(sockfd, 1);
    if (get_rcvbuf(sockfd) != payload)
        error_counter++;

    send_burst(3, 4);
    drain_and_check(sockfd, 1, 4);

    set_rcvbuf(sockfd, 0);
    if (get_rcvbuf(sockfd) != payload)
        error_counter++;

    send_burst(3, 5);
    drain_and_check(sockfd, 1, 5);

    /* A size above the limit is lowered to the limit without an error.  */
    set_rcvbuf(sockfd, 0x7FFFFFFF);
#ifdef NX_BSD_SOCKET_QUEUE_MAX_LIMIT
    if (get_rcvbuf(sockfd) != NX_BSD_SOCKET_QUEUE_MAX_LIMIT * payload)
        error_counter++;
#else
    if (get_rcvbuf(sockfd) != (int)pool_0.nx_packet_pool_total * payload)
        error_counter++;
#endif /* NX_BSD_SOCKET_QUEUE_MAX_LIMIT */

    ret = soc_close(sockfd);
    if (ret < 0)
        error_counter++;

    /* A new socket starts with the default depth again.  */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        error_counter++;

    if (get_rcvbuf(sockfd) != default_size)
        error_counter++;

    ret = soc_close(sockfd);
    if (ret < 0)
        error_counter++;

    /* TCP sockets keep the window semantics.  */
    tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sockfd < 0)
        error_counter++;

    value = 4096;
    if (setsockopt(tcp_sockfd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) < 0)
        error_counter++;

    value = 0;
    length = sizeof(value);
    if (getsockopt(tcp_sockfd, SOL_SOCKET, SO_RCVBUF, &value, &length) < 0)
        error_counter++;

    if (value != 4096)
        error_counter++;

    ret = soc_close(tcp_sockfd);
    if (ret < 0)
        error_counter++;
}


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{

    printf("NetX Test:   Basic BSD UDP SO_RCVBUF Test..................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    test_udp_rcvbuf();

    /* Stop the client thread.  */
    send_count = 0;
    tx_semaphore_put(&sema_send);

    tx_thread_sleep(1);

    validate_bsd_structure();

    if(error_counter)
        printf("ERROR!\n");
    else
        printf("SUCCESS!\n");

    if(error_counter)
        test_control_return(1);

    test_control_return(0);
}

static void    ntest_1_entry(ULONG thread_input)
{

UINT            status;
NX_PACKET       *packet_ptr;
ULONG           actual_status;
UINT            i;
UCHAR           data[2];


    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(3);
    }

    /* Create a socket.  */
    status =  nx_udp_socket_create(&ip_1, &client_socket, "Client Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 10);
    if (status)
        error_counter++;

    status = nx_udp_socket_bind(&client_socket, CLIENT_PORT, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    while (1)
    {
        tx_semaphore_get(&sema_send, NX_WAIT_FOREVER);

        if (send_count == 0)
            break;

        for (i = 0; i < send_count; i++)
        {

            status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
            if (status)
            {
                error_counter++;
                break;
            }

            data[0] = send_round;
            data[1] = (UCHAR)i;
            status = nx_packet_data_append(packet_ptr, data, sizeof(data), &pool_0, NX_WAIT_FOREVER);
            if (status)
                error_counter++;

            status =  nx_udp_socket_send(&client_socket, packet_ptr, IP_ADDRESS(1, 2, 3, 4), SERVER_PORT);
            if (status)
            {
                error_counter++;
                nx_packet_release(packet_ptr);
            }
        }

        /* Let both IP instances process everything that was sent.  */
        tx_thread_sleep(1);

        tx_semaphore_put(&sema_sent);
    }

    status = nx_udp_socket_unbind(&client_socket);
    if (status)
        error_counter++;

    status = nx_udp_socket_delete(&client_socket);
    if (status)
        error_counter++;
}

extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];
extern TX_BLOCK_POOL nx_bsd_socket_block_pool;
static void validate_bsd_structure(void)
{
int i;
    /* Make sure every BSD socket should be free by now. */

    for(i = 0; i < NX_BSD_MAX_SOCKETS; i++)
    {
        if(nx_bsd_socket_array[i].nx_bsd_socket_status_flags & NX_BSD_SOCKET_IN_USE)
        {
            error_counter++;
        }

        if(nx_bsd_socket_array[i].nx_bsd_socket_tcp_socket ||
           nx_bsd_socket_array[i].nx_bsd_socket_udp_socket)
        {
            error_counter++;
        }
    }

    /* Make sure all the NX SOCKET control blocks are released. */
    if(nx_bsd_socket_block_pool.tx_block_pool_available !=
       nx_bsd_socket_block_pool.tx_block_pool_total)
    {
        error_counter++;
    }

    /* Make sure all the sockets are released */
    if(ip_0.nx_ip_tcp_created_sockets_ptr ||
       ip_0.nx_ip_udp_created_sockets_ptr)
    {
        error_counter++;
        return;
    }
}

#else
extern void       test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_udp_rcvbuf_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD UDP SO_RCVBUF Test..................N/A\n");

    test_control_return(3);
}
#endif
