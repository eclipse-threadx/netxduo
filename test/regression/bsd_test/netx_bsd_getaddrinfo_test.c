/* This NetX test concentrates on the basic BSD TCP blocking operation.  */
/* The BSD APIs involved in this test are:  socket(), connect(), send(), soc_close() */

#include   "tx_api.h"
#include   "nx_api.h"
#ifdef NX_BSD_ENABLE
#include   "nx_icmpv6.h"
#include   "nxd_bsd.h"
#include   "nxd_dns.h"
#define     DEMO_STACK_SIZE         4096


static char response_cname_www_baidu_com[100] = {
0x18, 0x03, 0x73, 0x33, 0xc1, 0xbd, 0xc8, 0x3a, 
0x35, 0x60, 0x4b, 0x46, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x56, 0xa6, 0x10, 0x00, 0x00, 0x40, 0x11, 
0x52, 0xcc, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 
0x00, 0x69, 0x00, 0x35, 0xc7, 0x20, 0x00, 0x42, 
0x1b, 0x3d, 0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 
0x77, 0x77, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 
0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x05, 0x00,
0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00,
0x00, 0x01, 0xe7, 0x00, 0x0f, 0x03, 0x77, 0x77,
0x77, 0x01, 0x61, 0x06, 0x73, 0x68, 0x69, 0x66, 
0x65, 0x6e, 0xc0, 0x16 };

static char response_a_www_baidu_com[132] = {
0x00, 0x15, 0x5d, 0x64, 0x17, 0x05, 0x8c, 0xec, /* ..]d.... */
0x4b, 0x68, 0xd1, 0xfe, 0x08, 0x00, 0x45, 0x00, /* Kh....E. */
0x00, 0x76, 0x63, 0x9e, 0x40, 0x00, 0x40, 0x11, /* .vc.@.@. */
0x8d, 0x6d, 0xc0, 0xa8, 0x64, 0x02, 0xc0, 0xa8, /* .m..d... */
0x64, 0x18, 0x00, 0x35, 0xc1, 0x9f, 0x00, 0x62, /* d..5...b */
0x23, 0x29, 0x11, 0x95, 0x81, 0x80, 0x00, 0x01, /* #)...... */
0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, /* .......w */
0x77, 0x77, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, /* ww.baidu */
0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, /* .com.... */
0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, /* ........ */
0x00, 0x02, 0x01, 0x00, 0x0f, 0x03, 0x77, 0x77, /* ......ww */
0x77, 0x01, 0x61, 0x06, 0x73, 0x68, 0x69, 0x66, /* w.a.shif */
0x65, 0x6e, 0xc0, 0x16, 0xc0, 0x2b, 0x00, 0x01, /* en...+.. */
0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, /* ..... .. */
0x73, 0xef, 0xd2, 0x1b, 0xc0, 0x2b, 0x00, 0x01, /* s....+.. */
0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, /* ..... .. */
0x73, 0xef, 0xd3, 0x70                          /* s..p */
};

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           server_socket;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
static TX_SEMAPHORE            sema_0;
static TX_SEMAPHORE            sema_1;
static NX_DNS                  client_dns;
static NX_UDP_SOCKET           udp_socket;
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            10
#define DNS_START_OFFSET       (14 + 20 + 8)
/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static UINT                    response_sequence;
static ULONG                   packet_pool_area[(256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 8 / 4];

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS ipv6_address_ip0;
static NXD_ADDRESS ipv6_address_ip1;
#endif
static char *send_buffer = "Hello World";
static char *requests[4] = {"Request1", "Request2", "Request3", "Request4"};
static char *response[4] = {"Response1", "Response2", "Response3", "Response4"};
static void validate_bsd_structure(void);
#ifdef __PRODUCT_NETXDUO__
static char large_msg[1000];
#endif
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_getaddrinfo_test_application_define(void *first_unused_memory)
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

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, packet_pool_area, sizeof(packet_pool_area));


    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
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

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check UDP enable status.  */
    if (status)
        error_counter++;

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check BSD enable status.  */
    if (status)
        error_counter++;

    status = tx_semaphore_create(&sema_0, "SEMA 0", 0);
    status += tx_semaphore_create(&sema_1, "SEMA 1", 0);
    if(status)
        error_counter++;
}
typedef struct client_info_struct
{
    int sockfd;
    int message_id;
} client_info;

static client_info client_data[NUM_CLIENTS];
static ULONG stack_space[NUM_CLIENTS][DEMO_STACK_SIZE / sizeof(ULONG)];
static TX_THREAD helper_thread[NUM_CLIENTS];
#ifdef FEATURE_NX_IPV6
static ULONG stack_space6[NUM_CLIENTS][DEMO_STACK_SIZE / sizeof(ULONG)];
static TX_THREAD helper_thread6[NUM_CLIENTS];
#endif
static VOID bsd_server_helper_thread_entry(ULONG thread_input)
{
int         ret;
int         sockfd, message_id;
char        buf[30];
int         sockaddr_len;
fd_set      read_fds, write_fds, except_fds;
struct timeval wait_time;
#ifdef FEATURE_NX_IPV6
struct sockaddr_in6 remote_address;
#else
struct sockaddr_in remote_address;
#endif

    sockfd = client_data[thread_input].sockfd;
    message_id = client_data[thread_input].message_id;
    /* Receive data from the client. */
    if(message_id == 2)
    {
#ifdef FEATURE_NX_IPV6
        sockaddr_len = sizeof(struct sockaddr_in6);
#else
        sockaddr_len = sizeof(struct sockaddr_in);
#endif
        ret = recvfrom(sockfd, (char*)buf, sizeof(buf), 0, (struct sockaddr*)&remote_address, &sockaddr_len);

        if(ret < 0)
            error_counter++;
        if(nx_bsd_socket_array[sockfd - 0x20].nx_bsd_socket_family == AF_INET)
        {
            if(sockaddr_len != sizeof(struct sockaddr_in))
                error_counter++;
            if(((struct sockaddr_in*)&remote_address) -> sin_family != AF_INET)
                error_counter++;
            if(((struct sockaddr_in*)&remote_address) -> sin_addr.s_addr != htonl(0x01020305))
                error_counter++;
        }
#ifdef FEATURE_NX_IPV6
        else if(nx_bsd_socket_array[sockfd - 0x20].nx_bsd_socket_family == AF_INET6)
        {
            if(sockaddr_len != sizeof(struct sockaddr_in6))
                error_counter++;
            if((remote_address.sin6_addr._S6_un._S6_u32[0] != htonl(ipv6_address_ip1.nxd_ip_address.v6[0])) ||
               (remote_address.sin6_addr._S6_un._S6_u32[1] != htonl(ipv6_address_ip1.nxd_ip_address.v6[1])) ||
               (remote_address.sin6_addr._S6_un._S6_u32[2] != htonl(ipv6_address_ip1.nxd_ip_address.v6[2])) ||
               (remote_address.sin6_addr._S6_un._S6_u32[3] != htonl(ipv6_address_ip1.nxd_ip_address.v6[3])))
                error_counter++;
        }
#endif
    }
    else
    {

        /* Peek message test. */
        ret = recv(sockfd, buf, sizeof(buf), MSG_PEEK);

        /* Validate the data. */
        if((ret != (int)strlen(requests[message_id & 3])) || strncmp(buf, requests[message_id & 3], ret))
            error_counter++;

        ret = recv(sockfd, buf, sizeof(buf), 0);
    }
    if(ret <= 0)
        error_counter++;

    /* Validate the data. */
    if((ret != (int)strlen(requests[message_id & 3])) || strncmp(buf, requests[message_id & 3], ret))
        error_counter++;

    /* Invoke recvfrom with MSG_DONTWAIT flag. */
    ret = recvfrom(sockfd, (char*)buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&remote_address, &sockaddr_len);
    if(ret >= 0)
        error_counter++;
    else if((errno != EWOULDBLOCK) || (errno != EAGAIN))
        error_counter++;

    /* Invoke recv with MSG_DONTWAIT flag. */
    ret = recv(sockfd, (char*)buf, sizeof(buf), MSG_DONTWAIT);
    if(ret >= 0)
        error_counter++;
    else if((errno != EWOULDBLOCK) || (errno != EAGAIN))
        error_counter++;

    /* Send a response back. */
    ret = send(sockfd, response[message_id & 3], strlen(response[message_id & 3]), 0);
    if(ret != (int)strlen(response[message_id & 3]))
        error_counter++;

    tx_semaphore_get(&sema_1, 5 * NX_IP_PERIODIC_RATE);

#ifdef __PRODUCT_NETXDUO__
    /* Invoke send with MSG_DONTWAIT flag. The message is larger than tx_window. Partial data should be sent. */
    ret = send(sockfd, large_msg, sizeof(large_msg), MSG_DONTWAIT);
    if (ret <= 0)
        error_counter++;
#endif

    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&except_fds);
    FD_SET(sockfd, &read_fds);
    FD_SET(sockfd, &write_fds);
    FD_SET(sockfd, &except_fds);

    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    wait_time.tv_sec = 1;
    wait_time.tv_usec = 0;
    select(sockfd + 1, &read_fds, &write_fds, &except_fds, &wait_time);
    if((FD_ISSET(sockfd, &read_fds) && FD_ISSET(sockfd, &write_fds) && FD_ISSET(sockfd, &except_fds)) == 0)
        error_counter++;

    tx_semaphore_put(&sema_0);
    return;
}


static void test_tcp_client4(void)
{
int sockfd;
struct sockaddr_in local_addr;
#ifdef FEATURE_NX_IPV6
struct sockaddr_in6 local_addr6;
int port;
int sockfd1;
#endif
int bytes_sent;
int ret;
char buf;
struct addrinfo *server_info;

    if (getaddrinfo("1.2.3.5", "12", NX_NULL, &server_info) != 0)
    {
        error_counter++;
        return;
    }

    sockfd = socket(server_info -> ai_family, server_info -> ai_socktype,
                    server_info -> ai_protocol);
    if(sockfd < 0)
        error_counter++;

    if(connect(sockfd, server_info -> ai_addr, server_info -> ai_addrlen) < 0)
        error_counter++;

    freeaddrinfo(server_info);

    bytes_sent = send(sockfd, send_buffer, strlen(send_buffer), 0);

    if(bytes_sent != (int)strlen(send_buffer))
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* Get the port bind to any. */
    port = nx_bsd_socket_array[sockfd - NX_BSD_SOCKFD_START].nx_bsd_socket_tcp_socket -> nx_tcp_socket_port;

    sockfd1 = socket(AF_INET6, SOCK_STREAM, 0);
    if(sockfd1 < 0)
        error_counter++;

    memset(&local_addr6, 0, sizeof(local_addr6));
    local_addr6.sin6_family = AF_INET6;
    local_addr6.sin6_port = htons(port);

    /* Bind to the same port. */
    ret = bind(sockfd1, (struct sockaddr*)&local_addr6, sizeof(local_addr6));
    if(ret < 0)
        error_counter++;

    ret = soc_close(sockfd1);
    if(ret < 0)
        error_counter++;
#endif

    /* Call recv before peer orderly shutdown. */
    ret = recv(sockfd, &buf, 1, 0);
    if (ret != 0)
        error_counter++;

    /* Make sure the other side gets the message. */
    tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);

    /* Call recv after peer orderly shutdown. */
    ret = recv(sockfd, &buf, 1, 0);
    if (ret != 0)
        error_counter++;

    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}

static void test_tcp_server4(void)
{
int                sockfd;
struct sockaddr_in remote_addr, local_addr;
int                address_length;
int                ret;
int                newsock;
int                i;
UINT               status;
struct addrinfo    hints, *server_info;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NX_NULL, "12345", &hints, &server_info) != 0)
    {
        error_counter++;
        return;
    }

    sockfd = socket(server_info -> ai_family, server_info -> ai_socktype,
                    server_info -> ai_protocol);
    if(sockfd < 0)
        error_counter++;

    ret = bind(sockfd, server_info -> ai_addr, server_info -> ai_addrlen);
    if(ret < 0)
        error_counter++;

    freeaddrinfo(server_info);

    ret = listen(sockfd, 5);
    if(ret < 0)
        error_counter++;

    /* 3 iterations. */
    for(i = 0; i < NUM_CLIENTS; i++)
    {
        address_length = sizeof(remote_addr);

        newsock = accept(sockfd, (struct sockaddr*)&remote_addr, &address_length);

        if(newsock <= 0)
            error_counter++;
        else if(address_length != sizeof(remote_addr))
            error_counter++;
        else if((remote_addr.sin_family != AF_INET) || (remote_addr.sin_addr.s_addr != htonl(0x01020305)))
            error_counter++;

        address_length = sizeof(local_addr);
        ret = getsockname(newsock, (struct sockaddr*)&local_addr, &address_length);
        if(ret < 0)
            error_counter++;
        else if(address_length != sizeof(local_addr))
            error_counter++;
        else if(local_addr.sin_family != AF_INET)
            error_counter++;
        else if(local_addr.sin_port != htons(12345))
            error_counter++;
        else if(local_addr.sin_addr.s_addr != htonl(IP_ADDRESS(1, 2, 3, 4)))
            error_counter++;

        address_length = sizeof(remote_addr);
        ret = getpeername(newsock, (struct sockaddr*)&remote_addr, &address_length);
        if(ret < 0)
            error_counter++;
        else if(address_length != sizeof(remote_addr))
            error_counter++;
        else if(remote_addr.sin_family != AF_INET)
            error_counter++;
        else if(remote_addr.sin_addr.s_addr != htonl(IP_ADDRESS(1,2,3,5)))
            error_counter++;


        /* Set the client data */
        client_data[i].sockfd = newsock;
        client_data[i].message_id = i;

        /* Create a helper thread to handle the new socket. */
        status = tx_thread_create(&helper_thread[i], "helper thread", bsd_server_helper_thread_entry,
                                  i, stack_space[i], DEMO_STACK_SIZE, 2, 2, TX_NO_TIME_SLICE, TX_AUTO_START);
        if(status != TX_SUCCESS)
            error_counter++;

        tx_thread_relinquish();
    }

    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    for(i = 0; i < NUM_CLIENTS; i++)
    {

        /* Wakeup server thread. */
        tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);
    }
}


#ifdef FEATURE_NX_IPV6
static void test_tcp_client6(void)
{
int                 sockfd;
int                 bytes_sent;
int                 ret;
struct addrinfo    *server_info;

    if (getaddrinfo("fe80::211:22ff:fe33:4457", "12", NX_NULL, &server_info) != 0)
    {
        error_counter++;
        return;
    }

    sockfd = socket(server_info -> ai_family, server_info -> ai_socktype,
                    server_info -> ai_protocol);
    if(sockfd < 0)
        error_counter++;

    if(connect(sockfd, server_info -> ai_addr, server_info -> ai_addrlen) < 0)
        error_counter++;

    freeaddrinfo(server_info);

    bytes_sent = send(sockfd, send_buffer, strlen(send_buffer), 0);

    if(bytes_sent != (INT)strlen(send_buffer))
        error_counter++;

    /* Make sure the other side gets the message. */
    tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);

    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}

static void test_tcp_server6(void)
{
int                 sockfd;
struct sockaddr_in6 remote_addr, local_addr;
int                 address_length;
int                 ret;
int                 newsock;
int                 i;
UINT                status;
struct addrinfo    hints, *server_info;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NX_NULL, "12346", &hints, &server_info) != 0)
    {
        error_counter++;
        return;
    }

    sockfd = socket(server_info -> ai_family, server_info -> ai_socktype,
                    server_info -> ai_protocol);
    if(sockfd < 0)
        error_counter++;

    ret = bind(sockfd, server_info -> ai_addr, server_info -> ai_addrlen);
    if(ret < 0)
        error_counter++;

    freeaddrinfo(server_info);

    ret = listen(sockfd, 5);
    if(ret < 0)
        error_counter++;

    /* 3 iterations. */
    for(i = 0; i < NUM_CLIENTS; i++)
    {
        address_length = sizeof(remote_addr);

        newsock = accept(sockfd, (struct sockaddr*)&remote_addr, &address_length);

        if(newsock <= 0)
            error_counter++;

        if(address_length != sizeof(struct sockaddr_in6))
            error_counter++;

        if((remote_addr.sin6_family != AF_INET6) ||
           (remote_addr.sin6_addr._S6_un._S6_u32[0] != htonl(ipv6_address_ip1.nxd_ip_address.v6[0])) ||
           (remote_addr.sin6_addr._S6_un._S6_u32[1] != htonl(ipv6_address_ip1.nxd_ip_address.v6[1])) ||
           (remote_addr.sin6_addr._S6_un._S6_u32[2] != htonl(ipv6_address_ip1.nxd_ip_address.v6[2])) ||
           (remote_addr.sin6_addr._S6_un._S6_u32[3] != htonl(ipv6_address_ip1.nxd_ip_address.v6[3])))
            error_counter++;

        address_length = sizeof(local_addr);
        ret = getsockname(newsock, (struct sockaddr*)&local_addr, &address_length);
        if(ret < 0)
            error_counter++;
        else if(address_length != sizeof(local_addr))
            error_counter++;
        else if(local_addr.sin6_family != AF_INET6)
            error_counter++;
        else if(local_addr.sin6_port != htons(12346))
            error_counter++;
        else if((local_addr.sin6_addr._S6_un._S6_u32[0] != htonl(ipv6_address_ip0.nxd_ip_address.v6[0])) ||
                (local_addr.sin6_addr._S6_un._S6_u32[1] != htonl(ipv6_address_ip0.nxd_ip_address.v6[1])) ||
                (local_addr.sin6_addr._S6_un._S6_u32[2] != htonl(ipv6_address_ip0.nxd_ip_address.v6[2])) ||
                (local_addr.sin6_addr._S6_un._S6_u32[3] != htonl(ipv6_address_ip0.nxd_ip_address.v6[3])))
            error_counter++;

        address_length = sizeof(remote_addr);
        ret = getpeername(newsock, (struct sockaddr*)&remote_addr, &address_length);
        if(ret < 0)
            error_counter++;
        else if(address_length != sizeof(remote_addr))
            error_counter++;
        else if(remote_addr.sin6_family != AF_INET6)
            error_counter++;
        else if((remote_addr.sin6_family != AF_INET6) ||
                (remote_addr.sin6_addr._S6_un._S6_u32[0] != htonl(ipv6_address_ip1.nxd_ip_address.v6[0])) ||
                (remote_addr.sin6_addr._S6_un._S6_u32[1] != htonl(ipv6_address_ip1.nxd_ip_address.v6[1])) ||
                (remote_addr.sin6_addr._S6_un._S6_u32[2] != htonl(ipv6_address_ip1.nxd_ip_address.v6[2])) ||
                (remote_addr.sin6_addr._S6_un._S6_u32[3] != htonl(ipv6_address_ip1.nxd_ip_address.v6[3])))
            error_counter++;



        /* Set the client data */
        client_data[i].sockfd = newsock;
        client_data[i].message_id = i;

        /* Create a helper thread to handle the new socket. */
        status = tx_thread_create(&helper_thread6[i], "helper thread", bsd_server_helper_thread_entry,
                         i, stack_space6[i], DEMO_STACK_SIZE, 2, 2, TX_NO_TIME_SLICE, TX_AUTO_START);
        if(status)
            error_counter++;

        tx_thread_relinquish();
    }

    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    for(i = 0; i < NUM_CLIENTS; i++)
    {

        /* Wakeup server thread. */
        tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);
    }
}

#endif

static void    close_before_accept_test()
{
int     server_fd, client_fd;
int     ret;
struct  sockaddr_in remote_addr, local_addr;

    /* Setup server socket. */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0)
        error_counter++;

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(server_fd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    ret = listen(server_fd, 5);
    if(ret < 0)
        error_counter++;

    /* Setup client socket. */
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(client_fd < 0)
        error_counter++;

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(12345);
    remote_addr.sin_addr.s_addr = htonl(0x01020304);

    if(connect(client_fd, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0)
        error_counter++;

    /* Close before calling accept. */
    soc_close(server_fd);
    soc_close(client_fd);
}


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
int                sockfd;
struct sockaddr_in remote_addr;
#ifdef FEATURE_NX_IPV6
char mac_ip0[6];
char mac_ip1[6];
UINT status;
#endif
int                ret;


    printf("NetX Test:   Basic BSD getaddrinfo Test....................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#ifdef FEATURE_NX_IPV6
    /* First set up IPv6 addresses. */
    ipv6_address_ip0.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_ip0.nxd_ip_address.v6[0] = 0xfe800000;
    ipv6_address_ip0.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_ip0.nxd_ip_address.v6[2] = 0x021122ff;
    ipv6_address_ip0.nxd_ip_address.v6[3] = 0xfe334456;

    ipv6_address_ip1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_ip1.nxd_ip_address.v6[0] = 0xfe800000;
    ipv6_address_ip1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_ip1.nxd_ip_address.v6[2] = 0x021122ff;
    ipv6_address_ip1.nxd_ip_address.v6[3] = 0xfe334457;

    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_ip0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_ip1, 64, NX_NULL);

    status += nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    mac_ip0[0] = (CHAR)(ip_0.nx_ip_interface[0].nx_interface_physical_address_msw >> 8);
    mac_ip0[1] = ip_0.nx_ip_interface[0].nx_interface_physical_address_msw & 0xFF;
    mac_ip0[2] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 24) & 0xff;
    mac_ip0[3] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 16) & 0xff;
    mac_ip0[4] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 8) & 0xff;
    mac_ip0[5] = ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw  & 0xff;

    mac_ip1[0] = (CHAR)(ip_1.nx_ip_interface[0].nx_interface_physical_address_msw >> 8);
    mac_ip1[1] = ip_1.nx_ip_interface[0].nx_interface_physical_address_msw & 0xFF;
    mac_ip1[2] = (ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw >> 24) & 0xff;
    mac_ip1[3] = (ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw >> 16) & 0xff;
    mac_ip1[4] = (ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw >> 8) & 0xff;
    mac_ip1[5] = ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw  & 0xff;

    status += nxd_nd_cache_entry_set(&ip_0, ipv6_address_ip1.nxd_ip_address.v6, 0,  mac_ip1);
    status += nxd_nd_cache_entry_set(&ip_1, ipv6_address_ip0.nxd_ip_address.v6, 0,  mac_ip0);

    if(status)
        error_counter++;
#endif

    close_before_accept_test();

    tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);
    test_tcp_client4();

    tx_semaphore_put(&sema_1);
    test_tcp_server4();

#ifdef FEATURE_NX_IPV6
    tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);
    test_tcp_client6();

    tx_semaphore_put(&sema_1);
    test_tcp_server6();
#endif

    tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);
    /* Now open another socket and attempt to connect to the correct remote
       host but an unexpected port so we expect an unsuccessful connections. */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(13);
    remote_addr.sin_addr.s_addr = htonl(0x01020305);

    if(connect(sockfd, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) >= 0)
        error_counter++;
    if(errno != ECONNREFUSED)
        error_counter++;

    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    /* Now open another socket and attempt to connect to the an incorrect
       remote host so we expect an unsuccessful connections. */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;


    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(13);
    remote_addr.sin_addr.s_addr = htonl(0x01020306);

    if(connect(sockfd, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) >= 0)
        error_counter++;

    if(errno != ETIMEDOUT)
        error_counter++;
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    /* After the previous failed connection, make sure we can still open a socket. */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;

    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    validate_bsd_structure();

    if(error_counter)
        printf("ERROR!\n");
    else
        printf("SUCCESS!\n");

    if(error_counter)
        test_control_return(1);

    test_control_return(0);
}

static NX_TCP_SOCKET tcp_sockets[NUM_CLIENTS];
static void    multiple_client4(void)
{

int           i;
UINT          status = NX_SUCCESS;
NX_PACKET     *packet_ptr;
    for(i = 0; i < NUM_CLIENTS; i++)
    {
        status +=  nx_tcp_socket_create(&ip_1, &tcp_sockets[i], "Server Socket",
                                        NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                        NX_NULL, NX_NULL);
        status +=  nx_tcp_client_socket_bind(&tcp_sockets[i], NX_ANY_PORT, 0);
    }
    if(status != NX_SUCCESS)
        error_counter++;

    status = NX_SUCCESS;
    for(i = 0; i < NUM_CLIENTS; i++)
    {
        status += nx_tcp_client_socket_connect(&tcp_sockets[i], IP_ADDRESS(1, 2, 3, 4), 12345, NX_IP_PERIODIC_RATE);

    }
    if(status != NX_SUCCESS)
        error_counter++;

    status = NX_SUCCESS;

    /* Send messages to each server */
    for(i = 0; i < NUM_CLIENTS; i++)
    {
        status += nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        status += nx_packet_data_append(packet_ptr, requests[i & 3], strlen(requests[i & 3]),
                                        &pool_0, NX_NO_WAIT);
        status += nx_tcp_socket_send(&tcp_sockets[i], packet_ptr, NX_IP_PERIODIC_RATE);

    }

    if(status != NX_SUCCESS)
        error_counter++;

    status = NX_SUCCESS;
    /* Receive 3 messages. */

    for(i = 0; i < NUM_CLIENTS; i++)
    {
        status = nx_tcp_socket_receive(&tcp_sockets[i], &packet_ptr, 2 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
        {
            error_counter++;
            continue;
        }

        /* Validate the received data. */
        else if(packet_ptr -> nx_packet_length != strlen(response[i & 3]))
            error_counter++;
        else if(strncmp((char*)packet_ptr -> nx_packet_prepend_ptr, response[i & 3], packet_ptr -> nx_packet_length))
            error_counter++;
        nx_packet_release(packet_ptr);
    }

    for(i = 0; i < NUM_CLIENTS; i++)
    {

        /* Wakeup server thread. */
        tx_semaphore_put(&sema_1);
    }

    /* Shutdown the socket. */
    for(i = 0; i < NUM_CLIENTS; i++)
    {

        status = nx_tcp_socket_disconnect(&tcp_sockets[i], 1 * NX_IP_PERIODIC_RATE);
        if(status == NX_NOT_CONNECTED || status == NX_DISCONNECT_FAILED)
            status = 0;

        if(tcp_sockets[i].nx_tcp_socket_bound_next)
            status += nx_tcp_client_socket_unbind(&tcp_sockets[i]);


        status += nx_tcp_socket_delete(&tcp_sockets[i]);

        if(status != NX_SUCCESS)
            error_counter++;
    }


}


#ifdef FEATURE_NX_IPV6
static void    multiple_client6(void)
{

int           i;
UINT          status = NX_SUCCESS;
NX_PACKET     *packet_ptr;
    for(i = 0; i < NUM_CLIENTS; i++)
    {
        status +=  nx_tcp_socket_create(&ip_1, &tcp_sockets[i], "Server Socket",
                                        NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                        NX_NULL, NX_NULL);
        status +=  nx_tcp_client_socket_bind(&tcp_sockets[i], NX_ANY_PORT, 0);
    }
    if(status != NX_SUCCESS)
        error_counter++;

    status = NX_SUCCESS;
    for(i = 0; i < NUM_CLIENTS; i++)
    {
        status += nxd_tcp_client_socket_connect(&tcp_sockets[i], &ipv6_address_ip0, 12346, NX_IP_PERIODIC_RATE);
    }
    if(status != NX_SUCCESS)
        error_counter++;

    status = NX_SUCCESS;

    /* Send messages to each server */
    for(i = 0; i < NUM_CLIENTS; i++)
    {
        status += nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
        status += nx_packet_data_append(packet_ptr, requests[i & 3], strlen(requests[i & 3]),
                                        &pool_0, NX_NO_WAIT);
        status += nx_tcp_socket_send(&tcp_sockets[i], packet_ptr, NX_IP_PERIODIC_RATE);

    }

    if(status != NX_SUCCESS)
        error_counter++;

    status = NX_SUCCESS;
    /* Receive 3 messages. */

    for(i = 0; i < NUM_CLIENTS; i++)
    {
        status = nx_tcp_socket_receive(&tcp_sockets[i], &packet_ptr, 2 * NX_IP_PERIODIC_RATE);
        if(status != NX_SUCCESS)
        {
            error_counter++;
            continue;
        }

        /* Validate the received data. */
        else if(packet_ptr -> nx_packet_length != strlen(response[i & 3]))
            error_counter++;
        else if(strncmp((char *)packet_ptr -> nx_packet_prepend_ptr, response[i & 3], packet_ptr -> nx_packet_length))
            error_counter++;
        nx_packet_release(packet_ptr);
    }

    for(i = 0; i < NUM_CLIENTS; i++)
    {

        /* Wakeup server thread. */
        tx_semaphore_put(&sema_1);
    }

    /* Shutdown the socket. */
    for(i = 0; i < NUM_CLIENTS; i++)
    {

        nx_tcp_socket_disconnect(&tcp_sockets[i], 1 * NX_IP_PERIODIC_RATE);

        if(tcp_sockets[i].nx_tcp_socket_bound_next)
            status = nx_tcp_client_socket_unbind(&tcp_sockets[i]);
        status += nx_tcp_socket_delete(&tcp_sockets[i]);

        if(status != NX_SUCCESS)
            error_counter++;
    }

}
#endif

static void    netx_tcp_server(void)
{
NX_PACKET       *packet_ptr;
UINT             status;
    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 1 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Receive a TCP message from the socket.  */
    status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, 2 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if ((status) || (packet_ptr -> nx_packet_length != strlen(send_buffer)))
        error_counter++;
    else
    {
        if(memcmp(packet_ptr -> nx_packet_prepend_ptr, send_buffer, strlen(send_buffer)))
           error_counter++;

        nx_packet_release(packet_ptr);
    }

    tx_semaphore_put(&sema_0);

    /* Disconnect the server socket.  */
    status =  nx_tcp_socket_disconnect(&server_socket, 1 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup server socket for listening again.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, 12);

    /* Check for error.  */
    if (status)
        error_counter++;

    nx_tcp_socket_delete(&server_socket);
}

static UINT   nx_dns_response_packet_send(NX_UDP_SOCKET *server_socket, UINT port,
                                          USHORT transmit_id, UCHAR *data, UINT length)
{
UINT        status;
NX_PACKET   *response_packet;
UCHAR        *data_ptr;

    /* Allocate a response packet.  */
    status =  nx_packet_allocate(&pool_0, &response_packet, NX_UDP_PACKET, NX_NO_WAIT);
    
    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Write the DNS response messages into the packet payload!  */
    memcpy(response_packet -> nx_packet_prepend_ptr, data + DNS_START_OFFSET, length - DNS_START_OFFSET);

    /* Adjust the write pointer.  */
    response_packet -> nx_packet_length = length - DNS_START_OFFSET;
    response_packet -> nx_packet_append_ptr =  response_packet -> nx_packet_prepend_ptr + response_packet -> nx_packet_length;

    /* Update the DNS transmit ID.  */
    data_ptr = response_packet -> nx_packet_prepend_ptr + NX_DNS_ID_OFFSET;
    *data_ptr++ = (UCHAR)(transmit_id >> 8);
    *data_ptr = (UCHAR)transmit_id;

    /* Send the UDP packet with the correct port.  */
    status =  nx_udp_socket_send(server_socket, response_packet, IP_ADDRESS(1, 2, 3, 4), port);

    /* Check the status.  */
    if (status)      
        nx_packet_release(response_packet);         

    return status;
}

static void    receive_packet_function(NX_UDP_SOCKET *socket_ptr)
{
NX_PACKET *packet_ptr;
USHORT     transmit_id;
UCHAR     *data_ptr;
UINT       port;

    nx_udp_socket_receive(socket_ptr, &packet_ptr, NX_NO_WAIT);
    nx_udp_packet_info_extract(packet_ptr, NX_NULL ,NX_NULL, &port, NX_NULL);

    /* Get the DNS transmit ID.  */
    data_ptr = packet_ptr -> nx_packet_prepend_ptr + NX_DNS_ID_OFFSET;
    transmit_id = *data_ptr++;
    transmit_id =  (USHORT)((transmit_id << 8) | *data_ptr);

    nx_packet_release(packet_ptr);

    if (response_sequence == 0)
    {
        nx_dns_response_packet_send(socket_ptr, port, transmit_id, response_a_www_baidu_com, sizeof(response_a_www_baidu_com));
    }
    else
    {
        nx_dns_response_packet_send(socket_ptr, port, transmit_id, response_cname_www_baidu_com, sizeof(response_cname_www_baidu_com));
    }

    response_sequence++;
}

static void    dns_test()
{
struct addrinfo hints, *addrinfo;

    /* Initialize DNS client. */
    nx_dns_create(&client_dns, &ip_0, (UCHAR *)"DNS Client");
#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL   
    nx_dns_packet_pool_set(&client_dns, &pool_0);
#endif
    nx_dns_server_add(&client_dns, IP_ADDRESS(1, 2, 3, 5));

    /* Create a UDP socket to respond DNS query. */
    nx_udp_socket_create(&ip_1, &udp_socket, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    nx_udp_socket_bind(&udp_socket, 53, TX_WAIT_FOREVER);
    nx_udp_socket_receive_notify(&udp_socket, receive_packet_function);
    response_sequence = 0;

    /* Get CName by getaddrinfo. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    if (getaddrinfo("www.baidu.com", "80", &hints, &addrinfo) != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    if (addrinfo -> ai_canonname == NX_NULL)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#ifdef NX_DNS_ENABLE_EXTENDED_RR_TYPES
    if (strcmp(addrinfo -> ai_canonname, "www.a.shifen.com"))
#else
    if (strcmp(addrinfo -> ai_canonname, "www.baidu.com"))
#endif
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    freeaddrinfo(addrinfo);

    nx_udp_socket_unbind(&udp_socket);
    nx_udp_socket_delete(&udp_socket);
    nx_dns_delete(&client_dns);
}

static void    ntest_1_entry(ULONG thread_input)
{

UINT            status;
ULONG           actual_status;



    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef NX_BSD_ENABLE_DNS
    dns_test();
#endif

    tx_semaphore_put(&sema_0);

    netx_tcp_server();

    /* Server run first. */
    tx_semaphore_get(&sema_1, 5 * NX_IP_PERIODIC_RATE);

    /* Simulate a multiple client conneting to the same server. */
    multiple_client4();

#ifdef FEATURE_NX_IPV6
    tx_semaphore_put(&sema_0);
    netx_tcp_server();

    tx_semaphore_get(&sema_1, 5 * NX_IP_PERIODIC_RATE);
    multiple_client6();
#endif

    /* Client finished. */
    tx_semaphore_put(&sema_0);
}


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

#endif /* NX_BSD_ENABLE */
