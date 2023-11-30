/* This NetX test concentrates on the basic BSD RAW non-blocking operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#ifdef NX_BSD_ENABLE
#include   "nxd_bsd.h"
#include   "nx_icmpv6.h"
#define     DEMO_STACK_SIZE         4096


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
static TX_SEMAPHORE            sema_0;
static TX_SEMAPHORE            sema_1;
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            20
/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   packet_pool_area[(256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 8 / 4];


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS ipv6_address_ip0;
static NXD_ADDRESS ipv6_address_ip1;
#endif /* FEATURE_NX_IPV6 */
static char *requests[4] = {"Request1", "Request2", "Request3", "Request4"};
static char *response[4] = {"Response1", "Response2", "Response3", "Response4"};
static void validate_bsd_structure(void);
/* Define what the initial system looks like.  */
extern UINT _nxd_ip_raw_packet_send(NX_IP *ip_ptr, NX_PACKET *packet_ptr,  NXD_ADDRESS *destination_ip, ULONG protocol, UINT ttl, ULONG tos);
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_raw_basic_nonblocking_test_application_define(void *first_unused_memory)
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

    /* Enable raw processing for both IP instances.  */
    status = nx_ip_raw_packet_enable(&ip_0);
    status = nx_ip_raw_packet_enable(&ip_1);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check RAW enable and BSD init status.  */
    if (status)
        error_counter++;

    status = tx_semaphore_create(&sema_0, "SEMA 0", 0);
    status += tx_semaphore_create(&sema_1, "SEMA 1", 0);
    if(status != TX_SUCCESS)
        error_counter++;
}

static void test_raw_server4(void)
{
int                sockfd;
struct sockaddr_in remote_addr;
int                ret;
char               buf[30];
fd_set             read_fd;
struct timeval     tv;
int                addrlen;
int                error, len;


    sockfd = socket(AF_INET, SOCK_RAW, 100);
    if(sockfd < 0)
        error_counter++;
    
    /* Set the socket to non-blocking mode. */
    if(fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0)
        error_counter++;            

    /* Receive data from the client. */
    addrlen = sizeof(remote_addr);
    ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
    if(ret > 0)
        error_counter++;
    else
    {
        /* Check errno */
        if(errno != EWOULDBLOCK)
            error_counter++;
    }

    /* Select on the socket. */
    FD_ZERO(&read_fd);
    FD_SET(sockfd, &read_fd);

    tv.tv_sec  = 2;
    tv.tv_usec = 0;

    
    ret = select(sockfd + 1, &read_fd, NULL, NULL, &tv);
    if(ret != 1)
        error_counter++;

    if(!FD_ISSET(sockfd, &read_fd))
        error_counter++;

    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
#if 0
    if(error)
        error_counter++;
#endif

    addrlen = sizeof(remote_addr);
    ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
    if(ret < 0)
        error_counter++;

    if(addrlen != sizeof(struct sockaddr_in))
        error_counter++;

    if((remote_addr.sin_family != AF_INET) ||
       (remote_addr.sin_addr.s_addr != htonl(IP_ADDRESS(1,2,3,5))))
        error_counter++;

    /* Validate the data. */
    if(((ret - 20) != (int)strlen(requests[0])) || strncmp((buf + 20), requests[0], (ret - 20)))
        error_counter++;    

    /* Send a response back. */
    ret = sendto(sockfd, response[0], strlen(response[0]), 0, (struct sockaddr*)&remote_addr, addrlen);
    if(ret != (int)strlen(response[0]))
        error_counter++;


    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;
}

#ifdef FEATURE_NX_IPV6    
static void test_raw_server_ipv6(void)
{
int                 sockfd;
struct sockaddr_in6 remote_addr;
int                 ret;
char                buf[50];
int                 addrlen;
fd_set              read_fd;
struct timeval      tv;
int                 error, len;

    sockfd = socket(AF_INET6, SOCK_RAW, 100);
    if(sockfd < 0)
        error_counter++;

    /* Set the socket to non-blocking mode. */
    if(fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0)
        error_counter++;            

    /* Receive data from the client. */
    addrlen = sizeof(remote_addr);
    ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
    if(ret > 0)
        error_counter++;
    else
    {
        /* Check errno */
        if(errno != EWOULDBLOCK)
            error_counter++;
    }

    /* Select on the socket. */
    FD_ZERO(&read_fd);
    FD_SET(sockfd, &read_fd);

    tv.tv_sec  = 2;
    tv.tv_usec = 0;

    
    ret = select(sockfd + 1, &read_fd, NULL, NULL, &tv);
    if(ret != 1)
        error_counter++;

    if(!FD_ISSET(sockfd, &read_fd))
        error_counter++;

    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
#if 0
    if(error)
        error_counter++;
#endif

    addrlen = sizeof(remote_addr);
    ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
    if(ret <= 0)
        error_counter++;

    if(addrlen != sizeof(struct sockaddr_in6))
        error_counter++;

    if((remote_addr.sin6_family != AF_INET6) ||
       (remote_addr.sin6_addr._S6_un._S6_u32[0] != htonl(ipv6_address_ip1.nxd_ip_address.v6[0])) ||
       (remote_addr.sin6_addr._S6_un._S6_u32[1] != htonl(ipv6_address_ip1.nxd_ip_address.v6[1])) ||
       (remote_addr.sin6_addr._S6_un._S6_u32[2] != htonl(ipv6_address_ip1.nxd_ip_address.v6[2])) ||
       (remote_addr.sin6_addr._S6_un._S6_u32[3] != htonl(ipv6_address_ip1.nxd_ip_address.v6[3])))
        error_counter++;


    /* Validate the data. */
    if((ret != (INT)(strlen(requests[0]))) || strncmp(buf , requests[0], ret ))
        error_counter++;    

    /* Send a response back. */
    ret = sendto(sockfd, response[0], strlen(response[0]), 0, (struct sockaddr*)&remote_addr, addrlen);
    if(ret != (INT)strlen(response[0]))
        error_counter++;


    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;
}

#endif


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
#ifdef FEATURE_NX_IPV6    
char mac_ip0[6];
char mac_ip1[6];
UINT status;
#endif

    printf("NetX Test:   Basic BSD RAW Non-Blocking Test...............");

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
    
    mac_ip0[0] = ip_0.nx_ip_interface[0].nx_interface_physical_address_msw >> 8;
    mac_ip0[1] = ip_0.nx_ip_interface[0].nx_interface_physical_address_msw & 0xFF;
    mac_ip0[2] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 24) & 0xff;
    mac_ip0[3] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 16) & 0xff;
    mac_ip0[4] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 8) & 0xff;
    mac_ip0[5] = ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw  & 0xff;

    mac_ip1[0] = ip_1.nx_ip_interface[0].nx_interface_physical_address_msw >> 8;
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
    tx_semaphore_put(&sema_1);

    test_raw_server4();

#ifdef FEATURE_NX_IPV6    
    tx_semaphore_put(&sema_1);
    test_raw_server_ipv6();
#endif    

    tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);

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
NXD_ADDRESS     dest_addr;



    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(3);
    }

    tx_semaphore_get(&sema_1, 5 * NX_IP_PERIODIC_RATE);

    /* Allocate a packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Fill in the packet with data */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, requests[0], strlen(requests[0]));
    
    packet_ptr -> nx_packet_length = strlen(requests[0]);
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Send a RAW packet */
    dest_addr.nxd_ip_version = NX_IP_VERSION_V4;
    dest_addr.nxd_ip_address.v4 = IP_ADDRESS(1,2,3,4);
    status =  _nxd_ip_raw_packet_send(&ip_1, packet_ptr, &dest_addr, 100, 128, 0);
    if(status)
        error_counter++;

    /* Ready to reaceive a message */
    status = nx_ip_raw_packet_receive(&ip_1, &packet_ptr, 1 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;
    

    /* Validate the content. */
    if(packet_ptr -> nx_packet_length != strlen(response[0]))
        error_counter++;
    else if(strncmp((char*)packet_ptr -> nx_packet_prepend_ptr, (char*)response[0], strlen(response[0])))
        error_counter++;

#ifdef FEATURE_NX_IPV6    
    /* Test IPv6 */
    tx_semaphore_get(&sema_1, 5 * NX_IP_PERIODIC_RATE);

    /* Allocate a packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_IP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Fill in the packet with data */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, requests[0], strlen(requests[0]));
    
    packet_ptr -> nx_packet_length = strlen(requests[0]);
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    status =  _nxd_ip_raw_packet_send(&ip_1, packet_ptr, &ipv6_address_ip0, 100, 128, 0);
    if(status)
        error_counter++;

    /* Ready to reaceive a message */
    status = nx_ip_raw_packet_receive(&ip_1, &packet_ptr, 1 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;
 
    /* Validate the content. */
    if(packet_ptr -> nx_packet_length != strlen(response[0]))
        error_counter++;
    else if(strncmp((char *)packet_ptr -> nx_packet_prepend_ptr, (char *)response[0], strlen(response[0])))
        error_counter++;

#endif
    tx_semaphore_put(&sema_0);

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

#endif /* NX_BSD_ENABLE */

#else /* __PRODUCT_NETXDUO__ */

extern void    test_control_return(UINT status);
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_raw_basic_nonblocking_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Basic BSD RAW Non-Blocking Test...............N/A\n");
    test_control_return(3);
}
#endif /* __PRODUCT_NETXDUO__ */

