/* This NetX test concentrates on the basic BSD UDP non-blocking operation.  */


#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)

#include   "nx_icmpv6.h"
#include   "nxd_bsd.h"
#define     DEMO_STACK_SIZE         4096


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_UDP_SOCKET           server_socket;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
static TX_SEMAPHORE            netx_sema;
static TX_SEMAPHORE            bsd_sema;

#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            20
/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];
extern TX_BLOCK_POOL nx_bsd_socket_block_pool;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS ipv6_address_ip0[3][3];
static NXD_ADDRESS ipv6_address_ip1[3][3];
#endif /* FEATURE_NX_IPV6 */
static char *requests[4] = {"Request1", "Request22", "Request333", "Request4444"};
static char *response[4] = {"Response1", "Response22", "Response333", "Response4444"};
static void validate_bsd_structure(void);

#define IP0_IF0_V4_ADDR   IP_ADDRESS(1,2,3,4)  
#define IP0_IF1_V4_ADDR   IP_ADDRESS(2,2,3,4)  
#define IP0_IF2_V4_ADDR   IP_ADDRESS(3,2,3,4)  

#define IP1_IF0_V4_ADDR   IP_ADDRESS(1,2,3,5)  
#define IP1_IF1_V4_ADDR   IP_ADDRESS(2,2,3,5)  
#define IP1_IF2_V4_ADDR   IP_ADDRESS(3,2,3,5)  

#define ITERATIONS  100
static ULONG ip0_address[3] = {IP0_IF0_V4_ADDR, IP0_IF1_V4_ADDR, IP0_IF2_V4_ADDR};
static ULONG ip1_address[3] = {IP1_IF0_V4_ADDR, IP1_IF1_V4_ADDR, IP1_IF2_V4_ADDR};
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_udp_bind_test_application_define(void *first_unused_memory)
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
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, (256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 2);
    pointer = pointer + (256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 2;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP0_IF0_V4_ADDR, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Attach a 2nd interface */
    status += nx_ip_interface_attach(&ip_0, "ip_0_second", IP0_IF1_V4_ADDR, 0xFFFFFF00UL,  _nx_ram_network_driver_256);
    status += nx_ip_interface_attach(&ip_0, "ip_0_third", IP0_IF2_V4_ADDR, 0xFFFFFF00UL,  _nx_ram_network_driver_256);

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP1_IF0_V4_ADDR, 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;

    status += nx_ip_interface_attach(&ip_1, "ip_1_second", IP1_IF1_V4_ADDR, 0xFFFFFF00UL,  _nx_ram_network_driver_256);
    status += nx_ip_interface_attach(&ip_1, "ip_1_third", IP1_IF2_V4_ADDR, 0xFFFFFF00UL,  _nx_ram_network_driver_256);
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

    /* Enable UDP processing for both IP instances.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check UDP enable and BSD init status.  */
    if (status)
        error_counter++;

    status = tx_semaphore_create(&netx_sema, "NetX SEMA", 0);
    status += tx_semaphore_create(&bsd_sema, "BSD SEMA", 0);
    if(status != TX_SUCCESS)
        error_counter++;



}

static int sent_msg_id;
static int sent_if;
#ifdef FEATURE_NX_IPV6
static int sent_addr;
#endif


#ifdef FEATURE_NX_IPV6
static void test_udp_server6_bind_to_ANY(void)
{
int                 sockfd;
struct sockaddr_in6 remote_addr, local_addr;
int                 ret;
char                buf[30];
int                 addrlen;
int                 message_count = 0;


    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_port = htons(12345);


    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    error_counter += (ITERATIONS * 2);
    
    while(message_count < ITERATIONS)
    {
        /* Receive data from the client. */
        addrlen = sizeof(remote_addr);
        ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
        if(ret <= 0)
            error_counter++;
        else if(addrlen != sizeof(struct sockaddr_in6))
            error_counter++;
        else if((remote_addr.sin6_family != AF_INET6) ||
           (remote_addr.sin6_addr._S6_un._S6_u32[0] != htonl(ipv6_address_ip1[(message_count / 2) % 3][(message_count & 1) + 1].nxd_ip_address.v6[0])) ||
           (remote_addr.sin6_addr._S6_un._S6_u32[1] != htonl(ipv6_address_ip1[(message_count / 2) % 3][(message_count & 1) + 1].nxd_ip_address.v6[1])) ||
           (remote_addr.sin6_addr._S6_un._S6_u32[2] != htonl(ipv6_address_ip1[(message_count / 2) % 3][(message_count & 1) + 1].nxd_ip_address.v6[2])) ||
           (remote_addr.sin6_addr._S6_un._S6_u32[3] != htonl(ipv6_address_ip1[(message_count / 2) % 3][(message_count & 1) + 1].nxd_ip_address.v6[3])) ||
           (remote_addr.sin6_port != htons(54321)))
            error_counter++;
        /* Validate the data. */
        else if((ret != (INT)strlen(requests[message_count & 3])) || strncmp(buf, requests[message_count & 3], ret))
            error_counter++;    
        else 
            error_counter--;
        
        /* Send a response back. */
        ret = sendto(sockfd, response[message_count & 3], strlen(response[message_count & 3]), 0, (struct sockaddr*)&remote_addr, addrlen);
        if(ret != (INT)strlen(response[message_count & 3]))
            error_counter++;

        message_count ++;
    }

    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}

static void test_udp6_on_interface_address(int iface, int address, INT reuseaddr)
{
int                 sockfd;
struct sockaddr_in6 remote_addr, local_addr;
int                 ret;
char                buf[30];
int                 addrlen;


    sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;

    if(reuseaddr)
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(INT));
    
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin6_port = htons(12345);
    local_addr.sin6_family = AF_INET6;
    if(iface != 3)
    {
        local_addr.sin6_addr._S6_un._S6_u32[0] = htonl(ipv6_address_ip0[iface][address].nxd_ip_address.v6[0]);
        local_addr.sin6_addr._S6_un._S6_u32[1] = htonl(ipv6_address_ip0[iface][address].nxd_ip_address.v6[1]);
        local_addr.sin6_addr._S6_un._S6_u32[2] = htonl(ipv6_address_ip0[iface][address].nxd_ip_address.v6[2]);
        local_addr.sin6_addr._S6_un._S6_u32[3] = htonl(ipv6_address_ip0[iface][address].nxd_ip_address.v6[3]);
    }


    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    
    /* Receive data from the client. */
    addrlen = sizeof(remote_addr);
    ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
    if(ret <= 0)
        error_counter++;
    else if(addrlen != sizeof(struct sockaddr_in6))
        error_counter++;
    else if((remote_addr.sin6_family != AF_INET6) ||
            (remote_addr.sin6_addr._S6_un._S6_u32[0] != htonl(ipv6_address_ip1[sent_if][sent_addr].nxd_ip_address.v6[0])) ||
            (remote_addr.sin6_addr._S6_un._S6_u32[1] != htonl(ipv6_address_ip1[sent_if][sent_addr].nxd_ip_address.v6[1])) ||
            (remote_addr.sin6_addr._S6_un._S6_u32[2] != htonl(ipv6_address_ip1[sent_if][sent_addr].nxd_ip_address.v6[2])) ||
            (remote_addr.sin6_addr._S6_un._S6_u32[3] != htonl(ipv6_address_ip1[sent_if][sent_addr].nxd_ip_address.v6[3])) ||
            (remote_addr.sin6_port != htons(54321)))
        error_counter++;
    /* Make sure the source and the dest are in the same prefix range. */
    else if((iface != 3) &&
            ((ntohl(remote_addr.sin6_addr._S6_un._S6_u32[0]) != ipv6_address_ip0[iface][address].nxd_ip_address.v6[0]) ||
             (ntohl(remote_addr.sin6_addr._S6_un._S6_u32[1]) != ipv6_address_ip0[iface][address].nxd_ip_address.v6[1])))
        error_counter++;
    /* Validate the data. */
    else if((ret != (INT)strlen(requests[sent_msg_id])) || strncmp(buf, requests[sent_msg_id], ret))
        error_counter++;    
    

    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}


#endif /* FEATURE_NX_IPV6 */

static void test_udp_server4_bind_to_ANY(void)
{
int                 sockfd;
struct sockaddr_in  remote_addr, local_addr;
int                 ret;
char                buf[30];
int                 addrlen;
int                 message_count = 0;

    error_counter += (ITERATIONS * 2);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;

    /* Test bind to port 0. */
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = 0;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    addrlen = sizeof(local_addr);
    ret = getsockname(sockfd, (struct sockaddr*)&local_addr, &addrlen);
    if(ret < 0)
        error_counter++;

    /* Check whether port is zero. */
    if (local_addr.sin_port == 0)
        error_counter++;
    soc_close(sockfd);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;
    
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    while(message_count < ITERATIONS)
    {
        /* Receive data from the client. */
        addrlen = sizeof(remote_addr);
        ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
        if(ret <= 0)
            error_counter++;
        else if(addrlen != sizeof(struct sockaddr_in))
            error_counter++;
        else if((remote_addr.sin_family != AF_INET) ||
           (remote_addr.sin_addr.s_addr != htonl(ip1_address[message_count % 3])) ||
           (remote_addr.sin_port != htons(54321)))
            error_counter++;
        /* Validate the data. */
        else if((ret != (int)strlen(requests[message_count & 3])) || strncmp(buf, requests[message_count & 3], ret))
            error_counter++;    
        else 
            error_counter--;
        

        /* Send a response back. */
        ret = sendto(sockfd, response[message_count & 3], strlen(response[message_count & 3]), 0, (struct sockaddr*)&remote_addr, addrlen);
        if(ret != (int)strlen(response[message_count & 3]))
            error_counter++;
        message_count ++;
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE / 100);
    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}

static void test_udp_server4_bind_to_AF_INET(void)
{
int                 sockfd;
struct sockaddr_in  remote_addr, local_addr;
int                 ret;
char                buf[30];
int                 addrlen;
int                 message_count = 0;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;
    
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    while(message_count < 3)
    {
        /* Receive data from the client. */
        addrlen = sizeof(remote_addr);
        ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
        if(ret <= 0)
            error_counter++;
        else if(addrlen != sizeof(struct sockaddr_in))
            error_counter++;
        else if((remote_addr.sin_family != AF_INET) ||
                (remote_addr.sin_addr.s_addr != htonl(ip1_address[sent_if])) ||
                (remote_addr.sin_port != htons(54321)))
            error_counter++;
        /* Validate the data. */
        else if((ret != (int)strlen(requests[sent_msg_id])) || strncmp(buf, requests[sent_msg_id], ret))
            error_counter++;    
        message_count++;

    }

   
    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}
static TX_THREAD     client_threads[3];
static ULONG         client_thread_stack_area[3][DEMO_STACK_SIZE / sizeof(ULONG)];
static void    test_udp4_on_interface(int i, INT reuseaddr);

#ifdef FEATURE_NX_IPV6
static void test_udp6_on_interface_address(int iface, int address, INT reuseaddr);
static VOID client6_thread_entry(ULONG param)
{
INT reuseaddr = 1;    
    
     if(param == 0)
         test_udp6_on_interface_address((int)param, 1, reuseaddr);
     else 
         test_udp6_on_interface_address((int)param, param, reuseaddr);
         

    tx_semaphore_put(&bsd_sema);

}
#endif

static VOID client_thread_entry(ULONG param)
{
INT reuseaddr = 1;    
    test_udp4_on_interface((int)param, reuseaddr);

    tx_semaphore_put(&bsd_sema);

}
    


static void    test_udp_bind_to_three_interfaces(int if1, int if2, int if3)
{
int i;
UINT status;

    /* Wait for the client to be ready. */
    status = tx_semaphore_put(&netx_sema);

    if(status != TX_SUCCESS)
        error_counter++;
    /* Create 3 threads, each binds to a different interface. */
    tx_thread_create(&client_threads[0], "client thread0", client_thread_entry, if1, 
                     (CHAR*)client_thread_stack_area[0], DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    tx_thread_create(&client_threads[1], "client thread1", client_thread_entry, if2, 
                     (CHAR*)client_thread_stack_area[1], DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    tx_thread_create(&client_threads[2], "client thread2", client_thread_entry, if3, 
                     (CHAR*)client_thread_stack_area[2], DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
                     
    /* Wait for all three threads to quite. */
    for(i = 0; i < 3; i++)
    {
        status = tx_semaphore_get(&bsd_sema, 2 * NX_IP_PERIODIC_RATE);
        if(status == TX_NO_INSTANCE)
            error_counter++;
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE / 50);

    for(i = 0; i < 3; i++)
        status += tx_thread_delete(&client_threads[i]);
    if(status)
        error_counter++;

}
#ifdef FEATURE_NX_IPV6
static void    test_udp_bind_to_ipv6_addresses(int if1, int if2, int if3)
{
int i;
UINT status;


    status = tx_semaphore_put(&netx_sema);

    if(status != TX_SUCCESS)
        error_counter++;
    /* Create 3 threads, each binds to a different interface. */
    tx_thread_create(&client_threads[0], "client thread0", client6_thread_entry, if1, 
                     (CHAR*)client_thread_stack_area[0], DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    tx_thread_create(&client_threads[1], "client thread1", client6_thread_entry, if2, 
                     (CHAR*)client_thread_stack_area[1], DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    tx_thread_create(&client_threads[2], "client thread1", client6_thread_entry, if3, 
                     (CHAR*)client_thread_stack_area[2], DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    /* Wait for all three threads to quite. */
    for(i = 0; i < 3; i++)
    {
        status = tx_semaphore_get(&bsd_sema, NX_IP_PERIODIC_RATE);
        if(status == TX_NO_INSTANCE)
            error_counter++;
    }

    tx_thread_sleep(NX_IP_PERIODIC_RATE / 50);

    for(i = 0; i < 3; i++)
        status += tx_thread_delete(&client_threads[i]);
    if(status)
        error_counter++;

}
#endif
static void    test_udp4_on_interface(int i, INT reuseaddr)
{

int                 sockfd;
struct sockaddr_in  remote_addr, local_addr;
int                 ret;
char                buf[30];
int                 addrlen;


    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;
    if(reuseaddr)
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(INT));

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    if(i == 3)
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        local_addr.sin_addr.s_addr = htonl(ip0_address[i]);

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    /* Receive data from the client. */
    addrlen = sizeof(remote_addr);
    ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
    if(ret <= 0)
        error_counter++;
    else if(addrlen != sizeof(struct sockaddr_in))
        error_counter++;
    else if((remote_addr.sin_family != AF_INET) ||
            (remote_addr.sin_addr.s_addr != htonl(ip1_address[sent_if])) ||
            (remote_addr.sin_port != htons(54321)))
        error_counter++;
    /* Make sure the remote address and local address are on the same subnet*/
    else if((i < 3) && ((ntohl(remote_addr.sin_addr.s_addr) & 0xFFFFFF * NX_IP_PERIODIC_RATE) != (ip0_address[i] & 0xFFFFFF * NX_IP_PERIODIC_RATE)))
        error_counter++;
    /* Validate the data. */
    else if((ret != (int)strlen(requests[sent_msg_id])) || strncmp(buf, requests[sent_msg_id], ret))
        error_counter++;    

   
    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}
#define NUM_MESSAGES 5
static void test_udp4_receive_multiple(int iface)
{
int sockfd;
struct sockaddr_in  remote_addr, local_addr;
int                 ret;
char                buf[30];
int                 addrlen;
int                 packet_count;
UINT                status;
NX_BSD_SOCKET      *bsd_socket_ptr;

    status = tx_semaphore_put(&netx_sema);

    if(status != TX_SUCCESS)
        error_counter++;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    if(iface == 3)
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        local_addr.sin_addr.s_addr = htonl(ip0_address[iface]);

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    /* Sleep for three tick, gives the client a chance to send 10 packets. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 20);

    packet_count = 0;
    bsd_socket_ptr = &nx_bsd_socket_array[sockfd - NX_BSD_SOCKFD_START];
    while(bsd_socket_ptr -> nx_bsd_socket_received_packet)
    {
        /* Receive data from the client. */
        addrlen = sizeof(remote_addr);
        ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
        if(ret <= 0)
            error_counter++;
        else if(addrlen != sizeof(struct sockaddr_in))
            error_counter++;
        else if((remote_addr.sin_family != AF_INET) ||
                (remote_addr.sin_addr.s_addr != htonl(ip1_address[iface])) ||
                (remote_addr.sin_port != htons(54321)))
            error_counter++;
        /* Make sure the remote address and local address are on the same subnet*/
        else if((iface < 3) && ((ntohl(remote_addr.sin_addr.s_addr) & 0xFFFFFF * NX_IP_PERIODIC_RATE) != (ip0_address[iface] & 0xFFFFFF * NX_IP_PERIODIC_RATE)))
            error_counter++;
        /* Validate the data. */
        else if((ret != (int)strlen(requests[packet_count & 3])) || strncmp(buf, requests[packet_count & 3], ret))
            error_counter++;    
        else
            packet_count ++;
    }

    if(packet_count != NUM_MESSAGES)
        error_counter++;

   
    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;



}

/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
#ifdef FEATURE_NX_IPV6    
static char mac_ip0[6];
static char mac_ip1[6];
int j;
UINT status;
#endif
int i;

INT reuseaddr = 0;


    printf("NetX Test:   Basic BSD UDP Bind Test.......................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6    

    for(i = 0; i < 3; i++)
    {
        mac_ip0[0] = (char)(ip_0.nx_ip_interface[i].nx_interface_physical_address_msw >> 8);
        mac_ip0[1] = ip_0.nx_ip_interface[i].nx_interface_physical_address_msw & 0xFF;
        mac_ip0[2] = (ip_0.nx_ip_interface[i].nx_interface_physical_address_lsw >> 24) & 0xff;
        mac_ip0[3] = (ip_0.nx_ip_interface[i].nx_interface_physical_address_lsw >> 16) & 0xff;
        mac_ip0[4] = (ip_0.nx_ip_interface[i].nx_interface_physical_address_lsw >> 8) & 0xff;
        mac_ip0[5] = ip_0.nx_ip_interface[i].nx_interface_physical_address_lsw  & 0xff;
        
        mac_ip1[0] = (char)(ip_1.nx_ip_interface[i].nx_interface_physical_address_msw >> 8);
        mac_ip1[1] = ip_1.nx_ip_interface[i].nx_interface_physical_address_msw & 0xFF;
        mac_ip1[2] = (ip_1.nx_ip_interface[i].nx_interface_physical_address_lsw >> 24) & 0xff;
        mac_ip1[3] = (ip_1.nx_ip_interface[i].nx_interface_physical_address_lsw >> 16) & 0xff;
        mac_ip1[4] = (ip_1.nx_ip_interface[i].nx_interface_physical_address_lsw >> 8) & 0xff;
        mac_ip1[5] = ip_1.nx_ip_interface[i].nx_interface_physical_address_lsw  & 0xff;

        for(j = 0; j < 3; j ++)
        {
            if(j == 0)
            {
                /* First set up IPv6 linklocal addresses. */
                ipv6_address_ip0[i][j].nxd_ip_version = NX_IP_VERSION_V6;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[0] = 0xfe800000;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[1] = 0x00000000;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[2] = ((mac_ip0[0] | 0x2) << 24) | (mac_ip0[1] << 16) | (mac_ip0[2] << 8) | 0xFF;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[3] = (0xFE << 24) | ((mac_ip0[3] | 0x2) << 16) | (mac_ip0[4] << 8) | mac_ip0[5];
        
                ipv6_address_ip1[i][j].nxd_ip_version = NX_IP_VERSION_V6;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[0] = 0xfe800000;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[1] = 0x00000000;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[2] = 
                    ((mac_ip1[0] | 0x2) << 24) | (mac_ip1[1] << 16) | (mac_ip1[2] << 8) | 0xFF;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[3] = 
                    (0xFE << 24) | ((mac_ip1[3] | 0x2) << 16) | (mac_ip1[4] << 8) | mac_ip1[5];
        
                status = nxd_ipv6_address_set(&ip_0, i, &ipv6_address_ip0[i][j], 10, NX_NULL);
                status += nxd_ipv6_address_set(&ip_1, i, &ipv6_address_ip1[i][j], 10, NX_NULL);
            }
            else
            {
                /* Global Adddress */
                ipv6_address_ip0[i][j].nxd_ip_version = NX_IP_VERSION_V6;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[0] = 0x20000000 + i;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[1] = j;
                ipv6_address_ip0[i][j].nxd_ip_address.v6[2] = ipv6_address_ip0[i][0].nxd_ip_address.v6[2];
                ipv6_address_ip0[i][j].nxd_ip_address.v6[3] = ipv6_address_ip0[i][0].nxd_ip_address.v6[3];
        
                ipv6_address_ip1[i][j].nxd_ip_version = NX_IP_VERSION_V6;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[0] = 0x20000000 + i;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[1] = j;
                ipv6_address_ip1[i][j].nxd_ip_address.v6[2] = ipv6_address_ip1[i][0].nxd_ip_address.v6[2];
                ipv6_address_ip1[i][j].nxd_ip_address.v6[3] = ipv6_address_ip1[i][0].nxd_ip_address.v6[3];

        
                status = nxd_ipv6_address_set(&ip_0, i, &ipv6_address_ip0[i][j], 64, NX_NULL);
                status += nxd_ipv6_address_set(&ip_1, i, &ipv6_address_ip1[i][j], 64, NX_NULL);
            }
            status += nxd_nd_cache_entry_set(&ip_0, ipv6_address_ip1[i][j].nxd_ip_address.v6, 0,  mac_ip1);
            status += nxd_nd_cache_entry_set(&ip_1, ipv6_address_ip0[i][j].nxd_ip_address.v6, 0,  mac_ip0);        
        }

    }



    status += nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    


    if(status)
        error_counter++;
#endif
    tx_semaphore_put(&netx_sema);
    test_udp_server4_bind_to_ANY();

#ifdef FEATURE_NX_IPV6    
    tx_semaphore_put(&netx_sema);
    test_udp_server6_bind_to_ANY();
#endif
    
    /* Make sure a bind to IPv4 Address Family won't received UDP sent to IPv6 address. */
    tx_semaphore_put(&netx_sema);
    test_udp_server4_bind_to_AF_INET();

#ifdef FEATURE_NX_IPV6    
    /* Make sure a bind to IPv6 Address Family won't received UDP sent to IPv4 address. */
    tx_semaphore_put(&netx_sema);
    test_udp6_on_interface_address(3, 0, 0);
#endif

    /* Make sure a bind to interface 1 address does not receive UDP sent to interface2 and 3 addresses. */
    for(i = 0; i < 3; i++)
    {
        tx_semaphore_put(&netx_sema);
        test_udp4_on_interface(i, reuseaddr);

#ifdef FEATURE_NX_IPV6
        /* Make sure a bind to an IPv6 address does not receive UDP sent to another IPv6 address. */       
        for(j = 1; j < 3; j++)
        {
            tx_semaphore_put(&netx_sema);
            test_udp6_on_interface_address(i, j, 0);
        }


#endif
    }

    /* Test UDP sockets binding to address1, 2, 3 are able to receive packets according to their 
       binding information */
    test_udp_bind_to_three_interfaces(0, 1, 2);

    /* Test UDP sockets binding to address1, 3, and another bind to INADDR_ANY. 
       Traffic to address 1 goes to the INADDR_ANY bind. */
    test_udp_bind_to_three_interfaces(0, 2, 3);


    /* Test UDP sockets binding to INADDR_ANY, address0, 3.
       Traffic to address 1 goes to the INADDR_ANY bind. */
    test_udp_bind_to_three_interfaces(3, 2, 0);


#ifdef FEATURE_NX_IPV6
    /* Test UDP sockets binding to 3 different IPv6 addresses */
    test_udp_bind_to_ipv6_addresses(0, 1, 2);

    /* Test UDP sockets binding to 2 different IPv6 addresses and a 3rd one to INADDR_ANY
       and be able to catch all. */
    test_udp_bind_to_ipv6_addresses(0, 1, 3);

    test_udp_bind_to_ipv6_addresses(3, 2, 0);

    tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);

#endif

    test_udp4_receive_multiple(1);

    tx_semaphore_delete(&bsd_sema);
    tx_semaphore_delete(&netx_sema);
    
    validate_bsd_structure();

    if(error_counter)
        printf("ERROR!\n");
    else
        printf("SUCCESS!\n");

    if(error_counter)
        test_control_return(1);    

    test_control_return(0);    
}

#ifdef FEATURE_NX_IPV6
static void    udp_client6_to_ANY(void)
{

UINT            status;
NX_PACKET       *packet_ptr;
int             message_counter = 0;

    status = tx_semaphore_get(&netx_sema, 2 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Create a socket.  */
    status =  nx_udp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 10);
                                
    /* Check for error.  */
    if (status)
        error_counter++;


    /* Bind to a UDP port. */
    status = nx_udp_socket_bind(&server_socket, 54321, NX_WAIT_FOREVER);
    if(status)
        error_counter++;

    while(message_counter < ITERATIONS)
    {
        /* Allocate a packet. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
        if (status)
            error_counter++;

        /* Fill in the packet with data */
        memcpy(packet_ptr -> nx_packet_prepend_ptr, requests[message_counter & 3], strlen(requests[message_counter & 3]));
        
        packet_ptr -> nx_packet_length = strlen(requests[message_counter & 3]);
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;
        
        /* Send a UDP packet */
        status =  nxd_udp_socket_send(&server_socket, packet_ptr, &ipv6_address_ip0[(message_counter / 2) % 3][(message_counter & 1) + 1], 12345);
        if(status)
            error_counter++;

        /* Ready to reaceive a message */
        status = nx_udp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER);
        if(status)
            error_counter++;
    
        /* Validate the content. */
        if(packet_ptr -> nx_packet_length != strlen(response[message_counter & 3]))
            error_counter++;
        else if(strncmp((char*)packet_ptr -> nx_packet_prepend_ptr, response[message_counter & 3], strlen(response[message_counter & 3])))
            error_counter++;
        else
            error_counter--;
        nx_packet_release(packet_ptr);
        message_counter ++;
    }
    status = nx_udp_socket_unbind(&server_socket);
    if(status)
        error_counter++;

    status = nx_udp_socket_delete(&server_socket);
    if(status)
        error_counter++;
}
#endif

static void    udp_client_to_AF_INET_AF_INET6(void)
{

UINT            status;
NX_PACKET       *packet_ptr;
int             message_count = 0;
int             i;
#ifdef FEATURE_NX_IPV6
int j;
#endif
    status = tx_semaphore_get(&netx_sema, 2 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Create a socket.  */
    status =  nx_udp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 10);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind to a UDP port. */
    status = nx_udp_socket_bind(&server_socket, 54321, NX_WAIT_FOREVER);
    if(status)
        error_counter++;

    for(i = 2; i >= 0; i--)
    {
    
        /* Allocate a packet. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
        if (status)
            error_counter++;
    
        /* Fill in the packet with data */
        memcpy(packet_ptr -> nx_packet_prepend_ptr, requests[message_count & 3], strlen(requests[message_count & 3]));
    
        packet_ptr -> nx_packet_length = strlen(requests[message_count & 3]);
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

        sent_msg_id = message_count & 3;
        sent_if = i;
        /* Send a UDP packet */
        status =  nx_udp_socket_send(&server_socket, packet_ptr, ip0_address[i], 12345);
        if(status)
            error_counter++;

        message_count ++;
#ifdef FEATURE_NX_IPV6

        for(j = 0; j < 2; j++)
        {
            /* Allocate a packet. */
            status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
            if (status)
                error_counter++;

            /* Fill in the packet with data */
            memcpy(packet_ptr -> nx_packet_prepend_ptr, requests[message_count & 3], strlen(requests[message_count & 3]));
            
            packet_ptr -> nx_packet_length = strlen(requests[message_count & 3]);
            packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;
            
            
            /* Send a UDP packet */
            sent_msg_id = message_count & 3;
            sent_if = i;
            sent_addr = j + 1;
            status =  nxd_udp_socket_send(&server_socket, packet_ptr, &ipv6_address_ip0[i][j + 1], 12345);
            if(status)
                error_counter++;
            message_count ++;
        }
#endif
    }

    status = nx_udp_socket_unbind(&server_socket);
    if(status)
        error_counter++;

    status = nx_udp_socket_delete(&server_socket);
    if(status)
        error_counter++;
}


static void    udp_client4_to_ANY(void)
{

UINT            status;
NX_PACKET       *packet_ptr;
int             message_count = 0;


    status = tx_semaphore_get(&netx_sema, 2 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Create a socket.  */
    status =  nx_udp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 10);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind to a UDP port. */
    status = nx_udp_socket_bind(&server_socket, 54321, NX_WAIT_FOREVER);
    if(status)
        error_counter++;

    while(message_count < ITERATIONS)
    {
    
        /* Allocate a packet. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
        if (status)
            error_counter++;
    
        /* Fill in the packet with data */
        memcpy(packet_ptr -> nx_packet_prepend_ptr, requests[message_count & 3], strlen(requests[message_count & 3]));
    
        packet_ptr -> nx_packet_length = strlen(requests[message_count & 3]);
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;


        /* Send a UDP packet */
        status =  nx_udp_socket_send(&server_socket, packet_ptr, ip0_address[message_count % 3], 12345);
        if(status)
            error_counter++;

        /* Ready to reaceive a message */
        status = nx_udp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER);
        if(status)
            error_counter++;
        /* Validate the content. */
        else if(packet_ptr -> nx_packet_length != strlen(response[message_count & 3]))
            error_counter++;
        else if(strncmp((char*)packet_ptr -> nx_packet_prepend_ptr, response[message_count & 3], strlen(response[message_count & 3])))
            error_counter++;
        else 
            error_counter--;
        nx_packet_release(packet_ptr);

        message_count ++;
    }

    status = nx_udp_socket_unbind(&server_socket);
    if(status)
        error_counter++;

    status = nx_udp_socket_delete(&server_socket);
    if(status)
        error_counter++;


}



static void    udp_client4_to_interface(int iface)
{

UINT            status;
NX_PACKET       *packet_ptr;
int             message_count = 0;

    status = tx_semaphore_get(&netx_sema, 2 * NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;
      
    /* Create a socket.  */
    status =  nx_udp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 10);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind to a UDP port. */
    status = nx_udp_socket_bind(&server_socket, 54321, NX_WAIT_FOREVER);
    if(status)
        error_counter++;

    while(message_count < NUM_MESSAGES)
    {
    
        /* Allocate a packet. */
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
        if (status)
            error_counter++;
    
        /* Fill in the packet with data */
        memcpy(packet_ptr -> nx_packet_prepend_ptr, requests[message_count & 3], strlen(requests[message_count & 3]));
    
        packet_ptr -> nx_packet_length = strlen(requests[message_count & 3]);
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;


        /* Send a UDP packet */
        status =  nx_udp_socket_send(&server_socket, packet_ptr, ip0_address[iface], 12345);
        if(status)
            error_counter++;

        message_count ++;
    }

    status = nx_udp_socket_unbind(&server_socket);
    if(status)
        error_counter++;

    status = nx_udp_socket_delete(&server_socket);
    if(status)
        error_counter++;


}






static void    ntest_1_entry(ULONG thread_input)
{
ULONG           actual_status;
UINT            status;
UINT            i;
#ifdef FEATURE_NX_IPV6
UINT j;
#endif
    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(3);
    }

    udp_client4_to_ANY();

#ifdef FEATURE_NX_IPV6

    udp_client6_to_ANY();

#endif

    /* Make sure a bind to IPv4 Address Family won't received UDP sent to IPv6 address. */
    udp_client_to_AF_INET_AF_INET6();

#ifdef FEATURE_NX_IPV6

    /* Make sure a bind to IPv6 Address Family won't received UDP sent to IPv4 address. */
    udp_client_to_AF_INET_AF_INET6();
#endif

    /* Test UDP bind to 3 different interfaces, each with one IPv4, and 2 IPv6 GA. */
    /* So total there are 9 different addresses to test for. */
    for(i = 0; i < 3; i++)
    {
#if 0
        tx_semaphore_get(&netx_sema, TX_WAIT_FOREVER);
#endif
        udp_client_to_AF_INET_AF_INET6();

#ifdef FEATURE_NX_IPV6

        /* Make sure a bind to an IPv6 address does not receive UDP sent to another IPv6 address. */       
        for(j = 1; j < 3; j++)
        {
#if 0
            tx_semaphore_get(&netx_sema);
#endif
            udp_client_to_AF_INET_AF_INET6();
        }

#endif    
    }
    
    /* Start testing test_udp_bind_to_three_interfaces(0,1,2);*/
    udp_client_to_AF_INET_AF_INET6();

    /* Start testing test_udp_bind_to_three_interfaces(0,2,3);*/
    udp_client_to_AF_INET_AF_INET6();

    /* Start testing test_udp_bind_to_three_interfaces(3, 2,0);*/
    udp_client_to_AF_INET_AF_INET6();

#ifdef FEATURE_NX_IPV6
    /* Start testing test_udp_bind_to_ipv6_addresses */
    udp_client_to_AF_INET_AF_INET6();

    /* Start testing test_udp_bind_to_ipv6_addresses */
    udp_client_to_AF_INET_AF_INET6();


    /* Start testing test_udp_bind_to_ipv6_addresses */
    udp_client_to_AF_INET_AF_INET6();
#endif
    udp_client4_to_interface(1);

}

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
void    netx_bsd_udp_bind_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD UDP Bind Test.......................N/A\n"); 

    test_control_return(3);  
}      
#endif
