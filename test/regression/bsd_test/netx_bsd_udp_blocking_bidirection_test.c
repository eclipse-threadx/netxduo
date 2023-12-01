/* This NetX test concentrates on the basic BSD UDP blocking operation.  */
/* The BSD APIs involved in this test are:  socket(), connect(), send(), soc_close() */

#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nx_icmpv6.h"
#include   "nxd_bsd.h"
#define     DEMO_STACK_SIZE         4096
#define     NUM_MESSAGES              20

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            10
/* Define the counters used in the test application...  */

static ULONG                   error_counter;
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
static char *bsd_send_buffer  = "From BSD Test";
static char *netx_send_buffer  = "From Native NetX Test";
#ifdef FEATURE_NX_IPV6
static char *bsd_send_buffer6 = "From BSD Test 6";
static char *netx_send_buffer6 = "From Native NetX Test 6";
#endif

static void validate_bsd_structure(void);

static char *bsd_transmit_v4_thread_stack;
static char *bsd_receive_v4_thread_stack;
static char *netx_transmit_thread_stack;
static char *netx_receive_thread_stack;


static TX_THREAD netx_transmit_thread;
static TX_THREAD netx_receive_thread;
static TX_THREAD bsd_transmit_v4_thread;
static TX_THREAD bsd_receive_v4_thread;



#ifdef FEATURE_NX_IPV6
static char *bsd_transmit_v6_thread_stack;
static char *bsd_receive_v6_thread_stack;

static TX_THREAD bsd_transmit_v6_thread;
static TX_THREAD bsd_receive_v6_thread;
#endif

static TX_SEMAPHORE bsd_sema;
static TX_SEMAPHORE netx_sema;

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_udp_blocking_bidirection_test_application_define(void *first_unused_memory)
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
                     2, 2, TX_NO_TIME_SLICE, TX_AUTO_START);

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

    /* Enable UDP processing for both IP instances.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check UDP enable status.  */
    if (status)
        error_counter++;

    netx_transmit_thread_stack = pointer;
    pointer = pointer + DEMO_STACK_SIZE;
    netx_receive_thread_stack = pointer;
    pointer = pointer + DEMO_STACK_SIZE;

    bsd_transmit_v4_thread_stack = pointer;
    pointer = pointer + DEMO_STACK_SIZE;
    bsd_receive_v4_thread_stack = pointer;
    pointer = pointer + DEMO_STACK_SIZE;

#ifdef FEATURE_NX_IPV6
    bsd_transmit_v6_thread_stack = pointer;
    pointer = pointer + DEMO_STACK_SIZE;
    bsd_receive_v6_thread_stack = pointer;
    pointer = pointer + DEMO_STACK_SIZE;
#endif

    status = tx_semaphore_create(&netx_sema, "NetX test done", 0);
    status += tx_semaphore_create(&bsd_sema, "BSD test done", 0);
    if(status != TX_SUCCESS)
        error_counter++;
}

static void    transmit_entry(ULONG thread_input)
{
int sockfd = thread_input;
int ret;
int i;
struct sockaddr_in peer_addr;


    for(i = 0; i < NUM_MESSAGES; i++)
    {
        
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(12345);
        peer_addr.sin_addr.s_addr = htonl(IP_ADDRESS(1, 2, 3, 5));

        ret = sendto(sockfd, bsd_send_buffer, strlen(bsd_send_buffer), 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
        
        if(ret != (int)strlen(bsd_send_buffer))
            error_counter++;

        tx_thread_relinquish();
    }

    tx_semaphore_put(&bsd_sema);
    
}

static void    receive_entry(ULONG thread_input)
{
int  sockfd = thread_input;
int  ret;
int  i;
char buffer[30];
struct sockaddr_in peer_addr;
int    peer_addr_len;


    for(i = 0; i < NUM_MESSAGES; i++)
    {
        peer_addr_len = sizeof(peer_addr);
        
        ret = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&peer_addr, &peer_addr_len);
        
        if(peer_addr_len != sizeof(peer_addr))
            error_counter++;
        else if((peer_addr.sin_family != AF_INET) ||
                (peer_addr.sin_addr.s_addr != htonl(IP_ADDRESS(1, 2, 3, 5))))
            error_counter++;
        
        if(ret != (int)strlen(netx_send_buffer))
            error_counter++;
        else if(strncmp(buffer, netx_send_buffer, ret))
            error_counter++;

        tx_thread_relinquish();
    }

    tx_semaphore_put(&bsd_sema);

}

#ifdef FEATURE_NX_IPV6
static void    transmit6_entry(ULONG thread_input)
{
int sockfd = thread_input;
int ret;
int i;
struct sockaddr_in6 peer_address6;



    for(i = 0; i < NUM_MESSAGES; i++)
    {

        peer_address6.sin6_family = AF_INET6;
        peer_address6.sin6_port = htons(12345);
        peer_address6.sin6_addr._S6_un._S6_u32[0] = htonl(ipv6_address_ip1.nxd_ip_address.v6[0]);
        peer_address6.sin6_addr._S6_un._S6_u32[1] = htonl(ipv6_address_ip1.nxd_ip_address.v6[1]);
        peer_address6.sin6_addr._S6_un._S6_u32[2] = htonl(ipv6_address_ip1.nxd_ip_address.v6[2]);
        peer_address6.sin6_addr._S6_un._S6_u32[3] = htonl(ipv6_address_ip1.nxd_ip_address.v6[3]);
        
        ret = sendto(sockfd, bsd_send_buffer6, strlen(bsd_send_buffer6), 0, (struct sockaddr*)&peer_address6, sizeof(peer_address6));
       
        if(ret != (INT)strlen(bsd_send_buffer6))
            error_counter++;

        tx_thread_relinquish();
    }

    tx_semaphore_put(&bsd_sema);
    
}

static void    receive6_entry(ULONG thread_input)
{
int  sockfd = thread_input;
int  ret;
int  i;
char buffer[30];
struct sockaddr_in6 peer_addr;
int peer_addr_len;

    for(i = 0; i < NUM_MESSAGES; i++)
    {
        peer_addr_len = sizeof(peer_addr);
        
        ret = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&peer_addr, &peer_addr_len);

        if(peer_addr_len != sizeof(peer_addr))
            error_counter++;
        else if((peer_addr.sin6_family != AF_INET6) ||
                (peer_addr.sin6_addr._S6_un._S6_u32[0] != htonl(ipv6_address_ip1.nxd_ip_address.v6[0])) ||
                (peer_addr.sin6_addr._S6_un._S6_u32[1] != htonl(ipv6_address_ip1.nxd_ip_address.v6[1])) ||
                (peer_addr.sin6_addr._S6_un._S6_u32[2] != htonl(ipv6_address_ip1.nxd_ip_address.v6[2])) ||
                (peer_addr.sin6_addr._S6_un._S6_u32[3] != htonl(ipv6_address_ip1.nxd_ip_address.v6[3])))
            error_counter++;
        
        
        if(ret != (INT)strlen(netx_send_buffer6))
            error_counter++;
        else if(strncmp(buffer, netx_send_buffer6, ret))
            error_counter++;

        tx_thread_relinquish();
    }

    tx_semaphore_put(&bsd_sema);

}

#endif


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
int                 sockfd;
struct sockaddr_in  local_addr;
UINT                status;
#ifdef FEATURE_NX_IPV6    
struct sockaddr_in6 local_addr6;
char                mac_ip0[6];
char                mac_ip1[6];
int                 sockfd6;
INT                 reuseaddr = 1;
#endif
int                 ret;

    printf("NetX Test:   Basic BSD UDP Blocking Bidirection Test.......");

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

    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif    
    tx_semaphore_put(&netx_sema);

    /* Set up UDP socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd <= 0)
        error_counter++;

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));

    tx_thread_sleep(20);

    /* Create a thread to handle IPv4 UDP receive */
    ret = tx_thread_create(&bsd_transmit_v4_thread, "transmit v4 thread", transmit_entry, sockfd,
                           bsd_transmit_v4_thread_stack, DEMO_STACK_SIZE, 2, 2, 1, TX_AUTO_START);
    
    ret += tx_thread_create(&bsd_receive_v4_thread, "receive v4 thread", receive_entry, sockfd,
                            bsd_receive_v4_thread_stack, DEMO_STACK_SIZE, 2, 2, 1, TX_AUTO_START);
    if(ret != TX_SUCCESS)
        error_counter++;

#ifdef FEATURE_NX_IPV6    
    /* Set up UDP socket  */
    sockfd6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if(sockfd6 <= 0)
        error_counter++;

    setsockopt(sockfd6, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(INT));    
    memset(&local_addr6, 0, sizeof(local_addr6));
    local_addr6.sin6_family = AF_INET6;
    local_addr6.sin6_port = htons(12345);
    
    ret = bind(sockfd6, (struct sockaddr*)&local_addr6, sizeof(local_addr6));
    if(ret)
        error_counter++;

    /* Create a thread to handle IPv6 UDP receive */
    ret = tx_thread_create(&bsd_transmit_v6_thread, "transmit v6 thread", transmit6_entry, sockfd6,
                           bsd_transmit_v6_thread_stack, DEMO_STACK_SIZE, 2, 2, 1, TX_AUTO_START);
    
    ret += tx_thread_create(&bsd_receive_v6_thread, "receive v6 thread", receive6_entry, sockfd6,
                            bsd_receive_v6_thread_stack, DEMO_STACK_SIZE, 2, 2, 1, TX_AUTO_START);

    if(ret != TX_SUCCESS)
        error_counter++;

#endif

    status = tx_semaphore_get(&bsd_sema, TX_WAIT_FOREVER);
    status = tx_semaphore_get(&bsd_sema, TX_WAIT_FOREVER);
    
    /* Close down both sockets. */
#ifdef FEATURE_NX_IPV6    
    status = tx_semaphore_get(&bsd_sema, TX_WAIT_FOREVER);
    status = tx_semaphore_get(&bsd_sema, TX_WAIT_FOREVER);
    ret = soc_close(sockfd6);
#endif
    ret += soc_close(sockfd);
    if(ret) 
        error_counter++;
#ifdef FEATURE_NX_IPV6
    tx_thread_delete(&bsd_transmit_v6_thread);
    tx_thread_delete(&bsd_receive_v6_thread);
#endif

    tx_thread_delete(&bsd_transmit_v4_thread);
    tx_thread_delete(&bsd_receive_v4_thread);

    if(status)
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
    
static void    netx_transmit_entry(ULONG param)
{
NX_UDP_SOCKET *socket_ptr = (NX_UDP_SOCKET*)param;
int i;
NX_PACKET *packet_ptr;
ULONG status;


    for(i = 0; i < NUM_MESSAGES; i++)
    {

        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_NO_WAIT);
        status += nx_packet_data_append(packet_ptr, netx_send_buffer, strlen(netx_send_buffer),
                                        &pool_0, NX_NO_WAIT);
        status += nx_udp_socket_send(socket_ptr, packet_ptr, IP_ADDRESS(1,2,3,4), 12345);        

        if(status != NX_SUCCESS)
            error_counter++;
#ifdef FEATURE_NX_IPV6
        status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_NO_WAIT);
        status += nx_packet_data_append(packet_ptr, netx_send_buffer6, strlen(netx_send_buffer6),
                                        &pool_0, NX_NO_WAIT);
        status += nxd_udp_socket_send(socket_ptr, packet_ptr, &ipv6_address_ip0, 12345);        

        if(status != NX_SUCCESS)
            error_counter++;
#endif

        tx_thread_relinquish();
    }

    tx_semaphore_put(&netx_sema);    
}

static void    netx_receive_entry(ULONG param)
{
NX_UDP_SOCKET *socket_ptr = (NX_UDP_SOCKET*)param;
int i;
NX_PACKET *packet_ptr;
ULONG status;
int   num_messages;
    
    num_messages = NUM_MESSAGES;

#ifdef FEATURE_NX_IPV6
    num_messages += NUM_MESSAGES;
#endif

    for(i = 0; i < num_messages; i++)
    {

        /* Receive a UDP message from the socket.  */
        status =  nx_udp_socket_receive(socket_ptr, &packet_ptr, 2 * NX_IP_PERIODIC_RATE);


        if(status)
            error_counter++;
#ifdef __PRODUCT_NETXDUO__
        else if(packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
#endif
        {
            if(packet_ptr -> nx_packet_length != strlen(bsd_send_buffer))
                error_counter++;        
            else if(memcmp(packet_ptr -> nx_packet_prepend_ptr, bsd_send_buffer, packet_ptr -> nx_packet_length))
                error_counter++;
        }
#ifdef FEATURE_NX_IPV6
        else if(packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
        {
            if (packet_ptr -> nx_packet_length != strlen(bsd_send_buffer6))
                error_counter++;        
            if(memcmp(packet_ptr -> nx_packet_prepend_ptr, bsd_send_buffer6, packet_ptr -> nx_packet_length))
                error_counter++;
        }
#endif
#ifdef __PRODUCT_NETXDUO__
        else
            error_counter++;
#endif

        nx_packet_release(packet_ptr);

        tx_thread_relinquish();
    }

    tx_semaphore_put(&netx_sema);    
}



static void    netx_udp_test(void)
{
NX_UDP_SOCKET    udp_socket;
UINT             status;
    /* Create a socket.  */
    status =  nx_udp_socket_create(&ip_1, &udp_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 1 * NX_IP_PERIODIC_RATE);

                                
    /* Check for error.  */
    if (status)
        error_counter++;

    status = nx_udp_socket_bind(&udp_socket, 12345, NX_WAIT_FOREVER);
    if(status)
        error_counter++;

    tx_thread_sleep(20);

    status = tx_thread_create(&netx_transmit_thread, "netx transmit thread", netx_transmit_entry, (ULONG)&udp_socket,
                              netx_transmit_thread_stack, DEMO_STACK_SIZE, 2, 2, 1, TX_AUTO_START);
    
    status += tx_thread_create(&netx_receive_thread, "netx receive thread", netx_receive_entry, (ULONG)&udp_socket,
                               netx_receive_thread_stack, DEMO_STACK_SIZE, 2, 2, 1, TX_AUTO_START);

    if(status != TX_SUCCESS)
        error_counter++;


    tx_semaphore_get(&netx_sema, TX_WAIT_FOREVER);
    tx_semaphore_get(&netx_sema, TX_WAIT_FOREVER);
    

    tx_thread_delete(&netx_transmit_thread);
    tx_thread_delete(&netx_receive_thread);

    /* Unaccept the server socket.  */
    status =  nx_udp_socket_unbind(&udp_socket);

    status += nx_udp_socket_delete(&udp_socket);
    /* Check for error.  */
    if (status)
        error_counter++;

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
        test_control_return(3);
    }


    tx_semaphore_get(&netx_sema, TX_WAIT_FOREVER);
    netx_udp_test();


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

#else
extern void       test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_udp_blocking_bidirection_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD UDP Blocking Bidirection Test.......N/A\n"); 

    test_control_return(3);  
}      
#endif
