/* This NetX test concentrates on the basic BSD RAW Ping.  */

#include   "tx_api.h"
#include   "nx_api.h"
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4) && defined(NX_ENABLE_IP_RAW_PACKET_ALL_STACK)
#ifdef NX_BSD_ENABLE
#include   "nxd_bsd.h"
#include   "nx_icmpv6.h"
#define     DEMO_STACK_SIZE         8192
#define     LOOP                    100


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
#define BSD_THREAD_PRIORITY    2
/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS ipv6_address_ip0;
static NXD_ADDRESS ipv6_address_ip1;
#endif /* FEATURE_NX_IPV6 */
/* Echo request from 172.31.144.1 to 172.31.159.102. */
static char echo_request[] = 
"\x08\x00\x4d\x50\x00\x01\x00\x0b\x61\x62\x63\x64\x65\x66\x67\x68" \
"\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61" \
"\x62\x63\x64\x65\x66\x67\x68\x69";
/* Echo reply from 172.31.159.102 to 172.31.144.1. */
static char echo_reply[] = 
"\x00\x00\x55\x50\x00\x01\x00\x0b\x61\x62\x63\x64\x65\x66\x67\x68" \
"\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61" \
"\x62\x63\x64\x65\x66\x67\x68\x69";
static char receive_buffer[100];

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_raw_ping_test_application_define(void *first_unused_memory)
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


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, (256 + sizeof(NX_PACKET)) * 32);
    pointer = pointer + (256 + sizeof(NX_PACKET)) * 32;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(172, 31, 144, 1), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(172, 31, 159, 102), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
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

    /* Enable ICMP processing for both IP instances.  */
    status += nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Enable raw processing for both IP instances.  */
    status += nx_ip_raw_packet_enable(&ip_0);
    status += nx_ip_raw_packet_enable(&ip_1);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check RAW enable and BSD init status.  */
    if (status)
        error_counter++;
}

/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
int                sockfd;
struct sockaddr_in remote_addr;
int                ret;
int                addrlen;
int                option;
UINT               i;
UINT               original_threshold;

    printf("NetX Test:   Basic BSD Raw Ping Test.......................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    for (i = 0 ; (i < LOOP) && (error_counter == 0); i++)
    {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if(sockfd < 0)
            error_counter++;
    
        option = 1;
        ret = setsockopt(sockfd, IPPROTO_IP, IP_RAW_RX_NO_HEADER, (void*)&option, sizeof(option));
        if(ret != 0)
            error_counter++;  
    
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = 0;
        remote_addr.sin_addr.s_addr = htonl(IP_ADDRESS(172, 31, 159, 102));

        if (i == (LOOP >> 1))
        {

            /* Temporarily disable preemption.  */
            tx_thread_preemption_change(tx_thread_identify(), 0, &original_threshold);
        }
    
        /* Send echo request. */
        ret = sendto(sockfd, echo_request, sizeof(echo_request) - 1, 0, (struct sockaddr*)&remote_addr,
                     sizeof(remote_addr));
        if(ret < 0)
            error_counter++;

        if (i == (LOOP >> 1))
        {

            /* Special case: close socket before packet is received.  */    
            /* Close down the socket. */
            ret = soc_close(sockfd);
            if(ret < 0)
                error_counter++;

            /* Restore original preemption threshold.  */
            tx_thread_preemption_change(tx_thread_identify(), original_threshold, &original_threshold);

            tx_thread_sleep(NX_IP_PERIODIC_RATE);
            continue;
        }
    
        /* Receive echo reply. */
        addrlen = sizeof(remote_addr);
        ret = recvfrom(sockfd, receive_buffer, sizeof(receive_buffer), 0, (struct sockaddr*)&remote_addr, &addrlen);
        if(ret <= 0)
            error_counter++;
    
        if((remote_addr.sin_family != AF_INET) ||
           (remote_addr.sin_addr.s_addr != htonl(IP_ADDRESS(172, 31, 159, 102))))
            error_counter++;
    
        if ((ret != (sizeof(echo_reply) - 1)) || (memcmp(receive_buffer, echo_reply, ret)))
            error_counter++;
    
        /* Close down the socket. */
        ret = soc_close(sockfd);
        if(ret < 0)
            error_counter++;

        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    validate_bsd_structure();
    tx_thread_sleep(2);
    if(error_counter)
        printf("ERROR!\n");
    else
        printf("SUCCESS!\n");

    if(error_counter)
        test_control_return(1);    

    test_control_return(0);    
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
void    netx_bsd_raw_ping_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Basic BSD Raw Ping Test.......................N/A\n");
    test_control_return(3);
}
#endif /* __PRODUCT_NETXDUO__ */
