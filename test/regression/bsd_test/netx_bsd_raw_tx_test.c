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

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            20
/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* The IPv6 packet assumes 
   src address fe80::f584:1fdb:425:a239
   dst address ff02::1:ffd6:5775
*/
char ipv6_packet[] = {
0x60, 0x00, 
0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf5, 0x84, 
0x1f, 0xdb, 0x04, 0x25, 0xa2, 0x39, 0xff, 0x02, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
0x00, 0x01, 0xff, 0xd6, 0x57, 0x75, 0x87, 0x00, 
0x39, 0xad, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0x1a, 
0x23, 0x6c, 0xab, 0xd6, 0x57, 0x75, 0x01, 0x01, 
0x00, 0x1e, 0x8c, 0xd5, 0xd3, 0x1f };


/* In this test case the source IP address must be 
192.168.1.185, dest 157.56.52.38
Source MAC 18:a9:05:cc:8f:16
dst MAC 00:24:a5:b5:2c:58
*/
static char ipv4_packet[] = {
0x45, 0x00, 
0x00, 0x3c, 0x3e, 0xa2, 0x00, 0x00, 0x80, 0x11, 
0x68, 0x4f, 0xc0, 0xa8, 0x01, 0xb9, 0x9d, 0x38, 
0x34, 0x26, 0x34, 0x4f, 0x9c, 0x64, 0x00, 0x28, 
0xdc, 0x3e, 0xa6, 0x3e, 0x02, 0x00, 0x25, 0xbb, 
0xa3, 0x96, 0x53, 0x4c, 0x32, 0x2f, 0x5d, 0x8d, 
0x26, 0x51, 0x42, 0x0e, 0xf6, 0x5c, 0x6c, 0x96, 
0x1c, 0x7d, 0x64, 0x3d, 0xd1, 0x86, 0xe5, 0x62, 
0x67, 0x5b };


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS ipv6_address_ip0;
static NXD_ADDRESS ipv6_address_ip1;
#endif /* FEATURE_NX_IPV6 */

static int test_case = 0;
extern void (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

static void bsd_tx_packet_process_callback(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
char data_buffer[100];
ULONG           ip_id;
ULONG           checksum;
    switch(test_case)
    {
    case 0:
        if(packet_ptr -> nx_packet_length != sizeof(ipv4_packet))
            error_counter++;
        if(memcmp(packet_ptr -> nx_packet_prepend_ptr, 
                  ipv4_packet, sizeof(ipv4_packet)))
            error_counter++;
        break;
        
    case 1:
        if(packet_ptr -> nx_packet_length != sizeof(ipv4_packet))
            error_counter++;
        memcpy(data_buffer, ipv4_packet, sizeof(ipv4_packet));
        ip_id = (packet_ptr -> nx_packet_prepend_ptr[4] << 8);  
        ip_id = (ip_id | (packet_ptr -> nx_packet_prepend_ptr[5]));
        if(ip_id != ip_0.nx_ip_packet_id)
            error_counter++;
        checksum = _nx_ip_checksum_compute(packet_ptr, NX_IP_VERSION_V4,
                                           (packet_ptr -> nx_packet_prepend_ptr[0] & 0xF) << 2,
                                           NULL, NULL);

        checksum = ~checksum & NX_LOWER_16_MASK;
        if(checksum)
            error_counter++;

        data_buffer[4] = (ip_id & 0xFF00) >> 8;
        data_buffer[5] = ip_id & 0xFF;

        data_buffer[10] = packet_ptr -> nx_packet_prepend_ptr[10];
        data_buffer[11] = packet_ptr -> nx_packet_prepend_ptr[11];

        if(memcmp(packet_ptr -> nx_packet_prepend_ptr, 
                  data_buffer, sizeof(ipv4_packet)))
            error_counter++;
        break;

    case 2:
        if(packet_ptr -> nx_packet_length != (sizeof(ipv4_packet) + 20))
            error_counter++;
        if(memcmp(packet_ptr -> nx_packet_prepend_ptr + 20, 
                  ipv4_packet, sizeof(ipv4_packet)))
            error_counter++;
        break;        
    case 3:
        if(packet_ptr -> nx_packet_length != (sizeof(ipv6_packet)))
            error_counter++;
        if(memcmp(packet_ptr -> nx_packet_prepend_ptr,
                  ipv6_packet, sizeof(ipv6_packet)))
            error_counter++;
        break;

    case 4:
        if(packet_ptr -> nx_packet_length != (sizeof(ipv6_packet) + 40))
            error_counter++;
        if(memcmp(packet_ptr -> nx_packet_prepend_ptr + 40,
                  ipv6_packet, sizeof(ipv6_packet)))
            error_counter++;
        break;

    default:
        error_counter++;
        break;

    }

    nx_packet_release(packet_ptr);
}

/* Define what the initial system looks like.  */
extern UINT _nxd_ip_raw_packet_send(NX_IP *ip_ptr, NX_PACKET *packet_ptr,  NXD_ADDRESS *destination_ip, ULONG protocol, UINT ttl, ULONG tos);
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_raw_tx_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, (256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 2);
    pointer = pointer + (256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 2;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(192, 168, 1, 185), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Set up the gateway address */
    status = nx_ip_gateway_address_set(&ip_0, IP_ADDRESS(192, 168, 1, 1));
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    
    /* Enable raw processing for both IP instances.  */
    status = nx_ip_raw_packet_enable(&ip_0);


    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check RAW enable and BSD init status.  */
    if (status)
        error_counter++;
}


static char buffer[100];
static void test_raw_ipv4_sendto(int hdrincl)
{
int                 sockfd;
struct sockaddr_in  remote_addr;
int                 ret;

    /* Create a raw socket. */
    sockfd = socket(AF_INET, SOCK_RAW, 100);
    if(sockfd < 0)
        error_counter++;
    
    /* Set IP_HDRINCL */

    ret = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl));
    if(ret)
        error_counter++;

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(5);
    remote_addr.sin_addr.s_addr = htonl(IP_ADDRESS(1 ,2, 3, 4));

    memcpy(buffer, ipv4_packet, sizeof(ipv4_packet));

    if(hdrincl)
        test_case = 0;    
    else
        test_case = 2;

    ret = sendto(sockfd, buffer, sizeof(ipv4_packet), 0, (struct sockaddr*)&remote_addr,
                 sizeof(remote_addr));
    if(ret < 0)
        error_counter++;

    /* Test with sendto */
    if(hdrincl == 1)
    {

        /* Clear the IP ID field, and make sure the stack is able to fill in the ID value. */
        buffer[4] = 0;
        buffer[5] = 0;
        
        test_case = 1;
    }
    else
        test_case = 2;
    ret = sendto(sockfd, buffer, sizeof(ipv4_packet), 0, (struct sockaddr*)&remote_addr,
                 sizeof(remote_addr));
    if(ret < 0)
        error_counter++;

    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}

#ifdef FEATURE_NX_IPV6
static void test_raw_ipv6_sendto(int hdrincl)
{
int                  sockfd;
struct sockaddr_in6  remote_addr;
int                  ret;

    /* Create a raw socket. */
    sockfd = socket(AF_INET6, SOCK_RAW, 100);
    if(sockfd < 0)
        error_counter++;
    
    /* Set IP_HDRINCL */

    ret = setsockopt(sockfd, IPPROTO_IP, IP_RAW_IPV6_HDRINCL, &hdrincl, sizeof(hdrincl));
    if(ret)
        error_counter++;

    remote_addr.sin6_family = AF_INET6;
    remote_addr.sin6_port = htons(5);
    remote_addr.sin6_addr._S6_un._S6_u32[0] = htonl(0xff020000);
    remote_addr.sin6_addr._S6_un._S6_u32[1] = htonl(0);
    remote_addr.sin6_addr._S6_un._S6_u32[2] = htonl(0xf5841fdb);
    remote_addr.sin6_addr._S6_un._S6_u32[3] = htonl(0x0425a239);

    if(hdrincl)
        test_case = 3;    
    else
        test_case = 4;

    ret = sendto(sockfd, ipv6_packet, sizeof(ipv6_packet), 0, (struct sockaddr*)&remote_addr,
                 sizeof(remote_addr));
    if(ret < 0)
        error_counter++;


    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}

static void test_raw_ipv6_send(int hdrincl)
{
int                  sockfd;
struct sockaddr_in6  remote_addr;
int                  ret;

    /* Create a raw socket. */
    sockfd = socket(AF_INET6, SOCK_RAW, 100);
    if(sockfd < 0)
        error_counter++;
    
    /* Set IP_HDRINCL */

    ret = setsockopt(sockfd, IPPROTO_IP, IP_RAW_IPV6_HDRINCL, &hdrincl, sizeof(hdrincl));
    if(ret)
        error_counter++;
#if 1
    remote_addr.sin6_family = AF_INET6;
    remote_addr.sin6_port = htons(5);
    remote_addr.sin6_addr._S6_un._S6_u32[0] = htonl(0xff020000);
    remote_addr.sin6_addr._S6_un._S6_u32[1] = htonl(0);
    remote_addr.sin6_addr._S6_un._S6_u32[2] = htonl(0xf5841fdb);
    remote_addr.sin6_addr._S6_un._S6_u32[3] = htonl(0x0425a239);
#endif
    if(hdrincl)
        test_case = 3;    
    else
        test_case = 4;

    ret = sendto(sockfd, ipv6_packet, sizeof(ipv6_packet), 0, (struct sockaddr*)&remote_addr,
                 sizeof(remote_addr));
    if(ret < 0)
        error_counter++;


    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}
#endif /* FEATURE_NX_IPV6 */

static void test_raw_ipv4_send(int hdrincl)
{
int                 sockfd;
struct sockaddr_in  remote_addr;
int                 ret;

    /* Create a raw socket. */
    sockfd = socket(AF_INET, SOCK_RAW, 100);
    if(sockfd < 0)
        error_counter++;
    
    ret = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl));
    if(ret)
        error_counter++;

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(5);
    remote_addr.sin_addr.s_addr = htonl(IP_ADDRESS(1 ,2, 3, 4));
    
    ret = connect(sockfd, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
    if(ret < 0)
        error_counter++;

    /* Clear the IP ID field, and make sure the stack is able to fill in the ID value. */
    memcpy(buffer, ipv4_packet, sizeof(ipv4_packet));
    if(hdrincl)
        test_case = 0;
    else
        test_case = 2;
    ret = send(sockfd, buffer, sizeof(ipv4_packet), 0);
    if(ret < 0)
        error_counter++;

    if(hdrincl == 1)
    {
        buffer[4] = 0;
        buffer[5] = 0;
        
        test_case = 1;
    }
    else
        test_case = 2;
    ret = send(sockfd, buffer, sizeof(ipv4_packet), 0);
    if(ret < 0)
        error_counter++;

    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;
}

/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{

UINT status;
#ifdef FEATURE_NX_IPV6    
char mac_ip[6];
#endif

    printf("NetX Test:   Basic BSD RAW TX Test.........................");

    /* Populate the ARP table for the gateway address */
    status = nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(192, 168, 1, 1), (0x00 << 8) | 0x24,
                                      ((0xa5 << 24) | (0xb5 << 16) | (0x2c << 8) | 0x58));
    if(status)
        error_counter++;

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

    status = nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_ip0, 10, NX_NULL);

    ipv6_address_ip1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_ip1.nxd_ip_address.v6[0] = 0xfe800000;
    ipv6_address_ip1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_ip1.nxd_ip_address.v6[2] = 0xf5841fdb;
    ipv6_address_ip1.nxd_ip_address.v6[3] = 0x0425a239;

    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_ip1, 10, NX_NULL);
    
    status += nxd_ipv6_enable(&ip_0);
    
    mac_ip[0] = ip_0.nx_ip_interface[0].nx_interface_physical_address_msw >> 8;
    mac_ip[1] = ip_0.nx_ip_interface[0].nx_interface_physical_address_msw & 0xFF;
    mac_ip[2] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 24) & 0xff;
    mac_ip[3] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 16) & 0xff;
    mac_ip[4] = (ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw >> 8) & 0xff;
    mac_ip[5] = ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw  & 0xff;

    status += nxd_nd_cache_entry_set(&ip_0, ipv6_address_ip0.nxd_ip_address.v6, 0,  mac_ip);

    if(status)
        error_counter++;
#endif

    packet_process_callback = bsd_tx_packet_process_callback;

    test_raw_ipv4_sendto(1);

    test_raw_ipv4_send(1);

    test_raw_ipv4_sendto(0);

    test_raw_ipv4_send(0);

#ifdef FEATURE_NX_IPV6
    test_raw_ipv6_sendto(1);

    test_raw_ipv6_send(1);

    test_raw_ipv6_sendto(0);

    test_raw_ipv6_send(0);
#endif

    validate_bsd_structure();

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
void    netx_bsd_raw_tx_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Basic BSD RAW TX Test.........................N/A\n");
    test_control_return(3);
}
#endif /* __PRODUCT_NETXDUO__ */

