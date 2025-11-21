/* This NetX test concentrates on the basic BSD UDP non-blocking operation.  */
#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nx_ipv4.h"
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
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            20
/* Define the counters used in the test application...  */

static ULONG                   error_counter;
#define MULTICAST_ADDRESS      IP_ADDRESS(239, 1, 2, 3)
#define MULTICAST_TTL_VALUE    65

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
static char *requests[4] = {"Request1", "Request2", "Request3", "Request4"};
static char *response[4] = {"Response1", "Response2", "Response3", "Response4"};
static void validate_bsd_structure(void);
/* Define what the initial system looks like.  */

#ifdef __PRODUCT_NETX__
#define NX_IPV4_HEADER  NX_IP_HEADER
#endif

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_multicast_test_application_define(void *first_unused_memory)
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

    /* Enable UDP processing for both IP instances.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check UDP enable and BSD init status.  */
    if (status)
        error_counter++;
}

static void test_udp_server4(void)
{
int                sockfd;
struct sockaddr_in remote_addr, local_addr;
int                ret;
char               buf[30];
int                addrlen;
struct ip_mreq     mreq;
UCHAR              ttl;
int                status;
int                i;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;
    
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;
    
    memset(&mreq, 0, sizeof(struct ip_mreq));
    
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    mreq.imr_multiaddr.s_addr = htonl(MULTICAST_ADDRESS);

    status = setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if(status)
        error_counter++;
    
    ttl = MULTICAST_TTL_VALUE;
    status = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if(status)
        error_counter++;
    
    /* Make sure the address is recorded into the IGMP table. */
    error_counter++;
    for(i = 0; i < NX_MAX_MULTICAST_GROUPS; i++)
    {
#ifdef __PRODUCT_NETXDUO__
        if(ip_0.nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_count == 0)
            continue;

        if((ip_0.nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_list == MULTICAST_ADDRESS) &&
           (ip_0.nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_interface_list == &(ip_0.nx_ip_interface[0])))
        {
            error_counter--;
            break;
        }
#else
        if(ip_0.nx_ip_igmp_join_count[i] == 0)
            continue;

        if((ip_0.nx_ip_igmp_join_list[i] == MULTICAST_ADDRESS) &&
                (ip_0.nx_ip_igmp_join_interface_list[i] == &(ip_0.nx_ip_interface[0])))
        {
            error_counter--;
            break;
        }
#endif

    }
           
    /* Receive data from the client. */
    addrlen = sizeof(remote_addr);
    ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
    if(ret <= 0)
        error_counter++;

    if(addrlen != sizeof(struct sockaddr_in))
        error_counter++;

    if((remote_addr.sin_family != AF_INET) ||
       (remote_addr.sin_addr.s_addr != htonl(IP_ADDRESS(1,2,3,5))) ||
       (remote_addr.sin_port != htons(54321)))
        error_counter++;

    /* Validate the data. */
    if((ret != (int)strlen(requests[0])) || strncmp(buf, requests[0], ret))
        error_counter++;    

    /* Send a response back. */
    ret = sendto(sockfd, response[0], strlen(response[0]), 0, (struct sockaddr*)&remote_addr, addrlen);
    if(ret != (int)strlen(response[0]))
        error_counter++;

    tx_thread_sleep(1);

    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    mreq.imr_multiaddr.s_addr = htonl(MULTICAST_ADDRESS);
    status = setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

    if(status)
        error_counter++;

    /* Make sure the address has been removed from the IGMP table. */
    for(i = 0; i < NX_MAX_MULTICAST_GROUPS; i++)
    {
#ifdef __PRODUCT_NETXDUO__
        if(ip_0.nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_count == 0)
            continue;

        if((ip_0.nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_list == MULTICAST_ADDRESS) &&
           (ip_0.nx_ipv4_multicast_entry[i].nx_ipv4_multicast_join_interface_list == &(ip_0.nx_ip_interface[0])))
        {
            error_counter++;
            break;
        }
#else
        if(ip_0.nx_ip_igmp_join_count[i] == 0)
            continue;

        if((ip_0.nx_ip_igmp_join_list[i] == MULTICAST_ADDRESS) &&
                (ip_0.nx_ip_igmp_join_interface_list[i] == &(ip_0.nx_ip_interface[0])))
        {
            error_counter++;
            break;
        }
#endif
    }


    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}



/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
    printf("NetX Test:   Basic BSD Multicast Test......................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }


    test_udp_server4();

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
NX_IPV4_HEADER  *ipv4_header_ptr;


    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(3);
    }

    /* Create a socket.  */
    status =  nx_udp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, NX_IP_PERIODIC_RATE);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Enable IGMP */
    status = nx_igmp_enable(&ip_1);
    if(status)
        error_counter++;

    /* Join the test IGMP group */
    if(nx_igmp_multicast_join(&ip_1, MULTICAST_ADDRESS))
        error_counter++;


    /* Allocate a packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Fill in the packet with data */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, requests[0], strlen(requests[0]));
    
    packet_ptr -> nx_packet_length = strlen(requests[0]);
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;

    /* Bind to a UDP port. */
    status = nx_udp_socket_bind(&server_socket, 54321, NX_WAIT_FOREVER);
    if(status)
        error_counter++;

    /* Send a UDP packet */
    status =  nx_udp_socket_send(&server_socket, packet_ptr, IP_ADDRESS(1,2,3,4), 12345);
    if(status)
        error_counter++;

    /* Ready to reaceive a message */
    status = nx_udp_socket_receive(&server_socket, &packet_ptr, NX_WAIT_FOREVER);
    if(status)
        error_counter++;

    /* Validate the content. */
    if(packet_ptr -> nx_packet_length != strlen(response[0]))
        error_counter++;
    else if(strncmp((char*)packet_ptr -> nx_packet_prepend_ptr, response[0], strlen(response[0])))
        error_counter++;

    /* Verify the TTL value. */
#ifdef __PRODUCT_NETXDUO__
    ipv4_header_ptr = (NX_IPV4_HEADER*)packet_ptr -> nx_packet_ip_header;
#else
    ipv4_header_ptr = (NX_IP_HEADER*)(packet_ptr -> nx_packet_prepend_ptr - 8 - 20);
#endif
    if((ipv4_header_ptr -> nx_ip_header_word_2 >> 24) != MULTICAST_TTL_VALUE)
        error_counter++;

    status = nx_udp_socket_unbind(&server_socket);
    if(status)
        error_counter++;

    status = nx_udp_socket_delete(&server_socket);
    if(status)
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
void    netx_bsd_multicast_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD Multicast Test......................N/A\n"); 

    test_control_return(3);  
}      
#endif
