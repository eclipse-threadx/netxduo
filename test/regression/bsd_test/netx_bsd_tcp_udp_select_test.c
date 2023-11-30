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
static NX_UDP_SOCKET           udp_socket;
static NX_TCP_SOCKET           tcp_socket;
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
static char *requests[2] = {"Request1", "Request2"};

static void validate_bsd_structure(void);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_udp_select_test_application_define(void *first_unused_memory)
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

    /* Enable UDP processing for both IP instances.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);
    status += nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, pointer, DEMO_STACK_SIZE, BSD_THREAD_PRIORITY);

    /* Check UDP enable and BSD init status.  */
    if (status)
        error_counter++;
    pointer = pointer + DEMO_STACK_SIZE;

    status = tx_semaphore_create(&sema_0, "SEMA 0", 0);
    status += tx_semaphore_create(&sema_1, "SEMA 1", 0);
    if(status)
        error_counter++;
}




/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
struct sockaddr_in local_addr;
struct sockaddr_in peer_addr;
int peer_addr_len;
int tcp_sockfd, udp_sockfd, new_sockfd, nfd;
struct timeval tv;
fd_set readfd;
int n, i;
char buffer[20];

    printf("NetX Test:   Basic BSD TCP UDP Select Test.................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    /* Open TCP socket. */
    tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(tcp_sockfd < 0)
        error_counter++;

    if(bind(tcp_sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0)
        error_counter++;

    if(listen(tcp_sockfd, 5) < 0)
        error_counter++;

    udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp_sockfd < 0)
        error_counter++;
    
    if(bind(udp_sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0)
        error_counter++;

    peer_addr_len = sizeof(peer_addr);
    tx_semaphore_put(&sema_1);
    new_sockfd = accept(tcp_sockfd, (struct sockaddr*)&peer_addr, &peer_addr_len);

    if(new_sockfd < 0)
        error_counter++;
    
#if 0
    /* Now sleep for a second */
    tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);
#endif

    /* select on both sockets. */
    if(udp_sockfd < new_sockfd)
        nfd = new_sockfd + 1;
    else
        nfd = udp_sockfd + 1;

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    error_counter += 2;

    for(i = 0; i < 2;)
    {
        FD_ZERO(&readfd);
        FD_SET(new_sockfd, &readfd);
        FD_SET(udp_sockfd, &readfd);
        n = select(nfd, &readfd, NULL, NULL, &tv);

        if(n <= 0)
        {
            error_counter++;
            break;
        }
        i += n;

        if(FD_ISSET(new_sockfd, &readfd))
        {
            n = recv(new_sockfd, buffer, sizeof(buffer), 0);
            if(n < 0)
                error_counter++;
            else if(n != (int)strlen(requests[1])) 
                error_counter++;
            else if(strncmp(buffer, requests[1], n))
                error_counter++;
            else
                error_counter--;

        }
        if(FD_ISSET(udp_sockfd, &readfd))
        {
            peer_addr_len = sizeof(peer_addr);
            n = recvfrom(udp_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&peer_addr, &peer_addr_len);
            if(n < 0)
                error_counter++;
            else if(n != (int)strlen(requests[0])) 
                error_counter++;
            else if(strncmp(buffer, requests[0], n))
                error_counter++;
            else
                error_counter--;
        }
    }

    soc_close(new_sockfd);
    soc_close(tcp_sockfd);
    soc_close(udp_sockfd);

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



    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(3);
    }

    status =  nx_tcp_socket_create(&ip_1, &tcp_socket, "TCP Server Socket", 
                                    NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                    NX_NULL, NX_NULL);
    status +=  nx_tcp_client_socket_bind(&tcp_socket, NX_ANY_PORT, 0);
    if(status != NX_SUCCESS)
        error_counter++;

    
    

    /* Create a socket.  */
    status =  nx_udp_socket_create(&ip_1, &udp_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 10);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    tx_semaphore_get(&sema_1, 5 * NX_IP_PERIODIC_RATE);
    status = nx_tcp_client_socket_connect(&tcp_socket, IP_ADDRESS(1,2,3,4), 12345, NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
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
    status = nx_udp_socket_bind(&udp_socket, 54321, NX_WAIT_FOREVER);
    if(status)
        error_counter++;

    /* Send a UDP packet */
    status =  nx_udp_socket_send(&udp_socket, packet_ptr, IP_ADDRESS(1,2,3,4), 12345);
    if(status)
        error_counter++;


    /* Allocate a packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Fill in the packet with data */
    memcpy(packet_ptr -> nx_packet_prepend_ptr, requests[1], strlen(requests[1]));
    
    packet_ptr -> nx_packet_length = strlen(requests[1]);
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + packet_ptr -> nx_packet_length;


    /* Send a TCP packet */
    status =  nx_tcp_socket_send(&tcp_socket, packet_ptr, NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    status = nx_udp_socket_unbind(&udp_socket);
    if(status)
        error_counter++;

    status = nx_udp_socket_delete(&udp_socket);
    if(status)
        error_counter++;

    status = nx_tcp_socket_disconnect(&tcp_socket, 1 * NX_IP_PERIODIC_RATE);
    status += nx_tcp_client_socket_unbind(&tcp_socket);
    status += nx_tcp_socket_delete(&tcp_socket);
    
    if(status != NX_SUCCESS)
        error_counter++;
    
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

#else
extern void       test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_udp_select_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD TCP UDP Select Test.................N/A\n"); 

    test_control_return(3);  
}      
#endif
