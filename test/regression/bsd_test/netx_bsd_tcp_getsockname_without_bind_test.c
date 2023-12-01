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
static NX_TCP_SOCKET           server_socket;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            10
/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   packet_pool_area[(256 + sizeof(NX_PACKET)) * (NUM_CLIENTS + 4) * 8 / 4];
static ULONG                   client_ip;
static ULONG                   client_port;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];
static void validate_bsd_structure(void);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_getsockname_without_bind_test_application_define(void *first_unused_memory)
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
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

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

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}

static void    ntest_0_entry(ULONG thread_input)
{
int                ret;
int                sockfd;
int                address_length;
struct sockaddr_in remote_addr;
struct sockaddr_in local_addr;

    printf("NetX Test:   Basic BSD TCP getsockname Without Bind Test...");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;

    /* Connect to port not listening. */
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(13);
    remote_addr.sin_addr.s_addr = htonl(0x01020305);

    if(connect(sockfd, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) >= 0)
        error_counter++;

    address_length = sizeof(local_addr);
    ret = getsockname(sockfd, (struct sockaddr*)&local_addr, &address_length);
    if(ret < 0)
        error_counter++;
    else if(address_length != sizeof(local_addr))
        error_counter++;
    else if(local_addr.sin_family != AF_INET)
        error_counter++;
    else if(local_addr.sin_port == 0)
        error_counter++;

    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;


    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;

    /* Connect to port that is listening. */
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(12);
    remote_addr.sin_addr.s_addr = htonl(0x01020305);

    if(connect(sockfd, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0)
        error_counter++;

    address_length = sizeof(local_addr);
    ret = getsockname(sockfd, (struct sockaddr*)&local_addr, &address_length);
    if(ret < 0)
        error_counter++;
    else if(address_length != sizeof(local_addr))
        error_counter++;
    else if(local_addr.sin_family != AF_INET)
        error_counter++;
    else if(local_addr.sin_port != htons(client_port))
        error_counter++;
    else if(local_addr.sin_addr.s_addr != htonl(client_ip))
        error_counter++;

    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    validate_bsd_structure();

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
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

    status = nx_tcp_socket_peer_info_get(&server_socket, &client_ip, &client_port);

    /* Check for error.  */
    if (status)
        error_counter++;

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
void    netx_bsd_tcp_getsockname_without_bind_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD TCP getsockname Without Bind Test...N/A\n");

    test_control_return(3);
}
#endif
