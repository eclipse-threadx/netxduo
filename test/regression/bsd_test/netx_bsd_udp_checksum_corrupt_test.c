/* This NetX test concentrates on the BSD UDP socket reject packet with corrupted checksum.  */


#include   "nx_api.h"
#ifdef NX_BSD_ENABLE
#include   "nx_udp.h"
#include   "nxd_bsd.h"
#define     DEMO_STACK_SIZE         4096

#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            2

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_UDP_SOCKET           server_socket;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
static char *requests = "Request";
/* Define the counters used in the test application...  */

static ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
static VOID    udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_udp_checksum_corrupt_test_application_define(void *first_unused_memory)
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


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
int                sockfd;
struct sockaddr_in remote_addr, local_addr;
int                ret;
char               buf[30];
int                addrlen;

    printf("NetX Test:   BSD UDP Checksum Corrupt Test.................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    ip_0.nx_ip_udp_packet_receive = udp_packet_receive;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
        error_counter++;

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    /* Receive data from the client. */
    addrlen = sizeof(remote_addr);
    ret = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &addrlen);
#if !defined(NX_ENABLE_INTERFACE_CAPABILITY) && !defined(NX_DISABLE_UDP_RX_CHECKSUM)
    if(ret > 0)
        error_counter++;
#endif

    /* Close downt he socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    validate_bsd_structure();
}

static void    ntest_1_entry(ULONG thread_input)
{
UINT            status;
NX_PACKET       *packet_ptr;
ULONG           actual_status;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(3);
    }

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

    /* Allocate a packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Fill in the packet with data */
    status = nx_packet_data_append(packet_ptr, requests, strlen(requests),
                                   &pool_0, NX_WAIT_FOREVER);

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Send a UDP packet */
    status =  nx_udp_socket_send(&server_socket, packet_ptr, IP_ADDRESS(1,2,3,4), 12345);
    if(status)
        error_counter++;

    status = nx_udp_socket_unbind(&server_socket);
    if(status)
        error_counter++;

    status = nx_udp_socket_delete(&server_socket);
    if(status)
        error_counter++;

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

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

static VOID    udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{
NX_UDP_HEADER *udp_header_ptr;
USHORT checksum;

    udp_header_ptr =  (NX_UDP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
    checksum = udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF;
    checksum++;
    if (checksum == 0)
        checksum++;
    udp_header_ptr -> nx_udp_header_word_1 = (udp_header_ptr -> nx_udp_header_word_1 & 0xFFFF0000) | checksum;
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

    _nx_udp_packet_receive(ip_ptr, packet_ptr);
}
#endif /* NX_BSD_ENABLE */
