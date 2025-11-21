/* This NetX test concentrates on the basic BSD TCP blocking operation.  */
/* The BSD APIs involved in this test are:  socket(), connect(), send(), soc_close() */
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
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
static TX_SEMAPHORE            sema_0;
static TX_SEMAPHORE            sema_1;
#define BSD_THREAD_PRIORITY    2
#define NUM_CLIENTS            NX_BSD_MAX_SOCKETS
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
static char request[] = "Test_Request";
static char response[] = "Test_Response";
static void validate_bsd_structure(void);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_fionread_test_application_define(void *first_unused_memory)
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

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Enable BSD */
    status += bsd_initialize(&ip_0, &pool_0, (CHAR*)&bsd_thread_area[0], sizeof(bsd_thread_area), BSD_THREAD_PRIORITY);

    /* Check TCP enable status.  */
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

static client_info client_data;
static ULONG stack_space[DEMO_STACK_SIZE / sizeof(ULONG)];
static TX_THREAD helper_thread;

static VOID bsd_server_helper_thread_entry(ULONG thread_input)
{
int         ret;
int         sockfd, message_id;
char        buf[30] = {0};
int         size;

    sockfd = client_data.sockfd;
    message_id = client_data.message_id;

    /* Receive data from the client. */
    ret = recv(sockfd, buf, 4, 0);
    if(ret != 4)
        error_counter++;

    ret = ioctl(sockfd, FIONREAD, &size);
    if(ret)
        error_counter++;

    ret = recv(sockfd, buf + 4, sizeof(buf) - 4, 0);
    if(ret != size)
        error_counter++;

    /* Validate the data. */
    if((ret + 4) != (int)strlen(request) || strncmp(buf, request, (ret + 4)))
        error_counter++;

    /* Send a response back. */
    ret = send(sockfd, response, strlen(response), 0);
    if(ret != (int)strlen(response))
        error_counter++;

    tx_semaphore_get(&sema_1, 5 * NX_IP_PERIODIC_RATE);

    ret = soc_close(sockfd);
    if(ret)
        error_counter++;

    tx_semaphore_put(&sema_0);
    return;
}



static void test_tcp_server4(void)
{
int                sockfd;
struct sockaddr_in remote_addr, local_addr;
int                address_length;
int                ret;
int                newsock;
UINT               status;
int                accept_no_memory = 0;

  

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;
    
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret)
        error_counter++;
    
    ret = listen(sockfd, 5);
    if(ret)
        error_counter++;

    address_length = sizeof(remote_addr);

    newsock = accept(sockfd, (struct sockaddr*)&remote_addr, &address_length);

    if(newsock <= 0)
    {
        error_counter++;
    }
    else if(address_length != sizeof(remote_addr))
        error_counter++;
    else if((remote_addr.sin_family != AF_INET) || (remote_addr.sin_addr.s_addr != htonl(0x01020305)))
        error_counter++;


    /* Set the client data */
    client_data.sockfd = newsock;
    client_data.message_id = 0;
    
    /* Create a helper thread to handle the new socket. */
    status = tx_thread_create(&helper_thread, "helper thread", bsd_server_helper_thread_entry, 
                                0, stack_space, DEMO_STACK_SIZE, 2, 2, TX_NO_TIME_SLICE, TX_AUTO_START);
    if(status != TX_SUCCESS)
        error_counter++;

    tx_thread_relinquish();

    /* Close down the socket. */
    ret = soc_close(sockfd);
    if(ret)
        error_counter++;

    /* Wakeup server thread. */
    tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);
}


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{

    printf("NetX Test:   Basic BSD TCP FIONREAD Test...................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wakeup client. */
    tx_semaphore_put(&sema_1);

    test_tcp_server4();

    /* Wait until client finish. */
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
    
static NX_TCP_SOCKET tcp_socket;
static void    multiple_client4(void)
{

UINT          status = NX_SUCCESS;
NX_PACKET     *packet_ptr;

    status =  nx_tcp_socket_create(&ip_1, &tcp_socket, "Client Socket", 
                                    NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                    NX_NULL, NX_NULL);
    status +=  nx_tcp_client_socket_bind(&tcp_socket, NX_ANY_PORT, 0);

    if(status != NX_SUCCESS)
        error_counter++;

    status = nx_tcp_client_socket_connect(&tcp_socket, IP_ADDRESS(1, 2, 3, 4), 12345, NX_IP_PERIODIC_RATE);

    if(status != NX_SUCCESS)
        error_counter++;

    /* Send messages to each server */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
    status += nx_packet_data_append(packet_ptr, request, strlen(request),
                                    &pool_0, NX_NO_WAIT);
    status += nx_tcp_socket_send(&tcp_socket, packet_ptr, NX_IP_PERIODIC_RATE);

    if(status != NX_SUCCESS)
        error_counter++;

    /* Receive messages. */
    status = nx_tcp_socket_receive(&tcp_socket, &packet_ptr, 2 * NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Validate the received data. */
    else if(packet_ptr -> nx_packet_length != strlen(response))
        error_counter++;
    else if(strncmp((char*)packet_ptr -> nx_packet_prepend_ptr, response, packet_ptr -> nx_packet_length))
        error_counter++;
    nx_packet_release(packet_ptr);

    /* Wakeup server thread. */
    tx_semaphore_put(&sema_1);

    /* Shutdown the socket. */
    status = nx_tcp_socket_disconnect(&tcp_socket, 1 * NX_IP_PERIODIC_RATE);
    if(status == NX_NOT_CONNECTED || status == NX_DISCONNECT_FAILED)
        status = 0;

    if(tcp_socket.nx_tcp_socket_bound_next)
        status += nx_tcp_client_socket_unbind(&tcp_socket);


    status += nx_tcp_socket_delete(&tcp_socket);

    if(status != NX_SUCCESS)
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

    /* Server run first. */
    tx_semaphore_get(&sema_1, 5 * NX_IP_PERIODIC_RATE);

    /* Simulate a multiple client conneting to the same server. */
    multiple_client4();

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

#else
extern void       test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_fionread_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD TCP FIONREAD Test...................N/A\n"); 

    test_control_return(3);
}      
#endif
