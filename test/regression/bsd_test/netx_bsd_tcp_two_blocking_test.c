/* This NetX test concentrates on the basic BSD TCP blocking operation.  */
/* The BSD APIs involved in this test are:  socket(), connect(), send(), recv(), soc_close(), setsockopt() */

#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nxd_bsd.h"

#define     DEMO_STACK_SIZE         4096
#define BSD_THREAD_PRIORITY         2

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static TX_SEMAPHORE            sema_0;
static TX_SEMAPHORE            sema_1;
static int                     newsock_1;
static UCHAR                   loop;
static NX_TCP_SOCKET           client_0, client_1;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static UCHAR                   packet_pool_area[(256 + sizeof(NX_PACKET)) * 16];
static UCHAR                   recv_buff_0[32];
static UCHAR                   recv_buff_1[32];

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];
extern TX_BLOCK_POOL nx_bsd_socket_block_pool;
static char   *send_buffer = "Hello World";
/* Define what the initial system looks like.  */


#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_two_blocking_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    loop = NX_TRUE;

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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, 
                          _nx_ram_network_driver_256, pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, 
                           _nx_ram_network_driver_256, pointer, 2048, 1);
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
    status += bsd_initialize(&ip_0, &pool_0, pointer, DEMO_STACK_SIZE, BSD_THREAD_PRIORITY);
    pointer = pointer + DEMO_STACK_SIZE;

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

    status = tx_semaphore_create(&sema_0, "SEMA 0", 0);
    status += tx_semaphore_create(&sema_1, "SEMA 1", 0);
    if(status)
        error_counter++;
}

/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
int                sockfd, newsock_0;
struct sockaddr_in local_addr;
int                ret;
struct timeval     time_0, time_1;


    printf("NetX Test:   Basic BSD TCP Two Blocking Test...............");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a server socket. */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;
    
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;
    
    ret = listen(sockfd, 5);
    if(ret < 0)
        error_counter++;

    /* Let client thread start the connection. */
    tx_semaphore_put(&sema_1);

    /* Accept two connections. */
    newsock_0 = accept(sockfd, (struct sockaddr*)NX_NULL, 0);
    if(newsock_0 < 0)
        error_counter++;
    else
    {
        
#if 0
        /* Set timeout to 3 seconds. */
        time_0.tv_sec = 3;
        time_0.tv_usec = 0;
#else
        /* Set timeout to 30 ticks. */
        time_0.tv_sec = 0;
        time_0.tv_usec = 30 * NX_MICROSECOND_PER_CPU_TICK;
#endif
        setsockopt(newsock_0, SOL_SOCKET, SO_RCVTIMEO, &time_0, sizeof(time_0));
    }


    newsock_1 = accept(sockfd, (struct sockaddr*)NX_NULL, 0);
    if(newsock_1 < 0)
        error_counter++;
    else
    {

#if 0
        /* Set timeout to 1 second. */
        time_1.tv_sec = 1;
        time_1.tv_usec = 0;
#else
        /* Set timeout to 10 ticks. */
        time_0.tv_sec = 0;
        time_0.tv_usec = 10 * NX_MICROSECOND_PER_CPU_TICK;
#endif
        setsockopt(newsock_1, SOL_SOCKET, SO_RCVTIMEO, &time_1, sizeof(time_1));
    }

    /* Let client thread loop send and recv. */
    tx_semaphore_put(&sema_1);

    /* Receive on socket 0. */
    ret = recv(newsock_0, recv_buff_0, sizeof(recv_buff_0), 0);
    if((ret >= 0) || (errno != EAGAIN))
        error_counter++;

    /* Close down the server socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    /* Notify to end loop of thread 1. */
    loop = NX_FALSE;
    tx_semaphore_get(&sema_0, 1 * NX_IP_PERIODIC_RATE);

    /* Close down the new socket 0. */
    ret = soc_close(newsock_0);
    if(ret < 0)
        error_counter++;

    /* Close down the new socket 1. */
    soc_close(newsock_1);

    /* Check bsd wrapper. */
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

UINT               status;
ULONG              actual_status;
NX_PACKET         *my_packet;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(3);
    }

    /* Create a socket.  */
    status = nx_tcp_socket_create(&ip_1, &client_0, "Client Socket", 
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                  NX_NULL, NX_NULL);

    /* Create a socket.  */
    status += nx_tcp_socket_create(&ip_1, &client_1, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Bind the socket.  */
    status = nx_tcp_client_socket_bind(&client_0, 12, 1 * NX_IP_PERIODIC_RATE);
    status += nx_tcp_client_socket_bind(&client_1, 13, 1 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Wait for server thread first. */
    tx_semaphore_get(&sema_1, 1 * NX_IP_PERIODIC_RATE);

    status = nx_tcp_client_socket_connect(&client_0, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);
    status += nx_tcp_client_socket_connect(&client_1, IP_ADDRESS(1, 2, 3, 4), 12, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;
    
    /* Loop sending and receiving. */
    tx_semaphore_get(&sema_1, 1 * NX_IP_PERIODIC_RATE);
    while(loop)
    {

        /* Send packet. */
        status = nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_NO_WAIT);
        status += nx_packet_data_append(my_packet, send_buffer, strlen(send_buffer), &pool_0, NX_NO_WAIT);
        status = nx_tcp_socket_send(&client_1, my_packet, NX_NO_WAIT);

        /* Check for error.  */
        if(status)
            error_counter++;

        /* Receive data. */
        recv(newsock_1, recv_buff_1, sizeof(recv_buff_1), 0);
        
#if 0
        /* Sleep 1 second. */
        tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);
#else
        /* Sleep 100ms. */
        tx_thread_sleep(NX_IP_PERIODIC_RATE / 10);
#endif
    }
        
    nx_tcp_socket_disconnect(&client_0, 1);
    nx_tcp_socket_disconnect(&client_1, 1);

    /* Unbind the socket.  */
    status = nx_tcp_client_socket_unbind(&client_0);
    status += nx_tcp_client_socket_unbind(&client_1);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Delete the socket.  */
    status = nx_tcp_socket_delete(&client_0);
    status += nx_tcp_socket_delete(&client_1);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Let server thread go on. */
    tx_semaphore_put(&sema_0);
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
void    netx_bsd_tcp_two_blocking_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD TCP Two Blocking Test...............N/A\n"); 

    test_control_return(3);  
}      
#endif
