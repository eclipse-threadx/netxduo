/* This NetX test concentrates on the basic BSD TCP blocking operation.  */
/* The BSD APIs involved in this test are:  socket(), connect(), send(), soc_close() */

#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nx_icmpv6.h"
#include   "nxd_bsd.h"
#define     DEMO_STACK_SIZE         1024


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;
static TX_THREAD               ntest_2;
static TX_THREAD               ntest_3;
static TX_THREAD               ntest_4;
static TX_THREAD               ntest_5;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static ULONG                   bsd_thread_area[DEMO_STACK_SIZE / sizeof(ULONG)];
static TX_SEMAPHORE            sema_0;
static TX_SEMAPHORE            sema_1;
#define BSD_THREAD_PRIORITY    2
/* Define the counters used in the test application...  */
#define NUM_ITERATION          3000
static ULONG                   error_counter;
static ULONG                   packet_pool_area[(256 + sizeof(NX_PACKET)) * (100) / 4];

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_2_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];

static char *send_buffer = "Hello World";
typedef struct helper_thread_block_struct
{
    ULONG stack_space[DEMO_STACK_SIZE / sizeof(ULONG)];
    TX_THREAD helper_thread;
} HELPER_THREAD_BLOCK;

static HELPER_THREAD_BLOCK *helper_thread_block_ptr;

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_disconnect_test_application_define(void *first_unused_memory)
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
                     2, 2, 1, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     2, 2, 1, TX_AUTO_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;


    /* Create the main thread.  */
    tx_thread_create(&ntest_2, "client thread 1", ntest_2_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     2, 2, 1, TX_DONT_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_3, "client thread 2", ntest_2_entry, 1,  
                     pointer, DEMO_STACK_SIZE, 
                     2, 2, 1, TX_DONT_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_4, "client thread 3", ntest_2_entry, 2,  
                     pointer, DEMO_STACK_SIZE, 
                     2, 2, 1, TX_DONT_START);
    
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_5, "client thread 4", ntest_2_entry, 3,  
                     pointer, DEMO_STACK_SIZE, 
                     2, 2, 1, TX_DONT_START);
    
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
    
    helper_thread_block_ptr = (HELPER_THREAD_BLOCK*)pointer;
    pointer += sizeof(HELPER_THREAD_BLOCK) * 10;
        
    memset(helper_thread_block_ptr, 0, sizeof(HELPER_THREAD_BLOCK) * 10);
    
    status = tx_semaphore_create(&sema_0, "SEMA 0", 0);
    status += tx_semaphore_create(&sema_1, "SEMA 1", 0);
    if(status)
        error_counter++;
}

static VOID bsd_server_helper_thread_entry(ULONG thread_input)
{
int         ret;
int         sockfd;
char        buf[30];

    sockfd = thread_input;

    /* Receive data from the client. */
    ret = recv(sockfd, buf, sizeof(buf), 0);
    if(ret < 0)
        error_counter++;

    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    tx_semaphore_put(&sema_0);
}


static void test_tcp_client4(void)
{
int sockfd;
struct sockaddr_in remote_addr;
int bytes_sent;
int ret;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        error_counter++;
        return;
    }
    
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(12);
    remote_addr.sin_addr.s_addr = htonl(0x01020305);

    tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);
    if(connect(sockfd, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0)
        error_counter++;
    else 
    {
        bytes_sent = send(sockfd, send_buffer, strlen(send_buffer), 0);

        if(bytes_sent != (int)strlen(send_buffer))
            error_counter++;
    }
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

}

static void test_tcp_server4(void)
{
int                sockfd;
struct sockaddr_in remote_addr, local_addr;
int                address_length;
int                ret;
int                newsock;
int                i, j;
UINT               status;
HELPER_THREAD_BLOCK *helper_thread_ptr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
        error_counter++;
    
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;
    
    ret = listen(sockfd, 5);
    if(ret < 0)
        error_counter++;

    for(i = 0; i < 4; i++)
        tx_semaphore_put(&sema_1);

    /* 3 iterations. */
    for(i = 0; i < NUM_ITERATION; i++)
    {
        address_length = sizeof(remote_addr);

        newsock = accept(sockfd, (struct sockaddr*)&remote_addr, &address_length);
        
        if(newsock <= 0)
            error_counter++;
        
        if(address_length != sizeof(remote_addr))
            error_counter++;
        
        if((remote_addr.sin_family != AF_INET) || (remote_addr.sin_addr.s_addr != htonl(0x01020305)))
            error_counter++;



        for(j = 0; j < 10; j++)
        {
            helper_thread_ptr = (HELPER_THREAD_BLOCK *)((UINT)helper_thread_block_ptr + sizeof(HELPER_THREAD_BLOCK) * j);

            if((helper_thread_ptr -> helper_thread.tx_thread_id == 0) ||
               (helper_thread_ptr -> helper_thread.tx_thread_state == TX_COMPLETED))
            {

                if(helper_thread_ptr -> helper_thread.tx_thread_state == TX_COMPLETED)
                {
                    tx_thread_delete(&(helper_thread_ptr -> helper_thread));
                }
                status = tx_thread_create(&helper_thread_ptr -> helper_thread, "helper thread", bsd_server_helper_thread_entry, 
                                          newsock, &helper_thread_ptr -> stack_space[0], DEMO_STACK_SIZE, 2, 2, TX_NO_TIME_SLICE, TX_AUTO_START);
                if(status != TX_SUCCESS)
                    error_counter++;
                
                tx_thread_relinquish();
                break;
            }
        }
    }
    /* Close down the socket. */
    ret = soc_close(sockfd);
    if(ret < 0)
        error_counter++;

    for(i = 0; i < NUM_ITERATION; i++)
        tx_semaphore_get(&sema_0, 5 * NX_IP_PERIODIC_RATE);
}


    
/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
int iterations = 0;
int i;


    printf("NetX Test:   Basic BSD TCP Disconnect Test.................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    for(iterations = 0; iterations < NUM_ITERATION; iterations++)
    {
        test_tcp_client4();
    }

    tx_thread_resume(&ntest_2);
    tx_thread_resume(&ntest_3);
    tx_thread_resume(&ntest_4);
    tx_thread_resume(&ntest_5);

    test_tcp_server4();

    for(i = 0; i < 4; i++)
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

static NX_TCP_SOCKET tcp_sockets[4];
static void    nx_client4(int thread_input)
{
UINT          status = NX_SUCCESS;
NX_PACKET     *packet_ptr;

    status +=  nx_tcp_socket_create(&ip_1, &tcp_sockets[thread_input], "Server Socket", 
                                    NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                    NX_NULL, NX_NULL);
    status +=  nx_tcp_client_socket_bind(&tcp_sockets[thread_input], NX_ANY_PORT, 0);

    if(status != NX_SUCCESS)
        error_counter++;

    status = NX_SUCCESS;
    
    status = nx_tcp_client_socket_connect(&tcp_sockets[thread_input], IP_ADDRESS(1, 2, 3, 4), 12345, 1 * NX_IP_PERIODIC_RATE);


    if(status != NX_SUCCESS)
        error_counter++;

    status = NX_SUCCESS;

#if 0
    tx_thread_sleep(10 * NX_IP_PERIODIC_RATE);
#endif
    status += nx_packet_allocate(&pool_0, &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT);
    status += nx_packet_data_append(packet_ptr, send_buffer, strlen(send_buffer),
                                    &pool_0, NX_NO_WAIT);
    status += nx_tcp_socket_send(&tcp_sockets[thread_input], packet_ptr, NX_IP_PERIODIC_RATE);
        

    if(status != NX_SUCCESS)
        error_counter++;
#if 0
    status = NX_SUCCESS;

    status = nx_tcp_socket_receive(&tcp_sockets[thread_input], &packet_ptr, NX_IP_PERIODIC_RATE);
    if(status != NX_SUCCESS)
        error_counter++;
    /* Validate the received data. */
    else if(packet_ptr -> nx_packet_length != strlen(send_buffer))
        error_counter++;
    else if(strncmp((char*)packet_ptr -> nx_packet_prepend_ptr, send_buffer, packet_ptr -> nx_packet_length))
        error_counter++;
    nx_packet_release(packet_ptr);
#endif
    status = nx_tcp_socket_disconnect(&tcp_sockets[thread_input], 1 * NX_IP_PERIODIC_RATE);
    if(status == NX_NOT_CONNECTED || status == NX_DISCONNECT_FAILED)
        status = 0;
    
    if(tcp_sockets[thread_input].nx_tcp_socket_bound_next)
        status += nx_tcp_client_socket_unbind(&tcp_sockets[thread_input]);
    
    
    status += nx_tcp_socket_delete(&tcp_sockets[thread_input]);
    
    if(status != NX_SUCCESS)
        error_counter++;
}
static NX_TCP_SOCKET    server_socket;
static void    netx_tcp_server(void)
{

NX_PACKET       *packet_ptr;
UINT             status;
int              i;
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

    for(i = 0; i < NUM_ITERATION; i++)
    {
        tx_semaphore_put(&sema_0);

        /* Accept a client socket connection.  */
        status =  nx_tcp_server_socket_accept(&server_socket, 1 * NX_IP_PERIODIC_RATE);
        
        /* Check for error.  */
        if (status)
            error_counter++;
        
        /* Receive a TCP message from the socket.  */
        status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, 2 * NX_IP_PERIODIC_RATE);
        
        /* Check for error.  */
        if ((status) || (packet_ptr -> nx_packet_length != strlen(send_buffer)))
            error_counter++;
        else
        {
            if(memcmp(packet_ptr -> nx_packet_prepend_ptr, send_buffer, strlen(send_buffer)))
                error_counter++;
            
            nx_packet_release(packet_ptr);
        }

        /* Disconnect the server socket.  */
        status =  nx_tcp_socket_disconnect(&server_socket, 1 * NX_IP_PERIODIC_RATE);
        if(status == NX_NOT_CONNECTED || status == NX_DISCONNECT_FAILED)
            status = 0;

        /* Unaccept the server socket.  */
        status =  nx_tcp_server_socket_unaccept(&server_socket);
        
        /* Check for error.  */
        if (status)
            error_counter++;
        

        status = nx_tcp_server_socket_relisten(&ip_1, 12, &server_socket);
        if (status && (status != NX_CONNECTION_PENDING))
            error_counter++;
    }

    
    /* Setup server socket for listening again.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, 12);
    
    /* Check for error.  */
    if (status)
        error_counter++;

    nx_tcp_socket_delete(&server_socket);
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

    netx_tcp_server();

}

static void    ntest_2_entry(ULONG thread_input)
{
int             iterations = 0;

    tx_semaphore_get(&sema_1, 5 * NX_IP_PERIODIC_RATE);

    /* Simulate a multiple client conneting to the same server. */
    for(iterations = 0; iterations < (NUM_ITERATION / 4); iterations++)
        nx_client4(thread_input);

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
void    netx_bsd_tcp_disconnect_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD TCP Disconnect Test.................N/A\n"); 

    test_control_return(3);  
}      
#endif
