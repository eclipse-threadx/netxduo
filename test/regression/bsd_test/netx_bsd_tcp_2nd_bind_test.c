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

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
#define BSD_THREAD_PRIORITY    2

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
#define PACKET_SIZE        256
#define PACKET_POOL_SIZE ((PACKET_SIZE + sizeof(NX_PACKET)) * 2)


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    validate_bsd_structure(void);
extern NX_BSD_SOCKET  nx_bsd_socket_array[NX_BSD_MAX_SOCKETS];

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_tcp_2nd_bind_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pointer, PACKET_POOL_SIZE);
    if (status)
        error_counter++;
    
    pointer += PACKET_POOL_SIZE;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    if (status)
        error_counter++;

    /* Increment the free memory pointer. */
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    if (status)
        error_counter++;

    /* Increment the free memory pointer. */
    pointer = pointer + 1024;

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    if (status)
        error_counter++;

    /* Enable BSD */
    status = bsd_initialize(&ip_0, &pool_0, pointer, DEMO_STACK_SIZE, BSD_THREAD_PRIORITY);
    /* Check TCP enable status.  */
    if (status)
        error_counter++;

    pointer += DEMO_STACK_SIZE;

}


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
int                sockfd1;
int                sockfd2;

struct sockaddr_in local_addr;

int                ret;


    printf("NetX Test:   Basic BSD TCP 2nd Bind Test...................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the first socket. */
    sockfd1 = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd1 < 0)
        error_counter++;
    
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd1, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret < 0)
        error_counter++;

    /* Bind the 2nd socket to the same port. */
    sockfd2 = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd2 < 0)
        error_counter++;
    
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sockfd2, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if(ret >= 0)
        error_counter++;
    else if(errno != EADDRINUSE)
        error_counter++;

    ret = soc_close(sockfd1);
    ret += soc_close(sockfd2);
    
    if(ret)
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
void    netx_bsd_tcp_2nd_bind_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Basic BSD TCP 2nd Bind Test...................N/A\n"); 

    test_control_return(3);  
}      
#endif