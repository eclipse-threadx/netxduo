/* This NetX test concentrates on the BSD select spurious event bug (Issue #366).  */

#include   "tx_api.h"
#include   "nx_api.h"
#if defined(NX_BSD_ENABLE) && !defined(NX_DISABLE_IPV4)
#include   "nxd_bsd.h"
#define     DEMO_STACK_SIZE         4096

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
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

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_select_spurious_event_test_application_define(void *first_unused_memory)
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
int sockfd1, sockfd2, nfd;
struct timeval tv;
fd_set readfd, exceptfd;
int n;
char buffer[20];

    printf("NetX Test:   BSD Select Spurious Event Test................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Open two UDP sockets. */
    sockfd1 = socket(AF_INET, SOCK_DGRAM, 0);
    sockfd2 = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd1 < 0 || sockfd2 < 0)
        error_counter++;

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(12345);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(sockfd1, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0)
        error_counter++;

    local_addr.sin_port = htons(12346);
    if(bind(sockfd2, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0)
        error_counter++;

    /* Tell thread 1 we are ready. */
    tx_semaphore_put(&sema_1);

    /* Prepare select. */
    FD_ZERO(&readfd);
    FD_ZERO(&exceptfd);
    FD_SET(sockfd1, &readfd);
    FD_SET(sockfd1, &exceptfd);
    FD_SET(sockfd2, &readfd);
    FD_SET(sockfd2, &exceptfd);

    nfd = (sockfd1 > sockfd2 ? sockfd1 : sockfd2) + 1;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    /* Wait for a packet on either socket. Thread 1 will send to sockfd1. */
    n = select(nfd, &readfd, NULL, &exceptfd, &tv);

    /* We expect exactly 1 event (READ on sockfd1). */
    if (n != 1)
    {
        error_counter++;
    }

    /* Check if sockfd1 has READ set. */
    if (!FD_ISSET(sockfd1, &readfd))
    {
        error_counter++;
    }

    /* Check if sockfd1 has EXCEPTION set (it SHOULD NOT). */
    if (FD_ISSET(sockfd1, &exceptfd))
    {
        error_counter++;
    }

    /* Check if sockfd2 has READ set (it SHOULD NOT). */
    if (FD_ISSET(sockfd2, &readfd))
    {
        error_counter++;
    }

    /* Check if sockfd2 has EXCEPTION set (it SHOULD NOT). 
       This was the specific failure in Issue #366. */
    if (FD_ISSET(sockfd2, &exceptfd))
    {
        error_counter++;
    }

    if (n == 1 && FD_ISSET(sockfd1, &readfd))
    {
        /* Consume the packet. */
        recv(sockfd1, buffer, sizeof(buffer), 0);
    }

    soc_close(sockfd1);
    soc_close(sockfd2);

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
NX_UDP_SOCKET   udp_socket;

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, 1 * NX_IP_PERIODIC_RATE);
    if (status != NX_SUCCESS)
    {
        test_control_return(3);
    }

    /* Create a socket.  */
    status =  nx_udp_socket_create(&ip_1, &udp_socket, "Sender Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 10);
    if (status)
        error_counter++;

    status = nx_udp_socket_bind(&udp_socket, NX_ANY_PORT, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Wait for thread 0 to be ready. */
    tx_semaphore_get(&sema_1, 5 * NX_IP_PERIODIC_RATE);

    /* Small delay to ensure thread 0 is in select(). */
    tx_thread_sleep(NX_IP_PERIODIC_RATE / 2);

    /* Allocate a packet. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    memcpy(packet_ptr -> nx_packet_prepend_ptr, "Hello", 5);
    packet_ptr -> nx_packet_length = 5;
    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + 5;

    /* Send to sockfd1 (port 12345). */
    status =  nx_udp_socket_send(&udp_socket, packet_ptr, IP_ADDRESS(1,2,3,4), 12345);
    if(status)
        error_counter++;

    nx_udp_socket_delete(&udp_socket);
}

#else
extern void       test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_bsd_select_spurious_event_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   BSD Select Spurious Event Test................N/A\n"); 
    test_control_return(3);  
}      
#endif
