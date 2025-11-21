/* This NetX test concentrates on the packet suspension operations.  */

#include   "tx_api.h"
#include   "nx_api.h"

#define     DEMO_STACK_SIZE         2048

#ifndef NX_PACKET_ALIGNMENT
#define NX_PACKET_ALIGNMENT         sizeof(ULONG)
#endif /* NX_PACKET_ALIGNMENT */

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;   
static TX_THREAD               ntest_2;

static NX_PACKET_POOL          pool_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   ntest_1_counter;    
static ULONG                   ntest_2_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);  
static void    ntest_2_entry(ULONG thread_input);
extern void    test_control_return(UINT status);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_packet_suspension_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    ntest_1_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create another thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;    

    /* Create another thread.  */
    tx_thread_create(&ntest_2, "thread 2", ntest_2_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Align the starting address. */
    pointer = (CHAR *)(((ALIGN_TYPE)pointer + NX_PACKET_ALIGNMENT - 1) / NX_PACKET_ALIGNMENT * NX_PACKET_ALIGNMENT);

    /* Create first packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", NX_UDP_PACKET, pointer, 
                                    ((NX_UDP_PACKET + sizeof(NX_PACKET) + NX_PACKET_ALIGNMENT - 1) & ~(NX_PACKET_ALIGNMENT - 1)) * 3);
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet1;
NX_PACKET   *my_packet2;
NX_PACKET   *my_packet3;
ULONG       total_packets, free_packets, empty_pool_requests, empty_pool_suspensions, invalid_packet_releases;
    

    /* Print out test information banner.  */
    printf("NetX Test:   Packet Suspension Processing Test.........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate the three packets to ensure the other thread will suspend.  */
    status =   nx_packet_allocate(&pool_0, &my_packet1, NX_UDP_PACKET, NX_IP_PERIODIC_RATE/10);
    status +=  nx_packet_allocate(&pool_0, &my_packet2, NX_UDP_PACKET, NX_IP_PERIODIC_RATE/10);
    status +=  nx_packet_allocate(&pool_0, &my_packet3, NX_UDP_PACKET, NX_IP_PERIODIC_RATE/10);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Suspend for 1 second ticks to let the other thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Ensure the other thread is where it is supposed to be.  */
    if (ntest_1_counter != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release a packet, which should cause the other thread to resume.  */
    status =  nx_packet_release(my_packet1);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release a packet, which should cause the other thread to resume.  */
    status =  nx_packet_release(my_packet3);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Relinquish to the other thread so it can complete.  */
    tx_thread_relinquish();                                       

    /* Get information about the pool.  */
    status +=  nx_packet_pool_info_get(&pool_0, &total_packets, &free_packets, &empty_pool_requests, &empty_pool_suspensions, &invalid_packet_releases);

#ifndef NX_DISABLE_PACKET_INFO

    if((empty_pool_requests != 4) || (empty_pool_suspensions != 4))
        status++;
#endif

    /* Check status.  */
    if ((status) || (total_packets != 3) || (free_packets != 0) || (invalid_packet_releases) || (ntest_1_counter != 2) || (ntest_2_counter != 2) || (error_counter))
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

UINT        status;
NX_PACKET   *my_packet1;


    /* Set the counter to zero!  */
    ntest_1_counter =  0;

    /* Attempt to allocate a packet with a timeout.  */
    status =  nx_packet_allocate(&pool_0, &my_packet1, NX_UDP_PACKET, NX_IP_PERIODIC_RATE/10);

    /* Determine if we received a timeout error.  */
    if (status != NX_NO_PACKET)
        error_counter++;

    /* Increment counter.  */
    ntest_1_counter++;            

    /* Allocate packet again.  */
    status =  nx_packet_allocate(&pool_0, &my_packet1, NX_UDP_PACKET, NX_WAIT_FOREVER);

    /* Determine if we received a timeout error.  */
    if (status)
        error_counter++;

    /* Increment counter.  */
    ntest_1_counter++;
}                                   

static void    ntest_2_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet1;


    /* Set the counter to zero!  */
    ntest_2_counter =  0;

    /* Attempt to allocate a packet with a timeout.  */
    status =  nx_packet_allocate(&pool_0, &my_packet1, NX_UDP_PACKET, NX_IP_PERIODIC_RATE/10);

    /* Determine if we received a timeout error.  */
    if (status != NX_NO_PACKET)
        error_counter++;

    /* Increment counter.  */
    ntest_2_counter++;

    /* Allocate packet again.  */
    status =  nx_packet_allocate(&pool_0, &my_packet1, NX_UDP_PACKET, NX_WAIT_FOREVER);

    /* Determine if we received a timeout error.  */
    if (status)
        error_counter++;

    /* Increment counter.  */
    ntest_2_counter++;
}
