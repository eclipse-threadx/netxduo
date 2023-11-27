/* This NetX test concentrates on the basic packet operations.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_packet.h"

#define     DEMO_STACK_SIZE         2048

#define     TEST_SIZE               (NX_UDP_PACKET+28)

#ifndef NX_PACKET_ALIGNMENT
#define NX_PACKET_ALIGNMENT         sizeof(ULONG)
#endif /* NX_PACKET_ALIGNMENT */

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static NX_PACKET_POOL          pool_0;


/* Define the counters used in the test application...  */

static ULONG                   error_counter; 
#if !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__)
static UCHAR                   buffer[2048];
#endif

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void  test_control_return(UINT status);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_packet_data_append_test_application_define(void *first_unused_memory)
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

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the pools again.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", TEST_SIZE, pointer, (TEST_SIZE + sizeof(NX_PACKET)) * 10); 
    pointer = pointer + ((TEST_SIZE + sizeof(NX_PACKET)) * 10);

    /* Check status  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

#if !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__)
UINT        status;
NX_PACKET   *my_packet;
#endif /* !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__) */
    
    /* Print out test information banner.  */
    printf("NetX Test:   Packet Data Append Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                                            

#if !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__) 

    /* Allocate the packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet, 0, NX_NO_WAIT);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Append data that is two packet size. */
    status = nx_packet_data_append(my_packet, buffer, TEST_SIZE * 4, &pool_0, NX_NO_WAIT);

    /* Check the status.  */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Release the packet.  */
    status = nx_packet_release(my_packet);

    /* Check the status.  */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    printf("SUCCESS!\n");
    test_control_return(0);
}

