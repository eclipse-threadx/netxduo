/* This NetX test concentrates on the code coverage for packet functions,
 * _nx_packet_transmit_release.c
 * _nx_packet_release.c
 * _nx_packet_pool_cleanup.c
*/

#include "nx_api.h"
#include "tx_thread.h"
#include "nx_packet.h"
#include "nx_ip.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_test1;
static TX_THREAD               thread_test2;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

static UCHAR                   buffer[256];


/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static VOID    suspend_cleanup(TX_THREAD *thread_ptr NX_CLEANUP_PARAMETER);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_packet_branch_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable UDP processing for IP instance.  */
    status =  nx_udp_enable(&ip_0);

    /* Check UDP enable status.  */
    if (status)
        error_counter++;

    /* Enable TCP processing for IP instance.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

ULONG       thread_state;
NX_PACKET  *my_packet[2];

    /* Print out some test information banners.  */
    printf("NetX Test:   Packet Branch Test........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }      


#ifdef __PRODUCT_NETXDUO__
    /* Test _nx_packet_data_adjust() */
    /* header size (512) is larger than the payload size (256). */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    if (_nx_packet_data_adjust(my_packet[0], 512) == NX_SUCCESS)
    {
        error_counter++;
    }
    nx_packet_release(my_packet[0]);

#ifndef NX_DISABLE_PACKET_CHAIN
    /* header size (255) is odd and larger than the available size of the first packet. */
    nx_packet_allocate(&pool_0, &my_packet[0], 128, NX_NO_WAIT);
    nx_packet_data_append(my_packet[0], buffer, sizeof(buffer), &pool_0, NX_NO_WAIT);
    if (_nx_packet_data_adjust(my_packet[0], 255) == NX_SUCCESS)
    {
        error_counter++;
    }
    nx_packet_release(my_packet[0]);

    /* Adjust packet with packet chain. */
    nx_packet_allocate(&pool_0, &my_packet[0], 128, NX_NO_WAIT);
    nx_packet_data_append(my_packet[0], buffer, sizeof(buffer), &pool_0, NX_NO_WAIT);
    if (_nx_packet_data_adjust(my_packet[0], 256) != NX_SUCCESS)
    {
        error_counter++;
    }
    nx_packet_release(my_packet[0]);
#endif /* NX_DISABLE_PACKET_CHAIN */
#endif /* __PRODUCT_NETXDUO__ */


    /* Allocate the packet.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);

    /* Release the packet.  */
    _nx_packet_transmit_release(my_packet[0]);

    /* Release the packet again.  */
    _nx_packet_transmit_release(my_packet[0]);



#ifdef __PRODUCT_NETXDUO__
    /* Hit condition of if ((pool_ptr) && (pool_ptr -> nx_packet_pool_id == NX_PACKET_POOL_ID)) in _nx_packet_release().  */
    /* Allocate the packet.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_allocate(&pool_0, &my_packet[1], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ENQUEUED;
    my_packet[0] -> nx_packet_pool_owner -> nx_packet_pool_id = 0;
    _nx_packet_release(my_packet[0]);
#ifndef NX_DISABLE_PACKET_CHAIN                  
    my_packet[0] -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
    my_packet[0] -> nx_packet_next = my_packet[1];
    my_packet[1] -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ENQUEUED;
    my_packet[1] -> nx_packet_pool_owner = NX_NULL;
    _nx_packet_release(my_packet[0]);

    /* Recover.  */
    my_packet[0] -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
    my_packet[0] -> nx_packet_pool_owner = &pool_0;
    my_packet[0] -> nx_packet_pool_owner -> nx_packet_pool_id = NX_PACKET_POOL_ID;
    my_packet[0] -> nx_packet_next = NX_NULL; 
    my_packet[1] -> nx_packet_pool_owner = &pool_0;
#else

    /* Recover.  */
    my_packet[0] -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
    my_packet[0] -> nx_packet_pool_owner = &pool_0;
    my_packet[0] -> nx_packet_pool_owner -> nx_packet_pool_id = NX_PACKET_POOL_ID; 
#endif      
    _nx_packet_release(my_packet[0]);  
    _nx_packet_release(my_packet[1]);
#endif /* __PRODUCT_NETXDUO__  */



    /* Test _nx_packet_pool_cleanup().  */
    /* tx_thread_suspend_control_block is set to NULL. */
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    _nx_packet_pool_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* tx_thread_suspend_control_block is set to POOL but tx_thread_suspend_cleanup is set to NULL. */
    tx_thread_identify() -> tx_thread_suspend_control_block = &pool_0;
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    _nx_packet_pool_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* tx_thread_suspend_control_block is set to IP and tx_thread_suspend_cleanup is set to suspend_cleanup, but clear the IP ID. */
    tx_thread_identify() -> tx_thread_suspend_control_block = &pool_0;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    pool_0.nx_packet_pool_id = 0;
    _nx_packet_pool_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    pool_0.nx_packet_pool_id = NX_PACKET_POOL_ID;
    
    pool_0.nx_packet_pool_suspended_count ++;        
    tx_thread_identify() -> tx_thread_suspend_control_block = &pool_0;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspended_next = tx_thread_identify();
    thread_state = tx_thread_identify() -> tx_thread_state;
    tx_thread_identify() -> tx_thread_state = 0;
    _nx_packet_pool_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    tx_thread_identify() -> tx_thread_state = thread_state;
    
    pool_0.nx_packet_pool_suspended_count ++;               
    tx_thread_identify() -> tx_thread_suspend_control_block = &pool_0;
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspended_next = &thread_test1;
    tx_thread_identify() -> tx_thread_suspended_previous = &thread_test2;
    thread_state = tx_thread_identify() -> tx_thread_state;
    tx_thread_identify() -> tx_thread_state = 0;
    _nx_packet_pool_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    tx_thread_identify() -> tx_thread_state = thread_state;

    /* Check status.  */
    if (error_counter) 
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

static VOID    suspend_cleanup(TX_THREAD *thread_ptr NX_CLEANUP_PARAMETER)
{
}

