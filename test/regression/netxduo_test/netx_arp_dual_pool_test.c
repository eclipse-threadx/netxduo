/* This NetX test concentrates on the ARP packets from dual pool.  */

#include   "nx_api.h"
#include   "nx_arp.h"

extern void    test_control_return(UINT status);

#if defined(NX_ENABLE_DUAL_PACKET_POOL) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_PACKET_POOL          pool_1;
static NX_IP                   ip_0;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   arp_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_dual_pool_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    arp_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 512 + sizeof(NX_PACKET));
    pointer = pointer + 512 + sizeof(NX_PACKET);

    if (status)
        error_counter++;

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_1, "NetX Main Packet Pool", 256, pointer, 256 + sizeof(NX_PACKET));
    pointer = pointer + 256 + sizeof(NX_PACKET);

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *packet_ptr;

    /* Print out some test information banners.  */
    printf("NetX Test:   ARP Dual Pool Test........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Deal the packet with my routing.  */
    advanced_packet_process_callback = my_packet_process;

    /* Send a gratuitous ARP message.  */
    nx_arp_gratuitous_send(&ip_0, NX_NULL);

    /* Check the arp_counter.  */
    if (arp_counter != 1)
    {
        error_counter++;
    }

    /* Allocate the only one packet from default packet pool. */
    status = nx_packet_allocate(&pool_0, &packet_ptr, 0, NX_NO_WAIT);
    if (status)
    {
        error_counter++;
    }

    /* Send a gratuitous ARP message.  */
    nx_arp_gratuitous_send(&ip_0, NX_NULL);

    /* Check the arp_counter.  */
    if (arp_counter != 1)
    {
        error_counter++;
    }

    /* Now set dual packet pool. */
    status = nx_ip_auxiliary_packet_pool_set(&ip_0, &pool_1);
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Send a gratuitous ARP message.  */
    nx_arp_gratuitous_send(&ip_0, NX_NULL);

    /* Check the arp_counter.  */
    if (arp_counter != 2)
    {
        error_counter++;
    }

    /* Allocate the only one packet from default packet pool. */
    status = nx_packet_allocate(&pool_1, &packet_ptr, 0, NX_NO_WAIT);
    if (status)
    {
        error_counter++;
    }

    /* Send a gratuitous ARP message.  */
    nx_arp_gratuitous_send(&ip_0, NX_NULL);

    /* Check the arp_counter.  */
    if (arp_counter != 2)
    {
        error_counter++;
    }

    /* Determine if the test was successful.  */
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

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

    /* Check the packet length.  */
    if (packet_ptr ->nx_packet_length == NX_ARP_MESSAGE_SIZE)
    {

        /* Update the arp_counter.  */
        arp_counter++;
    }

    /* Return to caller.  */
    return NX_TRUE;
}
#else /* NX_ENABLE_DUAL_PACKET_POOL */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_dual_pool_test_application_define(void *first_unused_memory)
#endif
{   

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Dual Pool Test........................................N/A\n");

    test_control_return(3);

}
#endif /* NX_ENABLE_DUAL_PACKET_POOL */
