/* This NetX test concentrates on the ARP conflict operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_arp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   arp_packet_received;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_packet_allocate_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    arp_packet_received = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

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

UINT    i;
UINT    status;
UINT    packet_counter;
NX_PACKET   *my_packet[10];

    printf("NetX Test:   ARP Packet Allocate Test..................................");

    /* Setup callback function. */
    advanced_packet_process_callback = my_packet_process;

    /* Loop to allocate the all packets to let _nx_packet_data_append failure in nx_ip_forward_packet_process.c  */
    packet_counter = pool_0.nx_packet_pool_available;
    for (i = 0; i < packet_counter; i++)
    {
        status = nx_packet_allocate(&pool_0, &my_packet[i], 0, NX_NO_WAIT);

        /* Check status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Check the available counter.  */
    if (pool_0.nx_packet_pool_available != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set a dynamic ARP entry.  */
    status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0, 0);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the arp_packet_received counter.  */
    if (arp_packet_received != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Loop to release all packet.  */
    for (i = 0; i < packet_counter; i++)
    {

        /* Release the packet.  */
        status = nx_packet_release(my_packet[i]);

        /* Check status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }


    /* Check the available counter.  */
    if (pool_0.nx_packet_pool_available != packet_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set a dynamic ARP entry.  */
    status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 6), 0, 0);
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the arp_packet_received counter.  */
    if (arp_packet_received != 1)
    {

        printf("ERROR!\n");
        test_control_return(1);
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
ULONG *message;

    /* Counter ARP packet only. */
    if (packet_ptr -> nx_packet_length == NX_ARP_MESSAGE_SIZE)
    {
        message = (ULONG *)packet_ptr -> nx_packet_prepend_ptr;
        NX_CHANGE_ULONG_ENDIAN(*message);
        if(*message == (ULONG)((NX_ARP_HARDWARE_TYPE << 16) | NX_ARP_PROTOCOL_TYPE))
            arp_packet_received++;
        NX_CHANGE_ULONG_ENDIAN(*message);
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_packet_allocate_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Packet Allocate Test..................................N/A\n"); 

    test_control_return(3);  
}      
#endif