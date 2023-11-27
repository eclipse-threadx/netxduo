/* This NetX test concentrates on the ARP conflict operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_arp.h"

#define     DEMO_STACK_SIZE         2048

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4) && !defined(NX_ARP_DEFEND_BY_REPLY)

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   arp_packet_received;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern VOID    _nx_arp_packet_send(NX_IP *ip_ptr, ULONG destination_ip, NX_INTERFACE *nx_interface);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_conflict_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
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
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

    printf("NetX Test:   ARP Conflict Test.........................................");

    /* Setup callback function. */
    advanced_packet_process_callback = my_packet_process;

    /* Send conflict ARP packet.  */
    _nx_arp_packet_send(&ip_0, IP_ADDRESS(1, 2, 3, 4), &ip_0.nx_ip_interface[0]);

    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Three packets: one sent by this thread, one sent by ip_1 and one sent by ip_0. */
    if(arp_packet_received != 3)
        error_counter++;

    /* Send conflict ARP packet in 10 seconds.  */
    _nx_arp_packet_send(&ip_0, IP_ADDRESS(1, 2, 3, 4), &ip_0.nx_ip_interface[0]);

    /* Only more packet sent by this thread. */
    if(arp_packet_received != 4)
        error_counter++;

    tx_thread_sleep(10 * NX_IP_PERIODIC_RATE);

    /* Send conflict ARP packet after 10 seconds.  */
    _nx_arp_packet_send(&ip_0, IP_ADDRESS(1, 2, 3, 4), &ip_0.nx_ip_interface[0]);

    /* Three more packets: one sent by this thread, one sent by ip_1 and one sent by ip_0. */
    if(arp_packet_received != 7)
        error_counter++;

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
void    netx_arp_conflict_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Conflict Test.........................................N/A\n"); 

    test_control_return(3);  
}      
#endif

