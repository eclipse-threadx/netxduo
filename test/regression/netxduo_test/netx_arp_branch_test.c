/* This NetX test concentrates on the code coverage for ARP functions,
 *_nx_arp_static_entry_delete_internal
 *_nx_arp_interface_entries_delete
 *_nx_arp_packet_receive
 *_nx_arp_periodic_update
*/

#include "nx_arp.h"
#include "nx_api.h"
#include "tx_thread.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_ASSERT
static TX_THREAD               thread_for_assert;
#endif
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static CHAR                    *pointer;
static UINT                    arp_entries;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
#ifdef __PRODUCT_NETXDUO__
#ifndef NX_DISABLE_ASSERT
static void    thread_for_assert_entry(ULONG thread_input);
#endif
static UINT    arp_packet_allocate(NX_IP *ip_ptr, NX_PACKET **packet_ptr, UINT arp_type,
                                   ULONG source_ip, ULONG source_physical_msw, ULONG source_physical_lsw,
                                   ULONG target_ip, ULONG target_physical_msw, ULONG target_physical_lsw);
#endif


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_branch_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;

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

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 2048;
    arp_entries = 1024 / sizeof(NX_ARP);

    /* Check ARP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
#ifdef __PRODUCT_NETXDUO__
UINT        i;
ULONG       address; 
ULONG       msw;
ULONG       lsw;
NX_PACKET  *my_packet;
#endif /* __PRODUCT_NETXDUO__  */
NX_ARP      arp_entry;
NX_ARP      arp_entry_next;
NX_ARP     *arp_active_list;
ULONG       physical_msw, physical_lsw;

    /* Print out some test information banners.  */
    printf("NetX Test:   ARP Branch Test...........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef __PRODUCT_NETXDUO__

    _nx_arp_initialize();

    /* Hit false condition of if (arp_entry -> nx_arp_active_list_head) in _nx_arp_static_entry_delete_internal().  */
    nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, 7), 0x0011, 0x22334457);
    ip_0.nx_ip_arp_table[10] -> nx_arp_active_list_head = NX_NULL;
    _nx_arp_static_entry_delete_internal(&ip_0, ip_0.nx_ip_arp_table[10]);


    /* Hit condition of while (next_arp_entry) in _nx_arp_interface_entries_delete(). */
    ip_0.nx_ip_arp_static_list = &arp_entry;
    arp_entry.nx_arp_pool_previous = NX_NULL;
    arp_entry.nx_arp_pool_next = NX_NULL;
    arp_entry.nx_arp_ip_interface = NX_NULL;
    _nx_arp_interface_entries_delete(&ip_0, 0);

    /* Recover */
    ip_0.nx_ip_arp_static_list = NX_NULL;



    /* Test _nx_arp_packet_receive().  */

    /* Hit false condition (sender_ip_address == 0).
    if ((interface_ptr -> nx_interface_ip_address == 0) &&
        ((sender_ip_address == interface_ptr -> nx_interface_ip_probe_address) ||
         ((sender_ip_address == 0) && (target_ip_address == interface_ptr -> nx_interface_ip_probe_address))))
    */

    /* Clear the interface address.  */
    ip_0.nx_ip_interface[0].nx_interface_ip_address = 0;

    /* Set the probe address.  */
    ip_0.nx_ip_interface[0].nx_interface_ip_probe_address = IP_ADDRESS(1, 2, 3, 4);

    /* Allocate the packet.  */
    status = arp_packet_allocate(&ip_0, &my_packet, NX_ARP_OPTION_REQUEST, IP_ADDRESS(1, 2, 3, 5), 0x0011, 0x22334456, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the packet interface.  */
    my_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];

    /* Call _nx_arp_packet_receive.  */
    _nx_arp_packet_receive(&ip_0, my_packet);


    /* Hit false condition.
        if ((sender_physical_msw != interface_ptr -> nx_interface_physical_address_msw) ||
            (sender_physical_lsw != interface_ptr -> nx_interface_physical_address_lsw))

        if (interface_ptr -> nx_interface_ip_conflict_notify_handler)
    */

    /* Allocate ARP packet, */
    status = arp_packet_allocate(&ip_0, &my_packet, NX_ARP_OPTION_REQUEST, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the packet interface.  */
    my_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];

    /* Call _nx_arp_packet_receive.  */
    _nx_arp_packet_receive(&ip_0, my_packet);

    /* Allocate ARP packet, */
    status = arp_packet_allocate(&ip_0, &my_packet, NX_ARP_OPTION_REQUEST, IP_ADDRESS(1, 2, 3, 4), 0x0022, 0x22334456, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the packet interface.  */
    my_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];

    /* Call _nx_arp_packet_receive.  */
    _nx_arp_packet_receive(&ip_0, my_packet);

                                   
    /* Hit false condition.
        if ((sender_physical_msw != interface_ptr -> nx_interface_physical_address_msw) ||
            (sender_physical_lsw != interface_ptr -> nx_interface_physical_address_lsw))
    */

    /* Set the interface address.  */
    ip_0.nx_ip_interface[0].nx_interface_ip_address = IP_ADDRESS(1, 2, 3, 4); 

    /* Clear the probe address.  */
    ip_0.nx_ip_interface[0].nx_interface_ip_probe_address = IP_ADDRESS(0, 0, 0, 0);

    /* Allocate ARP packet, */
    status = arp_packet_allocate(&ip_0, &my_packet, NX_ARP_OPTION_REQUEST, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456, IP_ADDRESS(1, 2, 3, 5), 0x0011, 0x22334457);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the packet interface.  */
    my_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];

    /* Call _nx_arp_packet_receive.  */
    _nx_arp_packet_receive(&ip_0, my_packet);
    
    /* Allocate ARP packet, */
    status = arp_packet_allocate(&ip_0, &my_packet, NX_ARP_OPTION_REQUEST, IP_ADDRESS(1, 2, 3, 4), 0x0022, 0x22334456, IP_ADDRESS(1, 2, 3, 5), 0x0011, 0x22334457);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the packet interface.  */
    my_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];

    /* Call _nx_arp_packet_receive.  */
    _nx_arp_packet_receive(&ip_0, my_packet);

    /* Hit false condition.
        if (((ip_ptr -> nx_ip_arp_allocate)(ip_ptr, &(ip_ptr -> nx_ip_arp_table[index]), NX_FALSE)) == NX_SUCCESS)
    */

    /* Set the IP address.   */
    address = 20;

    /* Set the physical address.   */
    msw = 0x0033;
    lsw = 0x22334457;
                            
    /* Loop to added the static entries to fill the arp entries.  */
    for (i = 0; i < arp_entries; i++)
    {

        /* Set a static ARP entry.  */
        status =  nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, address), msw, lsw);
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
        else
        {
                          
            /* Update the IP address.  */
            address ++;

            /* Update the physical address.  */
            lsw ++;
        }
    }

    /* Allocate ARP packet, */
    status = arp_packet_allocate(&ip_0, &my_packet, NX_ARP_OPTION_REQUEST, IP_ADDRESS(1, 2, 3, 10), 0x0011, 0x22334458, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the packet interface.  */
    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];

    /* Call _nx_arp_packet_receive.  */
    _nx_arp_packet_receive(&ip_0, my_packet);

    /* Test packet_ptr -> nx_packet_length < NX_ARP_MESSAGE_SIZE.  */
    /* Allocate ARP packet, */
    status = arp_packet_allocate(&ip_0, &my_packet, NX_ARP_OPTION_REQUEST, IP_ADDRESS(1, 2, 3, 10), 0x0011, 0x22334458, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456);

    /* Check status.  */
    if (status != NX_TRUE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Reset the packet length.  */
    my_packet -> nx_packet_length -= 1;

    /* Call _nx_arp_packet_receive.  */
    _nx_arp_packet_receive(&ip_0, my_packet);

    /* Update the address.  */
    address --;
    lsw --;

    /* Loop to delete the static entries.  */
    for (i = 0; i < arp_entries; i++)
    {

        /* Set a static ARP entry.  */
        status =  nx_arp_static_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, address), msw, lsw);
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
        else
        {
                          
            /* Update the IP address.  */
            address --;

            /* Update the physical address.  */
            lsw --;
        }
    }



#ifndef NX_DISABLE_ASSERT
    /* Test _nx_arp_packet_send().  */
    /* Hit NX_ASSERT(nx_interface != NX_NULL);  */

    /* Create the main thread.  */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
#endif /* NX_DISABLE_ASSERT  */
#endif /* __PRODUCT_NETXDUO__  */



    /* Test _nx_arp_periodic_update().  */

#if 0
    /* Hit flase condition.
      if ((arp_entry -> nx_arp_physical_address_msw) || (arp_entry -> nx_arp_physical_address_lsw))
    */
    ip_0.nx_ip_arp_dynamic_active_count ++;
    ip_0.nx_ip_arp_dynamic_list = &arp_entry;
    arp_entry.nx_arp_entry_next_update = 1;
    arp_entry.nx_arp_physical_address_msw = 0x0000;
    arp_entry.nx_arp_physical_address_lsw = 0x22334456;
    arp_entry.nx_arp_retries = 0;
    arp_entry.nx_arp_active_list_head = NX_NULL;
    arp_entry.nx_arp_pool_next = &arp_entry;
    arp_entry.nx_arp_pool_previous = &arp_entry;
    arp_entry.nx_arp_packets_waiting = NX_NULL;
    _nx_arp_periodic_update(&ip_0);
                  
    /* Hit flase condition.
      if ((arp_entry -> nx_arp_physical_address_msw) || (arp_entry -> nx_arp_physical_address_lsw))
    */
    ip_0.nx_ip_arp_dynamic_active_count ++;
    ip_0.nx_ip_arp_dynamic_list = &arp_entry;
    arp_entry.nx_arp_entry_next_update = 1;
    arp_entry.nx_arp_physical_address_msw = 0x0011;
    arp_entry.nx_arp_physical_address_lsw = 0x00000000;
    arp_entry.nx_arp_retries = 0;
    arp_entry.nx_arp_active_list_head = NX_NULL;
    arp_entry.nx_arp_pool_next = &arp_entry;
    arp_entry.nx_arp_pool_previous = &arp_entry;
    arp_entry.nx_arp_packets_waiting = NX_NULL;
    _nx_arp_periodic_update(&ip_0);

    /* Hit flase condition.
      if ((arp_entry -> nx_arp_physical_address_msw) || (arp_entry -> nx_arp_physical_address_lsw))
    */
    ip_0.nx_ip_arp_dynamic_active_count ++;
    ip_0.nx_ip_arp_dynamic_list = &arp_entry;
    arp_entry.nx_arp_entry_next_update = 1;
    arp_entry.nx_arp_physical_address_msw = 0x0000;
    arp_entry.nx_arp_physical_address_lsw = 0x00000000;
    arp_entry.nx_arp_retries = 0;
    arp_entry.nx_arp_active_list_head = NX_NULL;
    arp_entry.nx_arp_pool_next = &arp_entry;
    arp_entry.nx_arp_pool_previous = &arp_entry;
    arp_entry.nx_arp_packets_waiting = NX_NULL;
    arp_entry.nx_arp_ip_address = IP_ADDRESS(1, 2, 3, 10);
    arp_entry.nx_arp_ip_interface = &ip_0.nx_ip_interface[0];
    _nx_arp_periodic_update(&ip_0);
#endif

    /* Hit flase condition.
      if ((arp_entry -> nx_arp_physical_address_msw) || (arp_entry -> nx_arp_physical_address_lsw))

      if (arp_entry -> nx_arp_active_list_head)

      if (arp_entry != arp_entry -> nx_arp_pool_next)
    */
    ip_0.nx_ip_arp_dynamic_active_count ++;
    ip_0.nx_ip_arp_dynamic_list = &arp_entry;
    arp_entry.nx_arp_entry_next_update = 1;
    arp_entry.nx_arp_physical_address_msw = 0;
    arp_entry.nx_arp_physical_address_lsw = 0;
    arp_entry.nx_arp_retries = NX_ARP_MAXIMUM_RETRIES;
    arp_entry.nx_arp_active_list_head = NX_NULL;
    arp_entry.nx_arp_pool_next = &arp_entry;
    arp_entry.nx_arp_pool_previous = &arp_entry;
    arp_entry.nx_arp_packets_waiting = NX_NULL;
    _nx_arp_periodic_update(&ip_0);


    /* Hit flase condition.
      if (*(arp_entry -> nx_arp_active_list_head) == arp_entry)
    */
    arp_active_list = &arp_entry_next;
    ip_0.nx_ip_arp_dynamic_active_count ++;
    ip_0.nx_ip_arp_dynamic_list = &arp_entry;
    arp_entry.nx_arp_entry_next_update = 1;
    arp_entry.nx_arp_physical_address_msw = 0;
    arp_entry.nx_arp_physical_address_lsw = 0;
    arp_entry.nx_arp_retries = NX_ARP_MAXIMUM_RETRIES;
    arp_entry.nx_arp_active_list_head = &arp_active_list;
    arp_entry.nx_arp_active_next = arp_active_list;
    arp_entry.nx_arp_active_previous = &arp_entry;
    arp_entry.nx_arp_packets_waiting = NX_NULL;  
    arp_active_list -> nx_arp_active_next  = &arp_entry;
    _nx_arp_periodic_update(&ip_0);



#ifdef __PRODUCT_NETXDUO__
    /* Test _nx_arp_static_entry_create */
    /* Hit false condition if (ip_ptr -> nx_ip_arp_dynamic_list == arp_ptr)  */
    _nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer += 1024;
    status = nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 29), 0x0011, 0x22334478);  /* arp index: 0  */

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 61), 0x0011, 0x22334488); /* arp index: 0  */

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 62), 0x0011, 0x22334499); /* arp index: 1  */

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    _nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, 61), 0x0011, 0x22334488);

    /* Recover, delete the arp entry.  */
    status = nx_arp_dynamic_entries_invalidate(&ip_0);
    
    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_arp_static_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, 61), 0x0011, 0x22334488);

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif


    /* Test _nx_arp_hardware_address_find */
    /* Hit false condition (arp_entry -> nx_arp_physical_address_msw | arp_entry -> nx_arp_physical_address_lsw)) for static arp list  */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, 61), 0x0011, 0x22334488);

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 61), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x0011) || (physical_lsw != 0x22334488))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Clear the MAC address.  */
    ip_0.nx_ip_arp_static_list -> nx_arp_physical_address_msw = 0x0000;
    ip_0.nx_ip_arp_static_list -> nx_arp_physical_address_lsw = 0x22334488;

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 61), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x0000) || (physical_lsw != 0x22334488))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /* Clear the MAC address.  */
    ip_0.nx_ip_arp_static_list -> nx_arp_physical_address_msw = 0x0011;
    ip_0.nx_ip_arp_static_list -> nx_arp_physical_address_lsw = 0x00000000;

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 61), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x0011) || (physical_lsw != 0x00000000))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /* Clear the MAC address.  */
    ip_0.nx_ip_arp_static_list -> nx_arp_physical_address_msw = 0x0000;
    ip_0.nx_ip_arp_static_list -> nx_arp_physical_address_lsw = 0x22334488;

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 61), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x0000) || (physical_lsw != 0x22334488))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Clear the MAC address.  */
    ip_0.nx_ip_arp_static_list -> nx_arp_physical_address_msw = 0x0000;
    ip_0.nx_ip_arp_static_list -> nx_arp_physical_address_lsw = 0x00000000;

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 61), &physical_msw, &physical_lsw);
    if (status != NX_ENTRY_NOT_FOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Recover the MAC address.  */
    ip_0.nx_ip_arp_static_list -> nx_arp_physical_address_msw = 0x0011;
    ip_0.nx_ip_arp_static_list -> nx_arp_physical_address_lsw = 0x22334488;

    status = nx_arp_static_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, 61), 0x0011, 0x22334488);

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Hit false condition (arp_entry -> nx_arp_physical_address_msw | arp_entry -> nx_arp_physical_address_lsw)) for dynamic arp list */
    status = nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 61), 0x0011, 0x22334488);

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 61), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x0011) || (physical_lsw != 0x22334488))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Clear the MAC address.  */
    ip_0.nx_ip_arp_dynamic_list -> nx_arp_physical_address_msw = 0x0000;
    ip_0.nx_ip_arp_dynamic_list -> nx_arp_physical_address_lsw = 0x22334488;

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 61), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x0000) || (physical_lsw != 0x22334488))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /* Clear the MAC address.  */
    ip_0.nx_ip_arp_dynamic_list -> nx_arp_physical_address_msw = 0x0011;
    ip_0.nx_ip_arp_dynamic_list -> nx_arp_physical_address_lsw = 0x00000000;

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 61), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x0011) || (physical_lsw != 0x00000000))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
       
    /* Clear the MAC address.  */
    ip_0.nx_ip_arp_dynamic_list -> nx_arp_physical_address_msw = 0x0000;
    ip_0.nx_ip_arp_dynamic_list -> nx_arp_physical_address_lsw = 0x22334488;

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 61), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x0000) || (physical_lsw != 0x22334488))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Clear the MAC address.  */
    ip_0.nx_ip_arp_dynamic_list -> nx_arp_physical_address_msw = 0x0000;
    ip_0.nx_ip_arp_dynamic_list -> nx_arp_physical_address_lsw = 0x00000000;

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 61), &physical_msw, &physical_lsw);
    if (status != NX_ENTRY_NOT_FOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Recover the MAC address.  */
    ip_0.nx_ip_arp_dynamic_list -> nx_arp_physical_address_msw = 0x0011;
    ip_0.nx_ip_arp_dynamic_list -> nx_arp_physical_address_lsw = 0x22334488;

    status = nx_arp_dynamic_entries_invalidate(&ip_0);  

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }



#ifdef __PRODUCT_NETXDUO__
    /* Test _nx_arp_static_entry_create()  */
    /* Hit condition of if (arp_ptr -> nx_arp_route_static == NX_FALSE)  */
    status = nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 61), 0x0011, 0x22334488);

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }    
    
    /* Create static entry.  */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, 61), 0x0011, 0x22334488);

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Create static entry.  */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, 61), 0x0011, 0x22334488);

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
               
    /* Recover, delete the ARP entry.  */
    status = nx_arp_static_entry_delete(&ip_0, IP_ADDRESS(1, 2, 3, 61), 0x0011, 0x22334488);

    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif


    /* Check status.  */
    if (status) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

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


#ifdef __PRODUCT_NETXDUO__
UINT  arp_packet_allocate(NX_IP *ip_ptr, NX_PACKET **packet_ptr, UINT arp_type,  
                          ULONG source_ip, ULONG source_physical_msw, ULONG source_physical_lsw, 
                          ULONG target_ip, ULONG target_physical_msw, ULONG target_physical_lsw)
{

NX_PACKET       *request_ptr;
ULONG           *message_ptr;


    /* Allocate a packet to build the ARP message in.  */
    if (nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &request_ptr, NX_PHYSICAL_HEADER, NX_NO_WAIT))
    {

        /* Error getting packet, so just get out!  */
        return (NX_FALSE);
    }

    /* Build the ARP request packet.  */
    
    /* Setup the size of the ARP message.  */
    request_ptr -> nx_packet_length =  NX_ARP_MESSAGE_SIZE;

    /* Setup the append pointer to the end of the message.  */
    request_ptr -> nx_packet_append_ptr =  request_ptr -> nx_packet_prepend_ptr + NX_ARP_MESSAGE_SIZE;

    /* Setup the pointer to the message area.  */
    message_ptr =  (ULONG *) request_ptr -> nx_packet_prepend_ptr;

    /* Write the Hardware type into the message.  */
    *message_ptr =      (ULONG) (NX_ARP_HARDWARE_TYPE << 16) | (NX_ARP_PROTOCOL_TYPE);
    *(message_ptr+1) =  (ULONG) (NX_ARP_HARDWARE_SIZE << 24) | (NX_ARP_PROTOCOL_SIZE << 16) | arp_type;
    *(message_ptr+2) =  (ULONG) (source_physical_msw << 16) | (source_physical_lsw >> 16);
    *(message_ptr+3) =  (ULONG) (source_physical_lsw << 16) | (source_ip >> 16);
    *(message_ptr+4) =  (ULONG) (source_ip << 16) | (target_physical_msw & 0xFFFF);
    *(message_ptr+5) =  (ULONG) target_physical_lsw;
    *(message_ptr+6) =  (ULONG) target_ip;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+1));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+2));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+3));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+4));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+5));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+6));

    /* Return packet.  */
    *packet_ptr = request_ptr;

    return (NX_TRUE);
}

#ifndef NX_DISABLE_ASSERT
/* Define the test threads.  */

static void    thread_for_assert_entry(ULONG thread_input)
{

    /* Call function with NULL interface.  */
    _nx_arp_packet_send(&ip_0, IP_ADDRESS(1, 2, 3, 5), NX_NULL);
}
#endif /* NX_DISABLE_ASSERT  */

#endif /* __PRODUCT_NETXDUO__  */
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_branch_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Branch Test...........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
