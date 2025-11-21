/**
 * @file sample.c
 * @brief This is a small demo of the high-performance NetX Duo TCP/IP stack.
 *        This program demonstrates link packet sending and receiving with a simulated Ethernet driver.
 *
 */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "netxtestcontrol.h"

extern void test_control_return(UINT);

#if defined(NX_ENABLE_VLAN)
#include   "nx_link.h"

#define     DEMO_STACK_SIZE 2048
#define     DEMO_DATA       "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
#define     PACKET_SIZE     1536
#define     POOL_SIZE       ((sizeof(NX_PACKET) + PACKET_SIZE) * 16)
#define     QUEUE_SIZE      1024
#define     ETHER_TYPE      0x8086
#define     VLAN_TAG        0x0001


/* Define the ThreadX and NetX object control blocks...  */

TX_THREAD               thread_0;
TX_THREAD               thread_1;
TX_THREAD               thread_2;

NX_PACKET_POOL          pool_0;
NX_IP                   ip_0;
NX_IP                   ip_1;
UCHAR                   pool_buffer[POOL_SIZE];
ULONG                   link_address_msb_0[2];
ULONG                   link_address_lsb_0[2];
ULONG                   link_address_msb_1[2];
ULONG                   link_address_lsb_1[2];
NX_LINK_RECEIVE_QUEUE   receive_queue[2];
TX_QUEUE                queue[2];



/* Define the counters used in the demo application...  */

ULONG thread_0_counter[2];
ULONG thread_1_and_2_counter[2];
ULONG error_counter;


/* Define thread prototypes.  */

void thread_0_entry(ULONG thread_input);
void thread_1_and_2_entry(ULONG thread_input);
UINT receive_callback(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                      ULONG physical_address_msw, ULONG physical_address_lsw,
                      UINT packet_type, UINT header_size, VOID *context,
                      struct NX_LINK_TIME_STRUCT *time_ptr);

void _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    test_control_return(UINT status);

static VOID    set_link_status(NX_IP *ip_ptr, UINT link_status)
{

    /* Set link status and notify IP layer. */
    ip_ptr -> nx_ip_interface[0].nx_interface_link_up = (UCHAR)link_status;
    _nx_ip_driver_link_status_event(ip_ptr, 0);
}

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ip_link_status_test2_application_define(void *first_unused_memory)
#endif
{

CHAR *pointer;
UINT  status;

    if (NX_PHYSICAL_HEADER < 20) {
        printf("NetX Test:   IP Link Status Test2.......................................N/A\n");
        test_control_return(3);
    }

    /* Setup the working pointer.  */
    pointer =  (CHAR *)first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_and_2_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_2, "thread 2", thread_1_and_2_entry, 1,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pool_buffer, POOL_SIZE);

    if (status)
    {
        error_counter++;
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFFFFUL, &pool_0,
                          _nx_ram_network_driver, pointer, DEMO_STACK_SIZE, 1);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFFFFUL, &pool_0,
                           _nx_ram_network_driver, pointer, DEMO_STACK_SIZE, 1);
    pointer =  pointer + DEMO_STACK_SIZE;

    if (status)
    {
        error_counter++;
    }

    /* Create a receive queue.  */
    status = tx_queue_create(&queue[0], "Queue 0", sizeof(NX_PACKET *) / sizeof(ULONG),
                             pointer, QUEUE_SIZE / sizeof(ULONG));
    pointer =  pointer + QUEUE_SIZE;

    /* Create another receive queue.  */
    status += tx_queue_create(&queue[1], "Queue 1", sizeof(NX_PACKET *) / sizeof(ULONG),
                              pointer, QUEUE_SIZE / sizeof(ULONG));
    pointer =  pointer + QUEUE_SIZE;

    if (status)
    {
        error_counter++;
    }
}


/* Define receive callback function.  */
UINT receive_callback(NX_IP *ip_ptr, UINT interface_index, NX_PACKET *packet_ptr,
                      ULONG physical_address_msw, ULONG physical_address_lsw,
                      UINT packet_type, UINT header_size, VOID *context,
                      struct NX_LINK_TIME_STRUCT *time_ptr)
{
    (VOID)(physical_address_msw);
    (VOID)(physical_address_lsw);
    (VOID)(context);
    (VOID)(time_ptr);

    if (packet_type == ETHER_TYPE)
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + header_size;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - header_size;

        if (tx_queue_send(&queue[interface_index], &packet_ptr, NX_NO_WAIT))
        {
            nx_packet_release(packet_ptr);
        }
        return(NX_SUCCESS);
    }
    return(NX_CONTINUE);
}

void conf_link_layer()
{
UINT  status;
UINT interface_0, interface_1;

    status = nx_link_vlan_interface_create(&ip_0, "NetX IP Interface 0:2", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFFFFUL, VLAN_TAG, 0, &interface_0);
    if (status)
    {
        error_counter++;
    }

    status = nx_link_vlan_interface_create(&ip_1, "NetX IP Interface 1:2", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFFFFUL, VLAN_TAG, 0, &interface_1);
    if (status)
    {
        error_counter++;
    }

    /* Set receive notify.  */
    status = nx_link_packet_receive_callback_add(&ip_1, 0, &receive_queue[0], ETHER_TYPE, receive_callback, NX_NULL);
    status += nx_link_packet_receive_callback_add(&ip_1, 1, &receive_queue[1],
                                                  NX_LINK_PACKET_TYPE_ALL, receive_callback, NX_NULL);

    if (status)
    {
        error_counter++;
    }
}

static VOID    link_status_change_notify(NX_IP *ip_ptr, UINT interface_index, UINT link_up)
{
}

/* Define the test threads.  */

void    thread_0_entry(ULONG thread_input)
{

UINT       status;
ULONG      actual_status;
NX_PACKET *packet_ptr;
ULONG      length;
ULONG      interface_index;
int        i;

    NX_PARAMETER_NOT_USED(thread_input);

    /* Ensure the IP instance has been initialized.  */
    nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_WAIT_FOREVER);

    conf_link_layer();
    status = nx_ip_interface_physical_address_get(&ip_0, 0, &link_address_msb_0[0], &link_address_lsb_0[0]);
    status += nx_ip_interface_physical_address_get(&ip_0, 1, &link_address_msb_0[1], &link_address_lsb_0[1]);
    status += nx_ip_interface_physical_address_get(&ip_1, 0, &link_address_msb_1[0], &link_address_lsb_1[0]);
    status += nx_ip_interface_physical_address_get(&ip_1, 1, &link_address_msb_1[1], &link_address_lsb_1[1]);

    /******************************************************/
    /* Tested the nx_ip_link_status_change_notify_set api */
    /******************************************************/

    /* Set link status change notify will NULL callback function pointer. */
    status = nx_ip_link_status_change_notify_set(&ip_0, link_status_change_notify);

    /* Check for error.  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* Loop to repeat things over and over again!  */
    for (i = 0; i < 10; i++)
    {

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            continue;
        }

        /* Write ABCs into the packet payload!  */
        nx_packet_data_append(packet_ptr, DEMO_DATA, sizeof(DEMO_DATA), &pool_0, TX_WAIT_FOREVER);

        status =  nx_packet_length_get(packet_ptr, &length);
        if ((status) || (length != sizeof(DEMO_DATA)))
        {
            error_counter++;
            continue;
        }

        /* Add link layer header.  */
        if (i % 2 == 0) {
            interface_index = 0;
        } else {
            interface_index = 1;
        }

        nx_packet_vlan_priority_set(packet_ptr, 2);
        status = nx_link_ethernet_packet_send(&ip_0, interface_index, packet_ptr,
                                              0xFFFF, 0xFFFFFFFF,
                                              ETHER_TYPE);

        /* Determine if the status is valid.  */
        if (status)
        {
            error_counter++;
            continue;
        }

        /* Increment thread 0's counter.  */
        thread_0_counter[interface_index]++;
        // printf("[%lu]: sent: %lu, received: %lu\n", interface_index, thread_0_counter[interface_index], thread_1_and_2_counter[interface_index]);
        tx_thread_sleep(1);
    }

    if ((thread_0_counter[0] != thread_1_and_2_counter[0]) ||
        (thread_0_counter[1] != thread_1_and_2_counter[1]))
    {
        error_counter++;
    }

    /* Link status change test */
    if (ip_0.nx_ip_interface[0].nx_interface_link_up != NX_TRUE) {
        error_counter++;
    }

    if (ip_0.nx_ip_interface[1].nx_interface_link_up != NX_TRUE) {
        error_counter++;
    }

    /* Simulator link down. */
    set_link_status(&ip_0, NX_FALSE);

    if (ip_0.nx_ip_interface[0].nx_interface_link_up == NX_TRUE) {
        error_counter++;
    }

    if (ip_0.nx_ip_interface[1].nx_interface_link_up == NX_TRUE) {
        error_counter++;
    }

    /*Check the status. */
    if (error_counter == 0)
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
    else
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

}

void    thread_1_and_2_entry(ULONG thread_input)
{

UINT       status;
NX_PACKET *packet_ptr;
ULONG      actual_status;

    /* Ensure the IP instance has been initialized.  */
    nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_WAIT_FOREVER);

    /* Loop to create and establish server connections.  */
    while (1)
    {

        /* Receive a link message from the socket.  */
        status = tx_queue_receive(&queue[thread_input], &packet_ptr, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }
        else
        {

            if (packet_ptr -> nx_packet_length != sizeof(DEMO_DATA))
            {
                error_counter++;
                continue;
            }

            if (memcmp(packet_ptr -> nx_packet_prepend_ptr, DEMO_DATA, sizeof(DEMO_DATA)))
            {
                error_counter++;
                continue;
            }

            /* Release the packet.  */
            nx_packet_release(packet_ptr);

            /* Increment thread 1's counter.  */
            thread_1_and_2_counter[thread_input]++;

            if(thread_1_and_2_counter[thread_input] == 5) {
                return;
            }
        }
    }
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ip_link_status_test2_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Link Status Test2.......................................N/A\n");
    test_control_return(3);
}

#endif
