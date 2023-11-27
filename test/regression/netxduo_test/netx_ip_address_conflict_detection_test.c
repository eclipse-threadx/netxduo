/* This NetX test concentrates on the IPv4 Address Conflict Detection.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_arp.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048

/* Define the timing and retry constants for ARP probe and announce.  */

#define NX_ARP_PROBE_WAIT               1
#define NX_ARP_PROBE_NUM                3
#define NX_ARP_PROBE_MIN                1
#define NX_ARP_PROBE_MAX                2
#define NX_ARP_ANNOUNCE_WAIT            2
#define NX_ARP_ANNOUNCE_NUM             2
#define NX_ARP_ANNOUNCE_INTERVAL        2

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   probe_counter;
static ULONG                   announce_counter;
static ULONG                   conflict_counter;
static ULONG                   gratuitous_responder_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    ip_address_conflict_detection(NX_IP *ip_ptr, UINT interface_index, ULONG ip_address, ULONG msw, ULONG lsw);
static void    gratuitous_responder_handler(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_address_conflict_detection_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;
    probe_counter = 0;
    announce_counter = 0;
    conflict_counter = 0;
    gratuitous_responder_counter = 0;

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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
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
UINT        packet_counter;
UINT        i;
ULONG       delay;
NX_PACKET   *my_packet[30];


    /* Print out some test information banners.  */
    printf("NetX Test:   IP Address Conflict Detection Test........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Deal the packet with my routing.  */
    advanced_packet_process_callback = my_packet_process;

    /* Set the IP address conflict callback function for probing.  */
    ip_0.nx_ip_interface[0].nx_interface_ip_conflict_notify_handler = ip_address_conflict_detection;

    /* Allocate all packet from packet pool.  */
    packet_counter = pool_0.nx_packet_pool_available;
    for(i =0; i < packet_counter; i ++)
    {

        /* Allocate the packet.  */
        status = nx_packet_allocate(&pool_0, &my_packet[i], NX_TCP_PACKET, NX_NO_WAIT);

        /* Check status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Call to send ARP Probe.  */
    status = _nx_arp_probe_send(&ip_0, 0, IP_ADDRESS(1, 2, 3, 4));

    /* Check status.  */
    if (status != NX_NO_PACKET)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release all allocated packet.  */
    for(i =0; i < packet_counter; i ++)
    {

        /* Allocate the packet.  */
        status = nx_packet_release(my_packet[i]);

        /* Check status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Delay before probing.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE * NX_ARP_PROBE_WAIT);

    /* Loop to probe for the specified local IP address according to RFC5227.  */
    for (i = 0; i < NX_ARP_PROBE_NUM; i++)
    {

        /* Send the ARP probe.  */
        _nx_arp_probe_send(&ip_0, 0, IP_ADDRESS(1, 2, 3, 4));

        /* Calculate the delay time.  */
        delay =  ((ULONG) NX_RAND()) % (NX_IP_PERIODIC_RATE * NX_ARP_PROBE_MAX);

        /* Determine if this is less than the minimum.  */
        if (delay < (NX_IP_PERIODIC_RATE * NX_ARP_PROBE_MIN))
        {

            /* Set the delay to the minimum.  */
            delay =  (NX_IP_PERIODIC_RATE * NX_ARP_PROBE_MIN);
        }

        /* Sleep for a small period of time.  */
        tx_thread_sleep(delay);
    }

    /* Check the probe counter.  */
    if ((probe_counter != 3) || (conflict_counter != 1))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Change new address and start probing.  */

    /* Delay before probing.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE * NX_ARP_PROBE_WAIT);

    /* Loop to probe for the specified local IP address according to RFC5227.  */
    for (i = 0; i < NX_ARP_PROBE_NUM; i++)
    {

        /* Send the ARP probe.  */
        _nx_arp_probe_send(&ip_0, 0, IP_ADDRESS(1, 2, 3, 5));

        /* Calculate the delay time.  */
        delay =  ((ULONG) NX_RAND()) % (NX_IP_PERIODIC_RATE * NX_ARP_PROBE_MAX);

        /* Determine if this is less than the minimum.  */
        if (delay < (NX_IP_PERIODIC_RATE * NX_ARP_PROBE_MIN))
        {

            /* Set the delay to the minimum.  */
            delay =  (NX_IP_PERIODIC_RATE * NX_ARP_PROBE_MIN);
        }
        
        /* Sleep for a small period of time.  */
        tx_thread_sleep(delay);
    }
    
    /* Check the probe counter.  */
    if ((probe_counter != 6) || (conflict_counter != 1))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the NetX IP address.  */
    status = nx_ip_interface_address_set(&ip_0, 0, IP_ADDRESS(1, 2, 3, 5), 0xFFFF0000);

    /* Check for status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Allocate all packet from packet pool.  */
    packet_counter = pool_0.nx_packet_pool_available;
    for(i =0; i < packet_counter; i ++)
    {

        /* Allocate the packet.  */
        status = nx_packet_allocate(&pool_0, &my_packet[i], NX_TCP_PACKET, NX_NO_WAIT);

        /* Check status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Send the ARP announcement.  */
    status = _nx_arp_announce_send(&ip_0, 0);

    /* Check status.  */
    if (status != NX_NO_PACKET)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release all allocated packet.  */
    for(i =0; i < packet_counter; i ++)
    {

        /* Allocate the packet.  */
        status = nx_packet_release(my_packet[i]);

        /* Check status.  */
        if (status)
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Delay before announcing.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE * NX_ARP_ANNOUNCE_WAIT);

    /* It is now time to go into an announce phase to indicate local IP address is ours!  
       Note:NetX do not give up its address during announce pahse.  */
    for (i = 0; i < NX_ARP_ANNOUNCE_NUM; i++)
    {

        /* Send the ARP announcement.  */
        _nx_arp_announce_send(&ip_0, 0);

        /* Calculate the delay time.  */
        delay =  (NX_IP_PERIODIC_RATE * NX_ARP_ANNOUNCE_INTERVAL);

        /* Sleep for announce interval.  */
        tx_thread_sleep(delay);
    }

    /* Check the announce counter.  */
    if (announce_counter != 2)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send a gratuitous ARP message.  */
    status =  nx_arp_gratuitous_send(&ip_0, gratuitous_responder_handler);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Sleep for IP conflict.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Check the announce counter.  */
    if ((announce_counter != 4) || (conflict_counter != 2) || (gratuitous_responder_counter != 1))
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
ULONG         *message_ptr;
ULONG         sender_physical_msw;
ULONG         sender_physical_lsw;
ULONG         sender_ip_address;
ULONG         target_physical_msw;
ULONG         target_physical_lsw;
ULONG         target_ip_address;
ULONG         message_type;

    /* Check the packet length.  */
    if (packet_ptr ->nx_packet_length != NX_ARP_MESSAGE_SIZE)
    {

        /* Update the error_counter.  */
        error_counter++;

        /* Release the packet  */
        nx_packet_release(packet_ptr);

        /* Return to caller.  */
        return NX_FALSE;
    }

    /* Setup a pointer to the ARP message.  */
    message_ptr =  (ULONG *) packet_ptr -> nx_packet_prepend_ptr;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+1));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+2));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+3));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+4));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+5));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+6));

    /* Pickup the ARP message type.  */
    message_type =  (ULONG) (*(message_ptr+1) & 0xFFFF);

    /* Determine if the ARP message type is valid.  */
    if (message_type != NX_ARP_OPTION_REQUEST)
    {

        /* Update the error_counter.  */
        error_counter++;
                      
        /* Release the packet  */
        nx_packet_release(packet_ptr);

        /* Return to caller.  */
        return NX_FALSE;
    }


    /* Pick up the sender's physical address from the message.  */
    sender_physical_msw =  (*(message_ptr+2) >> 16);
    sender_physical_lsw =  (*(message_ptr+2) << 16) | (*(message_ptr+3) >> 16);
    sender_ip_address =    (*(message_ptr+3) << 16) | (*(message_ptr+4) >> 16);
    target_physical_msw =  (*(message_ptr+4) & 0x0000FFFF);
    target_physical_lsw =  *(message_ptr+5);
    target_ip_address =    *(message_ptr+6);

    /* Check the sender and target information.  */
    if (((sender_physical_msw | sender_physical_lsw) != 0) && (sender_ip_address == 0) &&
        ((target_physical_msw | target_physical_lsw) == 0) && (target_ip_address != 0))
        probe_counter ++;

    else if (((sender_physical_msw | sender_physical_lsw) != 0) && (sender_ip_address != 0) &&
             ((target_physical_msw | target_physical_lsw) == 0) && (target_ip_address != 0))
        announce_counter ++;

    /* Let IP conflict.  */
    if ((probe_counter == 3) || (announce_counter == 3))
    {

        /* Modify the sender MAC address let IP address conflict.  */
        *(message_ptr+2) += 0x10;
    }

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+1));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+2));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+3));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+4));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+5));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+6));

    /* Let IP conflict.  */
    if ((probe_counter == 3) || (announce_counter == 3))
    {

        /* Directly receive this packet as conflict packet.  */
        _nx_arp_packet_deferred_receive(ip_ptr, packet_ptr);

        return NX_FALSE;
    }

    /* Release the packet  */
    nx_packet_release(packet_ptr);

    /* Return to caller.  */
    return NX_FALSE;
}

static void    ip_address_conflict_detection(NX_IP *ip_ptr, UINT interface_index, ULONG ip_address, ULONG msw, ULONG lsw)
{

    /* Update the conflict counter.  */
    conflict_counter ++;
}

static void    gratuitous_responder_handler(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

    /* Update the gratuitous_responder_counter.  */
    gratuitous_responder_counter ++;

    /* Release the packet.  */
    nx_packet_release(packet_ptr);

    return;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_address_conflict_detection_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Address Conflict Detection Test........................N/A\n"); 

    test_control_return(3);  
}      
#endif
