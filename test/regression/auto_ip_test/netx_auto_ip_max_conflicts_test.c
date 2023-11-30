/* This is a small demo of the NetX TCP/IP stack using the AUTO IP module.  */

#include "tx_api.h"
#include "nx_api.h"
#include "nx_arp.h"
#include "nx_auto_ip.h"
#include "nx_ram_network_driver_test_1500.h"


#define     DEMO_STACK_SIZE         4096

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the AUTO IP structures for each IP instance.   */

static NX_AUTO_IP              auto_ip_0;


/* Define the counters used in the demo application...  */
static ULONG                   error_counter;
static UINT                    current_time;
static UINT                    start_time;
static UINT                    arp_probe;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_arp_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_auto_ip_max_conflicts_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Initializes the variables. */
    error_counter = 0;
    current_time = 0;
    start_time = 0;
    arp_probe = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 4096, 1);
    pointer =  pointer + 4096;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;


    /* Create the AutoIP instance for each IP instance.   */
    status =  nx_auto_ip_create(&auto_ip_0, "AutoIP 0", &ip_0, pointer, 4096, 2);
    pointer = pointer + 4096;

    /* Check AutoIP create status.  */
    if (status)
        error_counter++;

    /* Start both AutoIP instances.  */
    status =  nx_auto_ip_start(&auto_ip_0, IP_ADDRESS(169,254,10,10));

    /* Check AutoIP start status.  */
    if (status)
        error_counter++;
}


/* Define the test threads.  */

void    ntest_0_entry(ULONG thread_input)
{

UINT         status;
ULONG        actual_status;
ULONG        conn_ip_address;
ULONG        network_mask;

    printf("NetX Test:   Auto_IP MAX Conflicts Processing Test.....................");

    advanced_packet_process_callback = my_arp_packet_process;

    /* Call IP status check routine.   */
    status =  nx_ip_status_check(&ip_0, NX_IP_ADDRESS_RESOLVED, &actual_status, NX_WAIT_FOREVER);

    /* Check status.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup the current IP address.  */ 
    nx_ip_address_get(&ip_0, &conn_ip_address, &network_mask);

    /* Check whether the AutoIP allocates addresses in the range of 169.254.1.0 through 169.254.254.255.*/
    if((conn_ip_address & 0xFFFF0000UL) != IP_ADDRESS(169, 254, 0, 0) || (conn_ip_address < IP_ADDRESS(169, 254, 1, 0)) || (conn_ip_address > IP_ADDRESS(169, 254, 254, 255)))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Stop the AutoIP instance auto_ip_0.  */
    status = nx_auto_ip_stop(&auto_ip_0);

    /* Check for error.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the AutoIP instance auto_ip_0.  */
    status =  nx_auto_ip_delete(&auto_ip_0);

    /* Check for error.  */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Determine if the test was successful.  */
    if ((error_counter) || (arp_probe != (NX_AUTO_IP_MAX_CONFLICTS + 2)) ||
        (auto_ip_0.nx_auto_ip_conflict_count != (NX_AUTO_IP_MAX_CONFLICTS + 1)))
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

static UINT    my_arp_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

ULONG                   *message_ptr;
UINT                    message_type;
ULONG                   sender_mac_msw;
ULONG                   sender_mac_lsw;
ULONG                   sender_ip;
ULONG                   receive_mac_msw;
ULONG                   receive_mac_lsw;
ULONG                   receive_ip;
NX_PACKET               *conflict_packet;


    /* Setup a pointer to the ARP message.  */
    message_ptr = (ULONG *) packet_ptr -> nx_packet_prepend_ptr;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 1));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 2));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 3));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 4));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 5));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 6));

    /* Pickup the ARP message type.  */
    message_type = (UINT)(*(message_ptr+1) & 0xFFFF);

    /* Pick up the mac and ip address.  */
    sender_mac_msw = (*(message_ptr + 2) >> 16);
    sender_mac_lsw = ((*(message_ptr + 2) & 0x0000FFFF) << 16) | (*(message_ptr + 3) >> 16);
    sender_ip = ((*(message_ptr + 3) & 0x0000FFFF) << 16) | (*(message_ptr + 4) >> 16);
    receive_mac_msw = (*(message_ptr + 4) & 0x0000FFFF);
    receive_mac_lsw = (*(message_ptr + 5));
    receive_ip = *(message_ptr + 6);

    /* Check if ARP probe.  */
    if ((message_type != NX_ARP_OPTION_REQUEST) ||
        (sender_mac_msw != ip_ptr -> nx_ip_interface[0].nx_interface_physical_address_msw) ||
        (sender_mac_lsw != ip_ptr -> nx_ip_interface[0].nx_interface_physical_address_lsw) ||
        (sender_ip != 0) ||
        (receive_mac_msw != 0) ||
        (receive_mac_lsw != 0) ||
        (receive_ip != auto_ip_0.nx_auto_ip_current_local_address))
    {
        error_counter++;
        return NX_TRUE;
    }

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 1));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 2));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 3));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 4));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 5));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 6));

    /* Update the arp counter.  */
    arp_probe ++;

    /* Check the arp counter.  */
    if (arp_probe <= (NX_AUTO_IP_MAX_CONFLICTS + 1))
    {

        /* Check the conflict count.  */
        if (arp_probe != (auto_ip_0.nx_auto_ip_conflict_count + 1))
        {        
            error_counter++;
            return NX_TRUE;
        }

        /* Initialize the conflict start time.  */
        if (arp_probe == (NX_AUTO_IP_MAX_CONFLICTS + 1))
           start_time = tx_time_get();

        /* Inject conflict arp.  */
        if (nx_packet_copy(packet_ptr, &conflict_packet, &pool_0, NX_NO_WAIT))
        {
            error_counter++;
            return NX_TRUE;
        }

        /* Setup a pointer to the conflict ARP message.  */
        message_ptr = (ULONG *) conflict_packet -> nx_packet_prepend_ptr;

        /* Just change the sender mac of probe to act as conflict ARP.  */
        *(message_ptr + 2) -= 1;

        /* Receive conflict arp.  */
        _nx_arp_packet_deferred_receive(ip_ptr, conflict_packet);
    }
    else
    {
        current_time = tx_time_get();

        /* Check the extra delay.  */
        if ((current_time - start_time) < (NX_IP_PERIODIC_RATE * NX_AUTO_IP_RATE_LIMIT_INTERVAL))
            error_counter++;

        advanced_packet_process_callback = NX_NULL;
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_auto_ip_max_conflicts_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Auto_IP MAX Conflicts Processing Test.....................N/A\n"); 

    test_control_return(3);  
}      
#endif
