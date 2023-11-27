/*  Having probed to determine a unique address to use, the host MUST then announce its claimed address by broadcasting
    ANNOUNCE_NUM ARP announcements, spaced ANNOUNCE_INTERVAL seconds apart.  */

#include "tx_api.h"
#include "nx_api.h"
#include "nx_tcp.h"
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
static ULONG                   address_changes;
static ULONG                   error_counter;
static UINT                    checkNum;
static ULONG                   conn_ip_address;
static UINT                    announce_num;
static UINT                    current_time;
static UINT                    start_time;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ip_address_changed(NX_IP *ip_ptr, VOID *auto_ip_address);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_arp_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_auto_ip_announce_num_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;


    /* Initializes the variables. */
    error_counter = 0;
    announce_num = 0;
    current_time = 0;
    start_time = 0;
    checkNum = NX_AUTO_IP_PROBE_NUM + NX_AUTO_IP_ANNOUNCE_NUM;

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

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check UDP enable status.  */
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


    /* Register an IP address change function for each IP instance.  */
    status =  nx_ip_address_change_notify(&ip_0, ip_address_changed, (void *) &auto_ip_0);

    /* Check IP address change notify status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

void    ntest_0_entry(ULONG thread_input)
{

UINT         status;
ULONG        actual_status;
ULONG        network_mask;

    printf("NetX Test:   Auto_IP Announce NUM Processing Test......................");

    advanced_packet_process_callback = my_arp_packet_process;

    /* Wait for IP address to be resolved.   */
    tx_thread_sleep(NX_AUTO_IP_PROBE_MAX * checkNum * NX_IP_PERIODIC_RATE);

    /* Call IP status check routine.   */
    status =  nx_ip_status_check(&ip_0, NX_IP_ADDRESS_RESOLVED, &actual_status, NX_IP_PERIODIC_RATE);

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
        error_counter++;

    /* Delete the AutoIP instance auto_ip_0.  */
    status =  nx_auto_ip_delete(&auto_ip_0);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Determine if the test was successful.  */
    if ((error_counter) ||(announce_num != NX_AUTO_IP_ANNOUNCE_NUM))
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
    
void  ip_address_changed(NX_IP *ip_ptr, VOID *auto_ip_address)
{

ULONG         ip_address;
ULONG         network_mask;
NX_AUTO_IP    *auto_ip_ptr;


    /* Setup pointer to auto IP instance.  */
    auto_ip_ptr =  (NX_AUTO_IP *) auto_ip_address;

    /* Pickup the current IP address.  */
    nx_ip_address_get(ip_ptr, &ip_address, &network_mask);

    /* Determine if the IP address has changed back to zero. If so, make sure the
       AutoIP instance is started.  */
    if (ip_address == 0)
    {

        /* Get the last AutoIP address for this node.  */
        nx_auto_ip_get_address(auto_ip_ptr, &ip_address);

        /* Start this AutoIP instance.  */
        nx_auto_ip_start(auto_ip_ptr, ip_address);
    }

    /* Determine if the IP address has transitioned to a non local IP address.  */
    else if ((ip_address & 0xFFFF0000UL) != IP_ADDRESS(169, 254, 0, 0))
    {

        /* Stop the AutoIP processing.  */
        nx_auto_ip_stop(auto_ip_ptr);

        /* Delete the AutoIP instance.  */
        nx_auto_ip_delete(auto_ip_ptr);
    }

    /* Increment a counter.  */
    address_changes++;
}



static UINT    my_arp_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

ULONG                   *message_ptr;
UINT                    message_type;

    /* Setup a pointer to the ARP message.  */
    message_ptr = (ULONG *) packet_ptr -> nx_packet_prepend_ptr;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+1));

    /* Pickup the ARP message type.  */
    message_type =  (UINT) (*(message_ptr+1) & 0xFFFF);

    if (message_type != NX_ARP_OPTION_REQUEST)
        error_counter++;
    else
    {
        if(announce_num == 0)
        {
            start_time = tx_time_get(); 
            announce_num++;
        }
        else
        {
            current_time = tx_time_get(); 

            if(current_time >= start_time + (announce_num * NX_IP_PERIODIC_RATE * NX_AUTO_IP_ANNOUNCE_INTERVAL))
                announce_num++;
        }
    }


    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+1));
    
    if(announce_num == NX_AUTO_IP_ANNOUNCE_NUM)
        advanced_packet_process_callback = NULL;

    return NX_TRUE;



}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_auto_ip_announce_num_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   Auto_IP Announce NUM Processing Test......................N/A\n"); 

    test_control_return(3);  
}      
#endif