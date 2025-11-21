/* Testing the multiple interface DHCP Client */

/* This is the DHCP Client that will run on both interfaces independently.
   Required: NX_MAX_PHYSICAL_INTERFACES >= 2 and NX_DHCP_CLIENT_MAX_RECORDS >= 2.
   There are two DHCP Client threads that independently activate the DHCP Client on
   the primary or secondary interface. When they reach the bound state, each interface Client
   deactivates the DHCP Client process and the DHCP Client goes back to the NOT STARTED state.
 
   There is one server thread handling DHCP Client messages on both interfaces. 
*/



#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_ram_network_driver_test_1500.h"
#include    "nxd_dhcp_client.h"

extern void test_control_return(UINT status);

#if (NX_MAX_PHYSICAL_INTERFACES >= 2) && (NX_DHCP_CLIENT_MAX_RECORDS >=2)

#define     DEMO_STACK_SIZE         4096
#define     PACKET_PAYLOAD          1518


/* Define the ThreadX, NetX object control blocks...  */

static UINT                    state_changes = 0;
static TX_THREAD               client_thread;
static NX_PACKET_POOL          client_pool;
static NX_IP                   client_ip;


/* Define the NetX FTP object control block.  */
static NX_DHCP                dhcp_client;

/* Define the counters used in the demo application...  */

static UINT                   error_counter = 0;
static UINT                   discover_counter = 0;

/* Replace the 'ram' driver with your Ethernet driver. */
extern  VOID nx_driver_ram_driver(NX_IP_DRIVER*); 
static void    client_thread_entry(ULONG thread_input);
extern   void _nx_ram_network_driver_1024(NX_IP_DRIVER *driver_req_ptr);
static  UINT   my_dhcp_process_bc_callback(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern  UINT  (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_interface_order_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
UCHAR   *pointer;

    
    /* Setup the working pointer.  */
    pointer =  (UCHAR *) first_unused_memory;

    /* Initialize NetX.  */
    nx_system_initialize();

    /* Set up the Client. */
    /* Create the main client thread.  */
    status = tx_thread_create(&client_thread, "Client Thread", client_thread_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              6, 6, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + DEMO_STACK_SIZE ;

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Create a packet pool for the client.  */
    status =  nx_packet_pool_create(&client_pool, "Client Packet Pool", PACKET_PAYLOAD, pointer, 7*PACKET_PAYLOAD);
    
        /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }
    
    pointer =  pointer + 7*PACKET_PAYLOAD;

    /* Create an IP instance for the client.  */
    status = nx_ip_create(&client_ip, " Client IP ", IP_ADDRESS(0,0,0,0), 0xFFFFFF00UL, 
                          &client_pool, _nx_ram_network_driver_1024, pointer, 2048, 1);
    
    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }
    pointer = pointer + 2048;

    /* Enable ARP and supply ARP cache memory for the Client IP.  */
    nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable UDP for client IP instance.  */
    nx_udp_enable(&client_ip);
    nx_icmp_enable(&client_ip);
}


/* Define the DHCP client thread.  */

void    client_thread_entry(ULONG thread_input)
{

UINT        status;

                  
    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Client Interface Order Test.........................."); 

    /* Check for earlier error. */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the advanced callback to ensure broadcast packets are routed correctly. */
    advanced_packet_process_callback = my_dhcp_process_bc_callback;

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp0");
    if (status)
        error_counter++;

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

    /* Clear the unicast flag on all interfaces. */
    status = nx_dhcp_clear_broadcast_flag(&dhcp_client, NX_TRUE);

    /* Set the client IP if the host is configured to do so. */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable DHCP feature on the second interface.  */
    status = nx_dhcp_interface_disable(&dhcp_client, 0);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable DHCP feature on the second interface.  */
    status = nx_dhcp_interface_enable(&dhcp_client, 1);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable DHCP feature on the second interface.  */
    status = nx_dhcp_interface_enable(&dhcp_client, 0);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Start DHCP feature on the second interface.  */
    status = nx_dhcp_interface_start(&dhcp_client, 0);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for Discover.  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    /* Check error_counter.  */
    if ((error_counter) || (discover_counter == 0))
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


static UINT my_dhcp_process_bc_callback(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{


    /* Is this a DHCP packet e.g. not an ARP packet? */
    if (packet_ptr -> nx_packet_length < 200)
    {
        /* Maybe an ARP packet. let the RAM driver deal with it */
        return NX_TRUE;
    }

    /* Check the interface index.  */
    if (packet_ptr -> nx_packet_ip_interface != &ip_ptr -> nx_ip_interface[0])
        error_counter++;

    /* Update the counter.  */
    discover_counter++;

    *operation_ptr = NX_RAMDRIVER_OP_DROP;

    return NX_TRUE;

}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_dhcp_client_interface_order_test_application_define(void * first_unused_memory)
#endif
{
    printf("NetX Test:   DHCP Client Interface Order Test..........................N/A!\n");
    test_control_return(3);
}     
#endif /* (NX_MAX_PHYSICAL_INTERFACES >= 2) && (NX_DHCP_CLIENT_MAX_RECORDS >=2) */


