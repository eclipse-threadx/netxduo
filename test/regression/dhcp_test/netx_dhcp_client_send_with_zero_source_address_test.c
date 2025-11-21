
#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_api.h"
#include   "nxd_dhcp_client.h"
#include   "nxd_dhcp_server.h"
#include "tx_timer.h"
#include "tx_thread.h"
#include "tx_mutex.h"
#include "tx_event_flags.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         NX_PACKET_SIZE * 8

#define     NX_DHCP_SERVER_IP_ADDRESS_0 IP_ADDRESS(10,0,0,1)   
#define     START_IP_ADDRESS_LIST_0     IP_ADDRESS(10,0,0,10)
#define     END_IP_ADDRESS_LIST_0       IP_ADDRESS(10,0,0,19)

#define     NX_DHCP_SUBNET_MASK_0       IP_ADDRESS(255,255,255,0)
#define     NX_DHCP_DEFAULT_GATEWAY_0   IP_ADDRESS(10,0,0,1)
#define     NX_DHCP_DNS_SERVER_0        IP_ADDRESS(10,0,0,1)

/* If defined, the host requests a (previous) client IP address. */
/*
#define REQUEST_CLIENT_IP
*/

/* If defined the client requests to jump to the boot state and skip the DISCOVER message. 
   If REQUEST_CLIENT_IP is not defined, this has no effect. */
/* 
#define SKIP_DISCOVER_MESSAGE 
*/

/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               client_thread;
static NX_PACKET_POOL          client_pool;
static NX_IP                   client_ip;
static NX_DHCP                 dhcp_client;
static NX_DHCP                 dhcp_client2;
static NX_DHCP                 dhcp_client3;
static ULONG dhcp_your_address = 0;
/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static CHAR                    *pointer;

/* Define thread prototypes.  */

static void    client_thread_entry(ULONG thread_input);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_1024(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_send_with_zero_source_address_test_applicaiton_define(void *first_unused_memory)
#endif
{

UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the client thread.  */
    tx_thread_create(&client_thread, "thread client", client_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Client.  */
    status = nx_ip_create(&client_ip, "DHCP Client", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1024, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&client_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
    
    return;
}

static UINT dhcp_user_option_add_with_long_length(NX_DHCP *dhcp_ptr, UINT iface_index, UINT message_type, UCHAR *user_option_ptr, UINT *user_option_length)
{
    *user_option_length = 1100;

    return NX_TRUE;
}

#if defined(__PRODUCT_NETXDUO__) && defined(NX_ENABLE_IP_PACKET_FILTER)
static UINT packet_filter_extended(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT direction)
{
    if ((direction == NX_IP_PACKET_OUT) &&
        ((packet_ptr -> nx_packet_ip_header == NX_NULL) ||
        (packet_ptr -> nx_packet_ip_header_length == 0)))
    {
        error_counter++;
    }
    return(NX_SUCCESS);
}
#endif

/* Define the test threads.  */
void    client_thread_entry(ULONG thread_input)
{
UINT        status;
ULONG       i;

    printf("NetX Test:   DHCP Client Send with Zero Source Address Test........................................");

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    if (status)
        error_counter++;

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

#if defined(__PRODUCT_NETXDUO__) && defined(NX_ENABLE_IP_PACKET_FILTER)
    client_ip.nx_ip_packet_filter_extended = packet_filter_extended;
#endif

#ifdef REQUEST_CLIENT_IP
    requested_ip = (ULONG)CLIENT_IP_ADDRESS;

    /* Request a specific IP address using the DHCP client address option. */
    status = nx_dhcp_request_client_ip(&dhcp_client, requested_ip, skip_discover_message);
    if (status)
        error_counter++;

    nx_dhcp_start(&dhcp_client);
#endif

    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REQUESTING;

    /* test _nx_dhcp_client_send_with_zero_source_address*/
    client_ip.nx_ip_interface[0].nx_interface_valid = NX_FALSE;
    client_ip.nx_ip_interface[0].nx_interface_link_up = NX_FALSE;
    nx_dhcp_interface_send_request(&dhcp_client, 0, NX_DHCP_TYPE_DHCPDISCOVER);
    client_ip.nx_ip_interface[0].nx_interface_valid = NX_TRUE;
    nx_dhcp_interface_send_request(&dhcp_client, 0, NX_DHCP_TYPE_DHCPDISCOVER);
    dhcp_client.nx_dhcp_ip_ptr->nx_ip_id = NX_IP_ID;
    nx_ip_fragment_enable(dhcp_client.nx_dhcp_ip_ptr);
    client_ip.nx_ip_interface[0].nx_interface_link_up = NX_TRUE;
    client_ip.nx_ip_interface[0].nx_interface_link_up = NX_TRUE;
    nx_dhcp_user_option_add_callback_set(&dhcp_client, dhcp_user_option_add_with_long_length);
    nx_dhcp_interface_send_request(&dhcp_client, 0, NX_DHCP_TYPE_DHCPDISCOVER);
    dhcp_client.nx_dhcp_socket.nx_udp_socket_fragment_enable = NX_FRAGMENT_OKAY;
    nx_dhcp_interface_send_request(&dhcp_client, 0, NX_DHCP_TYPE_DHCPDISCOVER);
    dhcp_client.nx_dhcp_socket.nx_udp_socket_fragment_enable = NX_DONT_FRAGMENT;

    /* Use this for loop to test the corner case when the computed checksum is 0
       in function _nx_dhcp_client_send_with_zero_source_address */
    for (i = 0; i < 60000; i++)
    {
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_ip_address = i;
        nx_dhcp_interface_send_request(&dhcp_client, 0, NX_DHCP_TYPE_DHCPDISCOVER);
    }

    nx_dhcp_interface_stop(&dhcp_client, 0);
    nx_dhcp_delete(&dhcp_client);

    printf("SUCCESS!\n");
    test_control_return(0);  
    return;
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_send_with_zero_source_address_test_applicaiton_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NetX DHCP Client Send with Zero Source Address Test...................................N/A\n"); 

    test_control_return(3);  
}      
#endif
