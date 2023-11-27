
#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#include   "nxd_dhcp_client.h"
#include   "nxd_dhcp_server.h"
#include   "tx_timer.h"
#include   "tx_thread.h"
#include   "tx_mutex.h"
#include   "tx_event_flags.h"

#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         NX_PACKET_SIZE * 8

#define     NX_DHCP_SERVER_IP_ADDRESS_0 IP_ADDRESS(10,0,0,1)   
#define     START_IP_ADDRESS_LIST_0     IP_ADDRESS(10,0,0,10)
#define     END_IP_ADDRESS_LIST_0       IP_ADDRESS(10,0,0,19)

#define     NX_DHCP_SUBNET_MASK_0       IP_ADDRESS(255,255,255,0)
#define     NX_DHCP_DEFAULT_GATEWAY_0   IP_ADDRESS(10,0,0,1)
#define     NX_DHCP_DNS_SERVER_0        IP_ADDRESS(10,0,0,1)

#define     DHCP_TEST_LONG_NAME         "dhcp_client_make_the_string_length_exceed_255_to_test_the_corner_case_in_function \
                                         netx_dhcp_send_request_internal__________________________________________________ \
                                         _________________________________________________________________________________ \
                                         _________________________________________________________________________________ \
                                         _________________________________________________________________________________ \
                                         _________________________________________________________________________________ \
                                         _________________________________________________________________________________ \
                                         _________________________________________________________________________________"

#define     NX_DHCP_OPTION_ARP_TIMEOUT  35

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

/* Frame (342 bytes) */
static unsigned char option_message[60] = {
0x35, 0x01, 0x02,                               /* DHCP message type */
0x01, 0x04, 0xff, 0xff, 0xff, 0x00,             /* Subnet Mask */
0x36, 0x04, 0xe0, 0xa8, 0x02, 0x01,             /* Server identifier */
0x33, 0x04, 0xff, 0xff, 0xff, 0xff,             /* IP address lease time */
0x03, 0x04, 0xc0, 0x02, 0x00, 0x00,             /* Router/gateway */
0x06, 0x04, 0xc0, 0xa8, 0x02, 0x01,             /* DNS server */
0x2a, 0x04, 0x7c, 0x6c, 0x14, 0x01,             /* NTP server */
0x3a, 0x04, 0xff, 0xff, 0xff, 0xff,             /* Renewal time */
0x3b, 0x04, 0xff, 0xff, 0xff, 0xff,             /* Rebind time */
0x23, 0x04, 0x00, 0x00, 0x01, 0x02,             /* ........ */
0xff, 0x00, 0x00
};

/* Define the counters used in the demo application...  */

static ULONG                   state_changes;
static ULONG                   error_counter;
static CHAR                    *pointer;

extern VOID  _nx_dhcp_packet_process(NX_DHCP *dhcp_ptr, NX_DHCP_INTERFACE_RECORD *interface_record, NX_PACKET *packet_ptr);
extern UINT  _nx_dhcp_packet_pool_set(NX_DHCP *dhcp_ptr, NX_PACKET_POOL *packet_pool_ptr);
extern UINT  _nx_dhcp_decline(NX_DHCP *dhcp_ptr);
/* Define thread prototypes.  */

static void    client_thread_entry(ULONG thread_input);
static void    dhcp_state_change(NX_DHCP *dhcp_ptr, UCHAR new_state);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_1024(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_coverage_test_applicaiton_define(void *first_unused_memory)
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

static void state_change_cb(NX_DHCP *dhcp_ptr, UCHAR state)
{
    return;
}

static UINT dhcp_user_option_add_with_false_return(NX_DHCP *dhcp_ptr, UINT iface_index, UINT message_type, UCHAR *user_option_ptr, UINT *user_option_length)
{
    return NX_FALSE;
}

static UINT dhcp_user_option_add(NX_DHCP *dhcp_ptr, UINT iface_index, UINT message_type, UCHAR *user_option_ptr, UINT *user_option_length)
{
    *user_option_length = 301;

    return NX_TRUE;
}

static void interface_state_change_cb(NX_DHCP *dhcp_ptr, UINT iface, UCHAR state)
{
    return;
}

static NX_PACKET * create_dhcp_packet(int length)
{
    NX_PACKET* packet_ptr;
#ifdef __PRODUCT_NETXDUO__
    nx_packet_allocate(&client_pool, &packet_ptr, NX_IPv4_UDP_PACKET, NX_NO_WAIT);
#else
    nx_packet_allocate(&client_pool, &packet_ptr, NX_UDP_PACKET, NX_NO_WAIT);
#endif
#ifdef __PRODUCT_NETXDUO__
    packet_ptr->nx_packet_ip_version = NX_IP_VERSION_V4;
#endif
    packet_ptr->nx_packet_queue_next = NX_NULL;
    packet_ptr->nx_packet_length = length;
#ifdef __PRODUCT_NETXDUO__
    packet_ptr->nx_packet_address.nx_packet_interface_ptr = &client_ip.nx_ip_interface[0];
#else
    packet_ptr->nx_packet_ip_interface = &client_ip.nx_ip_interface[0];
#endif
#ifdef __PRODUCT_NETXDUO__
    packet_ptr->nx_packet_ip_header = packet_ptr->nx_packet_prepend_ptr - sizeof(NX_IPV4_HEADER);
#endif
    packet_ptr->nx_packet_append_ptr += packet_ptr->nx_packet_length;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_XID] = ((dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_xid) >> 24) & 0xFF;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_XID + 1] = ((dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_xid) >> 16) & 0xFF;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_XID + 2] = ((dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_xid) >> 8) & 0xFF;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_XID + 3] = (dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_xid) & 0xFF;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_CLIENT_HW] = 0;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_CLIENT_HW + 1] = 0x11;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_CLIENT_HW + 2] = 0x22;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_CLIENT_HW + 3] = 0x33;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_CLIENT_HW + 4] = 0x44;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_CLIENT_HW + 5] = 0x56;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_YOUR_IP] = dhcp_your_address >> 24;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_YOUR_IP + 1] = (dhcp_your_address >> 16) & 0xFF ;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_YOUR_IP + 2] = (dhcp_your_address >> 8) & 0xFF;
    packet_ptr->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_YOUR_IP + 3] = dhcp_your_address & 0xFF;

    dhcp_client.nx_dhcp_socket.nx_udp_socket_receive_head = packet_ptr;
    dhcp_client.nx_dhcp_socket.nx_udp_socket_receive_count++;
    packet_ptr->nx_packet_prepend_ptr -=8;
    packet_ptr->nx_packet_length += 8;
    return(packet_ptr);

}

static NX_PACKET * build_dhcp_packet(int length, UCHAR option_type, UCHAR val_len,  UCHAR val)
{
    NX_PACKET *my_packet;

    my_packet = create_dhcp_packet(length);
    my_packet->nx_packet_prepend_ptr[8+NX_BOOTP_OFFSET_OPTIONS]=option_type;
    my_packet->nx_packet_prepend_ptr[8+NX_BOOTP_OFFSET_OPTIONS+1]=val_len;
    my_packet->nx_packet_prepend_ptr[8+NX_BOOTP_OFFSET_OPTIONS+2]=val;

    return(my_packet);
}
    
extern VOID _nx_dhcp_timeout_process(NX_DHCP* dhcp_ptr);
extern TX_THREAD _tx_timer_thread;
/* Define the test threads.  */
void    client_thread_entry(ULONG thread_input)
{
ULONG       current_system_state;
TX_THREAD  *current_thread_ptr;
UCHAR       buffer[4];
UINT        buffer_size = 4;
ULONG       long_val;
ULONG       payload_size = 0;

#ifdef REQUEST_CLIENT_IP
ULONG       requested_ip;
#endif

TX_TIMER *timer_ptr;
TX_MUTEX *mutex_ptr;
TX_THREAD *thread_ptr;
TX_EVENT_FLAGS_GROUP *event_flags;
NX_PACKET *my_packet = NX_NULL;
    printf("NetX Test:   DHCP coverage Test........................................");

    /* Force timer create to fail. */
    timer_ptr = _tx_timer_created_ptr;
    _tx_timer_created_ptr = &dhcp_client.nx_dhcp_timer;
    _tx_timer_created_count++;

    /* Create the DHCP instance.  */
    nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");

    /* Restore the timer structure. */
    _tx_timer_created_ptr = timer_ptr;
    _tx_timer_created_count--;

    /*  Force mutex create to fail. */
    mutex_ptr = _tx_mutex_created_ptr;
    _tx_mutex_created_ptr = &dhcp_client.nx_dhcp_mutex;
    _tx_mutex_created_count++;
    /* Create the DHCP instance.  */
    nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");

    /* Restore mutex. */
    _tx_mutex_created_ptr = mutex_ptr;
    _tx_mutex_created_count--;

    /* Force Thread create to fail.*/
    thread_ptr = _tx_thread_created_ptr;
    _tx_thread_created_ptr = &dhcp_client.nx_dhcp_thread;
    _tx_thread_created_count++;
    /* Create the DHCP instance.  */
    nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");

    /* Restore thread list. */
    _tx_thread_created_ptr = thread_ptr;
    _tx_thread_created_count--;

    /* Force event flag create to fail */
    event_flags = _tx_event_flags_created_ptr;
    _tx_event_flags_created_count ++;
    _tx_event_flags_created_ptr = &dhcp_client.nx_dhcp_events;
    nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");


    /* Restore event flasg */
    _tx_event_flags_created_ptr = event_flags;
    _tx_event_flags_created_count--;

    nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    nx_dhcp_stop(&dhcp_client);

    /* All done. Return resources to NetX and ThreadX. */    
    nx_dhcp_delete(&dhcp_client);

    /* Test nx_dhcp_interface_clear_broadcast_flag */
    nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_interface_clear_broadcast_flag(&dhcp_client, 0, 0);

    /* Enable one record */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_interface_index = 0;
    nx_dhcp_interface_clear_broadcast_flag(&dhcp_client, 0, 0);

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    /* Cover _nx_dhcp_packet_pool_set */
    nx_dhcp_packet_pool_set(&dhcp_client, NX_NULL);
    _nx_dhcp_packet_pool_set(&dhcp_client, NX_NULL);
    nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
#endif

    /* Cover _nxe_dhcp_reinitialize */
    nx_dhcp_reinitialize(&dhcp_client);

    /* Cover nx_dhcp_interface_reinitialize */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_interface_reinitialize(&dhcp_client, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    nx_dhcp_interface_reinitialize(&dhcp_client, 0);


    /* Cover nx_dhcp_(interface_)request_client_ip */
    nx_dhcp_request_client_ip(&dhcp_client, 1, 0);
    nx_dhcp_interface_request_client_ip(&dhcp_client, 0, 1, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_request_client_ip(&dhcp_client, 1, 0);
    nx_dhcp_interface_request_client_ip(&dhcp_client, 0, 1, 0);


    /* Cover nx_dhcp_force_renew */
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    nx_dhcp_force_renew(&dhcp_client);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    nx_dhcp_force_renew(&dhcp_client);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    nx_dhcp_force_renew(&dhcp_client);

    /* Cover nx_dhcp_interface_force_renew */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_interface_force_renew(&dhcp_client, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND - 1;
    nx_dhcp_interface_force_renew(&dhcp_client, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    dhcp_client.nx_dhcp_state_change_callback = state_change_cb;
    dhcp_client.nx_dhcp_interface_state_change_callback = interface_state_change_cb;
    nx_dhcp_interface_force_renew(&dhcp_client, 0);

    /* Cover _nx_dhcp_update_renewal_timeout through calling nx_dhcp_interface_force_renew */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_rebind_time = 8000;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_renewal_time = 1000;
    nx_dhcp_interface_force_renew(&dhcp_client, 0);

    /* Cover the static function _nx_dhcp_send_request_interval through calling API functions */
    payload_size = dhcp_client.nx_dhcp_packet_pool_ptr->nx_packet_pool_payload_size;
    dhcp_client.nx_dhcp_packet_pool_ptr->nx_packet_pool_payload_size = 0;
    nx_dhcp_interface_force_renew(&dhcp_client, 0);
    dhcp_client.nx_dhcp_packet_pool_ptr->nx_packet_pool_payload_size = payload_size;
    dhcp_client.nx_dhcp_name = DHCP_TEST_LONG_NAME;
    nx_dhcp_interface_force_renew(&dhcp_client, 0);
    dhcp_client.nx_dhcp_name = "dhcp_client";
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_ip_address = NX_BOOTP_BC_ADDRESS;
    nx_dhcp_interface_force_renew(&dhcp_client, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_server_ip = NX_BOOTP_BC_ADDRESS;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    nx_dhcp_send_request(&dhcp_client, NX_DHCP_TYPE_DHCPREQUEST);
    dhcp_client.nx_dhcp_name = NULL;
    nx_dhcp_send_request(&dhcp_client, NX_DHCP_TYPE_DHCPINFORM);
    dhcp_client.nx_dhcp_name = DHCP_TEST_LONG_NAME;
    nx_dhcp_send_request(&dhcp_client, NX_DHCP_TYPE_DHCPINFORM);
    nx_dhcp_user_option_add_callback_set(&dhcp_client, dhcp_user_option_add_with_false_return);
    nx_dhcp_send_request(&dhcp_client, NX_DHCP_TYPE_DHCPINFORM);
    dhcp_client.nx_dhcp_name = DHCP_TEST_LONG_NAME;
    nx_dhcp_send_request(&dhcp_client, NX_DHCP_TYPE_DHCPDISCOVER);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_ip_address = 1;
    nx_dhcp_decline(&dhcp_client);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_ip_address = NX_BOOTP_BC_ADDRESS;
    nx_dhcp_decline(&dhcp_client);
    nx_dhcp_user_option_add_callback_set(&dhcp_client, dhcp_user_option_add);
    nx_dhcp_send_request(&dhcp_client, NX_DHCP_TYPE_DHCPINFORM);

    /* Cover nx_dhcp_decline */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_decline(&dhcp_client);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND - 1;
    nx_dhcp_decline(&dhcp_client);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    nx_dhcp_decline(&dhcp_client);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_interface_decline(&dhcp_client, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND - 1;
    nx_dhcp_interface_decline(&dhcp_client, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    dhcp_client.nx_dhcp_state_change_callback = NX_NULL;
    dhcp_client.nx_dhcp_interface_state_change_callback = NX_NULL;
    nx_dhcp_interface_decline(&dhcp_client, 0);

    /* Test _nx_dhcp_release */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND - 1;
    nx_dhcp_release(&dhcp_client);

    /* Test nx_dhcp_interface_start */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_interface_start(&dhcp_client, 0);

    /* Test nx_dhcp_interface_release */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_interface_release(&dhcp_client, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND - 1;
    nx_dhcp_interface_release(&dhcp_client, 0);
    dhcp_client.nx_dhcp_state_change_callback = state_change_cb;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    nx_dhcp_interface_release(&dhcp_client, 0);

    /* Test nx_dhcp_interface_stop */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_interface_stop(&dhcp_client, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_NOT_STARTED;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    nx_dhcp_interface_stop(&dhcp_client, 0);

    /* Test nx_dhcp_user_option_retrieve*/
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    buffer_size = sizeof(buffer);
    nx_dhcp_user_option_retrieve(&dhcp_client, 0, buffer, &buffer_size);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND - 1;
    buffer_size = sizeof(buffer);
    nx_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 0, buffer, &buffer_size);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND - 1;
    buffer_size = sizeof(buffer);
    nx_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 0, buffer, &buffer_size);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    nx_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 0, buffer, &buffer_size);
    buffer_size = 1;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_options_size = 4;
    nx_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 0, buffer, &buffer_size);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_options_buffer[0] = 1;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_options_buffer[1] = 2;
    nx_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 1, buffer, &buffer_size);
    buffer_size = 4;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_options_buffer[0] = 0xFF;
    nx_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 0xFF, buffer, &buffer_size);

    /* Test _nx_dhcp_search_buffer through nx_dhcp_interface_user_option_retrieve */
    dhcp_client.nx_dhcp_interface_record->nx_dhcp_options_buffer[0] = 1;
    dhcp_client.nx_dhcp_interface_record->nx_dhcp_options_buffer[1] = 5;
    dhcp_client.nx_dhcp_interface_record->nx_dhcp_options_size = 4;
    nx_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 1, buffer, &buffer_size);
    memcpy(dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_options_buffer, option_message, 60);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_options_size = 60;
    nx_dhcp_interface_user_option_retrieve(&dhcp_client, 0, NX_DHCP_OPTION_ARP_TIMEOUT, buffer, &buffer_size);

    /* Test _nx_dhcp_interface_disable*/
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_interface_disable(&dhcp_client, 0);

    /* Test _nx_dhcp_user_option_retrieve*/
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND - 1;
    nx_dhcp_user_option_retrieve(&dhcp_client, 0, NX_NULL, NX_NULL);

    /* Test nx_dhcp_user_option_convert*/
    long_val = nx_dhcp_user_option_convert(buffer);

    /* Test nx_dhcp_send_request*/
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_send_request(&dhcp_client, 1);

    /* Test nx_dhcp_interface_send_request*/
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_interface_send_request(&dhcp_client, 0, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    nx_dhcp_interface_send_request(&dhcp_client, 0, NX_DHCP_TYPE_DHCPRELEASE);
    nx_dhcp_interface_send_request(&dhcp_client, 0, NX_DHCP_TYPE_DHCPDECLINE);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_NOT_STARTED;
    nx_dhcp_interface_send_request(&dhcp_client, 0, NX_DHCP_TYPE_DHCPACK);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    nx_dhcp_interface_send_request(&dhcp_client, 0, NX_DHCP_TYPE_DHCPACK);

    /*Test nx_dhcp_server_address_get*/
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_server_address_get(&dhcp_client, &long_val);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    nx_dhcp_server_address_get(&dhcp_client, &long_val);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND - 1;
    nx_dhcp_server_address_get(&dhcp_client, &long_val);

    /* Test nx_dhcp_interface_server_address_get*/
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;
    nx_dhcp_interface_server_address_get(&dhcp_client, 0, &long_val);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND;
    nx_dhcp_interface_server_address_get(&dhcp_client, 0, &long_val);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOUND - 1;
    nx_dhcp_interface_server_address_get(&dhcp_client, 0, &long_val);

    /* Test DHCP delete */
    current_system_state = _tx_thread_system_state;
    _tx_thread_system_state = 1;
    nx_dhcp_delete(&dhcp_client);
    _tx_thread_system_state = current_system_state;
    current_thread_ptr = _tx_thread_current_ptr;
    _tx_thread_current_ptr = TX_NULL;
    nx_dhcp_delete(&dhcp_client);
    _tx_thread_current_ptr = &_tx_timer_thread;
    nx_dhcp_delete(&dhcp_client);
    _tx_thread_current_ptr = current_thread_ptr;
    nx_dhcp_delete(&dhcp_client);

    nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    nx_dhcp_create(&dhcp_client2, &client_ip, "dhcp_client2");
    nx_dhcp_create(&dhcp_client3, &client_ip, "dhcp_client3");

    nx_dhcp_delete(&dhcp_client);
    nx_dhcp_delete(&dhcp_client2);
    nx_dhcp_delete(&dhcp_client3);


    current_system_state = _tx_thread_system_state;
    _tx_thread_system_state = 1;
    nx_dhcp_force_renew(&dhcp_client);
    _tx_thread_system_state = current_system_state;
    current_thread_ptr = _tx_thread_current_ptr;
    _tx_thread_current_ptr = TX_NULL;
    nx_dhcp_force_renew(&dhcp_client);
    _tx_thread_current_ptr = &_tx_timer_thread;
    nx_dhcp_force_renew(&dhcp_client);
    _tx_thread_current_ptr = current_thread_ptr;
    nx_dhcp_force_renew(&dhcp_client);
    nx_dhcp_delete(&dhcp_client);
    nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    /* Force nx_dhcp_start to fail. */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_FALSE;

    /* Start the DHCP Client.  */
    nx_dhcp_start(&dhcp_client);

    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_BOOT;
    /* Start the DHCP Client.  */
    nx_dhcp_start(&dhcp_client);

    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = 0;
    dhcp_client.nx_dhcp_socket.nx_udp_socket_bind_in_progress = _tx_thread_current_ptr;
    /* Start the DHCP Client.  */
    nx_dhcp_start(&dhcp_client);
    dhcp_client.nx_dhcp_socket.nx_udp_socket_bind_in_progress = TX_NULL;
    dhcp_client.nx_dhcp_thread.tx_thread_id = 0;
    nx_dhcp_start(&dhcp_client);
    dhcp_client.nx_dhcp_thread.tx_thread_id = TX_THREAD_ID;
    dhcp_client.nx_dhcp_timer.tx_timer_id = 0;
    nx_dhcp_start(&dhcp_client);
    dhcp_client.nx_dhcp_timer.tx_timer_id = TX_TIMER_ID;
    nx_dhcp_delete(&dhcp_client);

    nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    
    /* Test nx_dhcp_interface_enable */
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_interface_index = 0;
    nx_dhcp_interface_enable(&dhcp_client, 0);
    dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_interface_index = 1;
#if(NX_MAX_PHYSICAL_INTERFACES > 1)
    dhcp_client.nx_dhcp_interface_record[1].nx_dhcp_record_valid = NX_TRUE;
    dhcp_client.nx_dhcp_interface_record[1].nx_dhcp_interface_index = 2;
#endif
    nx_dhcp_interface_enable(&dhcp_client, 0);
    nx_dhcp_delete(&dhcp_client);

    /* Test nx_dhcp_packet_process */
    nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    nx_dhcp_start(&dhcp_client);
    dhcp_client.nx_dhcp_socket.nx_udp_socket_disable_checksum = NX_TRUE;

#ifndef NX_ENABLE_INTERFACE_CAPABILITY
    /* Inject a packet that causes nx_udp_packet_info_extract() to fail. */
    my_packet = create_dhcp_packet(30);
#ifdef __PRODUCT_NETXDUO__
    my_packet->nx_packet_ip_version = 0;
#endif
    tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
    tx_thread_sleep(1);
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

    /* Now test nx_dhcp_packet_process, test failures on the 1st check. */
    my_packet = create_dhcp_packet(30);
#ifdef __PRODUCT_NETXDUO__
    my_packet->nx_packet_ip_version = NX_IP_VERSION_V4;
#endif
    dhcp_client.nx_dhcp_socket.nx_udp_socket_receive_head = my_packet;
    dhcp_client.nx_dhcp_socket.nx_udp_socket_receive_count++;
    tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
    tx_thread_sleep(1);

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
#endif

    /* Attempt to cause the DHCP internal packet allocate to fail.*/
    {
        UINT status;
        NX_PACKET* packet1, * packet2, * packet3, * packet4, * packet5;
#ifdef __PRODUCT_NETXDUO__
        status = nx_packet_allocate(dhcp_client.nx_dhcp_packet_pool_ptr, &packet1, NX_IPv4_UDP_PACKET, NX_NO_WAIT);
        status += nx_packet_allocate(dhcp_client.nx_dhcp_packet_pool_ptr, &packet2, NX_IPv4_UDP_PACKET, NX_NO_WAIT);
        status += nx_packet_allocate(dhcp_client.nx_dhcp_packet_pool_ptr, &packet3, NX_IPv4_UDP_PACKET, NX_NO_WAIT);
        status += nx_packet_allocate(dhcp_client.nx_dhcp_packet_pool_ptr, &packet4, NX_IPv4_UDP_PACKET, NX_NO_WAIT);
        status += nx_packet_allocate(dhcp_client.nx_dhcp_packet_pool_ptr, &packet5, NX_IPv4_UDP_PACKET, NX_NO_WAIT);
#else
        status = nx_packet_allocate(dhcp_client.nx_dhcp_packet_pool_ptr, &packet1, NX_UDP_PACKET, NX_NO_WAIT);
        status += nx_packet_allocate(dhcp_client.nx_dhcp_packet_pool_ptr, &packet2, NX_UDP_PACKET, NX_NO_WAIT);
        status += nx_packet_allocate(dhcp_client.nx_dhcp_packet_pool_ptr, &packet3, NX_UDP_PACKET, NX_NO_WAIT);
        status += nx_packet_allocate(dhcp_client.nx_dhcp_packet_pool_ptr, &packet4, NX_UDP_PACKET, NX_NO_WAIT);
        status += nx_packet_allocate(dhcp_client.nx_dhcp_packet_pool_ptr, &packet5, NX_UDP_PACKET, NX_NO_WAIT);
#endif

        my_packet = create_dhcp_packet(1000);
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        nx_packet_release(packet1); nx_packet_release(packet2); nx_packet_release(packet3); nx_packet_release(packet4); nx_packet_release(packet5);
    
    }

    /* Attemp to send a bigger packet to test the case incoming packet bigger than DHCP packets.*/
    my_packet = create_dhcp_packet(1000);
    tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
    tx_thread_sleep(1);

    my_packet = create_dhcp_packet(400);
    my_packet->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_CLIENT_HW + 1] = 2;
    tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
    tx_thread_sleep(1);

    my_packet = create_dhcp_packet(400);
    my_packet->nx_packet_prepend_ptr[NX_BOOTP_OFFSET_CLIENT_HW + 5] = 0x55;
    tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
    tx_thread_sleep(1);

    {
        build_dhcp_packet(400, 0, 0, 0);
        /* intentionally set incorrect state.*/
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_ADDRESS_PROBING + 1;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);
    }
    {
        build_dhcp_packet(400, 0, 0, 0);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_SELECTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);
    }
    {

        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPOFFER+1);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_SELECTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);
    }
    {

        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPOFFER);
        dhcp_your_address = 0;
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_SELECTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        
        dhcp_your_address = 0xFFFFFFFF; 
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPOFFER);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_SELECTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        dhcp_your_address = 0x7F010001;
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPOFFER);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_SELECTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        dhcp_your_address = 0x80010001;
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPOFFER);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_SELECTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);
        
        dhcp_your_address = 0xC0010100;
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPOFFER);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_SELECTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);
    }
    {

        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_SERVER, 1, NX_DHCP_TYPE_DHCPOFFER);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REBINDING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        dhcp_your_address = 0;
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REBINDING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        dhcp_your_address = 0x10203040;
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REBINDING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPNACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REBINDING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPRELEASE);

        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REBINDING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

    }

    {
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_SERVER, 1, NX_DHCP_TYPE_DHCPOFFER);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_RENEWING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        dhcp_your_address = 0;
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_RENEWING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        dhcp_your_address = 0x10203040;
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_RENEWING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPNACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_RENEWING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPRELEASE);

        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_RENEWING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);
    }

    {
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_SERVER, 1, NX_DHCP_TYPE_DHCPOFFER);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REQUESTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);
        
        dhcp_your_address = 0;
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REQUESTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        dhcp_your_address = 0x10203040;
        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REQUESTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPNACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REQUESTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPRELEASE);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REQUESTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);

        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPNACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REQUESTING;
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_timeout = 1;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);


        build_dhcp_packet(400, NX_DHCP_OPTION_DHCP_TYPE, 1, NX_DHCP_TYPE_DHCPNACK);
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_state = NX_DHCP_STATE_REQUESTING;
        dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_renewal_time = NX_IP_PERIODIC_RATE + 1;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_RECEIVE_EVENT, TX_OR);
        tx_thread_sleep(1);
    }

    {
        NX_DHCP_INTERFACE_RECORD *interface_record = &dhcp_client.nx_dhcp_interface_record[0];

        interface_record->nx_dhcp_record_valid = NX_TRUE;
        interface_record->nx_dhcp_timeout = 1;
        interface_record->nx_dhcp_state = NX_DHCP_STATE_INIT;
        interface_record->nx_dhcp_ip_address = 1;
        interface_record->nx_dhcp_skip_discovery = NX_FALSE;
        interface_record->nx_dhcp_rtr_interval = 1;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_TIMER_EVENT, TX_OR);
        tx_thread_sleep(1);

        interface_record->nx_dhcp_record_valid = NX_TRUE;
        interface_record->nx_dhcp_timeout = 1;
        interface_record->nx_dhcp_state = NX_DHCP_STATE_SELECTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_TIMER_EVENT, TX_OR);
        tx_thread_sleep(1);


        interface_record->nx_dhcp_record_valid = NX_TRUE;
        interface_record->nx_dhcp_timeout = 1;
        interface_record->nx_dhcp_state = NX_DHCP_STATE_REQUESTING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_TIMER_EVENT, TX_OR);
        tx_thread_sleep(1);

        interface_record->nx_dhcp_record_valid = NX_TRUE;
        interface_record->nx_dhcp_timeout = 1;
        interface_record->nx_dhcp_state = NX_DHCP_STATE_ADDRESS_PROBING;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_TIMER_EVENT, TX_OR);
        tx_thread_sleep(1);

        interface_record->nx_dhcp_record_valid = NX_TRUE;
        interface_record->nx_dhcp_timeout = 1;
        interface_record->nx_dhcp_state = NX_DHCP_STATE_RENEWING;
        interface_record->nx_dhcp_rtr_interval = 2;
        interface_record->nx_dhcp_renewal_remain_time = 1;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_TIMER_EVENT, TX_OR);
        tx_thread_sleep(1);

        interface_record->nx_dhcp_record_valid = NX_TRUE;
        interface_record->nx_dhcp_timeout = 1;
        interface_record->nx_dhcp_state = NX_DHCP_STATE_RENEWING;
        interface_record->nx_dhcp_rtr_interval = 2;
        interface_record->nx_dhcp_renewal_remain_time = 7;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_TIMER_EVENT, TX_OR);
        tx_thread_sleep(1);

        interface_record->nx_dhcp_record_valid = NX_TRUE;
        interface_record->nx_dhcp_timeout = 1;
        interface_record->nx_dhcp_state = NX_DHCP_STATE_REBINDING;
        interface_record->nx_dhcp_rtr_interval = 2;
        interface_record->nx_dhcp_rebind_remain_time = 1;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_TIMER_EVENT, TX_OR);
        tx_thread_sleep(1);

        interface_record->nx_dhcp_record_valid = NX_TRUE;
        interface_record->nx_dhcp_timeout = 1;
        interface_record->nx_dhcp_state = NX_DHCP_STATE_REBINDING;
        interface_record->nx_dhcp_rtr_interval = 2;
        interface_record->nx_dhcp_rebind_remain_time = 10;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_TIMER_EVENT, TX_OR);
        tx_thread_sleep(1);

        interface_record->nx_dhcp_record_valid = NX_TRUE;
        interface_record->nx_dhcp_timeout = 1;
        interface_record->nx_dhcp_state = 0xFF;
        interface_record->nx_dhcp_rtr_interval = 2;
        interface_record->nx_dhcp_renewal_remain_time = 3;
        tx_event_flags_set(&dhcp_client.nx_dhcp_events, NX_DHCP_CLIENT_TIMER_EVENT, TX_OR);
        tx_thread_sleep(1);

    }

    printf("SUCCESS!\n");
    test_control_return(0);  
    return;
}


void dhcp_state_change(NX_DHCP *dhcp_ptr, UCHAR new_state)
{

    /* Increment state changes counter.  */
    state_changes++;

    return;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_coverage_test_applicaiton_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NetX DHCP Coverage Test...................................N/A\n"); 

    test_control_return(3);  
}      
#endif
