
#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
#include   "nxd_dhcp_client.h"
#include   "nxd_dhcp_server.h"

#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         NX_PACKET_SIZE * 8

#define     NX_DHCP_SERVER_IP_ADDRESS_0 IP_ADDRESS(10,0,0,1)   
#define     START_IP_ADDRESS_LIST_0     IP_ADDRESS(10,0,0,10)
#define     END_IP_ADDRESS_LIST_0       IP_ADDRESS(10,0,0,19)

#define     NX_DHCP_SUBNET_MASK_0       IP_ADDRESS(255,255,255,0)
#define     NX_DHCP_DEFAULT_GATEWAY_0   IP_ADDRESS(10,0,0,1)
#define     NX_DHCP_DNS_SERVER_0        IP_ADDRESS(10,0,0,1)
static NX_IP ip_0;
static NX_DHCP dhcp_client;
static NX_PACKET_POOL pool_0;
static NX_PACKET_POOL pool_1;
ULONG  stack_area[100];

static void error_checking_test(void);
extern volatile ULONG _tx_thread_system_state;
extern TX_THREAD *_tx_thread_current_ptr;
extern TX_THREAD _tx_timer_thread;

extern void    _nx_ram_network_driver_1024(struct NX_IP_DRIVER_STRUCT *driver_req);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

static CHAR                    *pointer;

    printf("NetX Test:   DHCP Client Error Checking  Test..........................");

    /* Create an IP instance for the DHCP Client.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;
    nx_ip_create(&ip_0, "DHCP Client", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1024, pointer, 2048, 1);

    
    _tx_thread_system_state = 0;    
    error_checking_test();
    _tx_thread_system_state = 1;
    error_checking_test();
    _tx_thread_system_state = 0;
    _tx_thread_current_ptr = TX_NULL;
    error_checking_test();
    _tx_thread_current_ptr = &_tx_timer_thread;
    error_checking_test();

    printf("SUCCESS!\n");
    test_control_return(0);    

}

static void error_checking_test(void)
{


UINT    status;
UCHAR   buf[4];
ULONG   val_ulong;

    /* Test _nxe_dhcp_create */
    _nxe_dhcp_create(0, 0, NX_NULL);
    ip_0.nx_ip_id = 0;
    _nxe_dhcp_create(0, &ip_0, NX_NULL);
    ip_0.nx_ip_id = NX_IP_ID;
    _nxe_dhcp_create(0, &ip_0, NX_NULL);
    

    /* Test _nxe_dhcp_clear_broadcast_flag */
    _nxe_dhcp_clear_broadcast_flag(NX_NULL, 0);

    /* Test _nxe_dhcp_interface_clear_broadcast_flag */
    _nxe_dhcp_interface_clear_broadcast_flag(NX_NULL, 0, 0);
    _nxe_dhcp_interface_clear_broadcast_flag(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES, 0);

    
    /* Test _nxe_dhcp_packet_pool_set */
    _nxe_dhcp_packet_pool_set(&dhcp_client, NX_NULL);
    _nxe_dhcp_packet_pool_set(NX_NULL, NX_NULL);
    pool_1.nx_packet_pool_payload_size = 0;
    _nxe_dhcp_packet_pool_set(&dhcp_client, &pool_1);

    /* Test _nxe_dhcp_reinitialize */
    _nxe_dhcp_reinitialize(NX_NULL);

    /* Test _nxe_dhcp_interface_reinitialize */
    _nxe_dhcp_interface_reinitialize(NX_NULL, 0);
    _nxe_dhcp_interface_reinitialize(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES);

    /* This one shall fail at "NX_THREADS_ONLY_CALLER_CHECKING */
    _nxe_dhcp_interface_reinitialize(&dhcp_client, 0); 

    /* Test _nxe_dhcp_request_client_ip */
    _nxe_dhcp_request_client_ip(NX_NULL, 0, 0);
    _nxe_dhcp_request_client_ip(&dhcp_client, NX_BOOTP_NO_ADDRESS, 0);

    /* Test _nxe_dhcp_interface_request_client_ip */
    _nxe_dhcp_interface_request_client_ip(NX_NULL, 0, 0, 0);
    _nxe_dhcp_interface_request_client_ip(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES, 0, 0);

    /* Test _nxe_dhcp_delete */
    _nxe_dhcp_delete(NX_NULL);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_delete(&dhcp_client);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_delete(&dhcp_client);

    /* Test _nxe_dhcp_force_renew */
    _nxe_dhcp_force_renew(NX_NULL);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_force_renew(&dhcp_client);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_force_renew(&dhcp_client);

    /* Test _nxe_dhcp_interface_force_renew */
    _nxe_dhcp_interface_force_renew(NX_NULL, 0);
    _nxe_dhcp_interface_force_renew(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES);

    /* Test _nxe_dhcp_decline */
    _nxe_dhcp_decline(NX_NULL);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_decline(&dhcp_client);    
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_decline(&dhcp_client);    


    /* Test _nxe_dhcp_interface_decline */
    _nxe_dhcp_interface_decline(NX_NULL, 0);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_interface_decline(&dhcp_client, 0);    
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_interface_decline(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES);    
    _nxe_dhcp_interface_decline(&dhcp_client, 0);    

    /* Test _nxe_dhcp_release */
    _nxe_dhcp_release(NX_NULL);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_release(&dhcp_client);    
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_release(&dhcp_client);    

    /* _nxe_dhcp_interface_release */
    _nxe_dhcp_interface_release(NX_NULL, 0);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_interface_release(&dhcp_client,  0);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_interface_release(&dhcp_client,  NX_MAX_PHYSICAL_INTERFACES);
    _nxe_dhcp_interface_release(&dhcp_client,  0);

    /* Test _nxe_dhcp_start */
    _nxe_dhcp_start(NX_NULL);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_start(&dhcp_client);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_start(&dhcp_client);

    /* Test _nxe_dhcp_interface_start */
    _nxe_dhcp_interface_start(NX_NULL, 0);
    _nxe_dhcp_interface_start(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES);
    _nxe_dhcp_interface_start(&dhcp_client, 0);

    /* Test _nxe_dhcp_interface_enable */
    _nxe_dhcp_interface_enable(NX_NULL, 0);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_interface_enable(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES);


    /* Test _nxe_dhcp_interface_disable */
    _nxe_dhcp_interface_disable(NX_NULL, 0);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_interface_disable(&dhcp_client, 0);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_interface_disable(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES);

    /* Test _nxe_dhcp_state_change_notify */
    _nxe_dhcp_state_change_notify(NX_NULL, NX_NULL);
    dhcp_client.nx_dhcp_id = 0;    
    _nxe_dhcp_state_change_notify(&dhcp_client, NX_NULL);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;    
    _nxe_dhcp_state_change_notify(&dhcp_client, NX_NULL);

    /* _nxe_dhcp_interface_state_change_notify */
    _nxe_dhcp_interface_state_change_notify(NX_NULL, NX_NULL);
    dhcp_client.nx_dhcp_id = 0;    
    _nxe_dhcp_interface_state_change_notify(&dhcp_client, NX_NULL);

    /* Test _nxe_dhcp_stop */
//    nx_dhcp_create(&dhcp_client, &ip_0, "dhcp_client");
    _nxe_dhcp_stop(NX_NULL);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_stop(&dhcp_client);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_stop(&dhcp_client);
//    nx_dhcp_delete(&dhcp_client);


    /* Test _nxe_dhcp_interface_stop  */
    _nxe_dhcp_interface_stop(NX_NULL, 0);
    _nxe_dhcp_interface_stop(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES);
    _nxe_dhcp_interface_stop(&dhcp_client, 0);

    /* Test _nxe_dhcp_user_option_retrieve */
    _nxe_dhcp_user_option_retrieve(NX_NULL, 0, NX_NULL, NX_NULL);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_user_option_retrieve(&dhcp_client, 0, NX_NULL, NX_NULL);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;    
    _nxe_dhcp_user_option_retrieve(&dhcp_client, 0, NX_NULL, NX_NULL);
    _nxe_dhcp_user_option_retrieve(&dhcp_client, 0, buf, NX_NULL);
    status = sizeof(buf);
    _nxe_dhcp_user_option_retrieve(&dhcp_client, 0, buf, &status);

    /* Test _nxe_dhcp_user_option_request */
    _nxe_dhcp_user_option_request(NX_NULL, 0);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_user_option_request(&dhcp_client, 0);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_user_option_request(&dhcp_client, 0);
    
    /* Test _nxe_dhcp_interface_user_option_retrieve */
    _nxe_dhcp_interface_user_option_retrieve(NX_NULL, 0, 0, NX_NULL, NX_NULL);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 0, NX_NULL, NX_NULL);
    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
    _nxe_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 0, NX_NULL, NX_NULL);
    _nxe_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 0, buf, NX_NULL);
    _nxe_dhcp_interface_user_option_retrieve(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES, 0, buf, &status);
    _nxe_dhcp_interface_user_option_retrieve(&dhcp_client, 0, 0, buf, &status);

    /* Test _nxe_dhcp_user_option_convert */
    _nxe_dhcp_user_option_convert(NX_NULL);

    /* Test _nxe_dhcp_user_option_add_callback_set */
    _nxe_dhcp_user_option_add_callback_set(NX_NULL, NX_NULL);
    dhcp_client.nx_dhcp_id = 0;
    _nxe_dhcp_user_option_add_callback_set(&dhcp_client, NX_NULL);

    /* Test _nxe_dhcp_server_address_get */
    _nxe_dhcp_server_address_get(NX_NULL, NX_NULL);
    _nxe_dhcp_server_address_get(&dhcp_client, NX_NULL);
    _nxe_dhcp_server_address_get(&dhcp_client, &val_ulong);

    /* Test _nxe_dhcp_interface_server_address_get */
    _nxe_dhcp_interface_server_address_get(NX_NULL, 0, NX_NULL);
    _nxe_dhcp_interface_server_address_get(&dhcp_client, 0, NX_NULL);
    _nxe_dhcp_interface_server_address_get(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES, &val_ulong);
    _nxe_dhcp_interface_server_address_get(&dhcp_client, 0, &val_ulong);
    

    /* Test _nxe_dhcp_set_interface_index  */
    _nxe_dhcp_set_interface_index(NX_NULL, 0);
    _nxe_dhcp_set_interface_index(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES);

    /* Test _nxe_dhcp_send_request */
    _nxe_dhcp_send_request(NX_NULL, 0);
    _nxe_dhcp_send_request(&dhcp_client, 0);
    _nxe_dhcp_send_request(&dhcp_client, NX_DHCP_TYPE_DHCPFORCERENEW + 1);

    /* Test _nxe_dhcp_interface_send_request*/
    nx_dhcp_interface_send_request(NX_NULL, 0, 0);
    nx_dhcp_interface_send_request(&dhcp_client, NX_MAX_PHYSICAL_INTERFACES + 1, 0);
    nx_dhcp_interface_send_request(&dhcp_client, 0, 0);

    dhcp_client.nx_dhcp_id = NX_DHCP_ID;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

static CHAR                    *pointer;

    printf("NetX Test:   DHCP Client Error Checking  Test..........................N/A\n");

    test_control_return(3);
}
#endif