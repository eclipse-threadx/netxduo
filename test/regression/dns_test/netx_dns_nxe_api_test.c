/* NetX DNS Client API error tests.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_udp.h"
#include   "nx_ip.h"
#include   "nxd_dns.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

/* DNS Client Error Checking Test.  */
static void error_checking_test(void);

static NX_IP ip_0;
static NX_DNS dns_0;
static UCHAR temp_uchar;
static UINT temp_uint;
static ULONG temp_ulong;
static USHORT temp_ushort;
static USHORT temp_ushort2; // we need a second ushort to make sure this one is not 32 bit aligned

#ifdef __PRODUCT_NETXDUO__
static NXD_ADDRESS address_0;
#endif

extern volatile ULONG _tx_thread_system_state;
extern TX_THREAD *_tx_thread_current_ptr;
extern TX_THREAD _tx_timer_thread;

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dns_nxe_api_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test: DNS Client Error Checking Test..........................\n");

    static CHAR *pointer;
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    
    error_checking_test();

    printf("SUCCESS!\n");
    test_control_return(0);
}

#define validate_expected_status(status,expected_status) if (expected_status != status) {printf("%s,%d: ERROR!",__FILE__, __LINE__);test_control_return(1);}


static void nxe_dns_server_add_remove_error_check_test(NX_DNS *dns_ptr, ULONG server_address, UINT expected_status)
{
    //_nxe_dns_server_add(NX_DNS *dns_ptr, ULONG server_address)
    validate_expected_status(_nxe_dns_server_add(dns_ptr, server_address), expected_status);

    //_nxe_dns_server_remove(NX_DNS *dns_ptr, ULONG server_address)
    validate_expected_status(_nxe_dns_server_remove(dns_ptr, server_address), expected_status);

    //_nxe_dns_server_remove_all(NX_DNS *dns_ptr)
    if (expected_status != NX_DNS_BAD_ADDRESS_ERROR) {
        validate_expected_status(_nxe_dns_server_remove_all(dns_ptr), expected_status);
    }
}

#ifdef __PRODUCT_NETXDUO__
static void nxde_address_error_checks() {
    dns_0.nx_dns_id = NX_DNS_ID;
    address_0.nxd_ip_version = NX_NULL;
    validate_expected_status(_nxde_dns_server_add(&dns_0, &address_0), NX_DNS_PARAM_ERROR);

    address_0.nxd_ip_version = 0x1;
    validate_expected_status(_nxde_dns_server_add(&dns_0, &address_0), NX_DNS_INVALID_ADDRESS_TYPE);
    validate_expected_status(_nxde_dns_server_remove(&dns_0, &address_0), NX_DNS_INVALID_ADDRESS_TYPE);

    address_0.nxd_ip_version = NX_IP_VERSION_V4;
    address_0.nxd_ip_address.v4 = 0;
    validate_expected_status(_nxde_dns_server_add(&dns_0, &address_0), NX_DNS_BAD_ADDRESS_ERROR);
    validate_expected_status(_nxde_dns_server_remove(&dns_0, &address_0), NX_DNS_BAD_ADDRESS_ERROR);

#ifdef FEATURE_NX_IPV6
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0;
    validate_expected_status(_nxde_dns_server_add(&dns_0, &address_0), NX_DNS_BAD_ADDRESS_ERROR);
    validate_expected_status(_nxde_dns_server_remove(&dns_0, &address_0), NX_DNS_BAD_ADDRESS_ERROR);
#endif
}
#endif

static void nx_dns_id_calls(void)
{
    validate_expected_status(_nxe_dns_delete(&dns_0), NX_CALLER_ERROR); 
    nxe_dns_server_add_remove_error_check_test(&dns_0, 1, NX_CALLER_ERROR); 
    validate_expected_status(_nxe_dns_get_serverlist_size(&dns_0, &temp_uint), NX_CALLER_ERROR);
    validate_expected_status(_nxe_dns_server_get(&dns_0, 0, &temp_ulong), NX_CALLER_ERROR);
    validate_expected_status(_nxe_dns_host_by_name_get(&dns_0, &temp_uchar, &temp_ulong, 1), NX_CALLER_ERROR);
    validate_expected_status(_nxe_dns_ipv4_address_by_name_get(&dns_0, &temp_uchar, (void*)&temp_ulong, 1, &temp_uint, 1), NX_CALLER_ERROR);
    validate_expected_status(_nxe_dns_host_by_address_get(&dns_0, 1, &temp_uchar, 1, 1), NX_CALLER_ERROR);
#ifdef __PRODUCT_NETXDUO__
#ifdef FEATURE_NX_IPV6
    validate_expected_status(_nxde_dns_ipv6_address_by_name_get(&dns_0, &temp_uchar, (void*)&temp_ulong, 1, &temp_uint, 1), NX_CALLER_ERROR);
    validate_expected_status(_nxde_dns_host_by_address_get(&dns_0, &address_0, &temp_uchar, 1, 1), NX_CALLER_ERROR);
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 13;
    address_0.nxd_ip_address.v6[1] = 14;
    address_0.nxd_ip_address.v6[2] = 13;
    address_0.nxd_ip_address.v6[3] = 14;
    validate_expected_status(_nxde_dns_server_add(&dns_0, &address_0), NX_CALLER_ERROR);
#endif    
    address_0.nxd_ip_version = NX_IP_VERSION_V4;
    address_0.nxd_ip_address.v4 = 1314;
    validate_expected_status(_nxde_dns_server_add(&dns_0, &address_0), NX_CALLER_ERROR);
    validate_expected_status(_nxde_dns_server_remove(&dns_0, &address_0), NX_CALLER_ERROR);
    validate_expected_status(_nxde_dns_server_get(&dns_0, 0, &address_0), NX_CALLER_ERROR);
    validate_expected_status(_nxde_dns_host_by_name_get(&dns_0, &temp_uchar, &address_0, 0, 1), NX_CALLER_ERROR);
#endif
}

static void error_checking_test(void)
{
    validate_expected_status(_nxe_dns_create(NX_NULL, NX_NULL, NX_NULL), NX_PTR_ERROR);

#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL
    validate_expected_status(_nxe_dns_packet_pool_set(NX_NULL, NX_NULL), NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_packet_pool_set(&dns_0, NX_NULL), NX_PTR_ERROR);
#endif

    validate_expected_status(_nxe_dns_delete(NX_NULL), NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_get_serverlist_size(NX_NULL, NX_NULL), NX_PTR_ERROR); 
    validate_expected_status(_nxe_dns_server_get(NX_NULL, 0, NX_NULL), NX_PTR_ERROR);
    nxe_dns_server_add_remove_error_check_test(NX_NULL, 1, NX_PTR_ERROR);

    validate_expected_status(_nxe_dns_host_by_name_get(NX_NULL, NX_NULL, NX_NULL, 1), NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_host_by_name_get(&dns_0, NX_NULL, NX_NULL, 1), NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_host_by_name_get(&dns_0, &temp_uchar, NX_NULL, 1), NX_PTR_ERROR);
        
    validate_expected_status(_nxe_dns_ipv4_address_by_name_get(NX_NULL, &temp_uchar, (void*)&temp_ulong, 1, &temp_uint, 1), NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_ipv4_address_by_name_get(&dns_0, NX_NULL, (void*)&temp_ulong, 1, &temp_uint, 1), NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_ipv4_address_by_name_get(&dns_0, &temp_uchar, NX_NULL, 1, &temp_uint, 1), NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_ipv4_address_by_name_get(&dns_0, &temp_uchar, (void*)&temp_ulong, 1, NX_NULL, 1), NX_PTR_ERROR);

    validate_expected_status(_nxe_dns_host_by_address_get(NX_NULL, 1, &temp_uchar, 1, 1), NX_PTR_ERROR);    
    validate_expected_status(_nxe_dns_host_by_address_get(&dns_0, 1, NX_NULL, 1, 1), NX_PTR_ERROR);    

#ifdef __PRODUCT_NETXDUO__
    validate_expected_status(_nxde_dns_ipv6_address_by_name_get(NX_NULL, &temp_uchar, (void*)&temp_ulong, 1, &temp_uint, 1), NX_PTR_ERROR); 
    validate_expected_status(_nxde_dns_ipv6_address_by_name_get(&dns_0, NX_NULL, (void*)&temp_ulong, 1, &temp_uint, 1), NX_PTR_ERROR); 
    validate_expected_status(_nxde_dns_ipv6_address_by_name_get(&dns_0, &temp_uchar, NX_NULL, 1, &temp_uint, 1), NX_PTR_ERROR); 
    validate_expected_status(_nxde_dns_ipv6_address_by_name_get(&dns_0, &temp_uchar, (void*)&temp_ulong, 1, NX_NULL, 1), NX_PTR_ERROR);


    validate_expected_status(_nxde_dns_host_by_address_get(NX_NULL, &address_0, &temp_uchar, 1, 1), NX_PTR_ERROR);
    validate_expected_status(_nxde_dns_host_by_address_get(&dns_0, NX_NULL, &temp_uchar, 1, 1), NX_PTR_ERROR);
    validate_expected_status(_nxde_dns_host_by_address_get(&dns_0, &address_0, NX_NULL, 1, 1), NX_PTR_ERROR);

    validate_expected_status(_nxde_dns_server_add(NX_NULL, &address_0), NX_PTR_ERROR);
    validate_expected_status(_nxde_dns_server_add(&dns_0, NX_NULL), NX_PTR_ERROR);

    validate_expected_status(_nxde_dns_server_remove(NX_NULL, &address_0), NX_PTR_ERROR);
    validate_expected_status(_nxde_dns_server_remove(&dns_0, NX_NULL), NX_PTR_ERROR);

    validate_expected_status(_nxde_dns_server_get(NX_NULL, 0, &address_0), NX_PTR_ERROR);
    validate_expected_status(_nxde_dns_server_get(&dns_0, 0, NX_NULL), NX_PTR_ERROR);
    
    //_nxde_dns_host_by_name_get(NX_DNS *dns_ptr, UCHAR *host_name, NXD_ADDRESS *host_address_ptr, ULONG wait_option, UINT lookup_type)
    validate_expected_status(_nxde_dns_host_by_name_get(NX_NULL, &temp_uchar, &address_0, 0, 0), NX_PTR_ERROR);
    validate_expected_status(_nxde_dns_host_by_name_get(&dns_0, NX_NULL, &address_0, 0, 0), NX_PTR_ERROR);
    validate_expected_status(_nxde_dns_host_by_name_get(&dns_0, &temp_uchar, NX_NULL, 0, 0), NX_PTR_ERROR);
    nxde_address_error_checks();
#endif

    ip_0.nx_ip_id = 0;
    validate_expected_status(_nxe_dns_create(NX_NULL, &ip_0, NX_NULL), NX_PTR_ERROR);

    ip_0.nx_ip_id = NX_IP_ID;
    validate_expected_status(_nxe_dns_create(NX_NULL, &ip_0, NX_NULL), NX_PTR_ERROR);
    
    dns_0.nx_dns_id = NX_DNS_ID;

    validate_expected_status(_nxe_dns_host_by_address_get(&dns_0, 0, &temp_uchar, 1, 1), NX_DNS_PARAM_ERROR);    
    validate_expected_status(_nxe_dns_host_by_address_get(&dns_0, 1, &temp_uchar, 0, 1), NX_DNS_PARAM_ERROR);    

#ifdef __PRODUCT_NETXDUO__
    validate_expected_status(_nxde_dns_host_by_address_get(&dns_0, &address_0, &temp_uchar, 0, 1), NX_DNS_PARAM_ERROR);
#endif

    validate_expected_status(_nxe_dns_create(&dns_0, &ip_0, NX_NULL), NX_PTR_ERROR);

    // Alignment check tests
    validate_expected_status(_nxe_dns_ipv4_address_by_name_get(&dns_0, &temp_uchar, (void*)&temp_ushort2 - 1, 1, &temp_uint, 1), NX_PTR_ERROR);
#ifdef __PRODUCT_NETXDUO__
    validate_expected_status(_nxde_dns_ipv6_address_by_name_get(&dns_0, &temp_uchar, (void*)&temp_ushort2 - 1, 1, &temp_uint, 1), NX_PTR_ERROR);
#endif

    nxe_dns_server_add_remove_error_check_test(&dns_0, 0, NX_DNS_BAD_ADDRESS_ERROR);
    validate_expected_status(_nxe_dns_get_serverlist_size(&dns_0, NX_NULL), NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_server_get(&dns_0, 0, NX_NULL), NX_PTR_ERROR);

    // apis that require requires nx_dns_id == NX_DNS_ID for the thread state tests
    _tx_thread_system_state = 1;
    nx_dns_id_calls();

    _tx_thread_system_state = 0;
    _tx_thread_current_ptr = TX_NULL;
    nx_dns_id_calls();

    _tx_thread_current_ptr = &_tx_timer_thread;
    nx_dns_id_calls();

#ifdef __PRODUCT_NETXDUO__
    validate_expected_status(_nxde_dns_host_by_name_get(&dns_0, &temp_uchar, &address_0, 0, 0), NX_DNS_PARAM_ERROR);
#endif

    dns_0.nx_dns_id = 0;
    validate_expected_status(_nxe_dns_delete(&dns_0), NX_PTR_ERROR);
    nxe_dns_server_add_remove_error_check_test(&dns_0, 1, NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_get_serverlist_size(&dns_0, 0), NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_server_get(&dns_0, 0, NX_NULL), NX_PTR_ERROR);
    validate_expected_status(_nxe_dns_host_by_name_get(&dns_0, &temp_uchar, &temp_ulong, 1), NX_DNS_PARAM_ERROR);
    validate_expected_status(_nxe_dns_ipv4_address_by_name_get(&dns_0, &temp_uchar, (void*)&temp_ulong, 1, &temp_uint, 1), NX_DNS_PARAM_ERROR);
    validate_expected_status(_nxe_dns_host_by_address_get(&dns_0, 1, &temp_uchar, 1, 1), NX_DNS_PARAM_ERROR);
#ifdef __PRODUCT_NETXDUO__
    validate_expected_status(_nxde_dns_ipv6_address_by_name_get(&dns_0, &temp_uchar, (void*)&temp_ulong, 1, &temp_uint, 1), NX_DNS_PARAM_ERROR);
    validate_expected_status(_nxde_dns_host_by_address_get(&dns_0, &address_0, &temp_uchar, 1, 1), NX_DNS_PARAM_ERROR);
    validate_expected_status(_nxde_dns_server_add(&dns_0, &address_0), NX_DNS_PARAM_ERROR);
    validate_expected_status(_nxde_dns_server_remove(&dns_0, &address_0), NX_PTR_ERROR);
    validate_expected_status(_nxde_dns_server_get(&dns_0, 0, &address_0), NX_PTR_ERROR);
    validate_expected_status(_nxde_dns_host_by_name_get(&dns_0, &temp_uchar, &address_0, 0, 1), NX_DNS_PARAM_ERROR);
#endif

    // apis that require requires nx_dns_id == 0 for the thread state tests
    _tx_thread_system_state = 1;
    validate_expected_status(_nxe_dns_create(&dns_0, &ip_0, NX_NULL), NX_CALLER_ERROR);

    _tx_thread_system_state = 0;
    _tx_thread_current_ptr = TX_NULL;
    validate_expected_status(_nxe_dns_create(&dns_0, &ip_0, NX_NULL), NX_CALLER_ERROR);

    _tx_thread_current_ptr = &_tx_timer_thread;
    validate_expected_status(_nxe_dns_create(&dns_0, &ip_0, NX_NULL), NX_CALLER_ERROR);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dns_api_error_test_application_define(void *first_unused_memory)
#endif
{
    /* Print out test information banner.  */
    printf("NetX Test: DNS Client Error Checking Test.......................N/A\n");
    test_control_return(3);  
}      
#endif