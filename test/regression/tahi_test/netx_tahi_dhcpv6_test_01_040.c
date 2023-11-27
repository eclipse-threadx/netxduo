#include "tx_api.h"
#include "nx_api.h"
#include "netx_tahi.h"
#if defined(FEATURE_NX_IPV6) && defined(NX_TAHI_ENABLE)
#include "nx_udp.h"
#include "nx_ip.h"
#include "nx_ipv6.h"
#include "nxd_dhcpv6_client.h"


#define     DEMO_STACK_SIZE     2048
#define     TEST_INTERFACE      0
#define     DHCPV6_IANA_ID      0xC0DEDBAD

static TX_THREAD                dhcpv6_client_thread;
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static NX_DHCPV6                dhcp_client;

static ULONG                    error_counter;

static void dhcpv6_client_thread_entry(ULONG thread_input);
extern void test_control_return(UINT status);
extern void _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern UINT tahi_dhcpv6_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
extern void tahi_dhcpv6_udp_packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

extern TAHI_TEST_SEQ tahi_dhcpv6_01_040[];
extern int  tahi_dhcpv6_01_040_size;

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_tahi_dhcpv6_test_01_040_define(void * first_unused_memory)
#endif
{
CHAR    *pointer;
UINT    status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;
    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);
    if(status)
        error_counter++;

    status = nx_udp_enable(&ip_0);
    if(status)
        error_counter++;

    /* Enable fragment processing for IP Instance 0.  */
    status = nx_ip_fragment_enable(&ip_0);
    if(status)
        error_counter++;

    /* Create a DHCPv6 Client. */
    status = nx_dhcpv6_client_create(&dhcp_client, &ip_0, "DHCPv6 Client", &pool_0, pointer, 2048, NX_NULL, NX_NULL);
    pointer += 2048;
    if(status)
        error_counter++;

    /* Create the main thread.  */
    tx_thread_create(&dhcpv6_client_thread, "dhcpv6 client thread", dhcpv6_client_thread_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

}

void dhcpv6_client_thread_entry(ULONG thread_input)
{
NXD_ADDRESS ipv6_address;
UINT        status;

    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);
    if(status)
        error_counter++;

    /* Create a Link Layer Plus Time DUID for the DHCPv6 Client. Set time ID field 
       to NULL; the DHCPv6 Client API will supply one. */
    status = nx_dhcpv6_create_client_duid(&dhcp_client, NX_DHCPV6_DUID_TYPE_LINK_TIME, 
            NX_DHCPV6_HW_TYPE_IEEE_802, 0);
    if(status)
        error_counter++;

    /* Create the DHCPv6 client's Identity Association (IA-NA) now. */
    status = nx_dhcpv6_create_client_iana(&dhcp_client, DHCPV6_IANA_ID, 0xFFFFFFFF,  0xFFFFFFFF); 
    if(status)
        error_counter++;

    memset(&ipv6_address,0x0, sizeof(NXD_ADDRESS)); 
    ipv6_address.nxd_ip_version = NX_IP_VERSION_V6 ;

    /* Create an IA address option. */
    if((ipv6_address.nxd_ip_address.v6[0] != 0) ||
       (ipv6_address.nxd_ip_address.v6[1] != 0) ||
       (ipv6_address.nxd_ip_address.v6[2] != 0) ||
       (ipv6_address.nxd_ip_address.v6[3] != 0))
    {

        status = nx_dhcpv6_create_client_ia(&dhcp_client, &ipv6_address, 0xFFFFFFFF, 
                0xFFFFFFFF);

        if (status != NX_SUCCESS)
        {
            return;
        }
    }

    /* Set the list of desired options to enabled. */
    nx_dhcpv6_request_option_timezone(&dhcp_client, NX_TRUE); 
    nx_dhcpv6_request_option_DNS_server(&dhcp_client, NX_TRUE);
    nx_dhcpv6_request_option_time_server(&dhcp_client, NX_TRUE);
    nx_dhcpv6_request_option_domain_name(&dhcp_client, NX_TRUE);

    /* Wait to finish the DAD. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Start the NetX DHCPv6 Client.  */
    status =  nx_dhcpv6_start(&dhcp_client); 

    advanced_packet_process_callback = tahi_dhcpv6_packet_process;
    ip_0.nx_ip_udp_packet_receive = tahi_dhcpv6_udp_packet_receive;

    status = nx_dhcpv6_request_solicit(&dhcp_client);            

    netx_tahi_run_test_case(&ip_0, &tahi_dhcpv6_01_040[0], tahi_dhcpv6_01_040_size);

    nx_dhcpv6_client_delete(&dhcp_client);

    test_control_return(0xdeadbeef);
}
#endif
