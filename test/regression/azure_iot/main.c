/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/

#include "nx_api.h"
#include "nx_azure_iot.h"
#ifndef DEMO_DHCP_DISABLE
#include "nxd_dhcp_client.h"
#endif /* DEMO_DHCP_DISABLE */
#include "nxd_dns.h"
#include "nx_secure_tls_api.h"
#include <setjmp.h>
#include <cmocka.h>  /* macros: https://api.cmocka.org/group__cmocka__asserts.html */

/* Include the demo.  */
extern VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time));

/* Define the helper thread for running Azure SDK on ThreadX (THREADX IoT Platform).  */
#ifndef DEMO_HELPER_STACK_SIZE
#define DEMO_HELPER_STACK_SIZE      (2048)
#endif /* DEMO_HELPER_STACK_SIZE  */

#ifndef DEMO_HELPER_THREAD_PRIORITY
#define DEMO_HELPER_THREAD_PRIORITY (4)
#endif /* DEMO_HELPER_THREAD_PRIORITY  */

/* Define user configurable symbols. */
#ifndef DEMO_IP_STACK_SIZE
#define DEMO_IP_STACK_SIZE          (2048)
#endif /* DEMO_IP_STACK_SIZE  */

#ifndef DEMO_PACKET_COUNT
#define DEMO_PACKET_COUNT           (32)
#endif /* DEMO_PACKET_COUNT  */

#ifndef DEMO_PACKET_SIZE
#define DEMO_PACKET_SIZE            (1536)
#endif /* DEMO_PACKET_SIZE  */

#define DEMO_POOL_SIZE              ((DEMO_PACKET_SIZE + sizeof(NX_PACKET)) * DEMO_PACKET_COUNT)

#ifndef DEMO_ARP_CACHE_SIZE
#define DEMO_ARP_CACHE_SIZE         (512)
#endif /* DEMO_ARP_CACHE_SIZE  */

#ifndef DEMO_IP_THREAD_PRIORITY
#define DEMO_IP_THREAD_PRIORITY     (1)
#endif /* DEMO_IP_THREAD_PRIORITY */

#ifdef DEMO_DHCP_DISABLE
#ifndef DEMO_IPV4_ADDRESS
/*#define DEMO_IPV4_ADDRESS         IP_ADDRESS(192, 168, 100, 33)*/
#error "SYMBOL DEMO_IPV4_ADDRESS must be defined. This symbol specifies the IP address of device. "
#endif /* DEMO_IPV4_ADDRESS */

#ifndef DEMO_IPV4_MASK
/*#define DEMO_IPV4_MASK            0xFFFFFF00UL*/
#error "SYMBOL DEMO_IPV4_MASK must be defined. This symbol specifies the IP address mask of device. "
#endif /* DEMO_IPV4_MASK */

#ifndef DEMO_GATEWAY_ADDRESS
/*#define DEMO_GATEWAY_ADDRESS      IP_ADDRESS(192, 168, 100, 1)*/
#error "SYMBOL DEMO_GATEWAY_ADDRESS must be defined. This symbol specifies the gateway address for routing. "
#endif /* DEMO_GATEWAY_ADDRESS */

#ifndef DEMO_DNS_SERVER_ADDRESS
/*#define DEMO_DNS_SERVER_ADDRESS   IP_ADDRESS(192, 168, 100, 1)*/
#error "SYMBOL DEMO_DNS_SERVER_ADDRESS must be defined. This symbol specifies the dns server address for routing. "
#endif /* DEMO_DNS_SERVER_ADDRESS */
#else
#define DEMO_IPV4_ADDRESS           IP_ADDRESS(0, 0, 0, 0)
#define DEMO_IPV4_MASK              IP_ADDRESS(0, 0, 0, 0)
#endif /* DEMO_DHCP_DISABLE */

#ifndef NETWORK_DRIVER
#define NETWORK_DRIVER              _nx_pcap_network_driver
#endif /* NETWORK_DRIVER */


static TX_THREAD        demo_helper_thread;
static NX_PACKET_POOL   pool_0;
static NX_IP            ip_0;
static NX_DNS           dns_0;
#ifndef DEMO_DHCP_DISABLE
static NX_DHCP          dhcp_0;
#endif /* DEMO_DHCP_DISABLE  */


/* Define the stack/cache for ThreadX.  */
static ULONG demo_ip_stack[DEMO_IP_STACK_SIZE / sizeof(ULONG)];
#ifndef DEMO_POOL_STACK_USER
static ULONG demo_pool_stack[DEMO_POOL_SIZE / sizeof(ULONG)];
static ULONG demo_pool_stack_size = sizeof(demo_pool_stack);
#else
extern ULONG demo_pool_stack[];
extern ULONG demo_pool_stack_size;
#endif
static ULONG demo_arp_cache_area[DEMO_ARP_CACHE_SIZE / sizeof(ULONG)];
static ULONG demo_helper_thread_stack[DEMO_HELPER_STACK_SIZE / sizeof(ULONG)];

/* Define the prototypes for demo thread.  */
static void demo_helper_thread_entry(ULONG parameter);
static void test_entry(void **state);

#ifndef DEMO_DHCP_DISABLE
static void dhcp_wait();
#endif /* DEMO_DHCP_DISABLE */

static UINT dns_create();

static UINT unix_time_get(ULONG *unix_time);

/* Include the platform IP driver. */
extern void NETWORK_DRIVER(NX_IP_DRIVER*);

int g_argc = 0;
char **g_argv = NULL;

/* Define main entry point.  */
int main(int argc, char **argv)
{

    /* Initialize random seed. */
    srand(time(0));

    /* Save arguments passed from command line. */
    g_argc = argc;
    g_argv = argv;

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
}

/* Define what the initial system looks like.  */
void    tx_application_define(void *first_unused_memory)
{

UINT  status;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", DEMO_PACKET_SIZE,
            (UCHAR *)demo_pool_stack , demo_pool_stack_size);

    /* Check for pool creation error.  */
    if (status)
    {
        printf("nx_packet_pool_create fail: %u\r\n", status);
        return;
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0",
                          DEMO_IPV4_ADDRESS, DEMO_IPV4_MASK,
                          &pool_0, NETWORK_DRIVER,
                          (UCHAR*)demo_ip_stack, sizeof(demo_ip_stack),
                          DEMO_IP_THREAD_PRIORITY);

    /* Check for IP create errors.  */
    if (status)
    {
        printf("nx_ip_create fail: %u\r\n", status);
        return;
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (VOID *)demo_arp_cache_area, sizeof(demo_arp_cache_area));

    /* Check for ARP enable errors.  */
    if (status)
    {
        printf("nx_arp_enable fail: %u\r\n", status);
        return;
    }

    /* Enable ICMP traffic.  */
    status = nx_icmp_enable(&ip_0);

    /* Check for ICMP enable errors.  */
    if (status)
    {
        printf("nx_icmp_enable fail: %u\r\n", status);
        return;
    }

    /* Enable TCP traffic.  */
    status = nx_tcp_enable(&ip_0);

    /* Check for TCP enable errors.  */
    if (status)
    {
        printf("nx_tcp_enable fail: %u\r\n", status);
        return;
    }

    /* Enable UDP traffic.  */
    status = nx_udp_enable(&ip_0);

    /* Check for UDP enable errors.  */
    if (status)
    {
        printf("nx_udp_enable fail: %u\r\n", status);
        return;
    }

    /* Initialize TLS.  */
    nx_secure_tls_initialize();
    
    /* Create demo helper thread. */
    status = tx_thread_create(&demo_helper_thread, "Demo Thread",
                              demo_helper_thread_entry, 0,
                              demo_helper_thread_stack, DEMO_HELPER_STACK_SIZE,
                              DEMO_HELPER_THREAD_PRIORITY, DEMO_HELPER_THREAD_PRIORITY, 
                              TX_NO_TIME_SLICE, TX_AUTO_START);    
    
    /* Check status.  */
    if (status)
    {
        printf("Demo helper thread creation fail: %u\r\n", status);
        return;
    }
}

/* Define demo helper thread entry.  */
void demo_helper_thread_entry(ULONG parameter)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test(test_entry),
    };

    setbuf(stdout, NULL);
    exit(cmocka_run_group_tests(tests, NULL, NULL));
}

static void log_callback(az_log_classification classification, UCHAR *msg, UINT msg_len)
{
    if (classification == AZ_LOG_IOT_AZURERTOS)
    {
        printf("%.*s", msg_len, (CHAR *)msg);
    }
}

static void test_entry(void **state)
{
UINT    status;
ULONG   ip_address = 0;
ULONG   network_mask = 0;
ULONG   gateway_address = 0;

#ifndef DEMO_DHCP_DISABLE
    dhcp_wait();
#else
    nx_ip_gateway_address_set(&ip_0, DEMO_GATEWAY_ADDRESS);
#endif /* DEMO_DHCP_DISABLE  */

    /* Get IP address and gateway address. */
    nx_ip_address_get(&ip_0, &ip_address, &network_mask);
    nx_ip_gateway_address_get(&ip_0, &gateway_address);

    /* Output IP address and gateway address. */
    printf("IP address: %lu.%lu.%lu.%lu\r\n",
           (ip_address >> 24),
           (ip_address >> 16 & 0xFF),
           (ip_address >> 8 & 0xFF),
           (ip_address & 0xFF));
    printf("Mask: %lu.%lu.%lu.%lu\r\n",
           (network_mask >> 24),
           (network_mask >> 16 & 0xFF),
           (network_mask >> 8 & 0xFF),
           (network_mask & 0xFF));
    printf("Gateway: %lu.%lu.%lu.%lu\r\n",
           (gateway_address >> 24),
           (gateway_address >> 16 & 0xFF),
           (gateway_address >> 8 & 0xFF),
           (gateway_address & 0xFF));

    /* Create DNS.  */
    status = dns_create();

    /* Check for DNS create errors.  */
    if (status)
    {
        printf("dns_create fail: %u\r\n", status);
        return;
    }

    nx_azure_iot_log_init(log_callback);

    /* Start demo.  */
    demo_entry(&ip_0, &pool_0, &dns_0, unix_time_get);
}

#ifndef DEMO_DHCP_DISABLE
static void dhcp_wait()
{
ULONG   actual_status;

    printf("DHCP In Progress...\r\n");

    /* Create the DHCP instance.  */
    nx_dhcp_create(&dhcp_0, &ip_0, "DHCP Client");

    /* Start the DHCP Client.  */
    nx_dhcp_start(&dhcp_0);

    /* Wait util address is solved. */
    nx_ip_status_check(&ip_0, NX_IP_ADDRESS_RESOLVED, &actual_status, NX_WAIT_FOREVER);
}
#endif /* DEMO_DHCP_DISABLE  */

static UINT dns_create()
{

UINT    status;
ULONG   dns_server_address[3];
UINT    dns_server_address_size = 12;

    /* Create a DNS instance for the Client.  Note this function will create
       the DNS Client packet pool for creating DNS message packets intended
       for querying its DNS server. */
    status = nx_dns_create(&dns_0, &ip_0, (UCHAR *)"DNS Client");
    if (status)
    {
        return(status);
    }

    /* Is the DNS client configured for the host application to create the packet pool? */
#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL

    /* Yes, use the packet pool created above which has appropriate payload size
       for DNS messages. */
    status = nx_dns_packet_pool_set(&dns_0, ip_0.nx_ip_default_packet_pool);
    if (status)
    {
        nx_dns_delete(&dns_0);
        return(status);
    }
#endif /* NX_DNS_CLIENT_USER_CREATE_PACKET_POOL */

#ifndef DEMO_DHCP_DISABLE
    /* Retrieve DNS server address.  */
    nx_dhcp_interface_user_option_retrieve(&dhcp_0, 0, NX_DHCP_OPTION_DNS_SVR, (UCHAR *)(dns_server_address),
                                           &dns_server_address_size);
#else
    dns_server_address[0] = DEMO_DNS_SERVER_ADDRESS;
#endif /* DEMO_DHCP_DISABLE */

    /* Add an IPv4 server address to the Client list. */
    status = nx_dns_server_add(&dns_0, dns_server_address[0]);
    if (status)
    {
        nx_dns_delete(&dns_0);
        return(status);
    }

    /* Output DNS Server address.  */
    printf("DNS Server address: %lu.%lu.%lu.%lu\r\n",
           (dns_server_address[0] >> 24),
           (dns_server_address[0] >> 16 & 0xFF),
           (dns_server_address[0] >> 8 & 0xFF),
           (dns_server_address[0] & 0xFF));

    return(NX_SUCCESS);
}

static UINT unix_time_get(ULONG *unix_time)
{

    *unix_time = (ULONG)time(NULL);

    return(NX_SUCCESS);
}
