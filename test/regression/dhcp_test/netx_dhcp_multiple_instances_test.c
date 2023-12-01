
#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_dhcp_client.h"
#include   "nxd_dhcp_server.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         (NX_PACKET_SIZE * 8)

#define     NX_DHCP_SERVER_IP_ADDRESS_0 IP_ADDRESS(10,0,0,1)   
#define     START_IP_ADDRESS_LIST_0     IP_ADDRESS(10,0,0,10)
#define     END_IP_ADDRESS_LIST_0       IP_ADDRESS(10,0,0,19)

#define     NX_DHCP_SUBNET_MASK_0       IP_ADDRESS(255,255,255,0)
#define     NX_DHCP_DEFAULT_GATEWAY_0   IP_ADDRESS(10,0,0,1)
#define     NX_DHCP_DNS_SERVER_0        IP_ADDRESS(10,0,0,1)

#define     NX_DHCP_SERVER_IP_ADDRESS_1 IP_ADDRESS(192,168,0,1)   
#define     START_IP_ADDRESS_LIST_1     IP_ADDRESS(192,168,0,10)
#define     END_IP_ADDRESS_LIST_1       IP_ADDRESS(192,168,0,19)

#define     NX_DHCP_SUBNET_MASK_1       IP_ADDRESS(255,255,255,0)
#define     NX_DHCP_DEFAULT_GATEWAY_1   IP_ADDRESS(192,168,0,1)
#define     NX_DHCP_DNS_SERVER_1        IP_ADDRESS(192,168,0,1)

/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               client_thread;
static NX_PACKET_POOL          client_pool_0;
static NX_PACKET_POOL          client_pool_1;
static NX_IP                   client_ip_0;
static NX_IP                   client_ip_1;
static NX_DHCP                 dhcp_client_0;
static NX_DHCP                 dhcp_client_1;

static TX_THREAD               server_thread;
static NX_PACKET_POOL          server_pool_0;
static NX_PACKET_POOL          server_pool_1;
static NX_IP                   server_ip_0;
static NX_IP                   server_ip_1;
static NX_DHCP_SERVER          dhcp_server_0;
static NX_DHCP_SERVER          dhcp_server_1;

static ULONG                   client_pool_stack_0[NX_PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                   client_pool_stack_1[NX_PACKET_POOL_SIZE / sizeof(ULONG)];

static ULONG                   server_pool_stack_0[NX_PACKET_POOL_SIZE / sizeof(ULONG)];
static ULONG                   server_pool_stack_1[NX_PACKET_POOL_SIZE / sizeof(ULONG)];

/* Define the counters used in the demo application...  */

static ULONG                   state_changes;
static ULONG                   error_counter;
static CHAR                    *pointer;

static UCHAR message[50] = "My Ping Request!" ;


/* Define thread prototypes.  */

static void    server_thread_entry(ULONG thread_input);
static void    client_thread_entry(ULONG thread_input);
static void    my_udp_packet_receive(NX_IP* ip_ptr, NX_PACKET* packet_ptr);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT* driver_req);
extern void    _nx_ram_network_driver_1024(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_multiple_instances_test_application_define(void *first_unused_memory)
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

    /* Create the server thread.  */
    tx_thread_create(&server_thread, "thread server", server_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create the client packet pool0.  */
    status =  nx_packet_pool_create(&client_pool_0, "NetX Main Packet Pool", 1024, client_pool_stack_0, sizeof(client_pool_stack_0));

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create the client packet pool1.  */
    status = nx_packet_pool_create(&client_pool_1, "NetX Main Packet Pool", 1024, client_pool_stack_1, sizeof(client_pool_stack_1));

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create the server packet pool0.  */
    status =  nx_packet_pool_create(&server_pool_0, "NetX Main Packet Pool", 1024, server_pool_stack_0, sizeof(server_pool_stack_0));

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create the server packet pool1.  */
    status = nx_packet_pool_create(&server_pool_1, "NetX Main Packet Pool", 1024, server_pool_stack_1, sizeof(server_pool_stack_1));

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Client.  */
    status = nx_ip_create(&client_ip_0, "DHCP Client 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &client_pool_0, _nx_ram_network_driver_512, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Client.  */
    status = nx_ip_create(&client_ip_1, "DHCP Client 1", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &client_pool_1, _nx_ram_network_driver_1024, pointer, 2048, 1);

    pointer = pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Server.  */
    status = nx_ip_create(&server_ip_0, "DHCP Server 0", NX_DHCP_SERVER_IP_ADDRESS_0, 0xFFFFFF00UL, &server_pool_0, _nx_ram_network_driver_512, pointer, 2048, 1);

    pointer = pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Server.  */
    status = nx_ip_create(&server_ip_1, "DHCP Server 1", NX_DHCP_SERVER_IP_ADDRESS_1, 0xFFFFFF00UL, &server_pool_1, _nx_ram_network_driver_1024, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for DHCP Client IP.  */
    status =  nx_arp_enable(&client_ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for DHCP Client IP.  */
    status = nx_arp_enable(&client_ip_1, (void*)pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for DHCP Server IP.  */
    status =  nx_arp_enable(&server_ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for DHCP Server IP.  */
    status = nx_arp_enable(&server_ip_1, (void*)pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&client_ip_0);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status = nx_udp_enable(&client_ip_1);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status = nx_udp_enable(&server_ip_0);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&server_ip_1);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&client_ip_0);

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status = nx_icmp_enable(&client_ip_1);

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status = nx_icmp_enable(&server_ip_0);

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&server_ip_1);

    /* Check for errors.  */
    if (status)
        error_counter++;

    return;
}

/* Define the test threads.  */

void    server_thread_entry(ULONG thread_input)
{

UINT        status;
UINT        addresses_added;

    printf("NetX Test:   NetX DHCP Multiple Instances Test.........................");

    /* Change udp receive function to my routine. */
    client_ip_0.nx_ip_udp_packet_receive = my_udp_packet_receive;
    client_ip_1.nx_ip_udp_packet_receive = my_udp_packet_receive;
    server_ip_0.nx_ip_udp_packet_receive = my_udp_packet_receive;
    server_ip_1.nx_ip_udp_packet_receive = my_udp_packet_receive;

    /* Create the DHCP Server 0.  */
    status =  nx_dhcp_server_create(&dhcp_server_0, &server_ip_0, pointer, DEMO_STACK_SIZE, 
                                   "DHCP Server 0", &server_pool_0);
    
    pointer = pointer + DEMO_STACK_SIZE;
    
    /* Check for errors creating the DHCP Server. */
    if (status)
        error_counter++;

    status = nx_dhcp_create_server_ip_address_list(&dhcp_server_0, 0, START_IP_ADDRESS_LIST_0, 
                                                   END_IP_ADDRESS_LIST_0, &addresses_added);

    /* Check for errors creating the list. */
    if (status)
    {
        error_counter++;
    }

    /* Verify all the addresses were added to the list. */
    if (addresses_added != 10)
    {
        error_counter++;
    }

    status = nx_dhcp_set_interface_network_parameters(&dhcp_server_0, 0, NX_DHCP_SUBNET_MASK_0, 
                                                      NX_DHCP_DEFAULT_GATEWAY_0, NX_DHCP_DNS_SERVER_0);

    /* Check for errors setting network parameters. */
    if (status)
    {
        error_counter++;
    }

    /* Start DHCP Server task.  */
    status = nx_dhcp_server_start(&dhcp_server_0);

    /* Check for errors starting up the DHCP server.  */
    if (status)
    {
        error_counter++;
    }

    /* Create the DHCP Server 1.  */
    status = nx_dhcp_server_create(&dhcp_server_1, &server_ip_1, pointer, DEMO_STACK_SIZE,
                                   "DHCP Server 1", &server_pool_1);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Check for errors creating the DHCP Server. */
    if (status)
        error_counter++;

    status = nx_dhcp_create_server_ip_address_list(&dhcp_server_1, 0, START_IP_ADDRESS_LIST_1,
                                                   END_IP_ADDRESS_LIST_1, &addresses_added);

    /* Check for errors creating the list. */
    if (status)
    {
        error_counter++;
    }

    /* Verify all the addresses were added to the list. */
    if (addresses_added != 10)
    {
        error_counter++;
    }

    status = nx_dhcp_set_interface_network_parameters(&dhcp_server_1, 0, NX_DHCP_SUBNET_MASK_1,
                                                      NX_DHCP_DEFAULT_GATEWAY_1, NX_DHCP_DNS_SERVER_1);

    /* Check for errors setting network parameters. */
    if (status)
    {
        error_counter++;
    }

    /* Start DHCP Server task.  */
    status = nx_dhcp_server_start(&dhcp_server_1);

    /* Check for errors starting up the DHCP server.  */
    if (status)
    {
        error_counter++;
    }

    tx_thread_sleep(20 * NX_IP_PERIODIC_RATE);

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }

    return;
}

UINT length;


/* Define the test threads.  */

void    client_thread_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
ULONG       ip_address_0;
ULONG       network_address_0;
ULONG       ip_address_1;
ULONG       network_address_1;

    /* Create the DHCP instance 0.  */
    status =  nx_dhcp_create(&dhcp_client_0, &client_ip_0, "dhcp_client_0");
    if (status)
        error_counter++;

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client_0, &client_pool_0);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

    /* Start the DHCP Client 0.  */
    status =  nx_dhcp_start(&dhcp_client_0);
    if (status)
        error_counter++;

    /* Create the DHCP instance 1.  */
    status = nx_dhcp_create(&dhcp_client_1, &client_ip_1, "dhcp_client_1");
    if (status)
        error_counter++;

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client_1, &client_pool_1);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

    /* Start the DHCP Client 1.  */
    status = nx_dhcp_start(&dhcp_client_1);
    if (status)
        error_counter++;

    /* Check for address resolution.  */
    status =  nx_ip_status_check(&client_ip_0, NX_IP_ADDRESS_RESOLVED, (ULONG *) &status, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Check for address resolution.  */
    status = nx_ip_status_check(&client_ip_1, NX_IP_ADDRESS_RESOLVED, (ULONG*)&status, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Check the IP address.  */
    status = nx_ip_address_get(&client_ip_0, &ip_address_0, &network_address_0);
    status += nx_ip_address_get(&client_ip_1, &ip_address_1, &network_address_1);

    /* Check status.  */
    if ((status) || (ip_address_0 != START_IP_ADDRESS_LIST_0) || (ip_address_1 != START_IP_ADDRESS_LIST_1))
        error_counter++;

    /* Send pings to another host on the network...  */
    status =  nx_icmp_ping(&client_ip_0, NX_DHCP_SERVER_IP_ADDRESS_0, (CHAR *)message, sizeof(message), &my_packet, NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
        nx_packet_release(my_packet);

    /* Send pings to another host on the network...  */
    status = nx_icmp_ping(&client_ip_1, NX_DHCP_SERVER_IP_ADDRESS_1, (CHAR*)message, sizeof(message), &my_packet, NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
        nx_packet_release(my_packet);

    /* Clean up.  */
    nx_dhcp_stop(&dhcp_client_0);
    nx_dhcp_delete(&dhcp_client_0);
    nx_dhcp_stop(&dhcp_client_1);
    nx_dhcp_delete(&dhcp_client_1);

    return;
}

static void    my_udp_packet_receive(NX_IP* ip_ptr, NX_PACKET* packet_ptr)
{
UCHAR* source_address_ptr;
ULONG source_address_msw;
ULONG source_address_lsw;

    /* Get the source mac address.  */
    source_address_ptr = packet_ptr->nx_packet_prepend_ptr - 20 - 8;
    source_address_msw = ((*source_address_ptr) << 8) | (*(source_address_ptr + 1));
    source_address_lsw = (*(source_address_ptr + 2) << 24) | (*(source_address_ptr + 3) << 16) | (*(source_address_ptr + 4) << 8) | (*(source_address_ptr + 5));

    /* Rules:
       client_ip_0 only receives data from server_ip_0;
       server_ip_1 only receives data from client_ip_0;
       client_ip_1 only receives data from server_ip_1;
       server_ip_1 only receives data from client_ip_1;
    */

    if (((ip_ptr == &client_ip_0) &&
         ((source_address_msw == server_ip_0.nx_ip_interface[0].nx_interface_physical_address_msw) &&
         ((source_address_lsw == server_ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw)))) ||
        ((ip_ptr == &server_ip_0) &&
          ((source_address_msw == client_ip_0.nx_ip_interface[0].nx_interface_physical_address_msw) &&
          ((source_address_lsw == client_ip_0.nx_ip_interface[0].nx_interface_physical_address_lsw)))) ||
        ((ip_ptr == &client_ip_1) &&
          ((source_address_msw == server_ip_1.nx_ip_interface[0].nx_interface_physical_address_msw) &&
          ((source_address_lsw == server_ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw)))) ||
        ((ip_ptr == &server_ip_1) &&
          ((source_address_msw == client_ip_1.nx_ip_interface[0].nx_interface_physical_address_msw) &&
          ((source_address_lsw == client_ip_1.nx_ip_interface[0].nx_interface_physical_address_lsw)))))
    {
        _nx_udp_packet_receive(ip_ptr, packet_ptr);
    }
    else
    {
        nx_packet_release(packet_ptr);
    }
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_multiple_instances_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NetX DHCP Multiple Instances Test.........................N/A\n"); 

    test_control_return(3);  
}      
#endif
