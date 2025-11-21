/* The DHCPREQUEST message MUST use the same value in the DHCP message header's 'secs' field and be sent to the same IP 
 * broadcast address as the original DHCPDISCOVER message.
 * rfc 2131, page 16, 3.1 Client-server interaction - allocating a network address
 */
#include   "tx_api.h"
#include   "nx_api.h"
#include   "netx_dhcp_clone_function.h"
#include   "nx_ipv4.h"
#include   "nxd_dhcp_client.h"

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


/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               client_thread;
static NX_PACKET_POOL          client_pool;
static NX_IP                   client_ip;
static NX_DHCP                 dhcp_client;

static TX_THREAD               server_thread;
static NX_PACKET_POOL          server_pool;
static NX_IP                   server_ip;
static NX_UDP_SOCKET           server_socket;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static CHAR                    *pointer;
static UINT                    test_done = NX_FALSE;

/* Define thread prototypes.  */

static void    server_thread_entry(ULONG thread_input);
static void    client_thread_entry(ULONG thread_input);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_parameter_request_test_application_define(void *first_unused_memory)
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

    /* Create the client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;
    
    /* Create the server packet pool.  */
    status =  nx_packet_pool_create(&server_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Client.  */
    status = nx_ip_create(&client_ip, "DHCP Client", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;
    
    /* Create an IP instance for the DHCP Server.  */
    status = nx_ip_create(&server_ip, "DHCP Server", NX_DHCP_SERVER_IP_ADDRESS_0, 0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1500, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for DHCP Client IP.  */
    status =  nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;
    
    /* Enable ARP and supply ARP cache memory for DHCP Server IP.  */
    status =  nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&client_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
    
    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&server_ip);

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&client_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP.  */
    status =  nx_icmp_enable(&server_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    return;
}

/* Define the test threads.  */

void    server_thread_entry(ULONG thread_input)
{

UINT        status;
UINT        i = 0;
UINT        index;
NX_PACKET   *my_packet;
UCHAR       *option_ptr;
UINT        option_size;

    printf("NetX Test:   DHCP Client Parameter Request Test........................");

    /* Create a  socket as the  server.  */
    status = nx_udp_socket_create(&server_ip, &server_socket, "Socket Server", NX_IP_NORMAL, NX_FRAGMENT_OKAY,  NX_IP_TIME_TO_LIVE, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status =  nx_udp_socket_bind(&server_socket, NX_DHCP_SERVER_UDP_PORT, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Receive DHCP message.  */
    status =  nx_udp_socket_receive(&server_socket, &my_packet, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {

        /* Check if there is NTP in parameter request list.  */
        option_ptr = dhcp_search_buffer(my_packet -> nx_packet_prepend_ptr, NX_DHCP_OPTION_DHCP_PARAMETERS, my_packet -> nx_packet_length);

        /* Check if found the parameter request option.  */
        if (option_ptr == NX_NULL)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
        else
        {
            option_size = (UINT)*option_ptr;
            option_ptr++;

            /* Check if option size is correct.  */
            if (option_size != 3 + NX_DHCP_CLIENT_MAX_USER_REQUEST_PARAMETER)
            {
                printf("ERROR!\n");
                test_control_return(1);
            }

            /* Check the default option.  */
            if ((*(option_ptr) != NX_DHCP_OPTION_SUBNET_MASK) ||
                (*(option_ptr + 1) != NX_DHCP_OPTION_GATEWAYS) ||
                (*(option_ptr + 2) != NX_DHCP_OPTION_DNS_SVR))
            {
                printf("ERROR!\n");
                test_control_return(1);
            }
            option_ptr += 3;

            /* Check the user option.   */
            for (index = 0; index < NX_DHCP_CLIENT_MAX_USER_REQUEST_PARAMETER; index ++)
            {
                if (*(option_ptr + index) != NX_DHCP_OPTION_NTP_SVR + index)
                {
                    printf("ERROR!\n");
                    test_control_return(1);
                }
            }
        }

        /* Release the packet.  */
        nx_packet_release(my_packet);
    }

    /* Wait for test done.  */
    while(test_done == NX_FALSE)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    if (error_counter)
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

/* Define the test threads.  */

void    client_thread_entry(ULONG thread_input)
{

UINT        status;
UINT        i;

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    if (status)
    {
        error_counter++;
    }

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

    /* Add default option: subnet mask.  */
    status =  nx_dhcp_user_option_request(&dhcp_client, NX_DHCP_OPTION_SUBNET_MASK);
    if (status != NX_DUPLICATED_ENTRY)
    {
        error_counter++;
    }

    /* Add default option: gateway.  */
    status =  nx_dhcp_user_option_request(&dhcp_client, NX_DHCP_OPTION_GATEWAYS);
    if (status != NX_DUPLICATED_ENTRY)
    {
        error_counter++;
    }

    /* Add default option: dns.  */
    status =  nx_dhcp_user_option_request(&dhcp_client, NX_DHCP_OPTION_DNS_SVR);
    if (status != NX_DUPLICATED_ENTRY)
    {
        error_counter++;
    }

    /* Try to add NTP server option.  */
    status =  nx_dhcp_user_option_request(&dhcp_client, NX_DHCP_OPTION_NTP_SVR);
    if (status)
    {
        error_counter++;
    }

    /* Try to add NTP server option again.  */
    status =  nx_dhcp_user_option_request(&dhcp_client, NX_DHCP_OPTION_NTP_SVR);
    if (status != NX_DUPLICATED_ENTRY)
    {
        error_counter++;
    }

    /* Loop to fill in the array.  */
    for (i = 0; i < NX_DHCP_CLIENT_MAX_USER_REQUEST_PARAMETER - 1; i++)
    {
        status =  nx_dhcp_user_option_request(&dhcp_client, NX_DHCP_OPTION_NTP_SVR + i + 1);
        if (status)
        {
            error_counter++;
        }
    }

    /* Try to add one more.  */
    status =  nx_dhcp_user_option_request(&dhcp_client, NX_DHCP_OPTION_NTP_SVR + i + 1);
    if (status != NX_NO_MORE_ENTRIES)
    {
        error_counter++;
    }

    /* Start the DHCP Client.  */
    status =  nx_dhcp_start(&dhcp_client);
    if (status)
    {
        error_counter++;
    }

    /* Let client sends out at least one message.  */
    while(dhcp_client.nx_dhcp_interface_record[0].nx_dhcp_discoveries_sent == 0)
    {
        tx_thread_sleep(NX_IP_PERIODIC_RATE);
    }

    /* Stopping the DHCP client. */
    nx_dhcp_stop(&dhcp_client);

    /* All done. Return resources to NetX and ThreadX. */
    nx_dhcp_delete(&dhcp_client);

    test_done = NX_TRUE;

    return;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_parameter_request_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Client Parameter Request Test........................N/A\n"); 

    test_control_return(3);  
}      
#endif