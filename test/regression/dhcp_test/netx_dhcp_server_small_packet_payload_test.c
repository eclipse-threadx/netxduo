/* In _nx_dhcp_server_packet_process(), the orginal logic is to check the incoming packet length, update the incoming packet length, then copy the incomping packet data.
   It will casue out of bound write. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nxd_dhcp_client.h"
#include   "nxd_dhcp_server.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE             4096
#define     NX_PACKET_SIZE              1536
#define     NX_PACKET_POOL_SIZE         NX_PACKET_SIZE * 8
#define     NX_SERVER_PACKET_SIZE       NX_DHCP_MINIMUM_PACKET_PAYLOAD
#define     NX_SERVER_PACKET_POOL_SIZE  ((NX_DHCP_MINIMUM_PACKET_PAYLOAD + sizeof(NX_PACKET)) * 2)

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

static TX_THREAD               server_thread;
static NX_PACKET_POOL          server_pool;
static ULONG                   server_pool_stack[NX_SERVER_PACKET_POOL_SIZE / sizeof(ULONG)];
static NX_IP                   server_ip;
static NX_DHCP_SERVER          dhcp_server;

/* Define the counters used in the demo application...  */

static ULONG                   state_changes;
static ULONG                   error_counter;
static CHAR                    *pointer;

static UCHAR message[50] = "My Ping Request!" ;


/* Define thread prototypes.  */

static void    server_thread_entry(ULONG thread_input);
static void    client_thread_entry(ULONG thread_input);
static void    dhcp_state_change(NX_DHCP *dhcp_ptr, UCHAR new_state);
static UINT    dhcp_user_option_add(NX_DHCP *dhcp_ptr, UINT iface_index, UINT message_type, UCHAR *user_option_ptr, UINT *user_option_length);

/******** Optionally substitute your Ethernet driver here. ***********/
extern void    _nx_ram_network_driver_1024(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_server_small_packet_payload_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&server_pool, "NetX Main Packet Pool", NX_SERVER_PACKET_SIZE, (UCHAR *)server_pool_stack, sizeof(server_pool_stack));

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Client.  */
    status = nx_ip_create(&client_ip, "DHCP Client", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &client_pool, _nx_ram_network_driver_1024, pointer, 2048, 1);

    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;
    
    /* Create an IP instance for the DHCP Server.  */
    status = nx_ip_create(&server_ip, "DHCP Server", NX_DHCP_SERVER_IP_ADDRESS_0, 0xFFFFFF00UL, &server_pool, _nx_ram_network_driver_1024, pointer, 2048, 1);

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

    return;
}

/* Define the test threads.  */

void    server_thread_entry(ULONG thread_input)
{

UINT        status;
UINT        iface_index;
UINT        addresses_added;

    printf("NetX Test:   DHCP Server Small Packet Payload..........................");

    /* Create the DHCP Server.  */
    status =  nx_dhcp_server_create(&dhcp_server, &server_ip, pointer, DEMO_STACK_SIZE, 
                                   "DHCP Server", &server_pool);
    
    pointer = pointer + DEMO_STACK_SIZE;
    
    /* Check for errors creating the DHCP Server. */
    if (status)
        error_counter++;

    /* Load the assignable DHCP IP addresses for the first interface.  */
    iface_index = 0;

    status = nx_dhcp_create_server_ip_address_list(&dhcp_server, iface_index, START_IP_ADDRESS_LIST_0, 
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

    status = nx_dhcp_set_interface_network_parameters(&dhcp_server, iface_index, NX_DHCP_SUBNET_MASK_0, 
                                                      NX_DHCP_DEFAULT_GATEWAY_0, NX_DHCP_DNS_SERVER_0);

    /* Check for errors setting network parameters. */
    if (status)
    {
        error_counter++;
    }

    /* Start DHCP Server task.  */
    status = nx_dhcp_server_start(&dhcp_server);

    /* Check for errors starting up the DHCP server.  */
    if (status)
    {
        error_counter++;
    }

    /* Let's DHCP server receive one packet packet.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Check if the memory of server ip is over overwritten.  */
    if ((server_ip.nx_ip_id != NX_IP_ID))
    {
        error_counter++;
    }

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


/* Define the test threads.  */

void    client_thread_entry(ULONG thread_input)
{

UINT        status;

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp_client");
    if (status)
        error_counter++;

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

    /* Register state change variable.  */
    status =  nx_dhcp_state_change_notify(&dhcp_client, dhcp_state_change);
    if (status)
        error_counter++;
    
    /* Set callback function to add user options.  */
    status =  nx_dhcp_user_option_add_callback_set(&dhcp_client, dhcp_user_option_add);
    if (status)
        error_counter++;

    /* Start the DHCP Client.  */
    status =  nx_dhcp_start(&dhcp_client);
    if (status)
        error_counter++;

    /* Let's DHCP client send one packet.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Stopping the DHCP client. */
    nx_dhcp_stop(&dhcp_client);

    /* All done. Return resources to NetX and ThreadX. */    
    nx_dhcp_delete(&dhcp_client);

    return;
}

/* In DHCP client, data size is 267, then fill in more data: NX_BOOT_BUFFER_SIZE - 267 - 1 (END Option) */
UINT dhcp_user_option_add(NX_DHCP *dhcp_ptr, UINT iface_index, UINT message_type, UCHAR *user_option_ptr, UINT *user_option_length)
{

    /* Update the option length.  */
    *user_option_length = NX_BOOT_BUFFER_SIZE - 267 - 1;
    return(NX_TRUE);
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
void    netx_dhcp_server_small_packet_payload_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Server Small Packet Payload..........................N/A\n"); 

    test_control_return(3);  
}      
#endif
