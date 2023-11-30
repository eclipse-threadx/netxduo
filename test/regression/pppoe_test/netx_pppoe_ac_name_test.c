/* This case tests processing AC name.  */
 
#include   "tx_api.h"
#include   "nx_api.h" 
#include   "nx_ppp.h"
#include   "nx_pppoe_server.h"
#include   "nx_pppoe_client.h"

extern void test_control_return(UINT);

#if !defined(NX_DISABLE_IPV4) && defined(NX_PPP_PPPOE_ENABLE) && defined(NX_PPPOE_SERVER_INITIALIZE_DRIVER_ENABLE) && defined(NX_PPPOE_CLIENT_INITIALIZE_DRIVER_ENABLE) && (NX_PHYSICAL_HEADER >= 24) && !defined(NX_PPPOE_SERVER_SESSION_CONTROL_ENABLE)

/* Defined NX_PPP_PPPOE_ENABLE if use PPP, since PPP module has been modified to match PPPoE moduler under this definition.  */
                
/* If the driver is not initialized in other module, define NX_PPPOE_SERVER_INITIALIZE_DRIVER_ENABLE to initialize the driver in PPPoE module .  
   In this demo, the driver has been initialized in IP module.  */

/* NX_PPPOE_SERVER_SESSION_CONTROL_ENABLE: 
   If defined, enables the feature that controls the PPPoE session. 
   PPPoE server does not automatically response to the request until application call specific API.  */

/* Define the block size.  */
#define     NX_PACKET_POOL_SIZE     ((1536 + sizeof(NX_PACKET)) * 12)
#define     DEMO_STACK_SIZE         2048
#define     PPPOE_THREAD_SIZE       2048

/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               thread_server;
static TX_THREAD               thread_client;

/* Define the packet pool and IP instance for normal IP instnace.  */
static NX_PACKET_POOL          pool_server;
static NX_IP                   ip_server;
static NX_PACKET_POOL          pool_client;
static NX_IP                   ip_client;
static CHAR                    pool_buffer_server[NX_PACKET_POOL_SIZE];
static CHAR                    pool_buffer_client[NX_PACKET_POOL_SIZE];
                
/* Define the PPP Server instance.  */
static NX_PPP                  ppp_server;
static NX_PPP                  ppp_client;

/* Define the PPPoE Server instance.  */
static NX_PPPOE_SERVER         pppoe_server;
static NX_PPPOE_CLIENT         pppoe_client;
                         
/* Define the counters.  */
static CHAR                    *pointer;
static ULONG                   error_counter; 

/* Define thread prototypes.  */
static void    thread_server_entry(ULONG thread_input);
static void    thread_client_entry(ULONG thread_input);

/***** Substitute your PPP driver entry function here *********/
extern void    _nx_ppp_driver(NX_IP_DRIVER *driver_req_ptr);

/***** Substitute your Ethernet driver entry function here *********/ 
extern void    _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

/* Define the callback functions.  */ 
static void    pppoe_server_packet_receive(UINT interfaceHandle, ULONG length, UCHAR *data, UINT packet_id);

/* Define the porting layer function for PPP.  
   Functions to be provided by PPP for calling by the PPPoE Stack.  */
static void    ppp_server_packet_send(NX_PACKET *packet_ptr);

/* Define the porting layer function for PPP.  
   Functions to be provided by PPP for calling by the PPPoE Stack.  */
static void    ppp_client_packet_send(NX_PACKET *packet_ptr);
static void    pppoe_client_packet_receive(NX_PACKET *packet_ptr);

#define SERVER_ADDRESS IP_ADDRESS(192, 168, 10, 43)
#define CLIENT_ADDRESS IP_ADDRESS(192, 168, 10, 44)

static UINT generate_login(CHAR *name, CHAR *password)
{

    /* Make a name and password, called "myname" and "mypassword".  */
    name[0] = 'm';
    name[1] = 'y';
    name[2] = 'n';
    name[3] = 'a';
    name[4] = 'm';
    name[5] = 'e';
    name[6] = (CHAR) 0;
    
    password[0] = 'm';
    password[1] = 'y';
    password[2] = 'p';
    password[3] = 'a';
    password[4] = 's';
    password[5] = 's';
    password[6] = 'w';
    password[7] = 'o';
    password[8] = 'r';
    password[9] = 'd';
    password[10] = (CHAR) 0;

    return(NX_SUCCESS);
}

static UINT verify_login(CHAR *name, CHAR *password)
{

if ((name[0] == 'm') &&
    (name[1] == 'y') &&
    (name[2] == 'n') &&
    (name[3] == 'a') &&
    (name[4] == 'm') &&
    (name[5] == 'e') &&
    (name[6] == (CHAR) 0) &&
    (password[0] == 'm') &&
    (password[1] == 'y') &&
    (password[2] == 'p') &&
    (password[3] == 'a') &&
    (password[4] == 's') &&
    (password[5] == 's') &&
    (password[6] == 'w') &&
    (password[7] == 'o') &&
    (password[8] == 'r') &&
    (password[9] == 'd') &&
    (password[10] == (CHAR) 0))
        return(NX_SUCCESS);
   else
        return(NX_PPP_ERROR);
}

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_pppoe_ac_name_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
                              
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool for normal IP instance.  */
    status = nx_packet_pool_create(&pool_server, "Server Packet Pool", 
                                   (1536 + sizeof(NX_PACKET)), 
                                   pool_buffer_server, NX_PACKET_POOL_SIZE); 
                 
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Create an normal IP instance.  */
    status = nx_ip_create(&ip_server, "Server IP Instance", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &pool_server, nx_ppp_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Create the PPP instance.  */
    status = nx_ppp_create(&ppp_server, "PPP Server Instance", &ip_server, pointer, 2048, 1, &pool_server, NX_NULL, NX_NULL);
    pointer = pointer + 2048;

    /* Check for PPP create error.   */
    if (status)
        error_counter++;

    /* Set the PPP packet send function.  */
    status = nx_ppp_packet_send_set(&ppp_server, ppp_server_packet_send);

    /* Check for PPP packet send function set error.   */
    if (status)
        error_counter++;

    /* Define IP address. This PPP instance is effectively the server since it has both IP addresses. */
    status = nx_ppp_ip_address_assign(&ppp_server, SERVER_ADDRESS, CLIENT_ADDRESS);
    
    /* Check for PPP IP address assign error.   */
    if (status)
        error_counter++;
        
    /* Setup PAP, this PPP instance is effectively the server since it will verify the name and password.  */
    status = nx_ppp_pap_enable(&ppp_server, NX_NULL, verify_login);

    /* Check for PPP PAP enable error.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for Normal IP Instance.  */
    status = nx_arp_enable(&ip_server, (void *) pointer, 1024);
    pointer = pointer + 1024; 

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP */
    status = nx_icmp_enable(&ip_server);
    if(status)
        error_counter++;

    /* Create the main thread.  */
    tx_thread_create(&thread_server, "thread server", thread_server_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create a packet pool for normal IP instance.  */
    status = nx_packet_pool_create(&pool_client, "Client Packet Pool", 
                                   (1536 + sizeof(NX_PACKET)), 
                                   pool_buffer_client, NX_PACKET_POOL_SIZE); 
                 
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Create an normal IP instance.  */
    status = nx_ip_create(&ip_client, "Client IP Instance", IP_ADDRESS(0, 0, 0, 0), 0xFFFFFF00UL, &pool_client, nx_ppp_driver,
                          pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Create the PPP instance.  */
    status = nx_ppp_create(&ppp_client, "PPP Client Instance", &ip_client, pointer, 2048, 1, &pool_client, NX_NULL, NX_NULL);
    pointer = pointer + 2048;

    /* Check for PPP create error.   */
    if (status)
        error_counter++;

    /* Set the PPP packet send function.  */
    status = nx_ppp_packet_send_set(&ppp_client, ppp_client_packet_send);

    /* Check for PPP packet send function set error.   */
    if (status)
        error_counter++;

    /* Define IP address. This PPP instance is effectively the client since it doesn't have any IP addresses. */
    status = nx_ppp_ip_address_assign(&ppp_client, IP_ADDRESS(0, 0, 0, 0), IP_ADDRESS(0, 0, 0, 0));
    
    /* Check for PPP IP address assign error.   */
    if (status)
        error_counter++;
        
    /* Setup PAP, this PPP instance is effectively the since it generates the name and password for the peer..  */
    status = nx_ppp_pap_enable(&ppp_client, generate_login, NX_NULL);

    /* Check for PPP PAP enable error.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for Normal IP Instance.  */
    status = nx_arp_enable(&ip_client, (void *) pointer, 1024);
    pointer = pointer + 1024; 

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP */
    status = nx_icmp_enable(&ip_client);
    if(status)
        error_counter++;

    /* Create the main thread.  */
    tx_thread_create(&thread_client, "thread client", thread_client_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     6, 6, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

}

static UCHAR PADI[] = 
{
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x57, 0x88, 0x63,
0x11, 0x09, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x64, 0x13,
0x85, 0x18,
};

static UCHAR PADR[] = 
{
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x11, 0x22, 0x33, 0x44, 0x57, 0x88, 0x63,
0x11, 0x19, 0x00, 0x00, 0x00, 0x14, 0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0x64, 0x13,
0x85, 0x18, 0x01, 0x02, 0x00, 0x04, 0x42, 0x52, 0x41, 0x53,
};

static void    thread_client_entry(ULONG thread_input)
{
UINT    status;
ULONG   ip_status;
NX_PACKET *recv_pkt;
ULONG   ip_address;
ULONG   network_mask;
NX_PACKET *send_packet;

    /* Create the PPPoE instance.  */
    status = nx_pppoe_client_create(&pppoe_client, (UCHAR *)"PPPoE Client", &ip_client, 0, &pool_client, pointer, PPPOE_THREAD_SIZE, 4, _nx_ram_network_driver, pppoe_client_packet_receive);
    pointer = pointer + PPPOE_THREAD_SIZE;
    if (status)
    {
        error_counter++;
    }

    /* Establish PPPoE Client sessione.  */
    nx_packet_allocate(&pool_client, &send_packet, NX_PHYSICAL_HEADER, NX_NO_WAIT);
    memcpy(send_packet -> nx_packet_prepend_ptr, PADI, sizeof(PADI));
    send_packet -> nx_packet_prepend_ptr += NX_PPPOE_SERVER_ETHER_HEADER_SIZE;
    send_packet -> nx_packet_length = sizeof(PADI) - NX_PPPOE_SERVER_ETHER_HEADER_SIZE;
    send_packet -> nx_packet_append_ptr = send_packet -> nx_packet_prepend_ptr + send_packet -> nx_packet_length;
    _nx_pppoe_server_packet_deferred_receive(send_packet);
    nx_packet_allocate(&pool_client, &send_packet, NX_PHYSICAL_HEADER, NX_NO_WAIT);
    memcpy(send_packet -> nx_packet_prepend_ptr, PADR, sizeof(PADR));
    send_packet -> nx_packet_prepend_ptr += NX_PPPOE_SERVER_ETHER_HEADER_SIZE;
    send_packet -> nx_packet_length = sizeof(PADR) - NX_PPPOE_SERVER_ETHER_HEADER_SIZE;
    send_packet -> nx_packet_append_ptr = send_packet -> nx_packet_prepend_ptr + send_packet -> nx_packet_length;
    pppoe_client.nx_pppoe_server_session.nx_pppoe_physical_address_msw = 0x11;
    pppoe_client.nx_pppoe_server_session.nx_pppoe_physical_address_lsw = 0x22334456;
    pppoe_client.nx_pppoe_state = NX_PPPOE_CLIENT_STATE_PADR_SENT;
    _nx_pppoe_server_packet_deferred_receive(send_packet);

    /* Wait for the link to come up.  */
    status = nx_ip_interface_status_check(&ip_client, 0, NX_IP_ADDRESS_RESOLVED, &ip_status, NX_WAIT_FOREVER);
    if (status)
    {
        error_counter++;
    }

    /* Check client IP address.  */
    status = nx_ip_address_get(&ip_client, &ip_address, &network_mask);
    if (status || ip_address != CLIENT_ADDRESS)
    {
        error_counter++;
    }

    /* Ping test.  */
    status = nx_icmp_ping(&ip_client, SERVER_ADDRESS, "abcd", 4, &recv_pkt, NX_WAIT_FOREVER);
    if (status)
    {
        error_counter++;
    }
    else
    {
        nx_packet_release(recv_pkt);
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
}

/* PPPoE Client receive function.  */
static void    pppoe_client_packet_receive(NX_PACKET *packet_ptr)
{

    /* Call PPP Client to receive the PPP data fame.  */
    nx_ppp_packet_receive(&ppp_client, packet_ptr);
}

/* PPP Client send function.  */
static void    ppp_client_packet_send(NX_PACKET *packet_ptr)
{

    /* Directly Call PPPoE send function to send out the data through PPPoE module.  */
    nx_pppoe_client_session_packet_send(&pppoe_client, packet_ptr);
}

/* Define the server threads.  */

static void    thread_server_entry(ULONG thread_input)
{
UINT    status;
ULONG   ip_status;
ULONG   ip_address;
ULONG   network_mask;
UCHAR   ac_name[] = "BRAS";

    /* Print out test information banner.  */
    printf("NetX Test:   PPPoE AC Name Test........................................");

    /* Create the PPPoE instance.  */
    status =  nx_pppoe_server_create(&pppoe_server, (UCHAR *)"PPPoE Server",  &ip_server, 0, _nx_ram_network_driver,  &pool_server, pointer, PPPOE_THREAD_SIZE, 4);
    pointer = pointer + PPPOE_THREAD_SIZE;
    if (status)
    {
        error_counter++;
    }

    /* Set AC name.  */
    nx_pppoe_server_ac_name_set(&pppoe_server, ac_name, sizeof(ac_name) - 1);

    /* Set the callback notify function.  */
    status = nx_pppoe_server_callback_notify_set(&pppoe_server, NX_NULL, NX_NULL, NX_NULL, NX_NULL, pppoe_server_packet_receive, NX_NULL);
    if (status)
    {
        error_counter++;
    }
    
    /* Enable PPPoE Server.  */
    status = nx_pppoe_server_enable(&pppoe_server);
    if (status)
    {
        error_counter++;
    }

    tx_thread_resume(&thread_client);

    /* Wait for the link to come up.  */
    status = nx_ip_interface_status_check(&ip_server, 0, NX_IP_ADDRESS_RESOLVED, &ip_status, NX_WAIT_FOREVER);
    if (status)
    {
        error_counter++;
    }

    /* Check server IP address.  */
    status = nx_ip_address_get(&ip_server, &ip_address, &network_mask);
    if (status || ip_address != SERVER_ADDRESS)
    {
        error_counter++;
    }
}

static void    pppoe_server_packet_receive(UINT interfaceHandle, ULONG length, UCHAR *data, UINT packet_id)
{

NX_PACKET   *packet_ptr;

    /* Get the notify that receive the PPPoE Session data.  */

    /* Call PPP Server to receive the PPP data fame.  */
    packet_ptr = (NX_PACKET *)(packet_id);
    nx_ppp_packet_receive(&ppp_server, packet_ptr);
}
  
/* PPP Server send function.  */
static void    ppp_server_packet_send(NX_PACKET *packet_ptr)
{      

/* For PPP test, the session should be the first session, so set interfaceHandle as 0.  */
UINT    interfaceHandle = 0;  

    /* Directly Call PPPoE send function to send out the data through PPPoE module.  */
    nx_pppoe_server_session_packet_send(&pppoe_server, interfaceHandle, packet_ptr);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_pppoe_ac_name_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   PPPoE AC Name Test........................................N/A\n"); 

    test_control_return(3);  
}      
#endif