/* Testing the multiple interface DHCP Client */

/* This is the DHCP Client that will run on both interfaces independently.
   Interface 0 stays bound; interface 1 declines the IP address and tries
   again at the INIT state to get a unique IP address.
 
   Required: NX_MAX_PHYSICAL_INTERFACES >= 2 and NX_DHCP_CLIENT_MAX_INTERFACES >= 2.
   Also NX_DHCP_CLIENT_SEND_ARP_PROBE must be enabled. Requires longer timeout in regression
   test netxtestcontrol.
  
   There is one server thread handling DHCP Client messages on both interfaces. 
*/



#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_ram_network_driver_test_1500.h"
#include    "nxd_dhcp_client.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         4096
#define     NX_PACKET_SIZE          1536
#define     NX_PACKET_POOL_SIZE     (NX_PACKET_SIZE * 8)

/* Define the ThreadX, NetX object control blocks...  */
static TX_THREAD               client_thread;
static NX_PACKET_POOL          client_pool;
static NX_IP                   client_ip;


/* Define the NetX FTP object control block.  */
static NX_DHCP                 dhcp_client;

/* Define the counters used in the demo application...  */
static  UINT                   error_counter = 0;

/* Replace the 'ram' driver with your Ethernet driver. */
static void    client_thread_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(NX_IP_DRIVER *driver_req_ptr);


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_ip_mutex_test_application_define(void *first_unused_memory)
#endif
{

UINT    status;
UCHAR   *pointer;


    /* Setup the working pointer.  */
    pointer =  (UCHAR *) first_unused_memory;

    /* Initialize NetX.  */
    nx_system_initialize();

    /* Create the client thread.  */
    tx_thread_create(&client_thread, "thread client", client_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the client packet pool.  */
    status =  nx_packet_pool_create(&client_pool, "NetX Main Packet Pool", 1024, pointer, NX_PACKET_POOL_SIZE);
    pointer = pointer + NX_PACKET_POOL_SIZE;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance for the DHCP Client.  */
    status = nx_ip_create(&client_ip, "DHCP Client", IP_ADDRESS(0, 0, 0, 0), 0x00, &client_pool, _nx_ram_network_driver_256, pointer, 2048, 1);
    pointer =  pointer + 2048;
    
    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for the Client IP.  */
    status = nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable UDP for client IP instance.  */
    status += nx_udp_enable(&client_ip);
    status += nx_icmp_enable(&client_ip);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;
}


/* Define the DHCP client thread.  */

void    client_thread_entry(ULONG thread_input)
{

UINT        status;


    printf("NetX Test:   DHCP Client IP Mutex Test.................................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create the DHCP instance.  */
    status =  nx_dhcp_create(&dhcp_client, &client_ip, "dhcp0");
    if (status != NX_SUCCESS) 
    {
        printf("ERROR!\n");
        test_control_return(1);        
    }

#ifdef NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL
    status = nx_dhcp_packet_pool_set(&dhcp_client, &client_pool);
    if (status)
        error_counter++;
#endif /* NX_DHCP_CLIENT_USER_CREATE_PACKET_POOL  */

    /* Start DHCP on all interfaces. */
    status = nx_dhcp_start(&dhcp_client);
    if (status != NX_SUCCESS) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for sending the first discovery message.  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

#ifndef NX_DISABLE_UDP_INFO
    /* Check if send out discovery message.  */
    if (client_ip.nx_ip_udp_packets_sent == 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_UDP_INFO  */

    /* Check if DHCP Thread did not release the IP mutex.  */
    if (client_ip.nx_ip_protection.tx_mutex_owner == &dhcp_client.nx_dhcp_thread)
    {
        error_counter++;
    }

    /* Release the mutex again before call test_control_cleanup */
    dhcp_client.nx_dhcp_thread.tx_thread_owned_mutex_list = NX_NULL;
    client_ip.nx_ip_protection.tx_mutex_owner = &client_thread;
    tx_mutex_put(&client_ip.nx_ip_protection);

    /* Check for error.  */
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
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dhcp_client_ip_mutex_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   DHCP Client IP Mutex Test.................................N/A\n"); 

    test_control_return(3);  
}      
#endif
