/* This NetX test concentrates on forward fragment operation.  */


#include   "tx_api.h"
#include   "nx_api.h"

#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined (NX_DISABLE_FRAGMENTATION) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_IP                   ip_2;


static NX_UDP_SOCKET           socket_1;
static NX_UDP_SOCKET           socket_2;


/* Define the counters used in the demo application...  */

static ULONG                   thread_0_counter;
static ULONG                   thread_1_counter;
static ULONG                   error_counter;
static ULONG                   notify_calls =  0;  

static UCHAR                   message[1024];

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);   
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern void    test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_udp_fragment_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    thread_0_counter =  0;
    thread_1_counter =  0;
    error_counter =  0;
    notify_calls =  0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* .  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1500, pointer, 1500 * 10);
    pointer = pointer + 1500 * 10;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;
    
    /* Create an forward IP Instance 0.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512, pointer, 2048, 1);
    pointer =  pointer + 2048;    
    if (status)
        error_counter++;

    /* Set the second interface for forward IP Instance 0.  */
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_256);    
    if (status)
        error_counter++;

    /* Create an IP Instance 1.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512, pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Set the gateway for IP Instance 1.  */
    status = nx_ip_gateway_address_set(&ip_1, IP_ADDRESS(1, 2, 3, 4));
    if (status)
        error_counter++;

    /* Create another IP Instance 2.  */
    status = nx_ip_create(&ip_2, "NetX IP Instance 1", IP_ADDRESS(2, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256, pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Set the gateway for IP Instance 2.  */
    status = nx_ip_gateway_address_set(&ip_2, IP_ADDRESS(2, 2, 3, 4));
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status  =  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
    
    /* Enable ARP and supply ARP cache memory for IP Instance 2.  */
    status  =  nx_arp_enable(&ip_2, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
    
    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);
    status += nx_udp_enable(&ip_2);
    
    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
    
    /* Enable the forwarding function for IP Instance 0.  */
    status = nx_ip_forwarding_enable(&ip_0);
    if (status)
        error_counter++;

    /* Enable the fragment function.  */
    status = nx_ip_fragment_enable(&ip_0);       
    status += nx_ip_fragment_enable(&ip_1);
    status += nx_ip_fragment_enable(&ip_2);  
    if (status)
        error_counter++;
}


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
UINT        free_port;
ULONG       packets_sent, bytes_sent, packets_received, bytes_received, packets_queued, receive_packets_dropped, checksum_errors;


    /* Print out some test information banners.  */
    printf("NetX Test:   Forward UDP Fragment Test.................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                           
    
    /* Create a UDP socket 1.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup the first free port for 0x89.  */
    status =  nx_udp_free_port_find(&ip_1, 0x89, &free_port);

    /* Check status.  */
    if ((status) || (free_port != 0x89))
    {
        
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, 0x89, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get the port that is actually bound to this socket.  */
    status =  nx_udp_socket_port_get(&socket_1, &free_port);

    /* Check status.  */
    if ((status) || (free_port != 0x89))
    {
        
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a UDP socket 2.  */
    status = nx_udp_socket_create(&ip_2, &socket_2, "Socket 2", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup the first free port for 0x8a.  */
    status =  nx_udp_free_port_find(&ip_2, 0x8a, &free_port);

    /* Check status.  */
    if ((status) || (free_port != 0x8a))
    {
        
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_2, 0x8a, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get the port that is actually bound to this socket.  */
    status =  nx_udp_socket_port_get(&socket_2, &free_port);

    /* Check status.  */
    if ((status) || (free_port != 0x8a))
    {
        
        printf("ERROR!\n");
        test_control_return(1);
    }                               

    /***********************************************************************/
    /*         Socket1 sends udp packet to Socket2                         */  
    /***********************************************************************/

    /* Let other threads run again.  */
    tx_thread_relinquish();
          
    /* Clear the message.  */
    memset(&message[0], 1, 1024);

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &message[0], 400);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  400;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 400;

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_1, my_packet, IP_ADDRESS(2, 2, 3, 5), 0x8a);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             
             
    /* Get UDP socket2 information.  */
    status =  nx_udp_socket_info_get(&socket_2, &packets_sent, &bytes_sent, &packets_received, &bytes_received, 
                                                &packets_queued, &receive_packets_dropped, &checksum_errors);
    
#ifndef NX_DISABLE_UDP_INFO

    if ((packets_sent != 0) || (bytes_sent != 0) || (packets_received != 1) || (bytes_received != 400))
    {
        error_counter++;
    }
#endif
    /* Check status.  */
    if ((error_counter) || (receive_packets_dropped) || (checksum_errors))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let other threads run again.  */
    tx_thread_relinquish();
    
    /***********************************************************************/
    /*         Socket1 sends udp packet to Socket2                         */    
    /***********************************************************************/

    /* Clear the message.  */
    memset(&message[0], 1, 1024);

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &message[0], 1024);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  1024;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 1024;

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_1, my_packet, IP_ADDRESS(2, 2, 3, 5), 0x8a);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             
    
    /* Let other threads run again.  */
    tx_thread_relinquish();

    /* Get UDP socket2 information.  */
    status =  nx_udp_socket_info_get(&socket_2, &packets_sent, &bytes_sent, &packets_received, &bytes_received, 
                                                &packets_queued, &receive_packets_dropped, &checksum_errors);
    
#ifndef NX_DISABLE_UDP_INFO

    if ((packets_sent != 0) || (bytes_sent != 0) || (packets_received != 2) || (bytes_received != 1424))
    {
        error_counter++;
    }
#endif
    /* Check status.  */
    if ((error_counter) || (receive_packets_dropped) || (checksum_errors))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_1);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_1);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_2);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_2);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    printf("SUCCESS!\n");
    test_control_return(0);
}    

static void    thread_1_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
                 
    
    /***********************************************************************/
    /*         Socket2 receives the udp packet from Socket1                */    
    /***********************************************************************/

    /* Receive a UDP packet.  */
    status =  nx_udp_socket_receive(&socket_2, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet.  */
    status =  nx_packet_release(my_packet);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Receive a UDP packet.  */
    status =  nx_udp_socket_receive(&socket_2, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Release the packet.  */
    status =  nx_packet_release(my_packet);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
}

#else

extern void    test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_udp_fragment_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Forward UDP Fragment Test.................................N/A\n");
    test_control_return(3);
}
#endif
