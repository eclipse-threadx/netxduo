/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_udp.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1;
#endif /* FEATURE_NX_IPV6 */


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);        
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req); 

/* Define what the initial system looks like.  */    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_packet_type_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_DONT_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* .  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

#ifndef NX_DISABLE_IPV4
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;
#endif

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 traffic.  */
    status += nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);

    /* Enable ICMP processing for both IP instances.  */
    status +=  nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);

    /* Check enable status.  */
    if (status)
        error_counter++;

    /* Set source and destination address with global address. */    
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010DB8;
    address_0.nxd_ip_address.v6[1] = 0x00010001;
    address_0.nxd_ip_address.v6[2] = 0x021122FF;
    address_0.nxd_ip_address.v6[3] = 0xFE334456;

    address_1.nxd_ip_version = NX_IP_VERSION_V6;
    address_1.nxd_ip_address.v6[0] = 0x20010DB8;
    address_1.nxd_ip_address.v6[1] = 0x00010001;
    address_1.nxd_ip_address.v6[2] = 0x021122FF;
    address_1.nxd_ip_address.v6[3] = 0xFE334499;

    status = nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL);
    status = nxd_ipv6_address_set(&ip_1, 0, &address_1, 64, NX_NULL);
#endif /* FEATURE_NX_IPV6 */

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
}                          


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;


    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Packet Type Test......................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_IPV4
    /**************************/
    /*   Test IPv4 packet     */
    /**************************/

    /* Allocate a packet that can fill the UDP header, IPv4 header and physical header.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, 8 + 20 + NX_PHYSICAL_HEADER, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet that can fill the UDP header and IPv4 header, can not fill physical header.  */
    status =  nx_packet_allocate(&pool_0, &my_packet,  8 + 20, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             

    /* Wait until thread 1 finished. */
    tx_thread_suspend(&thread_0);
#ifdef __PRODUCT_NETXDUO__
#ifndef NX_DISABLE_ERROR_CHECKING
    /* Allocate a packet that can fill the UDP header, can not fill IPv4 header and physical header.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, 8, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */ 
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    nx_packet_release(my_packet);

    /* Allocate a packet that can not fill the UDP header, IPv4 header and physical header.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, 0, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Wait until thread 1 finished. */
    tx_thread_suspend(&thread_0);
#endif /* NX_DISABLE_ERROR_CHECKING */
#endif /* __PRODUCT_NETXDUO__ */
#endif /* NX_DISABLE_IPV4 */
               
#ifdef FEATURE_NX_IPV6                  
                           
    /**************************/
    /*   Test IPv6 packet     */
    /**************************/

    /* Allocate a packet that can fill the UDP header, IPv6 header and physical header.  */
    status =  nx_packet_allocate(&pool_0, &my_packet,  8 + 40 + NX_PHYSICAL_HEADER, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;
                                                                                 
    /* Send the UDP packet.  */                                                       
    status =  nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
            
#ifndef NX_DISABLE_ERROR_CHECKING

    /* Allocate a packet that can fill the UDP header and IPv6 header, can not fill physical header.  */
    status =  nx_packet_allocate(&pool_0, &my_packet,  8 + 40, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the UDP packet.  */                                                        
    status =  nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             

    /* Sleep 2 second to wait socket_1 receive the packet.  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);
            
    /* Allocate a packet that can fill the UDP header, can not fill IPv6 header and physical header.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, 8, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the UDP packet.  */                                                         
    status =  nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);

    /* Check status.  */ 
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet that can not fill the UDP header, IPv6 header and physical header.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, 0, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS) 
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the UDP packet.  */                                                        
    status =  nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Wait until thread 1 finished. */
    tx_thread_suspend(&thread_0);
#endif /* NX_DISABLE_ERROR_CHECKING */

#endif /* FEATURE_NX_IPV6 */
                   
    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_0);

    /* Check status.  */
    if (status)
    {               
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_0);

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
                      
#ifdef FEATURE_NX_IPV6
    /* Sleep 5 seconds to finish DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)       
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

    /* Let thread 0 run. */
    tx_thread_resume(&thread_0);

#ifndef NX_DISABLE_IPV4
    /**************************/
    /*   Test IPv4 packet     */
    /**************************/

    /* Try to receive the first UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 1 * NX_IP_PERIODIC_RATE);

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
                      
    /* Try to receive the second UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let thread 0 run. */
    tx_thread_resume(&thread_0);
                         
#ifdef __PRODUCT_NETXDUO__
#ifndef NX_DISABLE_ERROR_CHECKING
    /* Try to receive the third UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }
                      
    /* Try to receive the forth UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let thread 0 run. */
    tx_thread_resume(&thread_0);
#endif /* NX_DISABLE_ERROR_CHECKING */
#endif /* __PRODUCT_NETXDUO__ */
#endif /* NX_DISABLE_IPV4 */
                 
#ifdef FEATURE_NX_IPV6                  
    /**************************/
    /*   Test IPv6 packet     */
    /**************************/
               
    /* Try to receive the first UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 1 * NX_IP_PERIODIC_RATE);

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
                      
#ifndef NX_DISABLE_ERROR_CHECKING
    /* Try to receive the second UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }
                         
    /* Try to receive the third UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }
                      
    /* Try to receive the forth UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let thread 0 run. */
    tx_thread_resume(&thread_0);
#endif
#endif

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
}
