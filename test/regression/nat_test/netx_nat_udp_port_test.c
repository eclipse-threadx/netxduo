
/* This NetX test concentrates on the UCP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"    
#include   "nx_tcp.h"
#include   "nx_udp.h" 
                         
extern void    test_control_return(UINT status);
#if defined NX_NAT_ENABLE && defined __PRODUCT_NETXDUO__ && (NX_MAX_PHYSICAL_INTERFACES >= 2) && !defined(NX_DISABLE_IPV4)
#include   "nx_nat.h"

#define     DEMO_STACK_SIZE         2048
                                                 
/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD                    thread_0;  
static TX_THREAD                    thread_1;

/* Set up the NAT components. */

/* Create a NAT instance, packet pool and translation table. */
                                                 
NX_PACKET_POOL                      nat_packet_pool;   
NX_NAT_DEVICE                       nat_server;  
NX_IP                               nat_ip;      
NX_IP                               local_ip;
NX_IP                               external_ip;   
NX_UDP_SOCKET                       local_socket;   
NX_UDP_SOCKET                       nat_socket;
NX_UDP_SOCKET                       external_socket; 
NX_UDP_SOCKET                       test_socket;
                                                                  

/* Configure the NAT network parameters. */

/* Set NetX IP packet pool packet size. This should be less than the Maximum Transmit Unit (MTU) of
   the driver (allow enough room for the Ethernet header plus padding bytes for frame alignment).  */
#define NX_NAT_PACKET_SIZE                          1536


/* Set the size of the NAT IP packet pool.  */
#define NX_NAT_PACKET_POOL_SIZE                     (NX_NAT_PACKET_SIZE * 10)

/* Set NetX IP helper thread stack size. */   
#define NX_NAT_IP_THREAD_STACK_SIZE                 2048

/* Set the server IP thread priority */
#define NX_NAT_IP_THREAD_PRIORITY                   2

/* Set ARP cache size of a NAT ip instance. */
#define NX_NAT_ARP_CACHE_SIZE                       1024 

/* Set NAT entries memory size. */
#define NX_NAT_ENTRY_CACHE_SIZE                     1024

/* Define NAT IP addresses, local host private IP addresses and external host IP address. */
#define NX_NAT_LOCAL_IPADR              (IP_ADDRESS(192, 168, 2, 1))  
#define NX_NAT_LOCAL_HOST1              (IP_ADDRESS(192, 168, 2, 3))
#define NX_NAT_LOCAL_HOST2              (IP_ADDRESS(192, 168, 2, 10)) 
#define NX_NAT_LOCAL_GATEWAY            (IP_ADDRESS(192, 168, 2, 1))    
#define NX_NAT_LOCAL_NETMASK            (IP_ADDRESS(255, 255, 255, 0))
#define NX_NAT_EXTERNAL_IPADR           (IP_ADDRESS(192, 168, 0, 10))   
#define NX_NAT_EXTERNAL_HOST            (IP_ADDRESS(192, 168, 0, 100))   
#define NX_NAT_EXTERNAL_GATEWAY         (IP_ADDRESS(192, 168, 0, 1))    
#define NX_NAT_EXTERNAL_NETMASK         (IP_ADDRESS(255, 255, 255, 0))  

/* Create NAT structures for preloading NAT tables with static 
   entries for local server hosts. */
NX_NAT_TRANSLATION_ENTRY            server_inbound_entry_udp1; 
NX_NAT_TRANSLATION_ENTRY            server_inbound_entry_udp2;

/* Set up generic network driver for demo program. */             
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);    


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input); 
static void    thread_1_entry(ULONG thread_input);
                                                                        

/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_nat_udp_port_test_application_define(void *first_unused_memory)
#endif
{

UINT     status;
UCHAR    *pointer;    
UINT     error_counter = 0;
    
    /* Initialize the NetX system. */
    nx_system_initialize();
    
    /* Setup the pointer to unallocated memory.  */
    pointer =  (UCHAR *) first_unused_memory;
                          
    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;        

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;   

    /* Create NAT packet pool. */   
    status =  nx_packet_pool_create(&nat_packet_pool, "NAT Packet Pool", 
                                    NX_NAT_PACKET_SIZE, pointer, 
                                    NX_NAT_PACKET_POOL_SIZE);

    /* Update pointer to unallocated (free) memory. */
    pointer = pointer + NX_NAT_PACKET_POOL_SIZE;    

    /* Check status.  */
    if (status)
        return;
                            
    /* Create IP instances for NAT server (global network) */
    status = nx_ip_create(&nat_ip, "NAT IP Instance", NX_NAT_EXTERNAL_IPADR, NX_NAT_EXTERNAL_NETMASK, 
                          &nat_packet_pool, _nx_ram_network_driver_1500, pointer, 
                          NX_NAT_IP_THREAD_STACK_SIZE, NX_NAT_IP_THREAD_PRIORITY);

    /* Update pointer to unallocated (free) memory. */
    pointer =  pointer + NX_NAT_IP_THREAD_STACK_SIZE;

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }
                 
    /* Set the private interface(private network).  */
    status += nx_ip_interface_attach(&nat_ip, "Private Interface", NX_NAT_LOCAL_IPADR, NX_NAT_LOCAL_NETMASK, _nx_ram_network_driver_1500);
             
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }                
                                     
    /* Create IP instances for Local network IP instance */
    status = nx_ip_create(&local_ip, "Local IP Instance", NX_NAT_LOCAL_HOST1, NX_NAT_LOCAL_NETMASK, 
                          &nat_packet_pool, _nx_ram_network_driver_1500, pointer, 
                          NX_NAT_IP_THREAD_STACK_SIZE, NX_NAT_IP_THREAD_PRIORITY);

    /* Update pointer to unallocated (free) memory. */
    pointer =  pointer + NX_NAT_IP_THREAD_STACK_SIZE;

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }
                  
    /* Create IP instances for external network IP instance */
    status = nx_ip_create(&external_ip, "External IP Instance", NX_NAT_EXTERNAL_HOST, NX_NAT_EXTERNAL_NETMASK, 
                          &nat_packet_pool, _nx_ram_network_driver_1500, pointer, 
                          NX_NAT_IP_THREAD_STACK_SIZE, NX_NAT_IP_THREAD_PRIORITY);

    /* Update pointer to unallocated (free) memory. */
    pointer =  pointer + NX_NAT_IP_THREAD_STACK_SIZE;

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }

    /* Set the global network gateway for NAT IP instance.  */
    status = nx_ip_gateway_address_set(&nat_ip, NX_NAT_EXTERNAL_GATEWAY);
                       
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }                     
    
    /* Set the global network gateway for Local IP instance.  */
    status = nx_ip_gateway_address_set(&local_ip, NX_NAT_LOCAL_GATEWAY);
                       
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }                     
    
    /* Set the global network gateway for External IP instance.  */
    status = nx_ip_gateway_address_set(&external_ip, NX_NAT_EXTERNAL_GATEWAY);
                       
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }                     

    
    /* Enable ARP and supply ARP cache memory for NAT IP isntance. */
    status =  nx_arp_enable(&nat_ip, (void **) pointer, 
                            NX_NAT_ARP_CACHE_SIZE);
                         
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }           
    
    /* Update pointer to unallocated (free) memory. */
    pointer = pointer + NX_NAT_ARP_CACHE_SIZE;
                                              
    /* Enable ARP and supply ARP cache memory for Local IP isntance. */
    status =  nx_arp_enable(&local_ip, (void **) pointer, 
                            NX_NAT_ARP_CACHE_SIZE);
                         
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }           
    
    /* Update pointer to unallocated (free) memory. */
    pointer = pointer + NX_NAT_ARP_CACHE_SIZE;
                                             
    /* Enable ARP and supply ARP cache memory for External IP isntance. */
    status =  nx_arp_enable(&external_ip, (void **) pointer, 
                            NX_NAT_ARP_CACHE_SIZE);
                         
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }           
    
    /* Update pointer to unallocated (free) memory. */
    pointer = pointer + NX_NAT_ARP_CACHE_SIZE;
                                     
    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&nat_ip);
    status += nx_udp_enable(&local_ip);
    status += nx_udp_enable(&external_ip);
                                           
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }  

    /* Create a NetX NAT server and cache with a global interface index.  */
    status =  nx_nat_create(&nat_server, &nat_ip, 0, pointer, NX_NAT_ENTRY_CACHE_SIZE);
                             
    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }           

    /* Update pointer to unallocated (free) memory. */
    pointer = pointer + NX_NAT_ENTRY_CACHE_SIZE;

    /* Enable the NAT service.  */
    nx_nat_enable(&nat_server);                    
}                    

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;                 
ULONG       packets_sent, bytes_sent, packets_received, bytes_received, packets_queued, receive_packets_dropped, checksum_errors;

    
    /* Print out test information banner.  */
    printf("NetX Test:   NAT UDP Port Processing Test..............................");                                                       
                                             
    /* Create a UDP local socket.  */
    status = nx_udp_socket_create(&nat_ip, &nat_socket, "NAT Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                                 
    /* Bind the UDP socket to the IP port as NX_NAT_START_UDP_PORT.  */
    status =  nx_udp_socket_bind(&nat_socket, NX_NAT_START_UDP_PORT, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               
          
    /* Preload a NAT entry with same external UDP port of local socket.  */
    status = nx_nat_inbound_entry_create(&nat_server, &server_inbound_entry_udp1, NX_NAT_LOCAL_HOST1, NX_NAT_START_UDP_PORT, NX_NAT_START_UDP_PORT, NX_PROTOCOL_UDP);
                
    /* Check status.  */
    if (status != NX_NAT_PORT_UNAVAILABLE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 
                                
    /* Preload a NAT entry with different external UDP port of local socket.  */
    status = nx_nat_inbound_entry_create(&nat_server, &server_inbound_entry_udp1, NX_NAT_LOCAL_HOST1, NX_NAT_START_UDP_PORT - 1, NX_NAT_START_UDP_PORT, NX_PROTOCOL_UDP);
                
    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  
                                   
    /* Preload a NAT entry with same external UDP port of NAT entry1.  */
    status = nx_nat_inbound_entry_create(&nat_server, &server_inbound_entry_udp2, NX_NAT_LOCAL_HOST1, NX_NAT_START_UDP_PORT - 1, NX_NAT_START_UDP_PORT, NX_PROTOCOL_UDP);
                
    /* Check status.  */
    if (status != NX_NAT_PORT_UNAVAILABLE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
             
                                                
    /* Create a UDP test socket.  */
    status = nx_udp_socket_create(&nat_ip, &test_socket, "TEST Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                                 
    /* Bind the UDP socket to the same external UDP port of NAT entry 1. NX_NAT_START_UDP_PORT - 1.  */
    status =  nx_udp_socket_bind(&test_socket, NX_NAT_START_UDP_PORT - 1, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_PORT_UNAVAILABLE)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the test socket.  */
    status = nx_udp_socket_delete(&test_socket);
     
    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the inbound entry.  */
    status = nx_nat_inbound_entry_delete(&nat_server, &server_inbound_entry_udp1);
                
    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Create a UDP local socket.  */
    status = nx_udp_socket_create(&local_ip, &local_socket, "Local Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                                 
    /* Bind the UDP socket to the IP port 0x88.  */
    status =  nx_udp_socket_bind(&local_socket, 0x88, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /* Create a UDP External socket.  */
    status = nx_udp_socket_create(&external_ip, &external_socket, "External Socket", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                         
    /* Bind the UDP socket to the IP port 0x89.  */
    status =  nx_udp_socket_bind(&external_socket, 0x89, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                     
                                                   
    /***********************************************************************/
    /*         Local Socket sends udp packet to External Socket            */    
    /***********************************************************************/

    /* Let other threads run again.  */
    tx_thread_relinquish();
    
    /* Allocate a packet.  */
    status =  nx_packet_allocate(&nat_packet_pool, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

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
    status =  nx_udp_socket_send(&local_socket, my_packet, NX_NAT_EXTERNAL_HOST, 0x89);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                                     
           
    /* Let other threads run again.  */
    tx_thread_relinquish();
                                  
    /* Check the NAT forwarded count.  */
#ifndef NX_DISABLE_NAT_INFO
    if ((nat_server.forwarded_packets_received != 1) || (nat_server.forwarded_packets_sent != 1) ||(nat_server.forwarded_packets_dropped != 0)) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Get UDP Local socket information.  */
    status =  nx_udp_socket_info_get(&local_socket, &packets_sent, &bytes_sent, &packets_received, &bytes_received, 
                                      &packets_queued, &receive_packets_dropped, &checksum_errors);
    
#ifndef NX_DISABLE_UDP_INFO

    if ((packets_sent != 1) || (bytes_sent != 28) || (packets_received != 0) || (bytes_received != 0))
    {                    
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif
    /* Check status.  */
    if ((receive_packets_dropped) || (checksum_errors))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Unbind the UDP nat socket.  */
    status =  nx_udp_socket_unbind(&nat_socket);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP nat socket.  */
    status =  nx_udp_socket_delete(&nat_socket);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    /* Unbind the UDP local socket.  */
    status =  nx_udp_socket_unbind(&local_socket);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP Local socket.  */
    status =  nx_udp_socket_delete(&local_socket);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                   
                          
    /* Unbind the UDP external socket.  */
    status =  nx_udp_socket_unbind(&external_socket);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP external socket.  */
    status =  nx_udp_socket_delete(&external_socket);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                         
    /* Output success.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}


static void    thread_1_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;   
ULONG       peer_ip_address;
UINT        peer_port;
                           

    /***********************************************************************/
    /*         External Socket receives the udp packet from Local Socket   */    
    /***********************************************************************/

    /* Receive a UDP packet.  */
    status =  nx_udp_socket_receive(&external_socket, &my_packet, 10 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
          
    /* Check the peer socket port.  */
    status = nx_udp_source_extract(my_packet, &peer_ip_address, &peer_port);

    /* Check status.  */
    if ((status) || (peer_ip_address != NX_NAT_EXTERNAL_IPADR) || (peer_port != NX_NAT_START_TCP_PORT + 1))
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
void    netx_nat_udp_port_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   NAT UDP Port Processing Test..............................N/A\n");
    test_control_return(3);
}
#endif
