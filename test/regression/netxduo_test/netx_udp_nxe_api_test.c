/* This NetX test concentrates on the basic UDP operation.  */


#include   "nx_udp.h"
#include   "tx_api.h"
#include   "nx_api.h"      
#include   "nx_ip.h"
#include   "nx_packet.h"

#ifdef FEATURE_NX_IPV6
#include   "nx_ipv6.h"
#endif
                                       
extern void  test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   invalid_ip;

static NX_UDP_SOCKET           socket_0; 
static NX_UDP_SOCKET           socket_1;

#ifdef FEATURE_NX_IPV6
static NXD_ADDRESS             address_0;
static NXD_ADDRESS             address_1; 
static NXD_ADDRESS             invalid_address;
#endif /* FEATURE_NX_IPV6 */


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);  

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_nxe_api_test_application_define(void *first_unused_memory)
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

    /* Check for IP create errors.  */
    if (status)
        error_counter++;             
    
    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);  

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;

#ifdef FEATURE_NX_IPV6
    /* Enable IPv6 traffic.  */
    status = nxd_ipv6_enable(&ip_0);

    /* Enable ICMP processing for both IP instances.  */
    status +=  nxd_icmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;

    /* Set source and destination address with global address. */    
    address_0.nxd_ip_version = NX_IP_VERSION_V6;
    address_0.nxd_ip_address.v6[0] = 0x20010DB8;
    address_0.nxd_ip_address.v6[1] = 0x00010001;
    address_0.nxd_ip_address.v6[2] = 0x021122FF;
    address_0.nxd_ip_address.v6[3] = 0xFE334456;       

    /* Set the destination address.  */
    address_1.nxd_ip_version = NX_IP_VERSION_V6;
    address_1.nxd_ip_address.v6[0] = 0x20010DB8;
    address_1.nxd_ip_address.v6[1] = 0x00010001;
    address_1.nxd_ip_address.v6[2] = 0x021122FF;
    address_1.nxd_ip_address.v6[3] = 0xFE334458;

    /* Set the IPv6 address.  */
    status += nxd_ipv6_address_set(&ip_0, 0, &address_0, 64, NX_NULL); 

    /* Check for status.  */
    if (status)
        error_counter++;

#endif /* FEATURE_NX_IPV6 */  
}                     

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
UINT        socket_id;
NX_PACKET   *my_packet;  
NX_PACKET   *unkown_packet = NX_NULL;
UINT        free_port;
UINT        port;
UINT        protocol;
UINT        if_index;
ULONG       udp_packets_sent, udp_bytes_sent, udp_packets_received, udp_bytes_received, 
            udp_invalid_packets, udp_receive_packets_dropped, udp_checksum_errors, udp_packet_quiequed;
#ifdef FEATURE_NX_IPV6
NXD_ADDRESS my_address;
NX_PACKET   *my_packet_2;  
#endif
ULONG       my_address_2;
ULONG       bytes_avalable;
#ifdef __PRODUCT_NETXDUO__
UCHAR       temp_interface_valid;
UCHAR       *temp;
NX_PACKET   *invalid_packet;
#endif /* __PRODUCT_NETXDUO__ */
NX_UDP_SOCKET * temp_socket;


    /* Print out some test information banners.  */
    printf("NetX Test:   UDP NXE API Test..........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6
    /* Sleep 5 seconds to finish DAD.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
#endif /* FEATURE_NX_IPV6 */   

    /* Create udp socket without ip instance. */
    status = nx_udp_socket_create(NX_NULL, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create udp socket with invalid ip instance. */
    invalid_ip.nx_ip_id = 0;
    status = nx_udp_socket_create(&invalid_ip, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create udp socket with NULL pointer. */
    status = nx_udp_socket_create(&ip_0, NX_NULL, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_ERROR_CHECKING
    /* Create udp socket with wrong size. */
    status = _nxe_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5, 0);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_ERROR_CHECKING */

    /* Create udp socket with invalid service type. */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", 0xFFFFFFFF, NX_FRAGMENT_OKAY, 0x80, 5);
    if(status != NX_OPTION_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create udp socket with invalid fragment option. */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, 11111, 0x80, 5);
    if(status != NX_OPTION_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Create udp socket with invalid time to live option. */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE_MASK+1, 5);
    if(status != NX_OPTION_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {                    
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create again. */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup the first free port for 0x88.  */
    status =  nx_udp_free_port_find(&ip_0, 0x88, &free_port);

    /* Check status.  */
    if ((status) || (free_port != 0x88))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_delete(&socket_0);
    if(status != NX_STILL_BOUND) 
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_bind(&socket_0, 0xFFFFFFFF, NX_IP_PERIODIC_RATE/10);
    if(status != NX_INVALID_PORT)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                
    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                    

    /* Append the packet.  */
    status = nx_packet_data_append(my_packet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the the packet with null socket.  */
    status = nx_udp_socket_send(&socket_1, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }           

#ifdef FEATURE_NX_IPV6

    /* Send the the packet with null socket.  */
    status = nxd_udp_socket_send(NX_NULL, my_packet, &address_1, 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Send the the packet with null packet.  */
    status = nxd_udp_socket_send(&socket_0, unkown_packet, &address_1, 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the null packet with null socket.  */
    status = nxd_udp_socket_send(NX_NULL, unkown_packet, &address_1, 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the the packet with null address.  */
    status = nxd_udp_socket_send(&socket_0, my_packet, 0, 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the the packet with error socket ID.  */
    socket_0.nx_udp_socket_id = 0;
    status = nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_id = NX_UDP_ID;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet_2, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                    

    /* Append the packet.  */
    status = nx_packet_data_append(my_packet_2, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the packet whose IP vesion is IPv6. */
    my_packet_2 -> nx_packet_ip_version = NX_IP_VERSION_V6;
    status = nx_udp_socket_send(&socket_0, my_packet_2, IP_ADDRESS(1, 2, 3, 5), 0x89);
#endif
          
    /* Send the the packet with unkown packet.  */
    status = nx_udp_socket_send(&socket_0, unkown_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }                                

#ifdef __PRODUCT_NETXDUO__
    /* Send the packet with freed packet.  */
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
    status = nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }  
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
#endif

    /* Send the packet with unbound socket.  */
    temp_socket = socket_0.nx_udp_socket_bound_next;
    socket_0.nx_udp_socket_bound_next = NX_NULL;
    status = nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);  

    /* Check status.  */
    if (status != NX_NOT_BOUND)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_bound_next = temp_socket;

#ifdef FEATURE_NX_IPV6  
    /* Send the the packet with null socket.  */
    status = nxd_udp_socket_send(&socket_0, unkown_packet, &address_1, 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }  
#endif

    /* Send the the packet with invalid address.  */
    status = nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(0, 0, 0, 0), 0x89);  
    if (status != NX_IP_ADDRESS_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }                  

#ifdef __PRODUCT_NETXDUO__
    /* Send the the packet with invalid address.  */
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(0, 0, 0 ,0), 0x89, 0);
    if (status != NX_IP_ADDRESS_ERROR)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }                  

    status = nx_udp_socket_source_send(NX_NULL, my_packet, IP_ADDRESS(1, 2, 3 ,5), 0x89, 0);
    if (status != NX_PTR_ERROR)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }                  
#endif /* __PRODUCT_NETXDUO__ */

#ifdef FEATURE_NX_IPV6  
    /* Send the the packet with null socket.  */
    status = nxd_udp_socket_send(&socket_0, my_packet, NX_NULL, 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }                     

    /* Send the the packet with invalid socket id.  */
    socket_0.nx_udp_socket_id = 0;
    status = nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_id = NX_UDP_ID;

    /* Send the the packet with freed packet.  */
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
    status = nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);  

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;

    /* Fake one invalid address.  */
    invalid_address.nxd_ip_version = 0x5; 
    invalid_address.nxd_ip_address.v4= 0;  

    /* Send the the packet with null socket.  */
    status = nxd_udp_socket_send(&socket_0, my_packet, &invalid_address, 0x89);  

    /* Check status.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Send the packet with invalid destination IP address. */
    status = nxd_udp_socket_source_send(&socket_0, my_packet, &invalid_address, 0x89, 0);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Fake one invalid address.  */
    invalid_address.nxd_ip_version = NX_IP_VERSION_V4; 
    invalid_address.nxd_ip_address.v4= 0;  

    /* Send the the packet with invalid IP address.  */
    status = nxd_udp_socket_send(&socket_0, my_packet, &invalid_address, 0x89);  

    /* Check status.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Send the null packet. */
    status = nxd_udp_socket_source_send(&socket_0, unkown_packet, &address_1, 0x89, 0) ;
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the packet to null address. */
    status = nxd_udp_socket_source_send(&socket_0, my_packet, NX_NULL, 0x89, 0) ;
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the packet from an  invalid interface index. */
    status = nxd_udp_socket_source_send(&socket_0, my_packet, &invalid_address, 0x89, 123) ;
    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the packet with invalid destination IP address. */
    status = nxd_udp_socket_source_send(&socket_0, my_packet, &invalid_address, 0x89, 0);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Fake one invalid address.  */
    invalid_address.nxd_ip_version = NX_IP_VERSION_V6; 
    invalid_address.nxd_ip_address.v6[0]= 0;     
    invalid_address.nxd_ip_address.v6[1]= 0;  
    invalid_address.nxd_ip_address.v6[2]= 0;  
    invalid_address.nxd_ip_address.v6[3]= 0;  

    /* Send the the packet with null socket.  */
    status = nxd_udp_socket_send(&socket_0, my_packet, &invalid_address, 0x89);  

    /* Check status.  */
    if (status != NX_IP_ADDRESS_ERROR)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Send the packet with invalid destination IP address. */
    status = nxd_udp_socket_source_send(&socket_0, my_packet, &invalid_address, 0x89, 0);
    if(status != NX_IP_ADDRESS_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Send the packet from an  invalid interface index. */
    status = nxd_udp_socket_source_send(&socket_0, my_packet, &address_1, 0x89, 123) ;
    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#endif    
                     
#ifdef __PRODUCT_NETXDUO__
    /* Send the packet from an  invalid interface index. */
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89, NX_MAX_PHYSICAL_INTERFACES+1) ;
    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    temp_interface_valid = ip_0.nx_ip_interface[NX_MAX_PHYSICAL_INTERFACES - 1].nx_interface_valid;
    ip_0.nx_ip_interface[NX_MAX_PHYSICAL_INTERFACES - 1].nx_interface_valid = NX_FALSE;
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89, NX_MAX_PHYSICAL_INTERFACES-1) ;
    if(status != NX_INVALID_INTERFACE)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    ip_0.nx_ip_interface[NX_MAX_PHYSICAL_INTERFACES - 1].nx_interface_valid = temp_interface_valid;
#endif /* __PRODUCT_NETXDUO__ */


    /* Send the the packet with big number port.  */
    status = nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0xFFFFFFFF);  

    /* Check status.  */
    if (status != NX_INVALID_PORT)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }          

#ifdef __PRODUCT_NETXDUO__
    /* Send the the packet with invalid port.  */
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0xFFFFFFFF, 0);  
    if(status != NX_INVALID_PORT)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* __PRODUCT_NETXDUO__ */

#ifdef FEATURE_NX_IPV6  
    /* Send the the packet with invalid port.  */
    status = nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0xFFFFFFFF);  

    /* Check status.  */
    if (status != NX_INVALID_PORT)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }  

    /* Send the the packet with invalid port.  */
    status = nxd_udp_socket_source_send(&socket_0, my_packet, &address_1, 0xFFFFFFFF, 0);  
    if(status != NX_INVALID_PORT)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#endif

    /* Send the the packet when udp disable.  */
    ip_0.nx_ip_udp_packet_receive = NX_NULL;
    status = nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);  
    if (status != NX_NOT_ENABLED)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }     

    /* Pickup free port with null IP instance. */
    status = nx_udp_free_port_find(NX_NULL, 0, NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup free port with invalid IP instance. */
    ip_0.nx_ip_id = 0;
    status = nx_udp_free_port_find(&ip_0, 0, NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    ip_0.nx_ip_id = NX_IP_ID;

    /* Pickup free port with UDP disabled. */
    status = nx_udp_free_port_find(&ip_0, 0x123, &free_port);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    status = nx_udp_info_get(NX_NULL, &udp_packets_sent, &udp_bytes_sent,
                             &udp_packets_received, &udp_bytes_received, &udp_invalid_packets, 
                             &udp_receive_packets_dropped, &udp_checksum_errors);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    invalid_ip.nx_ip_id = 0;
    status = nx_udp_info_get(&invalid_ip, &udp_packets_sent, &udp_bytes_sent,
                             &udp_packets_received, &udp_bytes_received, &udp_invalid_packets, 
                             &udp_receive_packets_dropped, &udp_checksum_errors);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_info_get(&ip_0, &udp_packets_sent, &udp_bytes_sent,
                             &udp_packets_received, &udp_bytes_received, &udp_invalid_packets, 
                             &udp_receive_packets_dropped, &udp_checksum_errors);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_bind(&socket_0, 0x123, 10);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_udp_socket_bytes_available(&socket_0, NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    socket_0.nx_udp_socket_id = 0;
    status = nx_udp_socket_bytes_available(&socket_0, &bytes_avalable);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_id = NX_UDP_ID;

    status = nx_udp_socket_bytes_available(&socket_0, &bytes_avalable);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_checksum_disable(&socket_0);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_checksum_enable(&socket_0);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_delete(&socket_0);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_info_get(&socket_0, &udp_packets_sent, &udp_bytes_sent,
                                    &udp_packets_received, &udp_bytes_received, &udp_packet_quiequed,
                                    &udp_receive_packets_dropped, &udp_checksum_errors);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    status = nx_udp_socket_port_get(&socket_0, &port);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    socket_0.nx_udp_socket_id = 0;
    status = nx_udp_socket_port_get(&socket_0, &port);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_id = NX_UDP_ID;

    status = nx_udp_socket_port_get(&socket_0, NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_receive(&socket_0, &my_packet, NX_IP_PERIODIC_RATE);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    socket_0.nx_udp_socket_id = 0;
    status = nx_udp_socket_receive(&socket_0, &my_packet, NX_IP_PERIODIC_RATE);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_id = NX_UDP_ID;

    status = nx_udp_socket_receive(&socket_0, NX_NULL, NX_IP_PERIODIC_RATE);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef __PRODUCT_NETXDUO__
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3 ,5), 0x89, 0);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* __PRODUCT_NETXDUO__ */

    status = nx_udp_socket_unbind(&socket_0);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


#ifdef FEATURE_NX_IPV6  
    status = nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);  

    /* Check status.  */
    if (status != NX_NOT_ENABLED)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }  

    status = nxd_udp_socket_source_send(&socket_0, my_packet, &address_1, 0x89, 0);
    if(status != NX_NOT_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif                            
                                       
    /* Enable UDP traffic again.  */
    status =  nx_udp_enable(&ip_0);  
    if (status)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Enable UDP again. */
    status = nx_udp_enable(&ip_0);
    if(status != NX_ALREADY_ENABLED)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    status = nx_udp_enable(NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    invalid_ip.nx_ip_id = 0;
    status = nx_udp_enable(&invalid_ip);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }


    /* Send the the packet with invalid packet structure.  */
    my_packet -> nx_packet_prepend_ptr = my_packet -> nx_packet_data_start;   
    status = nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);  

    /* Check status.  */
    if (status != NX_UNDERFLOW)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }    

#ifdef __PRODUCT_NETXDUO__
    /* Test packet with underflow pointer. */
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89, 0);
    if (status != NX_UNDERFLOW)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }    

#ifdef FEATURE_NX_IPV6  
    status = nxd_udp_socket_source_send(&socket_0, my_packet, &address_1, 0x89, 0);
    if (status != NX_UNDERFLOW)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }    
#endif /* FEATURE_NX_IPV6 */
#endif /* __PRODUCT_NETXDUO__ */

    status = nx_udp_source_extract(my_packet, &my_address_2, &port);
    if(status != NX_INVALID_PACKET)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef FEATURE_NX_IPV6  
    /* Send the the packet with null socket.  */
    status = nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);  

    /* Check status.  */
    if (status != NX_UNDERFLOW)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }  
#endif /* FEATURE_NX_IPV6 */
       
    /* Send the the packet with invalid packet.  */
    my_packet -> nx_packet_prepend_ptr = my_packet -> nx_packet_data_start + NX_UDP_PACKET; 
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_data_end + 1;

    status = nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);  
    if (status != NX_OVERFLOW)
    {                       

        printf("ERROR!\n");
        test_control_return(1);
    }    

#ifdef __PRODUCT_NETXDUO__
    /* Test packet with overflow packet. */
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89, 0);
    if (status != NX_OVERFLOW)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }    

#ifdef FEATURE_NX_IPV6  
    status = nxd_udp_socket_source_send(&socket_0, my_packet, &address_1, 0x89, 0);
    if (status != NX_OVERFLOW)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }    
#endif
#endif /* __PRODUCT_NETXDUO__ */


#ifdef FEATURE_NX_IPV6  
    /* Send the the packet with null socket.  */
    status = nxd_udp_socket_send(&socket_0, my_packet, &address_1, 0x89);  

    /* Check status.  */
    if (status != NX_OVERFLOW)
    {                       
        printf("ERROR!\n");
        test_control_return(1);
    }  
#endif                    

#ifdef FEATURE_NX_IPV6
    status = nxd_udp_source_extract(my_packet, &address_1, NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nxd_udp_source_extract(my_packet, NX_NULL, &port);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    temp = my_packet -> nx_packet_ip_header;
    my_packet -> nx_packet_ip_header = NX_NULL;
    /* Extract  info from an invalid packet. */
    status = nxd_udp_source_extract(my_packet, &address_1, &port);
    if(status != NX_INVALID_PACKET)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    /* Restore the packet. */
    my_packet -> nx_packet_ip_header = temp;

    /* Extract info from a NULL packet. */
    status = nxd_udp_packet_info_extract(NX_NULL, &my_address, &protocol, &port, &if_index);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#endif
    /* Pickup free port from an invalid port. */
    status = nx_udp_free_port_find(&ip_0, 0, &free_port);
    if(status != NX_INVALID_PORT)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup free port from an invalid port. */
    status = nx_udp_free_port_find(&ip_0, (NX_MAX_PORT + 1), &free_port);
    if(status != NX_INVALID_PORT)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup free port from with invalid pointer. */
    status = nx_udp_free_port_find(&ip_0, 0, NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_packet_info_extract(NX_NULL, &my_address_2, &protocol, &port, &if_index);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_bytes_available(NX_NULL, &bytes_avalable);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_checksum_disable(NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    socket_1.nx_udp_socket_id = 0;
    status = nx_udp_socket_checksum_disable(&socket_1);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_checksum_enable(&socket_1);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_1.nx_udp_socket_id = NX_UDP_ID;

    status = nx_udp_socket_checksum_enable(NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_delete(NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the socket with invalid ID.  */
    socket_0.nx_udp_socket_id = 0;
    status = nx_udp_socket_delete(&socket_0);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_id = NX_UDP_ID;

    status = nx_udp_socket_info_get(NX_NULL, &udp_packets_sent, &udp_bytes_sent,
                                    &udp_packets_received, &udp_bytes_received, &udp_packet_quiequed,
                                    &udp_receive_packets_dropped, &udp_checksum_errors);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    socket_1.nx_udp_socket_id = 0;
    status = nx_udp_socket_info_get(&socket_1, &udp_packets_sent, &udp_bytes_sent,
                                    &udp_packets_received, &udp_bytes_received, &udp_packet_quiequed,
                                    &udp_receive_packets_dropped, &udp_checksum_errors);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_1.nx_udp_socket_id = NX_UDP_ID;

    status = nx_udp_socket_port_get(NX_NULL, &port);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_receive(NX_NULL, &my_packet, NX_IP_PERIODIC_RATE/10);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_socket_receive_notify(NX_NULL, NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    socket_id = socket_0.nx_udp_socket_id;
    socket_0.nx_udp_socket_id = 0;
    status = nx_udp_socket_receive_notify(&socket_0, NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    socket_0.nx_udp_socket_id = NX_UDP_ID;
    status = nx_udp_socket_receive_notify(&socket_0, NX_NULL);
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_id = socket_id;

#ifdef __PRODUCT_NETXDUO__
    status = nx_udp_socket_source_send(NX_NULL, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89, 0);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    invalid_packet = NX_NULL;
    status = nx_udp_socket_source_send(&socket_0, invalid_packet, IP_ADDRESS(1, 2, 3, 5), 0x89, 0);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_data_end;
    socket_0.nx_udp_socket_bound_next = NX_NULL;
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89, 0);
    if(status != NX_NOT_BOUND)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_bound_next = &socket_0;

#ifdef __PRODUCT_NETXDUO__
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
#else
    my_packet -> nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_FREE;
#endif
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89, 0);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#ifdef __PRODUCT_NETXDUO__
    my_packet -> nx_packet_union_next.nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
#else
    my_packet -> nx_packet_tcp_queue_next = (NX_PACKET *)NX_PACKET_ALLOCATED;
#endif

    socket_0.nx_udp_socket_ip_ptr = NX_NULL;
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89, 0);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_ip_ptr = &ip_0;

    socket_0.nx_udp_socket_ip_ptr -> nx_ip_id = 0;
    status = nx_udp_socket_source_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89, 0);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_ip_ptr -> nx_ip_id = NX_IP_ID;
#endif /* __PRODUCT_NETXDUO__ */

    status = nx_udp_socket_unbind(NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Unbind with socket id mismatch.  */
    socket_0.nx_udp_socket_id = 0;
    status = nx_udp_socket_unbind(&socket_0);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    socket_0.nx_udp_socket_id = NX_UDP_ID;

    status = nx_udp_source_extract(NX_NULL, &my_address_2, &port);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_source_extract(my_packet, NX_NULL, &port);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_udp_source_extract(my_packet, &my_address_2, NX_NULL);
    if(status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifdef __PRODUCT_NETXDUO__
    temp = my_packet -> nx_packet_ip_header;
    my_packet -> nx_packet_ip_header = NX_NULL;
    status = nx_udp_source_extract(my_packet, &my_address_2, &port);
    if(status != NX_INVALID_PACKET)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    my_packet -> nx_packet_ip_header = temp;

#ifdef FEATURE_NX_IPV6                                                        
    temp = my_packet -> nx_packet_data_start;   
    my_packet -> nx_packet_ip_version = NX_IP_VERSION_V6;   

    /* Adjust the data start.  */
    my_packet -> nx_packet_data_start = my_packet -> nx_packet_prepend_ptr - (sizeof(NX_UDP_HEADER) + sizeof(NX_IPV6_HEADER) - 1);
    status = nx_udp_source_extract(my_packet, &my_address_2, &port);
    if(status != NX_INVALID_PACKET)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    my_packet -> nx_packet_ip_version = NX_IP_VERSION_V4;            
    my_packet -> nx_packet_data_start = temp;
#endif                         

#endif /* __PRODUCT_NETXDUO__ */    

    printf("SUCCESS!\n");
    test_control_return(0);
}   
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   UDP NXE API Test..........................................N/A\n"); 

    test_control_return(3);  
}      
#endif
