/* This NetX test concentrates on the IP Address Set operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#ifdef __PRODUCT_NETX__
#define nx_udp_socket_source_send nx_udp_socket_interface_send
#endif
                                 
#define     DEMO_STACK_SIZE         2048      

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_UDP_SOCKET           socket_0;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;    

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);  
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);  


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ip_gateway_address_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;       

    if (status)
        error_counter++;                                   

#if (NX_MAX_PHYSICAL_INTERFACES > 1) && defined(__PRODUCT_NETXDUO__)
    /* Attach the second interface. */
    status += nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(1, 3, 3, 4), 0xFFFF0000UL, _nx_ram_network_driver_1500);

    if (status)
        error_counter++;                                   
#endif

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);

    if (status)
        error_counter++;                                   
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;        

#if (NX_MAX_PHYSICAL_INTERFACES > 1) && defined(__PRODUCT_NETXDUO__)
ULONG       ip_address;
#endif
NX_PACKET  *packet_ptr;  
    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Gateway Address Test...................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }             
                               

#if (NX_MAX_PHYSICAL_INTERFACES > 1) && defined(__PRODUCT_NETXDUO__)
    /* Get the gateway address before setting gateway.  */
    status = nx_ip_gateway_address_get(&ip_0, &ip_address);

    /* Check the status.  */
    if (status != NX_NOT_FOUND)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }        
#endif

    /* Set the gateway address with another network address.  */
    status = nx_ip_gateway_address_set(&ip_0, IP_ADDRESS(2, 2, 3, 1));

    /* Check the status.  */
    if (status != NX_IP_ADDRESS_ERROR)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }           

    /* Set the gateway address with correct network address.  */
    status = nx_ip_gateway_address_set(&ip_0, IP_ADDRESS(1, 2, 3, 1));

    /* Check the status.  */
    if (status)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }     
                         
#if (NX_MAX_PHYSICAL_INTERFACES > 1) && defined(__PRODUCT_NETXDUO__)
    /* Get the gateway address.  */
    status = nx_ip_gateway_address_get(&ip_0, &ip_address);

    /* Check the status.  */
    if ((status) || (ip_address != IP_ADDRESS(1, 2, 3, 1)))
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }            
#endif

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &packet_ptr, NX_UDP_PACKET, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(packet_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28, &pool_0, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_IP_INFO
    if (ip_0.nx_ip_invalid_transmit_packets != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_IP_INFO */

    /* Send a packet out of network through the second interface. 
     * But the default gateway is set at first interface. */
    nx_udp_socket_source_send(&socket_0, packet_ptr, IP_ADDRESS(1, 4, 3, 5), 12, 1);

#if !defined(NX_DISABLE_IP_INFO) && (NX_MAX_PHYSICAL_INTERFACES > 1) && defined(__PRODUCT_NETXDUO__)
    /* Make sure the packet is dropped. */
    if (ip_0.nx_ip_invalid_transmit_packets == 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_IP_INFO */

    /* Output successful.  */   
    printf("SUCCESS!\n");
    test_control_return(0);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_gateway_address_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Gateway Address Test...................................N/A\n"); 

    test_control_return(3);  
}      
#endif
