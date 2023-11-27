/* This NetX test concentrates on the IP Static Route Find operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"

extern void  test_control_return(UINT status);

#if defined (__PRODUCT_NETXDUO__) && defined (NX_ENABLE_IP_STATIC_ROUTING) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */
static ULONG                   error_counter;
static ULONG                   icmp_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);
static VOID    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_static_route_find_test_application_define(void *first_unused_memory)
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 2);
    pointer =  pointer + 2048;
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

    /* Enable ICMP processing for both IP instances.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
ULONG       return_value;


    /* Print out test information banner.  */
    printf("NetX Test:   IP Static Route Find Test.................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the gateway address with another network address.  */
    status = nx_ip_static_route_add(&ip_0, IP_ADDRESS(2, 2, 3, 5), IP_ADDRESS(255, 255, 255, 0), IP_ADDRESS(1, 2, 3, 5));

    /* Check the status.  */
    if (status)   
    {                         
        printf("ERROR!\n");
        test_control_return(1);
    }
             
    /* Set the callback function to get the IPv4 packet.  */
    ip_1.nx_ipv4_packet_receive = my_packet_process;

    /* Ping an IP address in another network.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(2, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_NO_RESPONSE) || (my_packet) || (icmp_counter != 1))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set link status from up to down. */
    status = nx_ip_driver_interface_direct_command(&ip_0, NX_LINK_DISABLE, 0, &return_value);
    
    /* Check for earlier error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an IP address in another network again.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(2, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if the timeout error occurred.  */
    if ((status != NX_IP_ADDRESS_ERROR) || (my_packet) || (icmp_counter != 1))
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
    
static VOID   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{           
                                
NX_IPV4_HEADER   *ip_header_ptr;
ULONG            protocol;

    /* Ignore packet that is not ICMP. */
    if(packet_ptr -> nx_packet_length >= 28)
    {

        ip_header_ptr = (NX_IPV4_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);

        /* Get IP header. */
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
        protocol = (ip_header_ptr -> nx_ip_header_word_2 >> 16) & 0xFF;

        /* Is ICMP packet? */
        if(protocol == 1)
        {

            /* Yes it is. Update the counter.  */
            icmp_counter ++;
        }

        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
    }

    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(ip_ptr, packet_ptr);
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_static_route_find_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IP Static Route Find Test.................................N/A\n");
    test_control_return(3);
}
#endif
