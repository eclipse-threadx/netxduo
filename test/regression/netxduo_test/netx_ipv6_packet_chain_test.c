/* Test processing of packet chain. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"        

extern void    test_control_return(UINT status);
#if defined(FEATURE_NX_IPV6) && !defined(NX_DISABLE_PACKET_CHAIN)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter; 
static ULONG                   icmp_counter; 
static NXD_ADDRESS             global_address_0; 
static NXD_ADDRESS             global_address_1; 


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);   
static VOID    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_packet_chain_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 
    status += nxd_ipv6_enable(&ip_1);

    /* Check ipv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMPv6 processing for IP instances0 .  */
    status = nxd_icmp_enable(&ip_0);      
    status += nxd_icmp_enable(&ip_1);   

    /* Check ICMPv6 enable status.  */
    if(status)
        error_counter++;
    
    /* Set ipv6 global address for IP instance 0.  */
    global_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_0.nxd_ip_address.v6[0] = 0x20010000;
    global_address_0.nxd_ip_address.v6[1] = 0x00000000;
    global_address_0.nxd_ip_address.v6[2] = 0x00000000;
    global_address_0.nxd_ip_address.v6[3] = 0x10000001;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_0, 0, &global_address_0, 64, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;       

    /* Set ipv6 global address for IP instance 1.  */
    global_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    global_address_1.nxd_ip_address.v6[0] = 0x20010000;
    global_address_1.nxd_ip_address.v6[1] = 0x00000000;
    global_address_1.nxd_ip_address.v6[2] = 0x00000000;
    global_address_1.nxd_ip_address.v6[3] = 0x10000002;                              
                           
    /* Set the IPv6 address.  */
    status = nxd_ipv6_address_set(&ip_1, 0, &global_address_1, 64, NX_NULL);      

    /* Check status.  */
    if(status)
        error_counter++;   
}                 


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet; 

    
    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Packet Chain Test....................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);
                                           
    /* Set the callback function to get the IPv6 packet.  */
    ip_1.nx_ipv6_packet_receive = my_packet_process;

    /* Ping an IP address that does exist.  */
    status = nxd_icmp_ping(&ip_0, &global_address_1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if ((status == NX_SUCCESS) || (my_packet))
    {
#if defined(NX_ENABLE_INTERFACE_CAPABILITY)
        printf("ERROR!\n");
        test_control_return(1);
#endif
    }

    /* Check the error counter and icmp counter.  */
    if ((error_counter) || (icmp_counter != 1))   
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}         
     

static VOID   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{           

UINT            status;
NX_PACKET       *my_packet_1;
NX_PACKET       *my_packet_2;
NX_PACKET       *my_packet_3;
NX_IPV6_HEADER  *ip_header_ptr;


    /* Check the packet length.  */
    if (packet_ptr ->nx_packet_length == 76) // 28(DATA) + 8(ICMP HEADER) + 40(IPV6 HEADER)
    {

        /* Get the ICMP packet.  */
        icmp_counter ++;

        /***************************************************************************/
        /* nx_packet_length > pkt_length for chain packet nx_ipv6_packet_receive() */
        /* last packet < delta, two packet chain.                                  */
        /***************************************************************************/

        /* Copy the packet.  */
        status = nx_packet_copy(packet_ptr, &my_packet_1, &pool_0, NX_NO_WAIT);

        /* Check status.  */
        if (status)
            error_counter ++;

        /* Get the IPv6 header.  */  
        ip_header_ptr = (NX_IPV6_HEADER *)my_packet_1 -> nx_packet_prepend_ptr;

        /* Convert to host byte order. */
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);   

        /* Modified the packet length.  */
        ip_header_ptr -> nx_ip_header_word_1 -= 0x00040000;         

        /* Convert to host byte order. */
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

        /* Allocate a packet.  */
        status = nx_packet_allocate(&pool_0, &my_packet_2, NX_UDP_PACKET, TX_WAIT_FOREVER);
        if (status)
            error_counter++;

        /* Write ABCs into the packet payload!  */
        memcpy(my_packet_2 -> nx_packet_prepend_ptr, "ABC", 3);

        /* Adjust the write pointer.  bigger than 256 to cause fragmentation. */
        my_packet_2 -> nx_packet_length = 3;
        my_packet_2 -> nx_packet_append_ptr = my_packet_2 -> nx_packet_prepend_ptr + 3;

        /* Chain the packet.  */
        my_packet_1 -> nx_packet_next = my_packet_2;
        my_packet_1 -> nx_packet_last = my_packet_2;

        /* Call the _nx_ipv6_packet_receive function directly receive this packet.  */
        _nx_ipv6_packet_receive(&ip_1, my_packet_1);

        /***************************************************************************/
        /* nx_packet_length > pkt_length for chain packet nx_ipv6_packet_receive() */
        /* last packet < delta, three packet chain                                 */
        /***************************************************************************/

        /* Copy the packet.  */
        status = nx_packet_copy(packet_ptr, &my_packet_1, &pool_0, NX_NO_WAIT);

        /* Check status.  */
        if (status)
            error_counter ++;

        /* Get the IPv6 header.  */  
        ip_header_ptr = (NX_IPV6_HEADER *)my_packet_1 -> nx_packet_prepend_ptr;

        /* Convert to host byte order. */
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);   

        /* Modified the packet length.  */
        ip_header_ptr -> nx_ip_header_word_1 -= 0x00040000;         

        /* Convert to host byte order. */
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

        /* Allocate a packet.  */
        status = nx_packet_allocate(&pool_0, &my_packet_2, NX_UDP_PACKET, TX_WAIT_FOREVER);
        if (status)
            error_counter++;

        /* Write ABCs into the packet payload!  */
        memcpy(my_packet_2 -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26);

        /* Adjust the write pointer.  bigger than 256 to cause fragmentation. */
        my_packet_2 -> nx_packet_length = 26;
        my_packet_2 -> nx_packet_append_ptr = my_packet_2 -> nx_packet_prepend_ptr + 26;

        /* Allocate a packet.  */
        status = nx_packet_allocate(&pool_0, &my_packet_3, NX_UDP_PACKET, TX_WAIT_FOREVER);
        if (status)
            error_counter++;

        /* Write ABCs into the packet payload!  */
        memcpy(my_packet_3 -> nx_packet_prepend_ptr, "ABC", 3);

        /* Adjust the write pointer.  bigger than 256 to cause fragmentation. */
        my_packet_3 -> nx_packet_length = 3;
        my_packet_3 -> nx_packet_append_ptr = my_packet_3 -> nx_packet_prepend_ptr + 3;

        /* Chain the packet.  */
        my_packet_1 -> nx_packet_next = my_packet_2;
        my_packet_1 -> nx_packet_last = my_packet_3;
        my_packet_2 -> nx_packet_next = my_packet_3;

        /* Call the _nx_ipv6_packet_receive function directly receive this packet.  */
        _nx_ipv6_packet_receive(&ip_1, my_packet_1);

        /***************************************************************************/
        /* nx_packet_length > pkt_length for chain packet nx_ipv6_packet_receive() */
        /* last packet < delta, while(delta == 0).                                 */
        /***************************************************************************/

        /* Get the IPv6 header.  */  
        ip_header_ptr = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

        /* Convert to host byte order. */
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);   

        /* Modified the packet length.  */
        ip_header_ptr -> nx_ip_header_word_1 -= 0x00030000;         

        /* Convert to host byte order. */
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

        /* Allocate a packet.  */
        status = nx_packet_allocate(&pool_0, &my_packet_1, NX_UDP_PACKET, TX_WAIT_FOREVER);
        if (status)
            error_counter++;

        /* Write ABCs into the packet payload!  */
        memcpy(my_packet_1 -> nx_packet_prepend_ptr, "ABC", 3);

        /* Adjust the write pointer.  bigger than 256 to cause fragmentation. */
        my_packet_1 -> nx_packet_length = 3;
        my_packet_1 -> nx_packet_append_ptr = my_packet_1 -> nx_packet_prepend_ptr + 3;

        /* Chain the packet.  */
        packet_ptr -> nx_packet_next = my_packet_1;
        packet_ptr -> nx_packet_last = my_packet_1;
    }

    /* Call the _nx_ipv6_packet_receive function directly receive this packet.  */
    _nx_ipv6_packet_receive(&ip_1, packet_ptr);

}
#else    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_packet_chain_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Packet Chain Test....................................N/A\n");
    
    test_control_return(3);
}
#endif
