/* This NetX test concentrates on the IPv6 receive the invalid packet operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"        

extern void    test_control_return(UINT status);
#ifdef FEATURE_NX_IPV6

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

static char pkt1[] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x07, 0x2b, 0xff, 0x20, 0x01, /* ... .... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x10, 0x00, 0x00, 0x03, 0x20, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x3a, 0x00, /* "..3DV:. */
0x01, 0x04, 0x00, 0x00, 0x00,
};

static char pkt2[] = {
0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, /* .."3DV.. */
0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x18, 0x3c, 0xff, 0x20, 0x01, /* ... .... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x10, 0x00, 0x00, 0x03, 0x20, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x3c, 0x00, /* "..3DV:. */
0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, /* ........ */
0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, /* ........ */
0x03, 0x04, 0x05, 0x06, 0x07, 0x08              /* ...... */
};

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_invalid_packet_receive_test_application_define(void *first_unused_memory)
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
UINT        drop_counter = 0;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Invalid Packet Receive Test..........................");

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
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_IPv6_PACKET, 5 * NX_IP_PERIODIC_RATE);
               
    /* Write data into the packet payload, ignore the physical header!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt1[14 + 40], sizeof(pkt1) - 14 - 40);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length = sizeof(pkt1) - 14 - 40;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

    /* Set the interface.  */
    my_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];

    status = _nx_ipv6_process_routing_option(&ip_0, my_packet);

    /* Check the status. */
    if (status != NX_OPTION_HEADER_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

#ifndef NX_DISABLE_FRAGMENTATION

    nx_ip_fragment_enable(&ip_0);

    status = _nx_ipv6_process_fragment_option(&ip_0, my_packet);

    /* Check the status. */
    if (status != NX_OPTION_HEADER_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    nx_packet_release(my_packet);

    /* Allocate one packet.  */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_IPv6_PACKET, 5 * NX_IP_PERIODIC_RATE);
               
    /* Write data into the packet payload, ignore the physical header!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &pkt2[14], sizeof(pkt2) - 14);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length = sizeof(pkt2) - 14;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

    /* Set the interface.  */
    my_packet -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    my_packet -> nx_packet_ip_version = NX_IP_VERSION_V6;

    drop_counter = ip_0.nx_ip_receive_packets_dropped;

    /* Cover nx_ip_dispatch_process.c line 185. */
    _nx_ipv6_packet_receive(&ip_0, my_packet);
#ifndef NX_DISABLE_IP_INFO
    if (drop_counter == ip_0.nx_ip_receive_packets_dropped)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Check the error counter and icmp counter.  */
    if ((error_counter) || (icmp_counter != 1))   
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {

        /* Output successful.  */
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}         
     

static VOID   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{           

UINT            status;
NX_PACKET       *my_packet;
NX_IPV6_HEADER  *ip_header_ptr;


    /* Check the packet length.  */
    if (packet_ptr ->nx_packet_length == 76) // 28(DATA) + 8(ICMP HEADER) + 40(IPV6 HEADER)
    {

        /* Get the ICMP packet.  */
        icmp_counter ++;

        /* Copy the packet.  */
        status = nx_packet_copy(packet_ptr, &my_packet, &pool_0, NX_NO_WAIT);

        /* Check status.  */
        if (status)
            error_counter ++;


        /**********************************************************/ 
        /* nx_packet_length < pkt_length nx_ipv6_packet_receive() */
        /**********************************************************/

        /* Get the IPv6 header.  */  
        ip_header_ptr = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

        /* Convert to host byte order. */
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);   

        /* Modified the packet length.  */
        ip_header_ptr -> nx_ip_header_word_1 += 0x00010000;         

        /* Convert to host byte order. */
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

        /* Set the address state as NX_IPV6_ADDR_STATE_UNKNOWN, and receive the packet again, then recover the state.  
           Cover the code if (interface_ipv6_address_next -> nxd_ipv6_address_state != NX_IPV6_ADDR_STATE_UNKNOWN) in _nx_ipv6_packet_receive.  */
        ip_1.nx_ipv6_address[0].nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_UNKNOWN;
        _nx_ipv6_packet_receive(&ip_1, my_packet);
        ip_1.nx_ipv6_address[0].nxd_ipv6_address_state = NX_IPV6_ADDR_STATE_VALID;
    }  

    /* Call the _nx_ipv6_packet_receive function directly receive this packet.  */
    _nx_ipv6_packet_receive(&ip_1, packet_ptr);

}
#else    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv6_invalid_packet_receive_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   IPv6 Invalid Packet Receive Test..........................N/A\n");
    
    test_control_return(3);
}
#endif
