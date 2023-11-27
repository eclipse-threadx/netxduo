/* This NetX test concentrates on basic IP fragmentation.  */


#include   "tx_api.h"
#include   "nx_api.h"
#if !defined(NX_DISABLE_FRAGMENTATION) && defined(FEATURE_NX_IPV6)  
#include   "nx_ipv6.h"
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

static NXD_ADDRESS             ipv6_address_0;
static NXD_ADDRESS             ipv6_address_1;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static ULONG                   fragmentation_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);     
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);      
static VOID    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UCHAR   buffer[4500];


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void  netx_ipv6_fragmentation_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    fragmentation_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 4800, pointer, 5000*10);
    pointer = pointer + 5000*10;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_1500,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    status = nxd_ipv6_enable(&ip_0);
    status += nxd_ipv6_enable(&ip_1);
    if (status)
        error_counter++;

    /* Enable IP fragmentation logic on both IP instances.  */
    status =  nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);
    if (status)
        error_counter++;

    status = nxd_icmp_enable(&ip_0);
    status += nxd_icmp_enable(&ip_1);
    if (status)
        error_counter++;

    /* Set ipv6 version and address.  */
    ipv6_address_0.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_0.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_0.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_0.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_0.nxd_ip_address.v6[3] = 0x10000001;

    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0x20010000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[3] = 0x10000002;   

    /* Set interfaces' address */
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_0, 64, NX_NULL);
    status += nxd_ipv6_address_set(&ip_1, 0, &ipv6_address_1, 64, NX_NULL);

    if(status)
        error_counter++;

}                   


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;


    /* Print out some test information banners.  */
    printf("NetX Test:   IPv6 Fragmentation Processing Test........................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* DAD */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    /* Force enable ICMPv6 checksum capability. */
    ip_0.nx_ip_interface[0].nx_interface_capability_flag |= NX_INTERFACE_CAPABILITY_ICMPV6_TX_CHECKSUM;
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

    /* Disable IP fragmentation logic on IP instance 1.  */
    status =  nx_ip_fragment_disable(&ip_1);
    
    /* Check the status.  */
    if (status)
        error_counter++;

    /* Now ping an IP address that does exist.  */
    memcpy(buffer, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26);
    status = nxd_icmp_ping(&ip_0, &ipv6_address_1, buffer, 4500, &my_packet, TX_TIMER_TICKS_PER_SECOND);

    /* Check the status.  */
    if (status == NX_SUCCESS)
        error_counter++;                         
                          
    /* Enable IP fragmentation logic on IP instance 1.  */
    status =  nx_ip_fragment_enable(&ip_1);
    
    /* Check the status.  */
    if (status)
        error_counter++;

    /* Install IPv6 packet receive processing function pointer */
    ip_1.nx_ipv6_packet_receive = my_packet_process;
                   
    /* Now ping an IP address that does exist.  */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_1, buffer, 4500, &my_packet, TX_TIMER_TICKS_PER_SECOND);

    /* Check the status.  */
    if (status == NX_SUCCESS)
        error_counter++;  
                     
    /* Install IPv6 packet receive processing function pointer */
    ip_1.nx_ipv6_packet_receive = _nx_ipv6_packet_receive;
                                                   
    /* Disable IP fragmentation logic on IP instance 1 to release the fragmentation packet.  */
    status =  nx_ip_fragment_disable(&ip_1);
    
    /* Check the status.  */
    if (status)
        error_counter++; 

    /* Enable IP fragmentation logic on IP instance 1.  */
    status =  nx_ip_fragment_enable(&ip_1);
    
    /* Check the status.  */
    if (status)
        error_counter++;

    /* Now ping an IP address that does exist.  */
    status = nxd_icmp_ping(&ip_0, &ipv6_address_1, buffer, 4500, &my_packet, TX_TIMER_TICKS_PER_SECOND);

    /* Check the status.  */
    if ((status != NX_SUCCESS) || (my_packet -> nx_packet_length != 4500))
        error_counter++;  

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
     
static VOID   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_IPV6_HEADER   *ip_header_ptr;  
UCHAR             next_header_type;

    /* Points to the base of IPv6 header. */
    ip_header_ptr = (NX_IPV6_HEADER*)packet_ptr -> nx_packet_prepend_ptr;       

    /* Byte swap WORD 1 to obtain IPv6 payload length. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

    /* Get the next header type.  */
    next_header_type = (UCHAR)((ip_header_ptr -> nx_ip_header_word_1 >> 8) & 0xFF);

    /* Check the next header type.  */
    if (next_header_type == NX_PROTOCOL_NEXT_HEADER_FRAGMENT)
    {

        /* Update the counter.  */
        fragmentation_counter ++;

        if (fragmentation_counter == 3)
        {

            /* Modified the packet length.  */
            packet_ptr -> nx_packet_length = 65000;  

            /* Modified the payload length.  */
            ip_header_ptr -> nx_ip_header_word_1 &= 0x0000FFFF;      
            ip_header_ptr -> nx_ip_header_word_1 |= ((packet_ptr -> nx_packet_length - sizeof(NX_IPV6_HEADER)) << 16);
        }
    }

    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);

    /* Directly receive the packet.  */
    _nx_ipv6_packet_receive (ip_ptr, packet_ptr);
}

#else             
extern void    test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_ipv6_fragmentation_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   IPv6 Fragmentation Processing Test........................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_FRAGMENTATION  */
