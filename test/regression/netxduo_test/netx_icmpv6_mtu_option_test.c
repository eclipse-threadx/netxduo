/* This NetX test concentrates on the IPv6 process ICMPv6 Option for MTU 0.  
   change last two bytes from 0x05, 0x00 to 0x00, 0x00  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h" 

extern void    test_control_return(UINT status);
#if defined FEATURE_NX_IPV6 && defined NX_ENABLE_IPV6_PATH_MTU_DISCOVERY

#include   "nx_icmpv6.h"
#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

static char mtu_option[78] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, /* 33...... */
0x00, 0x00, 0x01, 0x00, 0x86, 0xdd, 0x60, 0x00, /* ......`. */
0x00, 0x00, 0x00, 0x18, 0x3a, 0xff, 0xfe, 0x80, /* ....:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, /* ........ */
0x00, 0xff, 0xfe, 0x00, 0x01, 0x00, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0x00, /* ........ */
0x45, 0x1b, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, /* E....... */
0x27, 0x10, 0x00, 0x00, 0x03, 0xe8, 0x05, 0x01, /* '....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00              /* ...... */
};


/* Define the counters used in the test application...  */

static ULONG                   error_counter; 


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmpv6_mtu_option_test_application_define(void *first_unused_memory)
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

    /* Check IP create status.  */
    if (status)
        error_counter++;
    
    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0); 

    /* Check IPv6 enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMPv6 processing for IP instances0 .  */
    status = nxd_icmp_enable(&ip_0); 

    /* Check ICMP enable status.  */
    if(status)
        error_counter++;
}


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet; 

    
    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 MTU Option Test....................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the linklocal address*/
    status = nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);

    /* Check status */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Sleep 5 seconds for Duplicate Address Detected. */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Inject RA packet. */
    status = nx_packet_allocate(&pool_0, &my_packet, NX_PHYSICAL_HEADER, NX_WAIT_FOREVER);

    /* Check status */
    if(status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Fill in the packet with data. Skip the MAC header.  */
    memcpy(my_packet -> nx_packet_prepend_ptr, &mtu_option[0], sizeof(mtu_option));
    my_packet -> nx_packet_length = sizeof(mtu_option);
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;
    
    /* Directly pointer to ICMPv6 MTU option.  */
    my_packet -> nx_packet_prepend_ptr += 70;

    /* Set the interface. */
    my_packet -> nx_packet_address.nx_packet_ipv6_address_ptr = &ip_0.nx_ipv6_address[0];

    /* Call function to process the MTU option.  */
    status = _nx_icmpv6_process_packet_too_big(&ip_0, my_packet); 

    /* Check the error counter.  */
    if (status != NX_INVALID_MTU_DATA)
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

#else    
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_icmpv6_mtu_option_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Test:   ICMPv6 MTU Option Test....................................N/A\n");
    
    test_control_return(3);
}
#endif