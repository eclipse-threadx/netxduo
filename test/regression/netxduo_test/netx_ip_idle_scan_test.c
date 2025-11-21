/* This NetX test concentrates on idle-scan as described in https://www.youtube.com/watch?v=v5QEB-T6pH0. 
   Idle scans are a way for an attacker to perform a port scan in a way that might evade network restrictions and detection mechanisms. The basic defense is to avoid predictably incrementing the IP Identification field. */

#include   "nx_api.h"
#include   "nx_ip.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4) && defined(NX_ENABLE_IP_ID_RANDOMIZATION)

#define     DEMO_STACK_SIZE         2048
#define     DEMO_LOOP               10

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static USHORT                  ip_ids[DEMO_LOOP];
static UINT                    ip_ids_index;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT   (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UINT   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_idle_scan_test_application_define(void *first_unused_memory)
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
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 4096);
    pointer = pointer + 4096;

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
UINT        i;

    
    /* Print out test information banner.  */
    printf("NetX Test:   IP Idle Scan Test.........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    packet_process_callback = my_packet_process;

    /* Now start ping multiple times.  */
    ip_ids_index = 0;
    for (i = 0; i < DEMO_LOOP; i++)
    {

        /* Initialize IP IDs to be consecutive values.  */
        ip_ids[i] = (USHORT)i;
        status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

        if(status)
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
        nx_packet_release(my_packet);
    }

    /* Make sure IP IDs are not consecutive.  */
    for (i = 0; i < DEMO_LOOP - 1; i++)
    {
        if ((ip_ids[i] + 1) != ip_ids[i + 1])
        {

            /* Not consecutive.  */
            break;
        }
    }

    /* Determine if the timeout error occurred.  */
    if ((i == (DEMO_LOOP - 1)) || error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    } 

    printf("SUCCESS!\n");
    test_control_return(0);
}
    
static UINT   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

#if defined(__PRODUCT_NETXDUO__)
NX_IPV4_HEADER   *ip_header_ptr;
#else
NX_IP_HEADER     *ip_header_ptr;
#endif
ULONG            protocol;

    /* Ignore packet from IP 1. */
    if(ip_ptr == &ip_1)
        return NX_TRUE;

    /* Ignore packet that is not IP packet. */
    if(packet_ptr -> nx_packet_length < 20)
        return NX_TRUE;

#if defined(__PRODUCT_NETXDUO__)
    ip_header_ptr = (NX_IPV4_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);

#else
    ip_header_ptr = (NX_IP_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);
#endif

    /* Get IP header. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);
    ip_ids[ip_ids_index++] = (ip_header_ptr -> nx_ip_header_word_1 >> NX_SHIFT_BY_16) & 0xFFFF;
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_1);
    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_idle_scan_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Idle Scan Test.........................................N/A\n"); 

    test_control_return(3);  
}      
#endif