/* This NetX test concentrates on the Forward ICMP ping with small header operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"       
#include   "nx_icmp.h" 
#include   "nx_ram_network_driver_test_1500.h" 

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_PACKET_CHAIN) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_IP                   ip_2;               


/* Define the counters used in the test application...  */

static ULONG                   error_counter = 0;  
static ULONG                   shift_size = 0;   
static ULONG                   callback_0_counter = 0;
static ULONG                   callback_1_counter = 0;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr); 
static VOID    ip_0_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);    
static UINT    driver_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_icmp_small_header_test3_application_define(void *first_unused_memory)
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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

    if (status)
        error_counter++;

    /* Create an forward IP Instance 0.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer =  pointer + 2048;    
    if (status)
        error_counter++;

    /* Set the second interface for forward IP Instance 0.  */
    status = nx_ip_interface_attach(&ip_0, "Second Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00UL, _nx_ram_network_driver_1500);    
    if (status)
        error_counter++;

    /* Create an IP Instance 1.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Set the gateway for IP Instance 1.  */
    status = nx_ip_gateway_address_set(&ip_1, IP_ADDRESS(1, 2, 3, 4));
    if (status)
        error_counter++;

    /* Create another IP Instance 2.  */
    status = nx_ip_create(&ip_2, "NetX IP Instance 1", IP_ADDRESS(2, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500, pointer, 2048, 3);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;
    
    /* Set the gateway for IP Instance 2.  */
    status = nx_ip_gateway_address_set(&ip_2, IP_ADDRESS(2, 2, 3, 4));
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;
    
    /* Enable ARP and supply ARP cache memory for IP Instance 2.  */
    status = nx_arp_enable(&ip_2, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if (status)
        error_counter++;

    /* Enable ICMP processing for both IP Instance 0.  */
    status = nx_icmp_enable(&ip_0);
    if (status)
        error_counter++;
    
    /* Enable ICMP processing for both IP Instance 1.  */
    status = nx_icmp_enable(&ip_1);
    if (status)
        error_counter++;
    
    /* Enable ICMP processing for both IP Instance 2.  */
    status = nx_icmp_enable(&ip_2);
    if (status)
        error_counter++;

    /* Enable the forwarding function for IP Instance 0.  */
    status = nx_ip_forwarding_enable(&ip_0);
    if (status)
        error_counter++;          
}


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
UINT        i;
UINT        size;
CHAR        data[256];

    
    /* Print out test information banner.  */
    printf("NetX Test:   Forward ICMP Small Header Processing Test3................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    
                          
    /* Setup static ARP entries.  */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0x0011, 0x22334458);

    /* Check the status.  */
    if (status)                
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    

    /* Setup static ARP entries.  */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(2, 2, 3, 5), 0x0011, 0x22334459);

    /* Check the status.  */
    if (status)            
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    
                      
    /* Setup static ARP entries.  */
    status = nx_arp_static_entry_create(&ip_1, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456);

    /* Check the status.  */
    if (status)                
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    

    /* Setup static ARP entries.  */
    status = nx_arp_static_entry_create(&ip_2, IP_ADDRESS(2, 2, 3, 4), 0x0011, 0x22334457);

    /* Check the status.  */
    if (status)            
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Set the callback function to get the IPv4 packet.  */
    ip_0.nx_ipv4_packet_receive = ip_0_packet_process;
                             
    /* Set the max size for ICMP.  */
    size = 256 - NX_IPv4_ICMP_PACKET - NX_ICMP_HEADER_SIZE; 

    /* Set the data.  */
    for (i = 0; i < size; i++)
        data[i] = 'a';

    /* Now ip_1 ping ip_2 again, this packet will be modified by callback function.  */
    status =  nx_icmp_ping(&ip_1, IP_ADDRESS(2, 2, 3, 5), data, size, &my_packet, NX_IP_PERIODIC_RATE);
                
    /* Check the status .  */
    if (status == NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                                                                   

    /* Check the counter.  */
    if ((callback_0_counter != 1) || (callback_1_counter != 0))
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
static VOID   ip_0_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{           
UINT        packet_counter;
UINT        i;
UINT        status;
NX_PACKET   *my_packet[10];

    /* Update the counter.  */
    callback_0_counter ++;

    /* Calculate the shift data size. */
    shift_size = (ULONG)(packet_ptr -> nx_packet_prepend_ptr - packet_ptr -> nx_packet_data_start);

    /* Update the data start pointer.  */
    packet_ptr -> nx_packet_data_start += shift_size;

    /* Set the callback function to get the IPv4 packet.  */
    advanced_packet_process_callback = driver_packet_process; 

    /* Reset the IP callback function.  */
    ip_0.nx_ipv4_packet_receive = _nx_ipv4_packet_receive;

    /* Loop to allocate the all packets to let _nx_packet_data_append failure in nx_ip_forward_packet_process.c  */
    packet_counter = pool_0.nx_packet_pool_available;
    for (i = 0; i < packet_counter; i++)
    {
        status = nx_packet_allocate(&pool_0, &my_packet[i], 0, NX_NO_WAIT);

        /* Check status.  */
        if (status)
            error_counter ++;
    }

    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(ip_ptr, packet_ptr);
}         
static UINT    driver_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
                  
    /* Update the counter.  */
    callback_1_counter ++;

    /* Check the packet pointer for forwarding packet.  */
    if ((packet_ptr -> nx_packet_prepend_ptr - packet_ptr -> nx_packet_data_start) != NX_PHYSICAL_HEADER)
        error_counter ++;

    /* Update the packet start pointer.*/
    packet_ptr -> nx_packet_data_start -= shift_size;
              
    /* Clear the callback function.  */
    advanced_packet_process_callback = NX_NULL;    

    return NX_TRUE;
}

#else                                                  
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_forward_icmp_small_header_test3_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   Forward ICMP Small Header Processing Test3................N/A\n");
    test_control_return(3);
}
#endif
