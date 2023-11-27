#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && (NX_MAX_PHYSICAL_INTERFACES > 1) && !defined(NX_DISABLE_IPV4)
#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_detachment_arp_table_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main threads.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
            pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
            pointer, 2048, 2);
    pointer =  pointer + 2048;
    if (status)
        error_counter++;

    /* Attach the 2nd interface to IP instance0 */
    status = nx_ip_interface_attach(&ip_0, "2nd interface", IP_ADDRESS(4, 3, 2, 10), 0xFF000000, _nx_ram_network_driver);
    if(status != NX_SUCCESS)    
        error_counter++;

    /* Attach the 2nd interface to IP instance1 */
    status = nx_ip_interface_attach(&ip_1, "2nd interface", IP_ADDRESS(4, 3, 2, 11), 0xFF000000, _nx_ram_network_driver);
    if(status != NX_SUCCESS)     
        error_counter++;

    /* Attach the 3rd interface to IP instance1 */
    status = nx_ip_interface_attach(&ip_1, "3rd interface", IP_ADDRESS(4, 3, 2, 12), 0xFF000000, _nx_ram_network_driver);
    if(status != NX_SUCCESS)     
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
NX_ARP      *arp_ptr;
UINT        arp_entry_counter = 0;

    printf("NetX Test:   IP Interface Detachment ARP table Test....................");
                                     
    /* Check earlier error. */
    if(error_counter)
    {                            
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an IP address to create dynamic arp entries associated with ip_0's 2nd interface.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(4, 3, 2, 11), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an IP address to create dynamic arp entries associated with ip_0's 2nd interface.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(4, 3, 2, 12), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ping an IP address to create dynamic arp entries associated with ip_0's 1st interface.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);
    if((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create static arp entries associated with ip_0's 2nd interface. */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(4,3,2,13), 0x0011, 0x22334458);
    status += nx_arp_static_entry_create(&ip_0, IP_ADDRESS(4,3,2,14), 0x0011, 0x22334459);
    if(status)
        error_counter++;

    /* Create static arp entries associated with ip_0's 2nd interface. */
    status = nx_arp_static_entry_create(&ip_0, IP_ADDRESS(1,2,3,10), 0x0011, 0x22334460);
    if(status)
        error_counter++;

    /* Check the whole arp table. */
    for(i = 0; i < NX_ARP_TABLE_SIZE; i++)
    {
        arp_ptr = ip_0.nx_ip_arp_table[i];
        while(arp_ptr)
        {
            if((arp_ptr -> nx_arp_ip_address == IP_ADDRESS(4, 3, 2, 11)) || 
               (arp_ptr -> nx_arp_ip_address == IP_ADDRESS(4, 3, 2, 12)) || 
               (arp_ptr -> nx_arp_ip_address == IP_ADDRESS(1, 2, 3, 5))  || 
               (arp_ptr -> nx_arp_ip_address == IP_ADDRESS(4, 3, 2, 13)) || 
               (arp_ptr -> nx_arp_ip_address == IP_ADDRESS(4, 3, 2, 14)) || 
               (arp_ptr -> nx_arp_ip_address == IP_ADDRESS(1, 2, 3, 10)))
            {
                arp_entry_counter++;
            }

            /* Move to the next active ARP entry. */
            arp_ptr = arp_ptr -> nx_arp_active_next;

            /* Determine if we are at the end of the ARP list. */
            if(arp_ptr == ip_0.nx_ip_arp_table[i])
                break;
        }
    }

    if(arp_entry_counter != 6)
        error_counter++;

    /* Reset the counter. */
    arp_entry_counter = 0;

    /* Detach the 2nd interface(4.3.2.11) from ip_0. */
    status = nx_ip_interface_detach(&ip_0, 1);
    if(status)
        error_counter++;

    /* Check the whole arp table. */
    for(i = 0; i < NX_ARP_TABLE_SIZE; i++)
    {
        arp_ptr = ip_0.nx_ip_arp_table[i];
        while(arp_ptr)
        {
            /* These entries should have been removed. */
            if((arp_ptr -> nx_arp_ip_address == IP_ADDRESS(4, 3, 2, 11)) || 
               (arp_ptr -> nx_arp_ip_address == IP_ADDRESS(4, 3, 2, 12)) || 
               (arp_ptr -> nx_arp_ip_address == IP_ADDRESS(4, 3, 2, 13)) || 
               (arp_ptr -> nx_arp_ip_address == IP_ADDRESS(4, 3, 2, 14))) 
            {
                error_counter++;
            }

            /* These entries should still be exsited. */
            else if((arp_ptr -> nx_arp_ip_address == IP_ADDRESS(1, 2, 3, 5)) || 
                    (arp_ptr -> nx_arp_ip_address == IP_ADDRESS(1, 2, 3, 10))) 
            {
                arp_entry_counter++;
            }

            /* Move to the next active ARP entry. */
            arp_ptr = arp_ptr -> nx_arp_active_next;

            /* Determine if we are at the end of the ARP list. */
            if(arp_ptr == ip_0.nx_ip_arp_table[i])
                break;
        }
    }

    if(arp_entry_counter != 2)
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
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_interface_detachment_arp_table_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   IP Interface Detachment ARP table Test....................N/A\n");
    test_control_return(3);
}
#endif
