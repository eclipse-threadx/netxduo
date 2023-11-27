/* This NetX test concentrates on IP fragmentation disable operation.  */


#include   "tx_api.h"
#include   "nx_api.h"   
#include   "nx_ip.h"       

extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_FRAGMENTATION) && !defined(NX_FRAGMENT_IMMEDIATE_ASSEMBLY) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048     

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;   
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;      

/* Define the counters used in the demo application...  */  

static ULONG                   error_counter;
static ULONG                   icmp_counter;  
static NX_PACKET               *copy_packet_0;
static NX_PACKET               *copy_packet_1;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);    
static void    thread_1_entry(ULONG thread_input);    
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static VOID    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
                                                                               

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_disable_test_application_define(void *first_unused_memory)
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
                              
    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 500, pointer, 4096);
    pointer = pointer + 4096;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
        error_counter++;

    /* Enable ICMP traffic.  */
    status =  nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check for ICMP enable errors.  */
    if (status)
        error_counter++;       

    /* Enable IP fragmentation logic on both IP instances.  */
    status =  nx_ip_fragment_enable(&ip_0);
    status += nx_ip_fragment_enable(&ip_1);

    /* Check for IP fragment enable errors.  */
    if (status)
        error_counter++;
}                    


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;   
CHAR        data[256];


    /* Print out some test information banners.  */
    printf("NetX Test:   IP Fragmentation Disable Test.............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                 
            
    /* Set the callback function to get the IPv4 packet.  */
    ip_1.nx_ipv4_packet_receive = my_packet_process;

    /* Now ip_0 ping ip_1 to check nx_ip_received_fragment_head and nx_ip_fragment_assembly_head.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), data, 300, &my_packet, 2 * NX_IP_PERIODIC_RATE);  
                             
    /* Check the status.  */
    if ((status == NX_SUCCESS) || (my_packet))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the error counter and icmp counter.  */
    if ((error_counter) || (icmp_counter != 2))   
    {
        printf("ERROR!\n");
        test_control_return(1);
    }   
                    
    /* Reset the callback function.  */
    ip_1.nx_ipv4_packet_receive = _nx_ipv4_packet_receive;

    /* Now ip_0 ping ip_1 to check nx_ipv4_packet_receive after ip_1 disable fragment feature .  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), data, 300, &my_packet, 1 * NX_IP_PERIODIC_RATE);  
                             
    /* Check the status.  */
    if ((status == NX_SUCCESS) || (my_packet))
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

/* Define the test threads.  */

static void    thread_1_entry(ULONG thread_input)
{      

UINT    status;

    /* Sleep 100 ticks to receive the fragment packet.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(&ip_1, copy_packet_0);

    /* Check the received/assembly fragment head.  */
    if ((ip_1.nx_ip_received_fragment_head) || ((ip_1.nx_ip_fragment_assembly_head == NX_NULL)))
        error_counter ++;   
                         
    /* Get mutex protection.  */
    tx_mutex_get(&(ip_1.nx_ip_protection), TX_WAIT_FOREVER);
                      
    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(&ip_1, copy_packet_1);
                    
    /* Check the received/assembly fragment head.  */
    if ((ip_1.nx_ip_received_fragment_head == NX_NULL) || (ip_1.nx_ip_fragment_assembly_head == NX_NULL))
        error_counter ++; 

    /* Disable the fragment.  */
    status = nx_ip_fragment_disable(&ip_1);

    /* Check the status.  */
    if (status)
        error_counter++;                     

    /* Check the received/assembly fragment head.  */
    if ((ip_1.nx_ip_received_fragment_head) || (ip_1.nx_ip_fragment_assembly_head))
        error_counter ++;  

    /* Release mutex protection.  */
    tx_mutex_put(&(ip_1.nx_ip_protection));
}

static VOID   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{           

UINT    status;

    /* Get the ICMP packet.  */
    icmp_counter ++;                                                   

    /* Check the icmp counter.  */
    if (icmp_counter == 1)
    {       

        /* First fragmentation.  */
        /* Copy the packet.  */
        status = nx_packet_copy(packet_ptr, &copy_packet_0, &pool_0, NX_IP_PERIODIC_RATE);

        /* Check the status.  */
        if (status)
            error_counter++;   

        /* Release the packet.  */
        nx_packet_release(packet_ptr);
    }      
    if (icmp_counter == 2)
    {       
                      
        /* Second fragmentation.  */
        /* Copy the packet.  */
        status = nx_packet_copy(packet_ptr, &copy_packet_1, &pool_0, NX_IP_PERIODIC_RATE); 

        /* Check the status.  */
        if (status)
            error_counter++;  

        /* Release the packet.  */
        nx_packet_release(packet_ptr);
    }
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_disable_test_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   IP Fragmentation Disable Test.............................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_FRAGMENTATION  */
