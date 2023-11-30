/* This NetX test concentrates on IP fragmentation disable operation.  */


#include   "tx_api.h"
#include   "nx_api.h"   
#include   "nx_ip.h"       
                                  
extern void    test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
                                                                                      
#define     DEMO_STACK_SIZE         2048     

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;   

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;      

/* Define the counters used in the demo application...  */  

static ULONG                   error_counter;
static ULONG                   icmp_counter;  

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);    
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static VOID    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
                                                                               

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_invalid_packet_receive_test_application_define(void *first_unused_memory)
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
}                    


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;   


    /* Print out some test information banners.  */
    printf("NetX Test:   IP Invalid Packet Receive Test............................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                 
            
    /* Set the callback function to get the IPv4 packet.  */
    ip_1.nx_ipv4_packet_receive = my_packet_process;

    /* Now ip_0 ping ip_1.  */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);  
                             
    /* Check the status.  */
    if ((status == NX_SUCCESS) || (my_packet))
    {
#if defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_DISABLE_IP_RX_CHECKSUM)
        if (my_packet -> nx_packet_length == 28)
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }

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
NX_PACKET       *copy_packet_0;  
NX_PACKET       *copy_packet_1;   
NX_PACKET       *copy_packet_2;    
#ifndef NX_DISABLE_PACKET_CHAIN
NX_PACKET       *copy_packet_3;   
NX_PACKET       *copy_packet_4;  
NX_PACKET       *copy_packet_5; 
#endif
#ifdef __PRODUCT_NETXDUO__
NX_IPV4_HEADER  *ip_header_ptr;
#else    
NX_IP_HEADER    *ip_header_ptr;
#endif

    /* Get the ICMP packet.  */
    icmp_counter ++;                                                   
                                                             
    /*************************************************************/ 
    /* nx_packet_length < header length nx_ipv4_packet_receive() */
    /*************************************************************/
    /* Copy the packet.  */
    status = nx_packet_copy(packet_ptr, &copy_packet_0, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status)
        error_counter++;   

    /* Set the invalid packet length.  */
    copy_packet_0 -> nx_packet_length = 18;
                  
    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(&ip_1, copy_packet_0);
                                               
    /**********************************************************/ 
    /* nx_packet_length < pkt_length nx_ipv4_packet_receive() */
    /**********************************************************/

    /* Copy the packet.  */
    status = nx_packet_copy(packet_ptr, &copy_packet_1, &pool_0, NX_IP_PERIODIC_RATE); 

    /* Check the status.  */
    if (status)
        error_counter++;  
                       
    /* Get the IPv4 header.  */   
#ifdef __PRODUCT_NETXDUO__
    ip_header_ptr = (NX_IPV4_HEADER *)copy_packet_1 -> nx_packet_prepend_ptr;
#else                                                              
    ip_header_ptr = (NX_IP_HEADER *)copy_packet_1 -> nx_packet_prepend_ptr;
#endif
                                                                    
    /* Convert to host byte order. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);   

    /* Modified the packet length.  */
    ip_header_ptr -> nx_ip_header_word_0 += 0x00000001;         
                          
    /* Convert to host byte order. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);  

    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(&ip_1, copy_packet_1);      
                                                                  
    /****************************************************************************/ 
    /* nx_packet_length > pkt_length for normal packet nx_ipv4_packet_receive() */
    /****************************************************************************/

    /* Copy the packet.  */
    status = nx_packet_copy(packet_ptr, &copy_packet_2, &pool_0, NX_IP_PERIODIC_RATE); 

    /* Check the status.  */
    if (status)
        error_counter++;  
                       
    /* Get the IPv4 header.  */   
#ifdef __PRODUCT_NETXDUO__
    ip_header_ptr = (NX_IPV4_HEADER *)copy_packet_2 -> nx_packet_prepend_ptr;
#else                                                              
    ip_header_ptr = (NX_IP_HEADER *)copy_packet_2 -> nx_packet_prepend_ptr;
#endif

    /* Convert to host byte order. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);   

    /* Modified the packet length.  */
    ip_header_ptr -> nx_ip_header_word_0 -= 0x00000001;   
                          
    /* Convert to host byte order. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);  

    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(&ip_1, copy_packet_2);        

#ifndef NX_DISABLE_PACKET_CHAIN        
                                  
    /***************************************************************************/ 
    /* nx_packet_length > pkt_length for chain packet nx_ipv4_packet_receive() */ 
    /* last packet < delta, two packet chain.                                  */
    /***************************************************************************/

    /* Copy the packet.  */
    status = nx_packet_copy(packet_ptr, &copy_packet_3, &pool_0, NX_IP_PERIODIC_RATE); 

    /* Check the status.  */
    if (status)
        error_counter++;                                  

    /* Get the IPv4 header.  */   
#ifdef __PRODUCT_NETXDUO__
    ip_header_ptr = (NX_IPV4_HEADER *)copy_packet_3 -> nx_packet_prepend_ptr;
#else                                                              
    ip_header_ptr = (NX_IP_HEADER *)copy_packet_3 -> nx_packet_prepend_ptr;
#endif

    /* Convert to host byte order. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);   

    /* Modified the packet length.  */
    ip_header_ptr -> nx_ip_header_word_0 -= 0x00000004;   
                          
    /* Convert to host byte order. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);  

    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &copy_packet_4, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(copy_packet_4 -> nx_packet_prepend_ptr, "ABC", 3);

    /* Adjust the write pointer.  bigger than 256 to cause fragmentation. */
    copy_packet_4 -> nx_packet_length = 3;
    copy_packet_4 -> nx_packet_append_ptr =  copy_packet_4 -> nx_packet_prepend_ptr + 3;

    /* Chain the packet.  */
    copy_packet_3 -> nx_packet_next = copy_packet_4;         
    copy_packet_3 -> nx_packet_last = copy_packet_4;

    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(&ip_1, copy_packet_3);
                                  
    /***************************************************************************/ 
    /* nx_packet_length > pkt_length for chain packet nx_ipv4_packet_receive() */ 
    /* last packet < delta, three packet chain                                 */
    /***************************************************************************/

    /* Copy the packet.  */
    status = nx_packet_copy(packet_ptr, &copy_packet_3, &pool_0, 1 * NX_IP_PERIODIC_RATE); 

    /* Check the status.  */
    if (status)
        error_counter++;                                  

    /* Get the IPv4 header.  */   
#ifdef __PRODUCT_NETXDUO__
    ip_header_ptr = (NX_IPV4_HEADER *)copy_packet_3 -> nx_packet_prepend_ptr;
#else                                                              
    ip_header_ptr = (NX_IP_HEADER *)copy_packet_3 -> nx_packet_prepend_ptr;
#endif

    /* Convert to host byte order. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);   

    /* Modified the packet length.  */
    ip_header_ptr -> nx_ip_header_word_0 -= 0x00000004;   
                          
    /* Convert to host byte order. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);  
                                                                         
    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &copy_packet_4, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(copy_packet_4 -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26);

    /* Adjust the write pointer.  bigger than 256 to cause fragmentation. */
    copy_packet_4 -> nx_packet_length = 26;
    copy_packet_4 -> nx_packet_append_ptr =  copy_packet_4 -> nx_packet_prepend_ptr + 26;

    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &copy_packet_5, NX_UDP_PACKET, TX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(copy_packet_5 -> nx_packet_prepend_ptr, "ABC", 3);

    /* Adjust the write pointer.  bigger than 256 to cause fragmentation. */
    copy_packet_5 -> nx_packet_length = 3;
    copy_packet_5 -> nx_packet_append_ptr =  copy_packet_5 -> nx_packet_prepend_ptr + 3;

    /* Chain the packet.  */
    copy_packet_3 -> nx_packet_next = copy_packet_4;         
    copy_packet_3 -> nx_packet_last = copy_packet_5;
    copy_packet_4 -> nx_packet_next = copy_packet_5;

    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(&ip_1, copy_packet_3);
#endif
    
    /*******************************************************************/ 
    /* ip_header_length < NX_IP_NORMAL_LENGTH nx_ipv4_packet_receive() */
    /*******************************************************************/

    /* Copy the packet.  */
    status = nx_packet_copy(packet_ptr, &copy_packet_0, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status)
        error_counter++;   

    /* Get the IPv4 header.  */   
#ifdef __PRODUCT_NETXDUO__
    ip_header_ptr = (NX_IPV4_HEADER *)copy_packet_0 -> nx_packet_prepend_ptr;
#else                                                              
    ip_header_ptr = (NX_IP_HEADER *)copy_packet_0 -> nx_packet_prepend_ptr;
#endif

    /* Convert to host byte order. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);   

    /* Modified the header length.  */
    ip_header_ptr -> nx_ip_header_word_0 -= 0x01000000;
                          
    /* Convert to host byte order. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0); 
                  
    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(&ip_1, copy_packet_0);

    /****************************************************************************/ 
    /* nx_packet_length = pkt_length and no IP address nx_ipv4_packet_receive() */ 
    /****************************************************************************/

    /* Clear the ip_1 instance address.  */
    nx_ip_address_set(&ip_1, 0, 0);

    /* Call the _nx_ipv4_packet_receive function directly receive this packet.  */
    _nx_ipv4_packet_receive(&ip_1, packet_ptr);
}      

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_ip_invalid_packet_receive_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IP Invalid Packet Receive Test............................N/A\n");

    test_control_return(3);

}
#endif
