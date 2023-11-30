/* This NetX test case test _nx_icmp_packet_receive and _nx_icmp_queue_process function with non standard operation .  */

#include    "tx_api.h"
#include    "nx_api.h"
extern void    test_control_return(UINT status);  

#if !defined(NX_DISABLE_ICMPV4_RX_CHECKSUM) && !defined(NX_ENABLE_ICMP_ADDRESS_CHECK) && !defined(NX_DISABLE_IPV4)
#include    "nx_icmp.h"
#include    "nx_ip.h" 

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     1

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;   
static UCHAR                   icmp_packet_received = NX_FALSE;                                                   
static NX_PACKET               *copy_packet_0;                                                                
static NX_PACKET               *copy_packet_1;       
static NX_PACKET               *copy_packet_2; 
static NX_PACKET               *copy_packet_3;                                                                       
static NX_PACKET               *copy_packet_4;

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);    
static void    packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_icmp_packet_receive_function_test_application_define(void *first_unused_memory)
#endif
{
    CHAR       *pointer;
    UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        1, 1, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = _nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += _nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1,2,3,5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
        pointer, 2048, 1);
    pointer = pointer + 2048;
                                     
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status += nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;       

    /* Check ARP enable status.  */
    if(status)
        error_counter++;

    /* Enable ICMP processing for both IP instances.  */
    status = nx_icmp_enable(&ip_0);
    status += nx_icmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT       status;
NX_PACKET  *my_packet;  
ULONG       pings_sent;
ULONG       ping_timeouts;
ULONG       ping_threads_suspended;
ULONG       ping_responses_received;
ULONG       icmp_checksum_errors;
ULONG       icmp_unhandled_messages; 

    /* Print out test information banner.  */
    printf("NetX Test:   ICMP Packet Receive Function Test.........................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
                      
    /* Point to new receive function */
    ip_1.nx_ip_icmp_packet_receive = packet_receive;
               
    /* Now ping an IP address that does exist.  */
    /* The reply packet contains checksum 0. */
    status =  nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "PjCZEZGZIZKZMZOZQZSZUZWZYZ", 28, &my_packet, NX_IP_PERIODIC_RATE);

    /* Get ICMP information for IP instance0.  */
    status += nx_icmp_info_get(&ip_0, &pings_sent, &ping_timeouts, &ping_threads_suspended, &ping_responses_received, &icmp_checksum_errors, &icmp_unhandled_messages);
   
#ifndef NX_DISABLE_ICMP_INFO
    if ((ping_timeouts != 0) || (pings_sent != 1) || (ping_responses_received != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif

    /* Determine if the timeout error occurred.  */
    if ((status != NX_SUCCESS) || (my_packet == NX_NULL) || (my_packet -> nx_packet_length != 28 /* data only */) ||
        (ping_threads_suspended) || (icmp_checksum_errors) || (icmp_unhandled_messages) || error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
              
#ifndef NX_DISABLE_ICMP_INFO
#ifdef __PRODUCT_NETXDUO__

    
#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    if ((copy_packet_2 -> nx_packet_address.nx_packet_interface_ptr -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_ICMPV4_RX_CHECKSUM) == 0)
    {
#endif /* NX_DISABLE_ICMP_INFO */

        /* Check the ICMP information for IP instance1.  */                                                                                                                      
        if ((ip_1.nx_ip_icmp_total_messages_received != 5) || (ip_1.nx_ip_icmp_invalid_packets != 3) || (ip_1.nx_ip_pings_received != 1) || (ip_1.nx_ip_pings_responded_to != 1) || (ip_1.nx_ip_icmp_checksum_errors != 1) || (ip_1.nx_ip_icmp_unhandled_messages != 1))
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    }
    else
    {

        /* Check the ICMP information for IP instance1.  */                                                                                                                      
        if ((ip_1.nx_ip_icmp_total_messages_received != 4) || (ip_1.nx_ip_icmp_invalid_packets != 2) || (ip_1.nx_ip_pings_received != 1) || (ip_1.nx_ip_pings_responded_to != 1) || (ip_1.nx_ip_icmp_checksum_errors != 0) || (ip_1.nx_ip_icmp_unhandled_messages != 1))
        {
            printf("ERROR!\n");
            test_control_return(1);
        }
    }
#endif /* NX_DISABLE_ICMP_INFO */
#else  
        
    /* Check the ICMP information for IP instance1.  */                                                                                                                      
    if ((ip_1.nx_ip_icmp_total_messages_received != 4) || (ip_1.nx_ip_icmp_invalid_packets != 2) || (ip_1.nx_ip_pings_received != 1) || (ip_1.nx_ip_pings_responded_to != 1) || (ip_1.nx_ip_icmp_checksum_errors != 1) || (ip_1.nx_ip_icmp_unhandled_messages != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* __PRODUCT_NETXDUO__ */
#endif /* NX_DISABLE_ICMP_INFO */

    /* Determine if the test was successful.  */
    if ((error_counter) || (icmp_packet_received != NX_TRUE))
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

static void    thread_1_entry(ULONG thread_input)
{
    UINT       status;
    ULONG      actual_status;  

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if(status != NX_SUCCESS)
    {
        error_counter++;
    }     
                                 
    /* Wait for receive the ICMP packet.  */
    while(icmp_packet_received == NX_FALSE)
    {   
        tx_thread_sleep(1);
    }

    /* Call _nx_icmp_packet_receive to directly receive the invalid packet.  */
    _nx_icmp_packet_receive(&ip_1, copy_packet_0); 
                                                
    /* Let IP thread to diretcly process the ICMP packet.  */
    tx_thread_sleep(1);

#ifdef __PRODUCT_NETXDUO__

    /* Disable ICMP feature.  */
    ip_1.nx_ip_icmpv4_packet_process = NX_NULL;

    /* Call _nx_icmp_packet_receive to directly receive the valid packet .  */
    _nx_icmp_packet_receive(&ip_1, copy_packet_1);  

    /* Let IP thread to diretcly process the ICMP packet.  */
    tx_thread_sleep(1);
                                                   
    /* Reenable ICMP feature.  */
    ip_1.nx_ip_icmpv4_packet_process = _nx_icmpv4_packet_process;
#endif
                  
#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    if ((copy_packet_2 -> nx_packet_address.nx_packet_interface_ptr -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_ICMPV4_RX_CHECKSUM) == 0)
    {
#endif
        /* Call _nx_icmp_packet_receive to directly receive the packet with incorrect checksum, and queue the packet to the ICMP message queue.  */
        _nx_icmp_packet_receive(&ip_1, copy_packet_2);  
#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    }
#endif

    /* Call _nx_icmp_packet_receive to receive the packet with incorrect code, and queue the packet to the ICMP message queue.  */
    _nx_icmp_packet_receive(&ip_1, copy_packet_3);                    

    /* Call _nx_icmp_packet_receive to receive the valid packet, and queue the packet to the ICMP message queue.  */
    _nx_icmp_packet_receive(&ip_1, copy_packet_4);    
}    
                                                                                                           
static void    packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{         
    
UINT    status;            
NX_ICMP_HEADER *header_ptr;    
ULONG           checksum;
ULONG           old_m;
ULONG           new_m;

    /* Store the ICMP ping packet.  */                 
                       
    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &copy_packet_0, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check for error.  */
    if((status != NX_SUCCESS))
    {                           
        error_counter++;
    }                  

    /* Set the packet length with invalid value.  */
    memcpy(copy_packet_0 -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ12", 28);
    copy_packet_0 -> nx_packet_length = sizeof(NX_ICMP_HEADER) - 1;
    copy_packet_0 -> nx_packet_append_ptr = copy_packet_0 -> nx_packet_prepend_ptr + copy_packet_0 -> nx_packet_length;

    /* Update the packet prepend and length to include the IP header.  */
    packet_ptr -> nx_packet_prepend_ptr -= 20;        
    packet_ptr -> nx_packet_length += 20;

    /* Store the packet.  */
    status = nx_packet_copy(packet_ptr, &copy_packet_1, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }
    else
    {            

        /* Update the packet prepend and length.  */
        copy_packet_1 -> nx_packet_prepend_ptr += 20;        
        copy_packet_1 -> nx_packet_length -= 20;
    }
            
    /* Store the packet.  */
    status = nx_packet_copy(packet_ptr, &copy_packet_2, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }
    else
    {            

        /* Update the packet prepend and length.  */
        copy_packet_2 -> nx_packet_prepend_ptr += 20;        
        copy_packet_2 -> nx_packet_length -= 20;

        /* Point to the ICMP message header.  */
        header_ptr =  (NX_ICMP_HEADER *) copy_packet_2 -> nx_packet_prepend_ptr;

        /* Set the incorrect checksum.  */   
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);    
        header_ptr -> nx_icmp_header_word_0 -= 1;
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);   
    } 

    /* Store the packet.  */
    status = nx_packet_copy(packet_ptr, &copy_packet_3, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }
    else
    {            

        /* Update the packet prepend and length.  */
        copy_packet_3 -> nx_packet_prepend_ptr += 20;        
        copy_packet_3 -> nx_packet_length -= 20;

        /* Point to the ICMP message header.  */
        header_ptr =  (NX_ICMP_HEADER *) copy_packet_3 -> nx_packet_prepend_ptr;

        /* Set the incorrect ICMP code.  */   
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);   

        /* Set the new ICMP code.  */
        header_ptr -> nx_icmp_header_word_0 += 0x01000000;     

        /* Get the old checksum (HC) in header. */
        checksum = header_ptr -> nx_icmp_header_word_0 & NX_LOWER_16_MASK;

        /* Get the new ICMP code in the header. */
        new_m = (header_ptr -> nx_icmp_header_word_0 & 0xFFFF0000) >> 16;

        /* Get the OLD ICMP code. */
        old_m = new_m - 0x0100;

        /* Update the checksum, get the new checksum(HC'),
        The new_m is ULONG value, so need get the lower value after invert. */
        checksum = ((~checksum) & 0xFFFF) + ((~old_m) & 0xFFFF) + new_m;

        /* Fold a 4-byte value into a two byte value */
        checksum = (checksum >> 16) + (checksum & 0xFFFF);

        /* Do it again in case previous operation generates an overflow */
        checksum = (checksum >> 16) + (checksum & 0xFFFF);

        /* Now store the new checksum in the IP header.  */
        header_ptr -> nx_icmp_header_word_0 =  ((header_ptr -> nx_icmp_header_word_0 & 0xFFFF0000) | ((~checksum) & NX_LOWER_16_MASK));

        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);   
    }
         
    /* Store the packet.  */
    status = nx_packet_copy(packet_ptr, &copy_packet_4, &pool_0, 2 * NX_IP_PERIODIC_RATE);   

    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }
    else
    {            

        /* Update the packet prepend and length.  */
        copy_packet_4 -> nx_packet_prepend_ptr += 20;        
        copy_packet_4 -> nx_packet_length -= 20;
    }

    /* Release the ICMP ping packet.  */
    nx_packet_release(packet_ptr);

    /* Update the flag.  */
    icmp_packet_received = NX_TRUE;

    /* Stop the process.  */
    return;
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_icmp_packet_receive_function_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   ICMP Packet Receive Function Test.........................N/A\n");
    test_control_return(3);
}
#endif
