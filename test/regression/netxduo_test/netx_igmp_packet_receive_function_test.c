/* This NetX test case test _nx_igmp_packet_receive and _nx_igmp_queue_process function with non standard operation .  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_igmp.h" 
#include    "nx_tcp.h"
#include    "nx_ip.h"

extern void    test_control_return(UINT status);  

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     1

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;     
static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;  
static UCHAR                   igmp_packet_received = NX_FALSE;                                                   
static NX_PACKET               *copy_packet_0;                                                                
static NX_PACKET               *copy_packet_1;                                                               
static NX_PACKET               *copy_packet_2;        

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req); 
static void    packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    igmp_checksum_compute(NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_igmp_packet_receive_function_test_application_define(void *first_unused_memory)
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

    /* Enable IGMP processing for both IP instances.  */
    status = nx_igmp_enable(&ip_0);
    status += nx_igmp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;          

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT       status;    
NX_PACKET  *my_packet;

    /* Print out test information banner.  */
    printf("NetX Test:   IGMP Packet Receive Function Test.........................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                    
                      
    /* Point to new receive function */
    ip_1.nx_ip_igmp_packet_receive = packet_receive;

    /* Perform IGMP join operations for IP instance1.  */
    status = nx_igmp_multicast_join(&ip_1, IP_ADDRESS(224,0,0,1));
               
    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                        

    /* Perform IGMP join operations for IP instance0.  */
    status = nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224,0,0,1));                                             
                   
    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Sleep 500 ticks to trigger the NX_IP_PERIODIC_EVENT event.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);  
                     
    /* Check the IGMP information for IP instance1.  */                                                                                                                      
#ifndef NX_DISABLE_IGMP_INFO
    if (ip_1.nx_ip_igmp_invalid_packets != 1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif                                         
                  
    /* Create and bind two UDP sockets.  */
    status =   nx_udp_socket_create(&ip_0, &socket_0, "Sending Socket", NX_IP_NORMAL, NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 5);
    status +=  nx_udp_socket_create(&ip_1, &socket_1, "Receiving Socket", NX_IP_NORMAL, NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 5);
    status +=  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);
    status +=  nx_udp_socket_bind(&socket_1, 0x89, TX_WAIT_FOREVER);

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;   

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(224, 0, 0, 1), 0x89);

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Receive the UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, NX_IP_PERIODIC_RATE);

    /* Determine if there is an error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Determine if the test was successful.  */
    if ((error_counter) || (igmp_packet_received != NX_TRUE))
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
                     
    /* Wait for receive the IGMP packet.  */
    while(igmp_packet_received == NX_FALSE)
    {
        tx_thread_sleep(1);
    }
                              
    /* Call _nx_igmp_packet_receive to directly receive the invalid packet.  */
    _nx_igmp_packet_receive(&ip_1, copy_packet_0);      

    /* Calculate the IGMP checksum. */
    igmp_checksum_compute(copy_packet_1);
    igmp_checksum_compute(copy_packet_2);

    /* Call _nx_icmp_packet_receive to receive the packet with incorrect checksum.  */
    _nx_igmp_packet_receive(&ip_1, copy_packet_1);  

    /* Call _nx_icmp_packet_receive to receive the valid packet.  */
    _nx_igmp_packet_receive(&ip_1, copy_packet_2);              
}    
                                                                                                           
static void    packet_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{         
    
UINT            status;  
NX_IGMP_HEADER *header_ptr;
                       
    /* Allocate a packet.  */
    status = nx_packet_allocate(&pool_0, &copy_packet_0, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check for error.  */
    if((status != NX_SUCCESS))
    {                           
        error_counter++;
    }                  

    /* Set the packet length with invalid value.  */
    memcpy(copy_packet_0 -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ12", 28);
    copy_packet_0 -> nx_packet_length = sizeof(NX_IGMP_HEADER) - 1;
    copy_packet_0 -> nx_packet_append_ptr = copy_packet_0 -> nx_packet_prepend_ptr + copy_packet_0 -> nx_packet_length;

    /* Update the packet prepend and length to include the IP header.  */
    packet_ptr -> nx_packet_prepend_ptr -= 20;        
    packet_ptr -> nx_packet_length += 20;
            
    /* Store the packet with incorrect checksum.  */
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

        /* Point to the ICMP message header.  */
        header_ptr =  (NX_IGMP_HEADER *) copy_packet_1 -> nx_packet_prepend_ptr;

        /* Set the incorrect checksum.  */   
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_0);    
        header_ptr -> nx_igmp_header_word_0 -= 1;
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_0);   

#ifdef __PRODUCT_NETXDUO__
        /* Set interface of packet. */
        copy_packet_1 -> nx_packet_address.nx_packet_interface_ptr = &ip_1.nx_ip_interface[0];
#endif /* __PRODUCT_NETXDUO__ */
    } 

    /* Store the packet with valid message.  */
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

#ifdef __PRODUCT_NETXDUO__
        /* Set interface of packet. */
        copy_packet_2 -> nx_packet_address.nx_packet_interface_ptr = &ip_1.nx_ip_interface[0];
#endif /* __PRODUCT_NETXDUO__ */
    }
            
    /* Release the IGMP packet.  */
    nx_packet_release(packet_ptr);

    /* Update the flag.  */
    igmp_packet_received = NX_TRUE;

    /* Stop the process.  */
    return;
}


static void    igmp_checksum_compute(NX_PACKET *packet_ptr)
{
ULONG               checksum;
ULONG               temp;
NX_IGMP_HEADER     *header_ptr;  

    /* Setup the pointer to the message area.  */
    header_ptr =  (NX_IGMP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_1);

    /* Clear the IGMP checksum. */
    header_ptr -> nx_igmp_header_word_0 &= 0xFFFF0000;


    /* Calculate the checksum.  */
    temp =      header_ptr -> nx_igmp_header_word_0;
    checksum =  (temp >> NX_SHIFT_BY_16);
    checksum += (temp & NX_LOWER_16_MASK);
    temp =      header_ptr -> nx_igmp_header_word_1;
    checksum += (temp >> NX_SHIFT_BY_16);
    checksum += (temp & NX_LOWER_16_MASK);

    /* Add in the carry bits into the checksum.  */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

    /* Do it again in case previous operation generates an overflow.  */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);    

    /* Place the checksum into the first header word.  */
    header_ptr -> nx_igmp_header_word_0 |= (~checksum & NX_LOWER_16_MASK);

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_1);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_igmp_packet_receive_function_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   IGMP Packet Receive Function Test.........................N/A\n"); 

    test_control_return(3);  
}      
#endif
