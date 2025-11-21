/* This NetX test case verifies that the IGMP packet data is included in the checksum, not just the header,
   and that it handles 2 byte data when there is zero length left. Also it must handled chained 
   packets.  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_igmp.h" 
#include    "nx_ip.h"         
#include   "nx_ram_network_driver_test_1500.h"
                                            
extern void  test_control_return(UINT status);

#if !defined(NX_DISABLE_PACKET_CHAIN) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


#define      DATA_SIZE         762
#define      PACKET_PAYLOAD    600

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;  

/* Define thread prototypes.  */                      
static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);   
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    igmp_checksum_compute(NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_igmp_checksum_computation_test_application_define(void *first_unused_memory)
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

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_PAYLOAD, pointer, PACKET_PAYLOAD*6);
    pointer = pointer + PACKET_PAYLOAD*6;

    if(status)
        error_counter++;


    /* Create an IP instance.  */
    status = _nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    
    pointer = pointer + 2048;            
                                     
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
                                     
    /* Check ARP enable status.  */
    if(status)
        error_counter++;

    /* Enable IGMP processing for both IP instances.  */
    status = nx_igmp_enable(&ip_0);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;               
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT       status;    

    /* Print out test information banner.  */
    printf("NetX Test:   IGMP Checksum Computation Test............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }                    
                      
    /* Point to new receive function */
    advanced_packet_process_callback = my_packet_process;

    /* Perform IGMP join operations for IP instance0.  */
    status = nx_igmp_multicast_join(&ip_0, IP_ADDRESS(224,0,0,1));
               
    /* Determine if there is an error.  */
    if (status)
    {
        error_counter++;
    }                                 

    return;
}

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{                           
    
NX_IGMP_HEADER  *header_ptr;  
NX_PACKET       *my_packet;
UINT            status; 
UCHAR           buffer[DATA_SIZE];


#ifndef NX_DISABLE_IGMPV2    
    /* Check the version.  */
    if (ip_ptr -> nx_ip_igmp_router_version == NX_IGMP_HOST_VERSION_2)
    {
        /* Setup a pointer to the IGMP packet header.  */
        header_ptr = (NX_IGMP_HEADER *) (packet_ptr -> nx_packet_prepend_ptr + 24);
    }
    else
    {
         
        /* Setup a pointer to the IGMP packet header.  */
        header_ptr = (NX_IGMP_HEADER *) (packet_ptr -> nx_packet_prepend_ptr + 20);
    }
#else 
    header_ptr = (NX_IGMP_HEADER *) (packet_ptr -> nx_packet_prepend_ptr + 20);
#endif                                                    
                            
    /* Do byte swapping for little endian processors before parsing
       IGMP header data. */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_0);
                             
#ifndef NX_DISABLE_IGMPV2     
    /* Is this IGMPv1 host's join request? */
    if (((header_ptr -> nx_igmp_header_word_0 & NX_IGMP_TYPE_MASK) == NX_IGMP_HOST_RESPONSE_TYPE) ||  
       /* ...Or an IGMPv2 host's join request? */
       ((header_ptr -> nx_igmp_header_word_0 & NX_IGMPV2_TYPE_MASK) == NX_IGMP_HOST_V2_JOIN_TYPE))   
#else

    /* Is this another IGMPv1 host's join request? */
    if ((header_ptr -> nx_igmp_header_word_0 & NX_IGMP_TYPE_MASK) == NX_IGMP_HOST_RESPONSE_TYPE)   
#endif   
    {

        /* Fill the buffer with 0x58. */
        memset(&buffer[0],0x58, DATA_SIZE);

        /* Ensure that the data is not symmetrical with respect to endianness or our test is meaningless. */
        if (DATA_SIZE > 8)
        {
          buffer[0] = 48;
          buffer[1] = 47;
          buffer[2] = 46;
          buffer[3] = 45;
          buffer[4] = 44;
          buffer[5] = 43;
          buffer[6] = 42;
          buffer[7] = 41;
        }
        
        /* Allocate a packet to place the IGMP Router query message in, IGMP version1.  */
        status = nx_packet_allocate(&pool_0, &my_packet, NX_IGMP_PACKET , TX_NO_WAIT);

        /* Check the status.  */
        if (status == NX_SUCCESS)
        {

           
            /* Setup the pointer to the message area.  */
            header_ptr =  (NX_IGMP_HEADER *) my_packet -> nx_packet_prepend_ptr;

            /* Build the IGMPv1 Router query message.  */
            header_ptr -> nx_igmp_header_word_0 =  (ULONG) (NX_IGMP_VERSION | NX_IGMP_ROUTER_QUERY_TYPE);
            header_ptr -> nx_igmp_header_word_1 =  ip_ptr -> nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list;

            /* Stamp the outgoing interface. */
            my_packet -> nx_packet_address.nx_packet_interface_ptr = ip_ptr -> nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list;

            /* set the append pointer past the IGMP header including the 2 extra bytes. */
            my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + NX_IGMP_HEADER_SIZE;
            my_packet -> nx_packet_length = NX_IGMP_HEADER_SIZE;   
            
            /* Add the IGMP 'data'. */
            nx_packet_data_append(my_packet, &buffer[0], DATA_SIZE, &pool_0, 200); 

            /* Calculate the IGMP checksum. */
            igmp_checksum_compute(my_packet);

            /* Call _nx_igmp_packet_receive to directly receive the valid packet.  */
            _nx_igmp_packet_receive(&ip_0, my_packet);  
                
        }
        else
          error_counter++;


    }                                                                                                    

    /* Determine if the test was successful.  */
    if ((error_counter) || (ip_0.nx_ip_igmp_checksum_errors != 0) || (ip_0.nx_ip_igmp_invalid_packets != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }  
    
    return NX_TRUE;
} 

static void    igmp_checksum_compute(NX_PACKET *packet_ptr)
{
  
NX_IGMP_HEADER  *header_ptr;                          
UCHAR           *word_ptr;
NX_PACKET       *current_packet;
ULONG           checksum;
ULONG           long_temp;
USHORT          short_temp;
ULONG           length;


    /* Setup a pointer to the IGMP packet header.  */
    header_ptr =  (NX_IGMP_HEADER *) packet_ptr -> nx_packet_prepend_ptr;

    /* Clear the IGMP checksum. */
    header_ptr -> nx_igmp_header_word_0 &= 0xFFFF0000;
    
    /* First verify the checksum is correct. */
    checksum = 0;       

    /* Setup the length of the packet checksum.  */
    length =  packet_ptr -> nx_packet_length;

    /* Check for an odd numbered (invalid) length packet payload. */
    if (((length/sizeof(USHORT))*sizeof(USHORT)) != length)
    {

        /* Discard the packet. */
        nx_packet_release(packet_ptr);

        return;
    }


    /* Swap back to host byte order to insert the checksum if little endian is specified. */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_1);

    /* Setup the pointer to the start of the packet.  */
    word_ptr =  (UCHAR *) packet_ptr -> nx_packet_prepend_ptr;

    /* Initialize the current packet to the input packet pointer.  */
    current_packet =  packet_ptr;

    checksum = 0;

    /* Loop to calculate the packet's checksum.  */
    while (length)
    {
        /* Determine if there is at least one ULONG left.  */
        if ((UINT)(current_packet -> nx_packet_append_ptr - word_ptr) >= sizeof(ULONG))
        {

            /* Pickup a whole ULONG.  */
            long_temp =  *((ULONG *) word_ptr);

            /* Add upper 16-bits into checksum.  */
            checksum =  checksum + (long_temp >> NX_SHIFT_BY_16);            
        
            /* Check for carry bits.  */
            if (checksum & NX_CARRY_BIT)
                checksum =  (checksum & NX_LOWER_16_MASK) + 1;
        
            /* Add lower 16-bits into checksum.  */
            checksum =  checksum + (long_temp & NX_LOWER_16_MASK);
        
            /* Check for carry bits.  */
           
            if (checksum & NX_CARRY_BIT)
                checksum =  (checksum & NX_LOWER_16_MASK) + 1;
        
            /* Move the word pointer and decrease the length.  */
            word_ptr =  word_ptr + sizeof(ULONG);
            length = length - sizeof(ULONG);
            
        }
        else
        {

            /* Pickup the 16-bit word.  */
            short_temp =  *((USHORT *) word_ptr);

            /* Add next 16-bit word into checksum.  */
            checksum =  checksum + short_temp;

            /* Check for carry bits.  */
            if (checksum & NX_CARRY_BIT)
                checksum =  (checksum & NX_LOWER_16_MASK) + 1;

            /* Move the word pointer and decrease the length.  */
            word_ptr =  word_ptr + sizeof(USHORT);
            length = length - sizeof(USHORT);
        }

        /* Determine if we are at the end of the current packet.  */
        if ((word_ptr >= (UCHAR *) current_packet -> nx_packet_append_ptr) &&
            (current_packet -> nx_packet_next))
        {

            /* We have crossed the packet boundary.  Move to the next packet
              structure.  */
            current_packet =  current_packet -> nx_packet_next;

            /* Setup the new word pointer.  */
            word_ptr =  (UCHAR *) current_packet -> nx_packet_prepend_ptr;
        }
    }
    
    /* Swap back to host byte order to insert the checksum if little endian is specified. */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_0);

    /* If little endian is specified, we need to byte swap the checksum instead of computing the
       data in network byte order. */
    NX_CHANGE_ULONG_ENDIAN(checksum);

    /* Place the checksum 1s complement into the first header word.  */
    header_ptr -> nx_igmp_header_word_0 |= (~(checksum >> NX_SHIFT_BY_16) & NX_LOWER_16_MASK);

    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_0);
}

#else  
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_igmp_checksum_computation_test_application_define(void *first_unused_memory)
#endif
{         

    /* Print out test information banner.  */
    printf("NetX Test:   IGMP Checksum Computation Test............................N/A\n");

    test_control_return(3);
}
#endif
