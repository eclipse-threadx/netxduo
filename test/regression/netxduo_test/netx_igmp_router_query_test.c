/* This NetX test case test router query type .  */

#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_igmp.h" 
#include    "nx_ip.h"         
#include   "nx_ram_network_driver_test_1500.h"
                                            
extern void  test_control_return(UINT status);

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;  
static UCHAR                   igmp_host_response = 0;

/* Define thread prototypes.  */                      
static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);   
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static void    igmp_checksum_compute(NX_PACKET *packet_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_igmp_router_query_test_application_define(void *first_unused_memory)
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
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = _nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
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
    printf("NetX Test:   IGMP Router Qeury Test....................................");

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

        printf("ERROR!\n");
        test_control_return(1);
    }                                 

    /* Sleep 2000 ticks to trigger the NX_IP_PERIODIC_EVENT event
       1. Receive the IGMP Host response message,    
       2. Send the IGMP Router query message with invalid checksum,
       3. Send the IGMP Router query message,
       4. Send the IGMP Router query message with not joined group address,
       5. Receive the IGMP Host repsonse message.  */
    tx_thread_sleep(20 * NX_IP_PERIODIC_RATE);                                                                                                    
                           
#ifndef NX_DISABLE_IGMP_INFO
    /* Check the count.  */
    if ((ip_0.nx_ip_igmp_reports_sent != 2) || (ip_0.nx_ip_igmp_queries_received != 4) || (ip_0.nx_ip_igmp_invalid_packets != 1) || (ip_0.nx_ip_igmp_checksum_errors != 1))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
#endif /* NX_DISABLE_IGMP_INFO */

    /* Determine if the test was successful.  */
    if ((error_counter) || (igmp_host_response != 2))
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

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{                           
    
NX_IGMP_HEADER  *header_ptr;  
NX_PACKET       *my_packet;
ULONG           checksum;
ULONG           temp;
UINT            status; 
UINT            router_alert = 0;
UINT            i;
                                       
                              
#ifndef NX_DISABLE_IGMPV2
    if (ip_ptr -> nx_ip_igmp_router_version == NX_IGMP_HOST_VERSION_2)
        router_alert = 4;
#endif
                              
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
                                
        /* Do byte swapping for little endian processors before parsing
           IGMP header data. */
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_0);

        /* Update the counter.  */
        igmp_host_response ++;             

        /* Check the igmp host repsone counter.  */
        if (igmp_host_response != 1) 
            return NX_TRUE;                            
                                
        /* Allocate a packet to place the IGMP Router query message in, IGMP version1.  */
        status = nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &my_packet, NX_IGMP_PACKET + router_alert, TX_NO_WAIT);

        /* Check the status.  */
        if (status == NX_SUCCESS)
        {

            /* Prepare a IGMP Router Query and send on the "all hosts" multicast
              address.  */     

            /* Calculate the IGMP response message size and store it in the 
               packet header.  */
            my_packet -> nx_packet_length =  NX_IGMP_HEADER_SIZE;

            /* Setup the append pointer to the end of the message.  */
            my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + NX_IGMP_HEADER_SIZE;

            /* Stamp the outgoing interface. */
            my_packet -> nx_packet_address.nx_packet_interface_ptr = ip_ptr -> nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list;

            /* Build the IGMP host response packet.  */

            /* Setup the pointer to the message area.  */
            header_ptr =  (NX_IGMP_HEADER *) my_packet -> nx_packet_prepend_ptr;

            /* Build the IGMPv1 Router query message.  */
            header_ptr -> nx_igmp_header_word_0 =  (ULONG) (NX_IGMP_VERSION | NX_IGMP_ROUTER_QUERY_TYPE);
            header_ptr -> nx_igmp_header_word_1 =  ip_ptr -> nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list;

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

            /* Modify checksum to invalid one. */
            checksum++;

            /* Place the checksum into the first header word.  */
            header_ptr -> nx_igmp_header_word_0 =  header_ptr -> nx_igmp_header_word_0 | (~checksum & NX_LOWER_16_MASK);

            /* IGMPv2 packets must be IPv4 packets. */
            my_packet -> nx_packet_ip_version = NX_IP_VERSION_V4;

            /* If NX_LITTLE_ENDIAN is defined, the headers need to be swapped.  */
            NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_0);
            NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_igmp_header_word_1);

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
            /* Clear the capability of calculating the IGMP checksum.  */
            ip_0.nx_ip_interface[0].nx_interface_capability_flag &= ~NX_INTERFACE_CAPABILITY_IGMP_RX_CHECKSUM; 
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

            /* Call _nx_icmp_packet_receive to directly receive the IGMP packet with invalid checksum.  */
            _nx_igmp_packet_receive(&ip_0, my_packet);  
        }
        else
        {

            /* Update the error counter.  */
            error_counter ++;
        }

        for (i = 0; i < 2; i++)
        {

            /* Allocate a packet to place the IGMP Router query message in, IGMP version1.  */
            status = nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &my_packet, NX_IGMP_PACKET + router_alert, TX_NO_WAIT);

            /* Check the status.  */
            if (status == NX_SUCCESS)
            {

                /* Prepare a IGMP Router Query and send on the "all hosts" multicast
                  address.  */     

                /* Calculate the IGMP response message size and store it in the 
                packet header.  */
                my_packet -> nx_packet_length =  NX_IGMP_HEADER_SIZE;

                /* Setup the append pointer to the end of the message.  */
                my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + NX_IGMP_HEADER_SIZE;

                /* Stamp the outgoing interface. */
                my_packet -> nx_packet_address.nx_packet_interface_ptr = ip_ptr -> nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list;

                /* Build the IGMP host response packet.  */

                /* Setup the pointer to the message area.  */
                header_ptr =  (NX_IGMP_HEADER *) my_packet -> nx_packet_prepend_ptr;

                /* Build the IGMPv1 Router query message.  */
                header_ptr -> nx_igmp_header_word_0 =  (ULONG) (NX_IGMP_VERSION | NX_IGMP_ROUTER_QUERY_TYPE | 0x00010000);
                header_ptr -> nx_igmp_header_word_1 =  ip_ptr -> nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list;

                /* IGMPv2 packets must be IPv4 packets. */
                my_packet -> nx_packet_ip_version = NX_IP_VERSION_V4;

                /* Calculate the IGMP checksum. */
                igmp_checksum_compute(my_packet);

                /* Call _nx_igmp_packet_receive to directly receive the valid packet.  */
                _nx_igmp_packet_receive(&ip_0, my_packet);  
            }
            else
            {

                /* Update the error counter.  */
                error_counter ++;
            }
        }

        /* Allocate a packet to place the IGMP Router query message in, IGMP version1. The group address is not joined.  */
        status = nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &my_packet, NX_IGMP_PACKET + router_alert, TX_NO_WAIT);

        /* Check the status.  */
        if (status == NX_SUCCESS)
        {

            /* Prepare a IGMP Router Query and send on the "all hosts" multicast
              address.  */     

            /* Calculate the IGMP response message size and store it in the 
            packet header.  */
            my_packet -> nx_packet_length =  NX_IGMP_HEADER_SIZE;

            /* Setup the append pointer to the end of the message.  */
            my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + NX_IGMP_HEADER_SIZE;

            /* Stamp the outgoing interface. */
            my_packet -> nx_packet_address.nx_packet_interface_ptr = ip_ptr -> nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list;

            /* Build the IGMP host response packet.  */

            /* Setup the pointer to the message area.  */
            header_ptr =  (NX_IGMP_HEADER *) my_packet -> nx_packet_prepend_ptr;

            /* Build the IGMPv1 Router query message.  */
            header_ptr -> nx_igmp_header_word_0 =  (ULONG) (NX_IGMP_VERSION | NX_IGMP_ROUTER_QUERY_TYPE);
            header_ptr -> nx_igmp_header_word_1 =  ip_ptr -> nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list + 1;

            /* IGMPv2 packets must be IPv4 packets. */
            my_packet -> nx_packet_ip_version = NX_IP_VERSION_V4;

            /* Calculate the IGMP checksum. */
            igmp_checksum_compute(my_packet);

            /* Call _nx_icmp_packet_receive to directly receive the IGMP packet with group address not joined.  */
            _nx_igmp_packet_receive(&ip_0, my_packet);  
        }
        else
        {

            /* Update the error counter.  */
            error_counter ++;
        }
                                  
        /* Allocate a packet to place the IGMP Router query message in, IGMP version1.  */
        status = nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &my_packet, NX_IGMP_PACKET + router_alert, TX_NO_WAIT);

        /* Check the status.  */
        if (status == NX_SUCCESS)
        {

            /* Prepare a IGMP Router Query and send on the "all hosts" multicast
              address.  */     

            /* Calculate the IGMP response message size and store it in the 
            packet header.  */
            my_packet -> nx_packet_length =  NX_IGMP_HEADER_SIZE;

            /* Setup the append pointer to the end of the message.  */
            my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + NX_IGMP_HEADER_SIZE;

            /* Stamp the outgoing interface. */
            my_packet -> nx_packet_address.nx_packet_interface_ptr = ip_ptr -> nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_interface_list;

            /* Build the IGMP host response packet.  */

            /* Setup the pointer to the message area.  */
            header_ptr =  (NX_IGMP_HEADER *) my_packet -> nx_packet_prepend_ptr;

            /* Build the IGMPv1 Router query message.  */
            header_ptr -> nx_igmp_header_word_0 =  (ULONG) (NX_IGMP_VERSION | NX_IGMP_ROUTER_QUERY_TYPE);
            header_ptr -> nx_igmp_header_word_1 =  ip_ptr -> nx_ipv4_multicast_entry[0].nx_ipv4_multicast_join_list;           

            /* Calculate the IGMP checksum. */
            igmp_checksum_compute(my_packet);

            /* Modify thread time so the random value get from tx_time_get will be in control. */
            tx_time_set((tx_time_get() & 0xFFFFFFF0) + 2);

            /* Call _nx_icmp_packet_receive to directly receive the valid packet.  */
            _nx_igmp_packet_receive(&ip_0, my_packet);  
        }
        else
        {

            /* Update the error counter.  */
            error_counter ++;
        }
    }

    return NX_TRUE;
} 

static void    igmp_checksum_compute(NX_PACKET *packet_ptr)
{
ULONG               checksum;
ULONG               temp;
NX_IGMP_HEADER     *header_ptr;  

    /* Setup the pointer to the message area.  */
    header_ptr =  (NX_IGMP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

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
void           netx_igmp_router_query_test_application_define(void *first_unused_memory)
#endif
{         

    /* Print out test information banner.  */
    printf("NetX Test:   IGMP Router Qeury Test....................................N/A\n"); 

    test_control_return(3);
}
#endif
