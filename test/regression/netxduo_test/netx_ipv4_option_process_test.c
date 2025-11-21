/* This NetX test concentrates on the ICMP ping operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ip.h"
#include   "nx_icmp.h"                 

#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   icmp_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT   (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static UINT   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv4_option_process_test_application_define(void *first_unused_memory)
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

    
    /* Print out test information banner.  */
    printf("NetX Test:   IPv4 Option Process Test..................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                    
    packet_process_callback = my_packet_process;

    /*  Test NX_IP_OPTION_NO_OPERATION and NX_IP_OPTION_END option by ping.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check the status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }               
    else
    {            

        /* Release the packet. */
        nx_packet_release(my_packet);
    }
             
    /*  Test illegal length of NX_IP_OPTION_INTERNET_TIMESTAMP option by ping.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check the status.  */  
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }          
                              
    /*  Test two NX_IP_OPTION_INTERNET_TIMESTAMP options by ping.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check the status.  */  
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    /*  Test illegal offset of NX_IP_OPTION_INTERNET_TIMESTAMP option by ping.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check the status.  */  
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    
       
    /*  Test illegal overflow NX_IP_OPTION_INTERNET_TIMESTAMP option by ping.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check the status.  */  
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }        

    /*  Test illegal flags of NX_IP_OPTION_INTERNET_TIMESTAMP option by ping.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check the status.  */  
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    /*  Test illegal option length of Stream Identifier option by ping.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check the status.  */  
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /*  Test illegal option length of Stream Identifier option by ping.  */
    status = nx_icmp_ping(&ip_0, IP_ADDRESS(1, 2, 3, 5), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 28, &my_packet, 1 * NX_IP_PERIODIC_RATE);

    /* Check the status.  */  
    if ((status != NX_NO_RESPONSE) || (my_packet))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }    

    printf("SUCCESS!\n");
    test_control_return(0);
}
    
static UINT   my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_IPV4_HEADER   *ip_header_ptr; 
NX_ICMP_HEADER   *icmp_header_ptr;
ULONG            ip_header_length; 
ULONG            protocol;
ULONG            checksum;  
ULONG            val;
ULONG            offset;
ULONG            shift; 
ULONG            message_word;

    /* Get the IP header pointer.  */
    ip_header_ptr = (NX_IPV4_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);  

    /* Get IP header. */
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);
    protocol = (ip_header_ptr -> nx_ip_header_word_2 >> 16) & 0xFF; 
    NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);

    /* Modify the ICMP packet from ip_0 instance. */
    if((protocol == NX_PROTOCOL_ICMP) && (ip_ptr == &ip_0))
    {

        /* Update the icmp_counter.  */
        icmp_counter++;

        /* Get the IP header pointer.  */
        ip_header_ptr = (NX_IPV4_HEADER*)(packet_ptr -> nx_packet_prepend_ptr);  
        
        /* Calculate the IPv4 option length.  */   
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);
        ip_header_length = ((ip_header_ptr -> nx_ip_header_word_0 & NX_IP_LENGTH_MASK) >> 24) * sizeof(ULONG);

        /* Get ICMP header. */
        icmp_header_ptr = (NX_ICMP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr + ip_header_length);

        /* Add the NX_IP_OPTION_NO_OPERATION and NX_IP_OPTION_END option.  */
        if (icmp_counter == 1)
        {

            /* Move the data to add the option. */
            offset = 4;
            shift = packet_ptr -> nx_packet_length - ip_header_length;
            memmove(((UCHAR *)(icmp_header_ptr)) + offset, icmp_header_ptr, shift);       

            /* Clear memory.  */
            memset(&message_word, 0, sizeof(ULONG));

            /* Add NX_IP_OPTION_NO_OPERATION and NX_IP_OPTION_END.  */
            message_word = (ULONG)((NX_IP_OPTION_NO_OPERATION << 24) | (NX_IP_OPTION_END << 16));

            /* Adjust for endianness. */
            NX_CHANGE_ULONG_ENDIAN(message_word);

            /* Copy the option into the buffer. */
            memcpy(icmp_header_ptr, &message_word, sizeof(ULONG));
        }      

        /* Add the two NX_IP_OPTION_INTERNET_TIMESTAMP options.  */
        else if (icmp_counter == 2)
        {                    

            /* Move the data to add the option. */
            offset = 24;
            shift = packet_ptr -> nx_packet_length - ip_header_length;
            memmove(((UCHAR *)(icmp_header_ptr)) + offset, icmp_header_ptr, shift);       

            /* Add the first option.  */

            /* Clear memory.  */
            memset(&message_word, 0, sizeof(ULONG));

            /* Add type, length, offset, overflw and flags.  */
            message_word = (ULONG)((NX_IP_OPTION_INTERNET_TIMESTAMP << 24) | (12 << 16) | (5 << 8));

            /* Adjust for endianness. */
            NX_CHANGE_ULONG_ENDIAN(message_word);
                                                       
            /* Add type, length, offset, overflw and flags.  */
            memcpy(icmp_header_ptr, &message_word, sizeof(ULONG));  

            /* Clear the time stamp value.  */
            memset(((UCHAR *)(icmp_header_ptr)) + sizeof(ULONG), 0 , 12 - sizeof(ULONG));
                         
            /* Add the second option.  */

            /* Clear memory.  */
            memset(&message_word, 0, sizeof(ULONG));

            /* Add type, length, offset, overflw and flags.  */
            message_word = (ULONG)((NX_IP_OPTION_INTERNET_TIMESTAMP << 24) | (12 << 16) | (5 << 8));

            /* Adjust for endianness. */
            NX_CHANGE_ULONG_ENDIAN(message_word);
                                                       
            /* Add type, length, offset, overflw and flags.  */
            memcpy(((UCHAR *)icmp_header_ptr) + 12, &message_word, sizeof(ULONG));  

            /* Clear the time stamp value.  */
            memset(((UCHAR *)(icmp_header_ptr)) + 12 + sizeof(ULONG), 0 , 12 - sizeof(ULONG));
        }

        /* Add the illegal length 7 for NX_IP_OPTION_INTERNET_TIMESTAMP option.  */
        else if (icmp_counter == 3)
        {                    

            /* Move the data to add the option. */
            offset = 12;
            shift = packet_ptr -> nx_packet_length - ip_header_length;
            memmove(((UCHAR *)(icmp_header_ptr)) + offset, icmp_header_ptr, shift);       

            /* Clear memory.  */
            memset(&message_word, 0, sizeof(ULONG));

            /* Add type, length, offset, overflw and flags.  */
            message_word = (ULONG)((NX_IP_OPTION_INTERNET_TIMESTAMP << 24) | (7 << 16) | (5 << 8) );

            /* Adjust for endianness. */
            NX_CHANGE_ULONG_ENDIAN(message_word);
                                                       
            /* Add type, length, offset, overflw and flags.  */
            memcpy(icmp_header_ptr, &message_word, sizeof(ULONG));  

            /* Clear the time stamp value.  */
            memset(((UCHAR *)(icmp_header_ptr)) + sizeof(ULONG), 0 , offset - sizeof(ULONG));
        }  

        /* Add the illegal offset 4 for NX_IP_OPTION_INTERNET_TIMESTAMP option.  */
        else if (icmp_counter == 4)
        {                    

            /* Move the data to add the option. */
            offset = 12;
            shift = packet_ptr -> nx_packet_length - ip_header_length;
            memmove(((UCHAR *)(icmp_header_ptr)) + offset, icmp_header_ptr, shift);       

            /* Clear memory.  */
            memset(&message_word, 0, sizeof(ULONG));

            /* Add type, length, offset, overflw and flags.  */
            message_word = (ULONG)((NX_IP_OPTION_INTERNET_TIMESTAMP << 24) | (12 << 16) | (4 << 8) );

            /* Adjust for endianness. */
            NX_CHANGE_ULONG_ENDIAN(message_word);
                                                       
            /* Add type, length, offset, overflw and flags.  */
            memcpy(icmp_header_ptr, &message_word, sizeof(ULONG));  

            /* Clear the time stamp value.  */
            memset(((UCHAR *)(icmp_header_ptr)) + sizeof(ULONG), 0 , offset - sizeof(ULONG));
        }        

        /* Add the illegal overflow 15 for NX_IP_OPTION_INTERNET_TIMESTAMP option.  */
        else if (icmp_counter == 5)
        {                    

            /* Move the data to add the option. */
            offset = 12;
            shift = packet_ptr -> nx_packet_length - ip_header_length;
            memmove(((UCHAR *)(icmp_header_ptr)) + offset, icmp_header_ptr, shift);       

            /* Clear memory.  */
            memset(&message_word, 0, sizeof(ULONG));

            /* Add type, length, offset, overflw and flags.  */
            message_word = (ULONG)((NX_IP_OPTION_INTERNET_TIMESTAMP << 24) | (12 << 16) | (5 << 8) | (15 << 4));

            /* Adjust for endianness. */
            NX_CHANGE_ULONG_ENDIAN(message_word);
                                                       
            /* Add type, length, offset, overflw and flags.  */
            memcpy(icmp_header_ptr, &message_word, sizeof(ULONG));  

            /* Clear the time stamp value.  */
            memset(((UCHAR *)(icmp_header_ptr)) + sizeof(ULONG), 0 , offset - sizeof(ULONG));
        }      

        /* Add the illegal flags 5 for NX_IP_OPTION_INTERNET_TIMESTAMP option.  */
        else if (icmp_counter == 6)
        {                    

            /* Move the data to add the option. */
            offset = 12;
            shift = packet_ptr -> nx_packet_length - ip_header_length;
            memmove(((UCHAR *)(icmp_header_ptr)) + offset, icmp_header_ptr, shift);       

            /* Clear memory.  */
            memset(&message_word, 0, sizeof(ULONG));

            /* Add type, length, offset, overflw and flags.  */
            message_word = (ULONG)((NX_IP_OPTION_INTERNET_TIMESTAMP << 24) | (12 << 16) | (5 << 8) | (5));

            /* Adjust for endianness. */
            NX_CHANGE_ULONG_ENDIAN(message_word);
                                                       
            /* Add type, length, offset, overflw and flags.  */
            memcpy(icmp_header_ptr, &message_word, sizeof(ULONG));  

            /* Clear the time stamp value.  */
            memset(((UCHAR *)(icmp_header_ptr)) + sizeof(ULONG), 0 , offset - sizeof(ULONG));
        }     
        
        /* Add the illegal length 0 of Stream Identifier option.  */
        else if (icmp_counter == 7)
        {                    

            /* Move the data to add the option. */
            offset = 4;
            shift = packet_ptr -> nx_packet_length - ip_header_length;
            memmove(((UCHAR *)(icmp_header_ptr)) + offset, icmp_header_ptr, shift);       

            /* Clear memory.  */
            memset(&message_word, 0, sizeof(ULONG));

            /* Add type, length, offset, overflw and flags.  */
            message_word = (ULONG)((136 << 24) | (0 << 16));

            /* Adjust for endianness. */
            NX_CHANGE_ULONG_ENDIAN(message_word);
                                                       
            /* Add type, length, offset, overflw and flags.  */
            memcpy(icmp_header_ptr, &message_word, sizeof(ULONG));
        }  

        /* Add the illegal length 5 of Stream Identifier option.  */
        else if (icmp_counter == 8)
        {                    

            /* Move the data to add the option. */
            offset = 4;
            shift = packet_ptr -> nx_packet_length - ip_header_length;
            memmove(((UCHAR *)(icmp_header_ptr)) + offset, icmp_header_ptr, shift);       

            /* Clear memory.  */
            memset(&message_word, 0, sizeof(ULONG));

            /* Add type, length, offset, overflw and flags.  */
            message_word = (ULONG)((136 << 24) | (5 << 16));

            /* Adjust for endianness. */
            NX_CHANGE_ULONG_ENDIAN(message_word);
                                                       
            /* Add type, length, offset, overflw and flags.  */
            memcpy(icmp_header_ptr, &message_word, sizeof(ULONG));
        }  

        /* Update the header IP length and total length.  */   
        ip_header_length += offset;       
        packet_ptr -> nx_packet_append_ptr += offset;
        packet_ptr -> nx_packet_length += offset;
                                                                                                 
        /* Rebuild the first 32-bit word of the IP header.  */
        ip_header_ptr -> nx_ip_header_word_0 =  (ULONG)((NX_IP_VERSION_V4 << 28) |
                                                        ((ip_header_length/sizeof(ULONG)) << 24) |
                                                        NX_IP_NORMAL |
                                                        (0xFFFF & packet_ptr -> nx_packet_length));  

        /* Endian swapping logic.  */  
        NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_0);

        /* Clear the checksum . */
        ip_header_ptr -> nx_ip_header_word_2 = ip_header_ptr -> nx_ip_header_word_2 & 0x0000FFFF;

        /* Calculate the checksum.  */
        checksum = _nx_ip_checksum_compute(packet_ptr, NX_IP_VERSION_V4,
                                           /* Length is the size of IP header, including options */
                                           (UINT)(ip_header_length),
                                           /* IPv4 header checksum does not use src/dest addresses */
                                           NULL, NULL);

        val = (ULONG)(~checksum);
        val = val & NX_LOWER_16_MASK;

        /* Convert to network byte order. */
        NX_CHANGE_ULONG_ENDIAN(val);

        /* Now store the checksum in the IP header.  */
        ip_header_ptr -> nx_ip_header_word_2 =  ip_header_ptr -> nx_ip_header_word_2 | val;
    }

    return NX_TRUE;
}
              
#else

extern void    test_control_return(UINT status);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ipv4_option_process_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Test:   IPv4 Option Process Test..................................N/A\n");
    test_control_return(3);
}
#endif
