/* This NetX test concentrates on basic IP fragmentation.  */
/* Requirement: __PRODUCT_NETXDUO__ is defined, NX_DISABLE_FRAGMENTATION is not defined. */
/* Test sequence:
 * 1. Client send UDP 1500 bytes to Server.
 * 2. Modify the protocol with ICMP and delay one second for first fragment packet. 
 * 2. Modify the protocol with ICMP for second fragment packet. 
 * 3. Check if Server receive the 1500 bytes.
 */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);
#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_FRAGMENTATION) && !defined(NX_DISABLE_IPV4)
#include   "nx_ip.h"
#define    DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;


/* Define the counters used in the demo application...  */

static ULONG    error_counter;
static ULONG    packet_counter;
static CHAR     msg[1500]={'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_wrong_protocol_field_test2_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    error_counter =  0;
    packet_counter=0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* .  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 1536*16);
    pointer = pointer + 1500*16;

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

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check for UDP enable errors.  */
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
UINT        packet_length;

    /* Print out some test information banners.  */
    printf("NetX Test:   IP Fragmentation Wrong Protocol Field Test2...............");

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x08, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, 0x89, NX_NO_WAIT);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Let Socket 0 send all packet. test _nx_ip_fragment_assembly()
       Hit the false condition: 442 [ +  - ]: if (fragment_head == ip_ptr -> nx_ip_fragment_assembly_tail)  */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    /* Initialize the value.  */
    packet_length = 0;

    /* Loop to receive the packets.  */
    while(1)
    {

        /* Receive the packet.  */
        status =  nx_udp_socket_receive(&socket_1, &my_packet, NX_NO_WAIT);

        /* Check status.  */
        if(status == NX_SUCCESS)
        {

            /* Update the packet length.  */
            packet_length += my_packet -> nx_packet_length;
        }
        else
        {
            break;
        }
    }

    /* Check the packet length.  */
    if (packet_length != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_1);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_1);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check status.  */
    if ((error_counter) || (packet_counter < 3))
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

UINT        status;
NX_PACKET   *my_packet;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x08, 5);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, NX_NO_WAIT);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Set the callback function.  */
    advanced_packet_process_callback = my_packet_process;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    status = nx_packet_data_append(my_packet, msg, 1500, &pool_0, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_0);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_0);

    /* Check status.  */
    if (status)
        error_counter++;
}


static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{

NX_IPV4_HEADER   *ip_header_ptr;  
ULONG            val; 
ULONG            checksum;

    /* Return if it is not an IP packet from ip_0. */
    if ((ip_ptr == &ip_0) && (packet_ptr -> nx_packet_length > 28))
    {

        /* Updated the packet_counter.  */
        packet_counter ++;

        /* Modify the first fragmentation packet.  */
        if (packet_counter == 1)
        {

            /* Point to the IP HEADER.  */
            ip_header_ptr =  (NX_IPV4_HEADER *) packet_ptr -> nx_packet_prepend_ptr;

            NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);

            /* Modify the protocol to ICMP. */
            ip_header_ptr -> nx_ip_header_word_2 &= 0xFF000000; 
            ip_header_ptr -> nx_ip_header_word_2 |= NX_IP_ICMP;

            NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);

            /* Calculate the IP checksum.  */
            checksum = _nx_ip_checksum_compute(packet_ptr, NX_IP_VERSION_V4,
                                               /* Length is the size of IP header, including options */
                                               20, 
                                               /* IPv4 header checksum doesn't care src/dest addresses */
                                               NULL, NULL);

            val = (ULONG)(~checksum);
            val = val & NX_LOWER_16_MASK;

            /* Convert to network byte order. */
            NX_CHANGE_ULONG_ENDIAN(val);

            /* Now store the checksum in the IP header.  */
            ip_header_ptr -> nx_ip_header_word_2 =  ip_header_ptr -> nx_ip_header_word_2 | val;

            /* Delay some seconds. */
            *operation_ptr = NX_RAMDRIVER_OP_DELAY;
            *delay_ptr = NX_IP_PERIODIC_RATE;
        }

        /* Modify the second fragmentation packet.  */
        if (packet_counter == 2)
        {

            /* Point to the IP HEADER.  */
            ip_header_ptr =  (NX_IPV4_HEADER *) packet_ptr -> nx_packet_prepend_ptr;

            NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);

            /* Modify the protocol to ICMP. */
            ip_header_ptr -> nx_ip_header_word_2 &= 0xFF000000; 
            ip_header_ptr -> nx_ip_header_word_2 |= NX_IP_ICMP;

            NX_CHANGE_ULONG_ENDIAN(ip_header_ptr -> nx_ip_header_word_2);

            /* Calculate the IP checksum.  */
            checksum = _nx_ip_checksum_compute(packet_ptr, NX_IP_VERSION_V4,
                                               /* Length is the size of IP header, including options */
                                               20, 
                                               /* IPv4 header checksum doesn't care src/dest addresses */
                                               NULL, NULL);

            val = (ULONG)(~checksum);
            val = val & NX_LOWER_16_MASK;

            /* Convert to network byte order. */
            NX_CHANGE_ULONG_ENDIAN(val);

            /* Now store the checksum in the IP header.  */
            ip_header_ptr -> nx_ip_header_word_2 =  ip_header_ptr -> nx_ip_header_word_2 | val;
        }
    }

    return NX_TRUE;
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_wrong_protocol_field_test2_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   IP Fragmentation Wrong Protocol Field Test2...............N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_FRAGMENTATION  */
