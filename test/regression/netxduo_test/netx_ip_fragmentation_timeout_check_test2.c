/* This NetX test concentrates on basic IP fragmentation.  */
/* Requirement: NX_DISABLE_FRAGMENTATION is not defined. */
/* Test sequence:
 * 1. Client send 600 bytes (all '0') to Server. It is fragmented into three packets (A, B and C).
 * 2. Client send another 600 bytes (all '1') to Server. It is fragmented into three packets (D, E and F).
 * 3. The packets are received in this sequence: C, A, D, E, B. Packet F is dropped.
 * 3. Check fragment head and tail after reassembly timeout. No packets are queued any more.
 */


#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);
#if !defined(NX_DISABLE_FRAGMENTATION) && !defined(NX_DISABLE_IPV4)
#define    DEMO_STACK_SIZE         2048

#include   "nx_ip.h"
#include   "nx_system.h"
#include   "nx_ram_network_driver_test_1500.h"

#ifdef __PRODUCT_NETX__
#define NX_IPV4_HEADER NX_IP_HEADER
#ifndef NX_IPV4_MAX_REASSEMBLY_TIME
#define NX_IPV4_MAX_REASSEMBLY_TIME 5
#endif /* NX_IPV4_MAX_REASSEMBLY_TIME */
#endif /* __PRODUCT_NETX__ */


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;


static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;


/* Define the counters used in the demo application...  */

static ULONG    error_counter;
static CHAR     msg[2][600];
static CHAR     rcv_buffer[600];
static UINT     operations[] = {NX_RAMDRIVER_OP_DELAY, NX_RAMDRIVER_OP_DELAY, NX_RAMDRIVER_OP_BYPASS,
                                NX_RAMDRIVER_OP_DELAY, NX_RAMDRIVER_OP_DELAY, NX_RAMDRIVER_OP_DROP};
static UINT     delays[] = {1, 10, 0, 2, 2, 0};
static UINT     operation_index;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);

extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_timeout_check_test_2_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    operation_index = 0;
    memset(msg[0], '0', sizeof(msg[0]));
    memset(msg[1], '1', sizeof(msg[1]));

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
            pointer, DEMO_STACK_SIZE,
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

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
NX_PACKET   *my_packet, *rcv_packet;
ULONG       len;

    /* Print out some test information banners.  */
    printf("NetX Test:   IP Fragmentation Timeout Check Test 2.....................");


    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 1, 5);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, 0x89, NX_NO_WAIT);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 1, 5);

    /* Check status.  */
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, NX_NO_WAIT);

    /* Check status.  */
    if (status)
        error_counter++;

    advanced_packet_process_callback = my_packet_process;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write all '0' into the packet payload!  */
    status = nx_packet_data_append(my_packet, msg[0], sizeof(msg[0]), &pool_0, NX_NO_WAIT);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write all '0' into the packet payload!  */
    status = nx_packet_data_append(my_packet, msg[1], sizeof(msg[1]), &pool_0, NX_NO_WAIT);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Sleep assembly timeout. */
    tx_thread_sleep((NX_IPV4_MAX_REASSEMBLY_TIME + 1) * NX_IP_PERIODIC_RATE);

    /* Check head and tail fragment link of ip_1. */
    /* The second packet in fragment link is dropped. */
    if ((ip_1.nx_ip_fragment_assembly_head != ip_1.nx_ip_fragment_assembly_tail) ||
        (ip_1.nx_ip_fragment_assembly_head != NX_NULL))
    {
        error_counter++;
    }

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

    /* Receive a UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &rcv_packet, 10 * NX_IP_PERIODIC_RATE);

    if(status == NX_SUCCESS)
    {

        status = nx_packet_data_retrieve(rcv_packet, rcv_buffer, &len);

        /* Check data length */
        if(len != sizeof(msg[0]))
            error_counter++;

        /* Check received data. */
        if(memcmp(rcv_buffer, msg[0], len))
            error_counter++;

        /* Release the packet.  */
        nx_packet_release(rcv_packet);
    }

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_1);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_1);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Check no packet is leak. */
    if (pool_0.nx_packet_pool_total != pool_0.nx_packet_pool_available)
        error_counter++;

    /* Check status.  */
    if (error_counter)
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
NX_IPV4_HEADER *header;

    /* Return if it is not an IP packet. */
    if (packet_ptr -> nx_packet_length <= 28)
        return NX_TRUE;

    /* Get IP header. */
    header = (NX_IPV4_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    NX_CHANGE_ULONG_ENDIAN(header -> nx_ip_header_word_1);

    /* Is it fragmented? */
    if (header -> nx_ip_header_word_1 & NX_IP_FRAGMENT_MASK)
    {

        /* Yes it is. Setup operations. */
        *operation_ptr = operations[operation_index];
        *delay_ptr = delays[operation_index++];
    }

    NX_CHANGE_ULONG_ENDIAN(header -> nx_ip_header_word_1);

    return NX_TRUE;
}

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ip_fragmentation_timeout_check_test_2_application_define(void *first_unused_memory)
#endif
{

    printf("NetX Test:   IP Fragmentation Timeout Check Test 2.....................N/A\n");
    test_control_return(3);
}
#endif /* NX_DISABLE_FRAGMENTATION  */
