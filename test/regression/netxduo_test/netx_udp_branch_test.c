/* This NetX test concentrates on the code coverage for UDP functions,
 * _nx_udp_receive_cleanup.c
 * _nx_udp_socket_unbind.c
 * _nx_udp_packet_info_extract.c
 */

#include "nx_api.h"
#include "tx_thread.h"
#include "nx_udp.h"
#include "nx_ip.h"
#ifdef FEATURE_NX_IPV6
#include  "nx_ipv6.h"
#endif

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_test1;
static TX_THREAD               thread_test2;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_UDP_SOCKET           socket_0;



/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0; 
static CHAR                    *pointer;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static VOID    suspend_cleanup(TX_THREAD *thread_ptr NX_CLEANUP_PARAMETER);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_branch_test_application_define(void *first_unused_memory)
#endif
{

UINT           status;
NX_PACKET     *my_packet;
NX_UDP_HEADER *udp_header_ptr;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

#ifndef NX_DISABLE_IPV4
    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;
#endif

    /* Enable UDP processing for IP instance.  */
    status =  nx_udp_enable(&ip_0);

    /* Check UDP enable status.  */
    if (status)
        error_counter++;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if (status != NX_SUCCESS)
        error_counter++;

    /* Test _nx_udp_packet_receive()  */
    /* Hit condition: _tx_thread_current_ptr = NX_NULL
       [ +  - ][ +  - ]:  if ((_tx_thread_current_ptr) && (_tx_thread_system_state == 0))  line 199 and 263 */

    /* Allocate the packet.  */
    nx_packet_allocate(&pool_0, &my_packet, 0, NX_NO_WAIT);
    udp_header_ptr =  (NX_UDP_HEADER *)my_packet -> nx_packet_prepend_ptr;
    udp_header_ptr -> nx_udp_header_word_0 = 0x24681234;
    udp_header_ptr -> nx_udp_header_word_1 = 0x00090000;
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + 9;
    my_packet -> nx_packet_length = 9;

    _nx_udp_packet_receive(&ip_0, my_packet);

    /* Hit condition: _tx_thread_current_ptr = NX_NULL
       [ +  - ][ +  - ]:  if ((_tx_thread_current_ptr) && (_tx_thread_system_state == 0))  line 312 */    
    _nx_udp_socket_bind(&socket_0, 0x1234, NX_NO_WAIT);

    /* Allocate the packet.  */
    nx_packet_allocate(&pool_0, &my_packet, 0, NX_NO_WAIT);
    udp_header_ptr =  (NX_UDP_HEADER *)my_packet -> nx_packet_prepend_ptr;
    udp_header_ptr -> nx_udp_header_word_0 = 0x24681234;
    udp_header_ptr -> nx_udp_header_word_1 = 0x00090000;
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + 9;
    my_packet -> nx_packet_length = 9;

    _nx_udp_packet_receive(&ip_0, my_packet);
    _nx_udp_socket_unbind(&socket_0);
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

ULONG       thread_state;
ULONG       system_state;
NX_PACKET  *my_packet[2]; 
NX_UDP_SOCKET   *temp_socket;
TX_THREAD       *temp_thread;
#ifdef __PRODUCT_NETXDUO__
ULONG       ip_address;
NX_PACKET  *receive_packet;
#endif                   
NX_UDP_HEADER *udp_header_ptr;
#ifdef FEATURE_NX_IPV6
NX_IPV6_HEADER *ipv6_header_ptr;
#endif

    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Branch Test...........................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }



    /* Test _nx_udp_receive_cleanup().  */
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    socket_0.nx_udp_socket_id = NX_UDP_ID;
    _nx_udp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = &socket_0;
    socket_0.nx_udp_socket_id = 0;
    _nx_udp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    socket_0.nx_udp_socket_id = 0;
    _nx_udp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = &socket_0;
    socket_0.nx_udp_socket_id = NX_UDP_ID;
    _nx_udp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    socket_0.nx_udp_socket_id = NX_UDP_ID;
    _nx_udp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = &socket_0;
    socket_0.nx_udp_socket_id = 0;
    _nx_udp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    socket_0.nx_udp_socket_id = 0;
    _nx_udp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = &socket_0; 
    tx_thread_identify() -> tx_thread_suspended_next = &thread_test1;
    tx_thread_identify() -> tx_thread_suspended_previous = &thread_test2;
    thread_state = tx_thread_identify() -> tx_thread_state;
    socket_0.nx_udp_socket_id = NX_UDP_ID;
    socket_0.nx_udp_socket_receive_suspended_count ++;
    tx_thread_identify() -> tx_thread_state = 0;
    _nx_udp_receive_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT); 
    tx_thread_identify() -> tx_thread_state = thread_state;
    socket_0.nx_udp_socket_receive_suspension_list = TX_NULL;



    /* Test _nx_udp_bind_cleanup  */
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    socket_0.nx_udp_socket_id = NX_UDP_ID;
    _nx_udp_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = &socket_0;
    socket_0.nx_udp_socket_id = 0;
    _nx_udp_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    socket_0.nx_udp_socket_id = 0;
    _nx_udp_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = &socket_0;
    socket_0.nx_udp_socket_id = NX_UDP_ID;
    _nx_udp_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    socket_0.nx_udp_socket_id = NX_UDP_ID;
    _nx_udp_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = &socket_0;
    socket_0.nx_udp_socket_id = 0;
    _nx_udp_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);
    
    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID.  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = NX_NULL;
    tx_thread_identify() -> tx_thread_suspend_control_block = NX_NULL;
    socket_0.nx_udp_socket_id = 0;
    _nx_udp_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT);

    /* Setup tx_thread_suspend_cleanup, socket_ptr, and socket ID to hit false condition of if (thread_ptr -> tx_thread_state == TX_TCP_IP)  */
    tx_thread_identify() -> tx_thread_suspend_cleanup = suspend_cleanup;
    tx_thread_identify() -> tx_thread_suspend_control_block = &socket_0;
    socket_0.nx_udp_socket_id = NX_UDP_ID;
    tx_thread_identify() -> tx_thread_suspended_next = tx_thread_identify();
    socket_0.nx_udp_socket_bound_previous = &socket_0;
    socket_0.nx_udp_socket_bind_suspended_count ++;
    thread_state = tx_thread_identify() -> tx_thread_state;
    tx_thread_identify() -> tx_thread_state = 0;
    _nx_udp_bind_cleanup(tx_thread_identify() NX_CLEANUP_ARGUMENT); 
    tx_thread_identify() -> tx_thread_state = thread_state;

    /* Recover.  */
    tx_thread_identify() -> tx_thread_suspended_next = TX_NULL;
    socket_0.nx_udp_socket_bound_previous = NX_NULL;



    /* Test _nx_udp_socket_unbind().  */
    /* Hit [ +  + ][ -  + ] condition
       if ((socket_ptr -> nx_udp_socket_bound_next) ||
           (socket_ptr -> nx_udp_socket_bind_in_progress))  */
    temp_socket = socket_0.nx_udp_socket_bound_next;
    socket_0.nx_udp_socket_bound_next = NX_NULL;
    temp_thread = socket_0.nx_udp_socket_bind_in_progress;
    socket_0.nx_udp_socket_bind_in_progress = tx_thread_identify();
    nx_udp_socket_bind(&socket_0, 1234, NX_NO_WAIT);
    socket_0.nx_udp_socket_bound_next = temp_socket;
    socket_0.nx_udp_socket_bind_in_progress = temp_thread;


    /* Hit true condition of if (socket_ptr -> nx_udp_socket_receive_count)*/
    nx_udp_socket_bind(&socket_0, 1234, NX_NO_WAIT);

    /* Allocate the packet. queue two packet on receive list.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    nx_packet_allocate(&pool_0, &my_packet[1], 0, NX_NO_WAIT);
    socket_0.nx_udp_socket_receive_head = my_packet[0];
    my_packet[0] -> nx_packet_queue_next = my_packet[1];
    my_packet[1] -> nx_packet_queue_next = NX_NULL;
    socket_0.nx_udp_socket_receive_tail = my_packet[1];
    socket_0.nx_udp_socket_receive_count = 2;

    /* Recover.  Unbind the socket.  */
    _nx_udp_socket_unbind(&socket_0);



#if defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_IPV4)
    /* Hit false condition of if (status == NX_SUCCESS) in _nx_udp_packet_info_extract.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_ip_version = 0;
    _nx_udp_packet_info_extract(my_packet[0], &ip_address, NX_NULL, NX_NULL, NX_NULL);
    nx_packet_release(my_packet[0]); 


    /* Test _nx_udp_socket_receive()  */
    /* Hit condition:
    [ +  - ][ +  + ]:     if ((!socket_ptr -> nx_udp_socket_disable_checksum && (*(temp_ptr + 1) & NX_LOWER_16_MASK)) || 
            [ +  + ]          ((*packet_ptr) -> nx_packet_ip_version == NX_IP_VERSION_V6))  */ 
    nx_udp_socket_bind(&socket_0, 1234, NX_NO_WAIT);
    /* Allocate the packet. queue one packet on receive list.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 9;
    my_packet[0] -> nx_packet_length = 9;
    my_packet[0] -> nx_packet_ip_version = NX_IP_VERSION_V4;
    my_packet[0] -> nx_packet_address.nx_packet_interface_ptr = &ip_0.nx_ip_interface[0];
    socket_0.nx_udp_socket_receive_count = 1;
    socket_0.nx_udp_socket_receive_head = my_packet[0];
    my_packet[0] -> nx_packet_queue_next = NX_NULL;
    socket_0.nx_udp_socket_receive_tail = my_packet[0];
    socket_0.nx_udp_socket_disable_checksum = 1;
    _nx_udp_socket_receive(&socket_0, &receive_packet, 0);
    nx_packet_release(receive_packet);

    /* Recover.  Unbind the socket.  */
    socket_0.nx_udp_socket_disable_checksum = 0;
    _nx_udp_socket_unbind(&socket_0);
#endif /* __PRODUCT_NETXDUO__  */



    /* Test _nx_udp_packet_receive()  */
    /* Hit condition:
       [ +  - ][ +  - ]:  if ((_tx_thread_current_ptr) && (_tx_thread_system_state == 0))  line 199 and 263 */

    /* Allocate the packet.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    udp_header_ptr =  (NX_UDP_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    udp_header_ptr -> nx_udp_header_word_0 = 0x24681234;
    udp_header_ptr -> nx_udp_header_word_1 = 0x00090000;
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 9;
    my_packet[0] -> nx_packet_length = 9;

    system_state = _tx_thread_system_state ;
    _tx_thread_system_state = 1;
    _nx_udp_packet_receive(&ip_0, my_packet[0]); 
    _tx_thread_system_state = system_state;


    /* Hit condition:
       [ +  - ][ +  - ]:  if ((_tx_thread_current_ptr) && (_tx_thread_system_state == 0))  line 312 */    
    nx_udp_socket_bind(&socket_0, 0x1234, NX_NO_WAIT);

    /* Allocate the packet.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    udp_header_ptr =  (NX_UDP_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    udp_header_ptr -> nx_udp_header_word_0 = 0x24681234;
    udp_header_ptr -> nx_udp_header_word_1 = 0x00090000;
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 9;
    my_packet[0] -> nx_packet_length = 9;

    system_state = _tx_thread_system_state ;
    _tx_thread_system_state = 1;
    _nx_udp_packet_receive(&ip_0, my_packet[0]); 
    _tx_thread_system_state = system_state;  
    _nx_udp_socket_unbind(&socket_0);


#ifndef NX_DISABLE_IPV4
#ifdef __PRODUCT_NETXDUO__
    /* Hit condition:
       [ +  + ][ +  - ]:  if ((packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4) &&
     :                        (ip_ptr -> nx_ip_icmpv4_packet_process)) line 334   */
    nx_udp_socket_bind(&socket_0, 0x0100, NX_NO_WAIT);

    /* Allocate the packet.  */
    nx_packet_allocate(&pool_0, &my_packet[0], 0, NX_NO_WAIT);
    udp_header_ptr =  (NX_UDP_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    udp_header_ptr -> nx_udp_header_word_0 = 0x24688100;
    udp_header_ptr -> nx_udp_header_word_1 = 0x00090000;
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 9;
    my_packet[0] -> nx_packet_length = 9;
    my_packet[0] -> nx_packet_ip_version = 4;
    ip_0.nx_ip_icmpv4_packet_process = NX_NULL;

    _nx_udp_packet_receive(&ip_0, my_packet[0]);
    _nx_udp_socket_unbind(&socket_0);
#endif
#endif


#ifdef FEATURE_NX_IPV6
    /* Hit condition:
       [ +  - ]:  if ((ip_header -> nx_ip_header_destination_ip[0] & (ULONG)0xFF000000) != (ULONG)0xFF000000)  line 359  */
    nx_udp_socket_bind(&socket_0, 0x0100, NX_NO_WAIT);

    /* Allocate the packet.  */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_IPv6_PACKET, NX_NO_WAIT);
    udp_header_ptr =  (NX_UDP_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    udp_header_ptr -> nx_udp_header_word_0 = 0x24688100;
    udp_header_ptr -> nx_udp_header_word_1 = 0x00090000;
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 9;
    my_packet[0] -> nx_packet_length = 9;  
    my_packet[0] -> nx_packet_ip_version = 6;
    my_packet[0] -> nx_packet_ip_header = my_packet[0] -> nx_packet_prepend_ptr - 40;
    ipv6_header_ptr = (NX_IPV6_HEADER *)my_packet[0] -> nx_packet_ip_header;
    ipv6_header_ptr -> nx_ip_header_destination_ip[0] = 0xFF000000;

    _nx_udp_packet_receive(&ip_0, my_packet[0]); 
    _nx_udp_socket_unbind(&socket_0);
#endif

    /* Test packet_ptr -> nx_packet_length < sizeof(NX_UDP_HEADER) */
    /* Allocate the packet.  */
    nx_packet_allocate(&pool_0, &my_packet[0], NX_IP_PACKET, NX_NO_WAIT);
    udp_header_ptr =  (NX_UDP_HEADER *)my_packet[0] -> nx_packet_prepend_ptr;
    udp_header_ptr -> nx_udp_header_word_0 = 0x24688100;
    udp_header_ptr -> nx_udp_header_word_1 = 0x00090000;
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
    my_packet[0] -> nx_packet_append_ptr = my_packet[0] -> nx_packet_prepend_ptr + 8;

    /* Reset the packet length to make sure the packet length is small than NX_UDP_HEADER   */
    my_packet[0] -> nx_packet_length = 7;
    _nx_udp_packet_receive(&ip_0, my_packet[0]); 

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

static VOID    suspend_cleanup(TX_THREAD *thread_ptr NX_CLEANUP_PARAMETER)
{
}
