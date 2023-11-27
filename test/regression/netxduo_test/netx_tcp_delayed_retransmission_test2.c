/* This NetX test concentrates on delayed retransmission TCP packet.  
 * 1. Send packet A.
 * 2. Drop packet A in driver.
 * 4. Retransmit packet A.
 * 5. Copy the data in A and transmit it. Delay packet A for 1 seconds.
 * 6. Wait 2 seconds.
 * 7. Check all packets are released.
 * 8. Check no invalid packet released. */

#include   "nx_api.h"
extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#include   "nx_ram_network_driver_test_1500.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;



/* Define the counters used in the demo application...  */

static ULONG                   error_counter =     0;

static NX_PACKET              *drop_packet;
static NX_PACKET              *duplicate_packet;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_delayed_retransmission_test_2_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =     0;
    drop_packet = NX_NULL;
    duplicate_packet = NX_NULL;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

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

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check ARP enable status.  */
    if (status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
    
}



/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET  *my_packet;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Delayed Retransmission Test 2.........................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;


    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 0x88, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Set driver packet process callback. */
    advanced_packet_process_callback = packet_process;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    if (status)
        error_counter++;

    status = nx_packet_data_append(my_packet, "A", 1, &pool_0, NX_IP_PERIODIC_RATE);
    if(status)
        error_counter++;

    /* Drop the first packet. */
    drop_packet = my_packet;

    /* Send the packet out!  */
    status =  nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE);
    if (status)
    {
        error_counter++;
        nx_packet_release(my_packet);
    }

    /* Wait two seconds. */
    tx_thread_sleep(2 * NX_IP_PERIODIC_RATE);

    /* Verify all packets are released from TX queue. */
    if (client_socket.nx_tcp_socket_tx_outstanding_bytes != 0)
        error_counter++;

    /* Verify pool is full. */
    if (pool_0.nx_packet_pool_available != pool_0.nx_packet_pool_total)
        error_counter++;

#ifndef NX_DISABLE_PACKET_INFO
    /* Verify no packet is released invalid. */
    if (pool_0.nx_packet_pool_invalid_releases != 0)
        error_counter++;
#endif /* NX_DISABLE_PACKET_INFO */

    /* Disconnect this socket.  */
    status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&client_socket);
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&client_socket);
    if (status)
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
    

static void    thread_1_entry(ULONG thread_input)
{

UINT            status;
NX_PACKET      *packet_ptr;
ULONG           actual_status;


    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 65535,
                                   NX_NULL, NX_NULL);
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, NX_NULL);
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Receive a TCP message from the socket.  */
    status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;
    else
    {
        if(memcmp(packet_ptr -> nx_packet_prepend_ptr, "A", 1))
            error_counter++;

        nx_packet_release(packet_ptr);
    }

    /* Disconnect the server socket.  */
    status =  nx_tcp_socket_disconnect(&server_socket, 5 * NX_IP_PERIODIC_RATE);
    if (status)
        error_counter++;

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&server_socket);
    if (status)
        error_counter++;

    /* Unlisten on the server port 12.  */
    status =  nx_tcp_server_socket_unlisten(&ip_1, 12);
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&server_socket);
    if (status)
        error_counter++;

}

static UINT    packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
    if (packet_ptr == drop_packet)
    {

        /* This packet should be dropped. */
        *operation_ptr = NX_RAMDRIVER_OP_DROP;

        if (duplicate_packet == NX_NULL)
        {

            /* Duplicate this packet next time. */
            duplicate_packet = drop_packet;
        }
        drop_packet = NX_NULL;
    }
    else if (packet_ptr == duplicate_packet)
    {

        /* This packet should be duplicated and delayed for 1 second. */
        *operation_ptr = NX_RAMDRIVER_OP_DELAY;
        *delay_ptr = NX_IP_PERIODIC_RATE;

        if (nx_packet_allocate(&pool_0, &duplicate_packet, 16, NX_NO_WAIT) == NX_SUCCESS)
        {

            /* Copy data from original packet. */
            memcpy(duplicate_packet -> nx_packet_prepend_ptr, packet_ptr -> nx_packet_prepend_ptr,
                   packet_ptr -> nx_packet_length);
            duplicate_packet -> nx_packet_length = packet_ptr -> nx_packet_length;
            duplicate_packet -> nx_packet_append_ptr += duplicate_packet -> nx_packet_length;

            /* Let IP 0 receive the packet. */
            _nx_ip_packet_deferred_receive(&ip_1, duplicate_packet);
        }
        else
        {
            error_counter++;
        }

        duplicate_packet = NX_NULL;
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_delayed_retransmission_test_2_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   TCP Delayed Retransmission Test 2.........................N/A\n"); 

    test_control_return(3);  
}      
#endif