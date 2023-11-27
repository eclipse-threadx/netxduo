/* This case tests advanced packet process callback feature for ramdriver. */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_udp.h"
#include   "nx_ram_network_driver_test_1500.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE    2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_UDP_SOCKET           client_socket;
static NX_UDP_SOCKET           server_socket;
static NX_PACKET               *send_packet, *recv_packet;

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static UINT                    driver_op;
static UINT                    driver_delay;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    advanced_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_netx_ramdriver_callback_application_define(void *first_unused_memory)
#endif
{

UCHAR       *pointer;
UINT        status;

    /* Setup the working pointer.  */
    pointer = (UCHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 2);
    pointer = pointer + 2048;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status = nx_arp_enable(&ip_1, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT       status;
CHAR       msg[20];


    printf("NetX Test:   RAMDriver callback test...................................");

    /* Create client socket.  */
    status = nx_udp_socket_create(&ip_0, &client_socket, "Client Socket",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Bind the socket.  */
    status +=  nx_udp_socket_bind(&client_socket, 0x88, TX_WAIT_FOREVER);

    /* Create server socket.  */
    status += nx_udp_socket_create(&ip_1, &server_socket, "Server Socket",
                                  NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Bind the socket.  */
    status +=  nx_udp_socket_bind(&server_socket, 0x88, TX_WAIT_FOREVER);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Setup advanced callback function. */
    advanced_packet_process_callback = advanced_packet_process;


    /* Test delay feature. */
    driver_op = NX_RAMDRIVER_OP_DELAY;
    driver_delay = 4 * NX_IP_PERIODIC_RATE;

    /* Create a packet.  */
    status = nx_packet_allocate(&pool_0, &send_packet, NX_UDP_PACKET, NX_IP_PERIODIC_RATE);
    
    /* Set message for delayed packet. */
    memcpy(msg, "1234567890", 10);

    /* Fill in the packet with data.     */
    status += nx_packet_data_append(send_packet, msg, 10, &pool_0, NX_NO_WAIT);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Send the packet out!  */
    status = nx_udp_socket_send(&client_socket, send_packet, IP_ADDRESS(1, 2, 3, 5), 0x88);

    /* Check status.  */
    if(status)
    {
        error_counter++;
        nx_packet_release(send_packet);
    }

    /* Try to receive on server socket. */
    status = nx_udp_socket_receive(&server_socket, &recv_packet, driver_delay / 2);

    /* No packet should be received. */
    if(status != NX_NO_PACKET)
    {
        error_counter++;
        if(status == NX_SUCCESS)
            nx_packet_release(recv_packet);
    }

    /* Try to receive on server socket. */
    status = nx_udp_socket_receive(&server_socket, &recv_packet, (driver_delay / 2 + 1 * NX_IP_PERIODIC_RATE));

    /* The packet should be received. */
    if(status)
        error_counter++;
    else
    {

        /* Check packet data. */
        if(memcmp(msg, recv_packet -> nx_packet_prepend_ptr, 10))
            error_counter++;

        /* Release the packet */
        status = nx_packet_release(recv_packet);

        /* Check for error.  */
        if(status)
            error_counter++;
    }


    /* Test drop feature. */
    driver_op = NX_RAMDRIVER_OP_DROP;

    /* Create a packet.  */
    status = nx_packet_allocate(&pool_0, &send_packet, NX_UDP_PACKET, NX_IP_PERIODIC_RATE);
    
    /* Set message for dropped packet. */
    memcpy(msg, "abcdefghij", 10);

    /* Fill in the packet with data.     */
    status += nx_packet_data_append(send_packet, msg, 10, &pool_0, NX_NO_WAIT);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Send the packet out!  */
    status = nx_udp_socket_send(&client_socket, send_packet, IP_ADDRESS(1, 2, 3, 5), 0x88);

    /* Check status.  */
    if(status)
    {
        error_counter++;
        nx_packet_release(send_packet);
    }

    /* Try to receive on server socket. */
    status = nx_udp_socket_receive(&server_socket, &recv_packet, 5 * NX_IP_PERIODIC_RATE);

    /* No packet should be received. */
    if(status != NX_NO_PACKET)
    {
        error_counter++;
        if(status == NX_SUCCESS)
            nx_packet_release(recv_packet);
    }

     
    /* Test duplicate feature. */
    driver_op = NX_RAMDRIVER_OP_DUPLICATE;

    /* Create a packet.  */
    status = nx_packet_allocate(&pool_0, &send_packet, NX_UDP_PACKET, NX_IP_PERIODIC_RATE);
    
    /* Set message for duplicated packet. */
    memcpy(msg, "ABCDEFGHIJ", 10);

    /* Fill in the packet with data.     */
    status += nx_packet_data_append(send_packet, msg, 10, &pool_0, NX_NO_WAIT);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Send the packet out!  */
    status = nx_udp_socket_send(&client_socket, send_packet, IP_ADDRESS(1, 2, 3, 5), 0x88);

    /* Check status.  */
    if(status)
    {
        error_counter++;
        nx_packet_release(send_packet);
    }

    /* Try to receive on server socket. */
    status = nx_udp_socket_receive(&server_socket, &recv_packet, 5 * NX_IP_PERIODIC_RATE);

    /* The original packet received. */
    if(status)
        error_counter++;
    else
    {

        /* Check packet data. */
        if(memcmp(msg, recv_packet -> nx_packet_prepend_ptr, 10))
            error_counter++;

        /* Release the packet */
        status = nx_packet_release(recv_packet);

        /* Check for error.  */
        if(status)
            error_counter++;
    }

    /* Try to receive on server socket. */
    status = nx_udp_socket_receive(&server_socket, &recv_packet, 5 * NX_IP_PERIODIC_RATE);

    /* The duplicated packet received. */
    if(status)
        error_counter++;
    else
    {

        /* Check packet data. */
        if(memcmp(msg, recv_packet -> nx_packet_prepend_ptr, 10))
            error_counter++;

        /* Release the packet */
        status = nx_packet_release(recv_packet);

        /* Check for error.  */
        if(status)
            error_counter++;
    }

    /* Cleanup */
    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&client_socket);
    status +=  nx_udp_socket_unbind(&server_socket);

    /* Delete the UDP socket.  */
    status +=  nx_udp_socket_delete(&client_socket);
    status +=  nx_udp_socket_delete(&server_socket);
    
    /* Check for error.  */
    if(status)
        error_counter++;


    /* Clean advanced callback function. */
    advanced_packet_process_callback = NX_NULL;

    /* Determine if the test was successful.  */
    if((error_counter))
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

static UINT    advanced_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
    if(packet_ptr == send_packet)
    {
        *operation_ptr = driver_op;
        *delay_ptr = driver_delay;
    }

    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_netx_ramdriver_callback_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   RAMDriver callback test...................................N/A\n"); 

    test_control_return(3);  
}      
#endif