/* This NetX test concentrates on the ARP Gratuitous operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_arp.h"

extern void  test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;
static TX_THREAD               ntest_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_TCP_SOCKET           client_socket;
static NX_TCP_SOCKET           server_socket;



/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static ULONG                   announce_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
static void    ntest_1_entry(ULONG thread_input);
static void    ntest_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
static void    ntest_1_disconnect_received(NX_TCP_SOCKET *server_socket);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*advanced_packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);
static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_gratuitous_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;
    announce_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Create the main thread.  */
    tx_thread_create(&ntest_1, "thread 1", ntest_1_entry, 0,  
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

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}



/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
NX_PACKET   *my_packet;
ULONG       ip_address;
ULONG       physical_msw;
ULONG       physical_lsw;
ULONG       requests_sent;
ULONG       requests_received;
ULONG       responses_sent;
ULONG       responses_received;
ULONG       dynamic_entries;
ULONG       static_entries;
ULONG       aged_entries;
ULONG       invalid_messages;


    /* Print out some test information banners.  */
    printf("NetX Test:   ARP Gratuitous Entry Processing Test......................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set a dynamic ARP entry.  */
    status =  nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0x0011, 0x22334457);
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Find the IP address.  */
    status = nx_arp_ip_address_find(&ip_0, &ip_address, 0x0011, 0x22334457);
    if ((status) || (ip_address != IP_ADDRESS(1, 2, 3, 5)))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Find the hardware address.  */
    status = nx_arp_hardware_address_find(&ip_0, IP_ADDRESS(1, 2, 3, 5), &physical_msw, &physical_lsw);
    if ((status) || (physical_msw != 0x0011) || (physical_lsw != 0x22334457))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the ARP packet.  */
    advanced_packet_process_callback = my_packet_process;

    /* Send a gratuitous ARP message.  */
    status =  nx_arp_gratuitous_send(&ip_0, NX_NULL);
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the ARP packet.  */
    advanced_packet_process_callback = NX_NULL;
    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                NX_NULL, NX_NULL);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Attempt to connect the socket.  */
    status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, 2 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, "ABCDEFGHIJKLMNOPQRSTUVWXYZ  ", 28);

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  28;
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + 28;

    /* Send the packet out!  */
    status =  nx_tcp_socket_send(&client_socket, my_packet, 5 * NX_IP_PERIODIC_RATE);

    /* Determine if the status is valid.  */
    if (status)
    {
        error_counter++;
        nx_packet_release(my_packet);
    }

    /* Disconnect this socket.  */
    status =  nx_tcp_socket_disconnect(&client_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Determine if the status is valid.  */
    if (status)
        error_counter++;

    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Get ARP information.  */
    status =  nx_arp_info_get(&ip_0, &requests_sent, &requests_received, &responses_sent, &responses_received, &dynamic_entries, &static_entries, &aged_entries, &invalid_messages);

    /* Check for error conditions - and look for the ARP message being sent!  */
    if ((status) || (requests_received)|| (responses_sent) || (responses_received) || (dynamic_entries != 1) || (static_entries) || (aged_entries) || (invalid_messages))
        error_counter++;
#ifndef NX_DISABLE_ARP_INFO
    if(requests_sent != 1)
        error_counter++;
#endif

    /* Check announce_counter. */
    if (announce_counter == 0)
        error_counter++;

    /* Determine if the test was successful.  */
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
    

static void    ntest_1_entry(ULONG thread_input)
{

UINT            status;
NX_PACKET       *packet_ptr;
ULONG           actual_status;


    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set a dynamic ARP entry.  */
    status =  nx_arp_dynamic_entry_set(&ip_1, IP_ADDRESS(1, 2, 3, 4), 0x0011, 0x22334456);
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket", 
                                NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                NX_NULL, ntest_1_disconnect_received);
                                
    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, ntest_1_connect_received);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Accept a client socket connection.  */
    status =  nx_tcp_server_socket_accept(&server_socket, 200 /* 100 */);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Receive a TCP message from the socket.  */
    status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if ((status) || (packet_ptr -> nx_packet_length != 28))
        error_counter++;
    else
        /* Release the packet.  */
        nx_packet_release(packet_ptr);
        
    /* Disconnect the server socket.  */
    status =  nx_tcp_socket_disconnect(&server_socket, 5 * NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Unaccept the server socket.  */
    status =  nx_tcp_server_socket_unaccept(&server_socket);

    /* Check for error.  */
    if (status)
        error_counter++;

    /* Setup server socket for listening again.  */
    status =  nx_tcp_server_socket_relisten(&ip_1, 12, &server_socket);

    /* Check for error.  */
    if (status)
        error_counter++;
}


static void  ntest_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if ((socket_ptr != &server_socket) || (port != 12))
        error_counter++;
}


static void  ntest_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if (socket != &server_socket)
        error_counter++;
}

static UINT    my_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT *operation_ptr, UINT *delay_ptr)
{
ULONG         *message_ptr;
ULONG         sender_physical_msw;
ULONG         sender_physical_lsw;
ULONG         sender_ip_address;
ULONG         target_physical_msw;
ULONG         target_physical_lsw;
ULONG         target_ip_address;
ULONG         message_type;

    /* Check the packet length.  */
    if (packet_ptr ->nx_packet_length != NX_ARP_MESSAGE_SIZE)
    {

        /* Update the error_counter.  */
        error_counter++;

        /* Release the packet  */
        nx_packet_release(packet_ptr);

        /* Return to caller.  */
        return NX_FALSE;
    }

    /* Setup a pointer to the ARP message.  */
    message_ptr =  (ULONG *) packet_ptr -> nx_packet_prepend_ptr;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+1));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+2));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+3));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+4));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+5));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+6));

    /* Pickup the ARP message type.  */
    message_type =  (ULONG) (*(message_ptr+1) & 0xFFFF);

    /* Determine if the ARP message type is valid.  */
    if (message_type != NX_ARP_OPTION_REQUEST)
    {

        /* Update the error_counter.  */
        error_counter++;
                      
        /* Release the packet  */
        nx_packet_release(packet_ptr);

        /* Return to caller.  */
        return NX_FALSE;
    }


    /* Pick up the sender's physical address from the message.  */
    sender_physical_msw =  (*(message_ptr+2) >> 16);
    sender_physical_lsw =  (*(message_ptr+2) << 16) | (*(message_ptr+3) >> 16);
    sender_ip_address =    (*(message_ptr+3) << 16) | (*(message_ptr+4) >> 16);
    target_physical_msw =  (*(message_ptr+4) & 0x0000FFFF);
    target_physical_lsw =  *(message_ptr+5);
    target_ip_address =    *(message_ptr+6);

    /* Check the sender and target information.  */
    if (((sender_physical_msw | sender_physical_lsw) != 0) && (sender_ip_address != 0) &&
        ((target_physical_msw | target_physical_lsw) == 0) && (target_ip_address != 0))
        announce_counter ++;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the ARP message.  */
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+1));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+2));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+3));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+4));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+5));
    NX_CHANGE_ULONG_ENDIAN(*(message_ptr+6));

    /* Return to caller.  */
    return NX_TRUE;
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_arp_gratuitous_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   ARP Gratuitous Entry Processing Test......................N/A\n"); 

    test_control_return(3);  
}      
#endif
