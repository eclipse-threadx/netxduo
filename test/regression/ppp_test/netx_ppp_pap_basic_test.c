/* This tests the basic PPP logic with PAP authentication.  */

#include "tx_api.h"
#include "nx_api.h"
#include "nx_ppp.h"
  
extern void         test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)

/* Define demo stack size.   */

#define DEMO_STACK_SIZE     2048
#define DEMO_DATA           "ABCDEFGHIJKLMNOPQRSTUVWXYZ "


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_IP                   ip_1;
static NX_PPP                  ppp_0;
static NX_PPP                  ppp_1;
static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter = 0; 
static UINT                    thread_1_alive = NX_TRUE;
static ULONG                   ppp_0_link_up_counter;
static ULONG                   ppp_0_link_down_counter;
static ULONG                   ppp_1_link_up_counter;
static ULONG                   ppp_1_link_down_counter;

/* Define thread prototypes.  */
static void         thread_0_entry(ULONG thread_input);
static void         thread_1_entry(ULONG thread_input);
static void         ppp_0_serial_byte_output(UCHAR byte);
static void         ppp_1_serial_byte_output(UCHAR byte);
static void         invalid_packet_handler(NX_PACKET *packet_ptr);
static void         link_up_callback(NX_PPP *ppp_ptr);
static void         link_down_callback(NX_PPP *ppp_ptr);
static UINT         generate_login(CHAR *name, CHAR *password);
static UINT         verify_login(CHAR *name, CHAR *password);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_pap_basic_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the thread 0.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;
                   
    /* Create the thread 1.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 2 * NX_PPP_MIN_PACKET_PAYLOAD, pointer, 2048);
    pointer = pointer + 2048;

    /* Check for pool creation error.  */
    if (status)
    {
        error_counter++;
    }

    /* Create the first PPP instance.  */
    status =  nx_ppp_create(&ppp_0, "PPP 0", &ip_0, pointer, 2048, 1, &pool_0, invalid_packet_handler, ppp_0_serial_byte_output);
    pointer =  pointer + 2048;

    /* Check for PPP create error.   */
    if (status)
    {
        error_counter++;
    }

    /* Define IP address. This PPP instance is effectively the server since it has both IP addresses. */
    status =  nx_ppp_ip_address_assign(&ppp_0, IP_ADDRESS(1, 2, 3, 4), IP_ADDRESS(1, 2, 3, 5));
    
    /* Check for PPP IP address assign error.   */
    if (status)
    {
        error_counter++;
    }

    /* Register the link up/down callbacks.  */
    status =  nx_ppp_link_up_notify(&ppp_0, link_up_callback);
    status += nx_ppp_link_down_notify(&ppp_0, link_down_callback);

    /* Check for PPP link up/down callback registration error(s).   */
    if (status)
    {
        error_counter++;
    }

    /* Setup PAP, this PPP instance is effectively the server since it will verify the name and password.  */
    status =  nx_ppp_pap_enable(&ppp_0, NX_NULL, verify_login);

    /* Check for PPP PAP enable error.  */
    if (status)
    {
        error_counter++;
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(0, 0, 0, 0), 0xFFFFF000UL, &pool_0, nx_ppp_driver,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create error.   */
    if (status)
    {
        error_counter++;
    }

    /* Create the next PPP instance.  */
    status =  nx_ppp_create(&ppp_1, "PPP 1", &ip_1, pointer, 2048, 1, &pool_0, invalid_packet_handler, ppp_1_serial_byte_output);
    pointer =  pointer + 2048;

    /* Check for PPP create error.   */
    if (status)
    {
        error_counter++;
    }

    /* Define IP address. This PPP instance is effectively the client since it doesn't have any IP addresses. */
    status =  nx_ppp_ip_address_assign(&ppp_1, IP_ADDRESS(0, 0, 0, 0), IP_ADDRESS(0, 0, 0, 0));

    /* Check for PPP IP address assign error.   */
    if (status)
    {
        error_counter++;
    }

    /* Register the link up/down callbacks.  */
    status =  nx_ppp_link_up_notify(&ppp_1, link_up_callback);
    status += nx_ppp_link_down_notify(&ppp_1, link_down_callback);

    /* Check for PPP link up/down callback registration error(s).   */
    if (status)
    {
        error_counter++;
    }

    /* Setup PAP, this PPP instance is effectively the since it generates the name and password for the peer.  */
    status =  nx_ppp_pap_enable(&ppp_1, generate_login, NX_NULL);

    /* Check for PPP PAP enable error.  */
    if (status)
    {
        error_counter++;
    }

    /* Create another IP instance.  */
    status = nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(0, 0, 0, 0), 0xFFFFF000UL, &pool_0, nx_ppp_driver,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create error.   */
    if (status)
    {
        error_counter++;
    }

    /* Enable UDP traffic.  */
    status = nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);
    if (status)
    {
        error_counter++;
    }
}


/* Define the test threads.  */

void    thread_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_status;
NX_PACKET   *my_packet;


    printf("NetX Test:   PPP PAP Basic Test........................................");

    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for the link to come up.  */
    do
    {
    
        status =  nx_ip_status_check(&ip_0, NX_IP_LINK_ENABLED, &ip_status, 20 * NX_IP_PERIODIC_RATE);
    }while(status != NX_SUCCESS);
  
    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        error_counter++;
    }

    /* Disable checksum logic for this socket.  */
    nx_udp_socket_checksum_disable(&socket_0);

    /* Let receiver thread run.  */
    tx_thread_relinquish();

    /* Allocate a packet.  */
    status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Write ABCs into the packet payload!  */
    nx_packet_data_append(my_packet, DEMO_DATA, sizeof(DEMO_DATA), &pool_0, NX_WAIT_FOREVER);

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }

    /* Relinquish to thread 1.  */
    tx_thread_relinquish();

    /* Wait for the other thread to finish. */
    while(thread_1_alive)
    {
        tx_thread_sleep(1 * NX_IP_PERIODIC_RATE);
    }

    /* Receive a UDP packet.  */
    status =  nx_udp_socket_receive(&socket_0, &my_packet, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
    }
    else
    {

        /* Check the echo data.  */
        if (memcmp(my_packet -> nx_packet_prepend_ptr, DEMO_DATA, sizeof(DEMO_DATA)) != 0)
        {
            error_counter++;
        }

        /* Release the packet.  */
        status =  nx_packet_release(my_packet);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
        }
    }

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

void    thread_1_entry(ULONG thread_input)
{

UINT        status;
ULONG       ip_status;
NX_PACKET   *my_packet;


    /* Wait for the link to come up.  */
    do
    {
    
        status =  nx_ip_status_check(&ip_1, NX_IP_LINK_ENABLED, &ip_status, 20 * NX_IP_PERIODIC_RATE);
    }while(status != NX_SUCCESS);

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        thread_1_alive = NX_FALSE;
        return;
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, 0x89, NX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        thread_1_alive = NX_FALSE;
        return;
    }

    /* Receive a UDP packet.  */
    status =  nx_udp_socket_receive(&socket_1, &my_packet, 5 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        thread_1_alive = NX_FALSE;
        return;
    }

    /* Send the UDP packet.  */
    status =  nx_udp_socket_send(&socket_1, my_packet, IP_ADDRESS(1, 2, 3, 4), 0x88);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;

        /* Release the packet.  */
        status =  nx_packet_release(my_packet);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            thread_1_alive = NX_FALSE;
            return;
        }
    }

    thread_1_alive = NX_FALSE;

    return;

}

/* Define serial output routines.  Normally these routines would
   map to physical UART routines and the nx_ppp_byte_receive call
   would be made from a UART receive interrupt.  */

static void    ppp_0_serial_byte_output(UCHAR byte)
{

    /* Just feed the PPP 1 input routine.  */
    nx_ppp_byte_receive(&ppp_1, byte);
}

static void    ppp_1_serial_byte_output(UCHAR byte)
{

    /* Just feed the PPP 0 input routine.  */
    nx_ppp_byte_receive(&ppp_0, byte);
}

static void invalid_packet_handler(NX_PACKET *packet_ptr)
{
    /* Print out the non-PPP byte. In Windows, the string "CLIENT" will
       be sent before Windows PPP starts. Once CLIENT is received, we need
       to send "CLIENTSERVER" to establish communication. It's also possible
       to receive modem commands here that might need some response to 
       continue.  */
    nx_packet_release(packet_ptr);
}

static void link_up_callback(NX_PPP *ppp_ptr)
{

    /* Just increment the link up counter.  */
    if (ppp_ptr == &ppp_0)
        ppp_0_link_up_counter++;
    else
        ppp_1_link_up_counter++;
}

static void link_down_callback(NX_PPP *ppp_ptr)
{

    /* Just increment the link down counter.  */
    if (ppp_ptr == &ppp_0)
        ppp_0_link_down_counter++;
    else
        ppp_1_link_down_counter++;

    /* Restart the PPP instance.  */
    nx_ppp_restart(ppp_ptr);
}

static UINT generate_login(CHAR *name, CHAR *password)
{

    /* Make a name and password, called "myname" and "mypassword".  */
    name[0] = 'm';
    name[1] = 'y';
    name[2] = 'n';
    name[3] = 'a';
    name[4] = 'm';
    name[5] = 'e';
    name[6] = (CHAR) 0;
    
    password[0] = 'm';
    password[1] = 'y';
    password[2] = 'p';
    password[3] = 'a';
    password[4] = 's';
    password[5] = 's';
    password[6] = 'w';
    password[7] = 'o';
    password[8] = 'r';
    password[9] = 'd';
    password[10] = (CHAR) 0;

    return(NX_SUCCESS);
}

static UINT verify_login(CHAR *name, CHAR *password)
{

if ((name[0] == 'm') &&
    (name[1] == 'y') &&
    (name[2] == 'n') &&
    (name[3] == 'a') &&
    (name[4] == 'm') &&
    (name[5] == 'e') &&
    (name[6] == (CHAR) 0) &&
    (password[0] == 'm') &&
    (password[1] == 'y') &&
    (password[2] == 'p') &&
    (password[3] == 'a') &&
    (password[4] == 's') &&
    (password[5] == 's') &&
    (password[6] == 'w') &&
    (password[7] == 'o') &&
    (password[8] == 'r') &&
    (password[9] == 'd') &&
    (password[10] == (CHAR) 0))
        return(NX_SUCCESS);
   else
        return(NX_PPP_ERROR);
}
#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_ppp_pap_basic_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   PPP PAP Basic Test........................................N/A\n"); 

    test_control_return(3);  
}      
#endif

