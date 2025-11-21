/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;
static TX_THREAD               thread_1;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0; 

static NX_UDP_SOCKET           socket_0;
static NX_UDP_SOCKET           socket_1;
static NX_UDP_SOCKET           socket_2;


/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
static void    thread_1_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);

extern void  test_control_return(UINT status);
/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_udp_bind_cleanup_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    error_counter =  0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;    

    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;    

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 2048);
    pointer = pointer + 2048;

    /* Check for pool creation error.  */
    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;      
                                 
    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);   

    /* Check for UDP enable errors.  */
    if (status)
        error_counter++;
}             


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;
UINT        free_port;


    /* Print out some test information banners.  */
    printf("NetX Test:   UDP Bind Cleanup Test.....................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)   
        error_counter++;
          
    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)          
        error_counter++;

    /* Pickup the first free port for 0x88.  */
    status =  nx_udp_free_port_find(&ip_0, 0x88, &free_port);

    /* Check status.  */
    if ((status) || (free_port != 0x88))  
        error_counter++;

    /* Bind the UDP socket 0 to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, 2 * NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)      
        error_counter++;

    /* Bind the UDP socket 1 to the same IP port to trigger the udp_bind_cleanup. */
    status =  nx_udp_socket_bind(&socket_1, 0x88, 250);

    /* Check status.  */
    if (!status)    
        error_counter++;       

    /* Unbind the UDP socket.  */
    status =  nx_udp_socket_unbind(&socket_0);

    /* Check status.  */
    if (status)  
        error_counter++;
           
    /* Unbind the UDP socket 1.  */
    status =  nx_udp_socket_unbind(&socket_1);

    /* Check status.  */
    if (status != NX_NOT_BOUND)     
        error_counter++;

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_0);

    /* Check status.  */
    if (status)   
        error_counter++;

    /* Delete the UDP socket.  */
    status =  nx_udp_socket_delete(&socket_1);

    /* Check status.  */
    if ((status) || (error_counter))
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
UINT    status;

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_2, "Socket 2", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);
    if(status != NX_SUCCESS)
        error_counter++;

    /* Bind the UDP socket 1 to the same IP port to trigger the udp_bind_cleanup. */
    status =  nx_udp_socket_bind(&socket_2, 0x88, 2 * NX_IP_PERIODIC_RATE);
    if(status == NX_SUCCESS)
        error_counter++;

    status = nx_udp_socket_unbind(&socket_2);
    if(status != NX_NOT_BOUND)
        error_counter++;

    status = nx_udp_socket_delete(&socket_2);
    if(status != NX_SUCCESS)
        error_counter++;

}
