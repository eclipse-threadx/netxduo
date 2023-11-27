/* This NetX test concentrates on the fast disconnect TCP operation.  */

#include   "tx_api.h"
#include   "nx_api.h"

#define     DEMO_STACK_SIZE         2048
                                            
/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;   
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           client_socket;   


/* Define the counters used in the demo application...  */   
static ULONG                   error_counter =     0;


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_client_socket_port_get_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

    
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

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}             


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;    
UINT        client_port;
UINT        compare_port;


    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Client Socket Port Get Test...........................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                  

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)             
    {

        printf("ERROR!\n");
        test_control_return(1);
    }                    
                     
    /* Pickup the port for the client socket before port bind.  */
    status =  nx_tcp_client_socket_port_get(&client_socket, &compare_port);

    /* Check for error.  */
    if (status != NX_NOT_BOUND)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Get a free port for the client's use.  */
    status =  nx_tcp_free_port_find(&ip_0, 1, &client_port);

    /* Check for error.  */
    if (status)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Bind the socket.  */
    status =  nx_tcp_client_socket_bind(&client_socket, client_port, NX_WAIT_FOREVER);

    /* Check for error.  */
    if (status)            
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Pickup the port for the client socket.  */
    status =  nx_tcp_client_socket_port_get(&client_socket, &compare_port);

    /* Check for error.  */
    if ((status) || (client_port != compare_port))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Unbind the socket.  */
    status =  nx_tcp_client_socket_unbind(&client_socket);

    /* Check for error.  */
    if (status)            
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete the socket.  */
    status =  nx_tcp_socket_delete(&client_socket);

    /* Check for error.  */
    if (status)                
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}