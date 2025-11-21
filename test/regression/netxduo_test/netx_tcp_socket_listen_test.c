/* This NetX test concentrates on the TCP Socket unaccept operation.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
                                        

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           server_socket[NX_MAX_LISTEN_REQUESTS + 1]; 


/* Define the counters used in the demo application...  */

static ULONG                   error_counter = 0;          


/* Define thread prototypes.  */

static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);  
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);    


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_tcp_socket_listen_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;
UINT    status;

                     
    error_counter =     0;

    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;   

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
                                       
    /* Enable TCP processing for IP instance.  */
    status =  nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if (status)
        error_counter++;
}              


/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

UINT        status;  
UINT        i;
UINT        server_port;

    /* Print out some test information banners.  */
    printf("NetX Test:   TCP Socket Listen Test....................................");

    /* Check for earlier error.  */
    if (error_counter)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
                  
    /* Initialize the server port.  */
    server_port = 80;

    /* Loop to create the server socket.  */
    for (i = 0; i < NX_MAX_LISTEN_REQUESTS; i++, server_port++)
    {

        /* Create a socket.  */
        status =  nx_tcp_socket_create(&ip_0, &server_socket[i], "Server Socket", 
                                       NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                       NX_NULL, NX_NULL);

        /* Check for error.  */
        if (status)            
        {

            printf("ERROR!\n");
            test_control_return(1);
        }   

        /* Setup this thread to listen.  */
        status =  nx_tcp_server_socket_listen(&ip_0, server_port, &server_socket[i], 5, NX_NULL);

        /* Check for error.  */
        if (status)             
        {

            printf("ERROR!\n");
            test_control_return(1);
        }
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_0, &server_socket[i], "Server Socket", 
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                   NX_NULL, NX_NULL);

    /* Check for error.  */
    if (status)            
    {

        printf("ERROR!\n");
        test_control_return(1);
    }   

    /* Setup this socket to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_0, server_port, &server_socket[i], 5, NX_NULL);

    /* Check for error.  */
    if (status != NX_MAX_LISTEN)             
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Output successful.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}
    