/* This NetX test concentrates on the basic UDP operation.  */


#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_udp.h"
#include "tx_mutex.h"
#include   "nxd_dns.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)
#define validate_expected_status(status,expected_status) if (expected_status != status) {printf("%s,%d: ERROR!",__FILE__, __LINE__);test_control_return(1);}

#define     DEMO_STACK_SIZE         2048


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               client_thread;
static NX_IP                   client_ip;
static NX_DNS                  client_dns;
static NX_PACKET_POOL          pool_0;
#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL   
NX_PACKET_POOL                 client_pool;
#endif
static TX_MUTEX               *mutex_ptr;

#define DNS_SERVER_ADDRESS     IP_ADDRESS(10,0,0,1)  

static CHAR                   *pointer;
static UINT                    status;
static ULONG                   error_counter = 0;

/* Define thread prototypes.  */

static void    client_thread_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_512(struct NX_IP_DRIVER_STRUCT *driver_req);

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dns_coverage_test_application_define(void *first_unused_memory)
#endif
{

    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    
    /* Create the DNS main thread.  */
    tx_thread_create(&client_thread, "client thread", client_thread_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1500, pointer, 8192);
    pointer = pointer + 8192;

    /* Create an IP instance.  */
    nx_ip_create(&client_ip, "NetX IP Instance 0", IP_ADDRESS(10, 0, 0, 10), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_512,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable UDP traffic.  */
    nx_udp_enable(&client_ip);
}



/* Define the test thread.  */
static void    client_thread_entry(ULONG thread_input)
{
    
#ifdef NX_DNS_CLIENT_USER_CREATE_PACKET_POOL
    /* creates a packet pool that has payloads that are too small.  */
    status = nx_packet_pool_create(&client_pool, "DNS Client Packet Pool", 1, pointer, NX_DNS_PACKET_POOL_SIZE - 1);
    pointer = pointer + NX_DNS_PACKET_POOL_SIZE;
    if (status)
    {
        error_counter++;
    }

    status = nx_dns_packet_pool_set(&client_dns, &client_pool);
    if (status != NX_DNS_PARAM_ERROR)
    {
        error_counter++;
    }
#endif

#ifndef NX_DISABLE_ERROR_CHECKING
    /*  Force mutex create to fail. */
    mutex_ptr = _tx_mutex_created_ptr;
    _tx_mutex_created_ptr = &client_dns.nx_dns_mutex;
    _tx_mutex_created_count++;

    /* Attempt to create the DNS instance.  */
    status = nx_dns_create(&client_dns, &client_ip, (UCHAR *)"DNS Client");
    if (status != TX_MUTEX_ERROR)
    {
        error_counter++;
    }

    /* Restore mutex. */
    _tx_mutex_created_ptr = mutex_ptr;
    _tx_mutex_created_count--;
#endif

    /* Check the error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_dns_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   DNS Coverage Test.........................................N/A\n"); 

    test_control_return(3);  
}      
#endif