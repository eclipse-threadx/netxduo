/* 
   netx_sntp_request_unicast_rest.c

   This test tests that the nx_sntp_client_request_unicast_time service sends an asynchronous unicast
   SNTP request independently of the SNTP CLient periodic polling of the SNTP server.  It also verifies
   that the SNTP Client when it receives the server response correctly updates the local clock. 

   Note that for this test to work correctly, the following configuration option must be defined in the 
   preprocessor options:

   #define NX_SNTP_CLIENT_MIN_TIME_ADJUSTMENT          1000
*/

#include "nx_api.h"
#include "nx_ip.h"
#include <stdio.h>
#include "nxd_sntp_client.h"

extern void test_control_return(UINT status);

#if !defined(NX_DISABLE_IPV4)
                 
/* Define SNTP packet size. */
#define NX_SNTP_CLIENT_PACKET_SIZE                 (NX_UDP_PACKET + 100)

/* Define SNTP packet pool size. */
#ifdef __PRODUCT_NETXDUO__
#define NX_SNTP_CLIENT_PACKET_POOL_SIZE            (4 * (NX_SNTP_CLIENT_PACKET_SIZE + sizeof(NX_PACKET) + NX_PACKET_ALIGNMENT))
#else
#define NX_SNTP_CLIENT_PACKET_POOL_SIZE            (4 * (NX_SNTP_CLIENT_PACKET_SIZE + sizeof(NX_PACKET)))
#endif

/* NTP server reply. */
static char pkt_data[90] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x57, 0x00, 0x0c, 
    0x29, 0x1e, 0xaa, 0x4f, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x4c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 
    0xbc, 0xa3, 0xc0, 0xa8, 0x7e, 0x82, 0xc0, 0xa8, 
    0x7e, 0x2a, 0x00, 0x7b, 0x00, 0x7b, 0x00, 0x38,
    /* checksum*/
    0x7f, 0xa0, 
/* start of NTP word */
    /* stratum*//* peer_clock_precision*/
    0x1c, 0x02, 0x00, 0xec, 
                /* root delay*/
    0x00, 0x00, 0x07, 0xdd, 
                /* clock dispersion */
    0x00, 0x00, 0x06, 0x6e, 
    0x89, 0xbd, 0x04, 0x0a, 
    0xd6, 0x4b, 0xd7, 0xeb, 
    0xb3, 0x25, 0xe0, 0x52, 
    0xd2, 0xc9, 0x6b, 0x90, 
    0xa1, 0x32, 0xdb, 0x1e, 
    0xd6, 0x4b, 0xd8, 0x5b, 
    0x20, 0x27, 0x62, 0xa4, 
    /*  seconds */
    0xd6, 0x4b, 0xd8, 0x5b, 
    /*  fraction */
    0x20, 0x2c, 0x4b, 0x46 };

static UINT pkt_size = 90;


static char pkt_data_asynch[90] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x57, 0x00, 0x0c, 
    0x29, 0x1e, 0xaa, 0x4f, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x4c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 
    0xbc, 0xa3, 0xc0, 0xa8, 0x7e, 0x82, 0xc0, 0xa8, 
    0x7e, 0x2a, 0x00, 0x7b, 0x00, 0x7b, 0x00, 0x38,
    /* checksum*/
    0x7f, 0x9f, 
    /* stratum*//* peer_clock_precision*/
    0x1c, 0x02, 0x00, 0xec, 
                /* root delay*/
    0x00, 0x00, 0x07, 0xdd, 
                /* clock dispersion */
    0x00, 0x00, 0x06, 0x6e, 
    0x89, 0xbd, 0x04, 0x0a, 
    0xd6, 0x4b, 0xd7, 0xeb, 
    0xb3, 0x25, 0xe0, 0x52, 
    0xd2, 0xc9, 0x6b, 0x90, 
    0xa1, 0x32, 0xdb, 0x1e, 
    0xd6, 0x4b, 0xd8, 0x5b, 
    0x20, 0x27, 0x62, 0xa4, 
    /*  seconds */
    0xd6, 0x4b, 0xd8, 0x5c, 
    /*  fraction */
    0x20, 0x2c, 0x4b, 0x46 
};

static UINT pkt_size_asynch = 90;


static ULONG expected_seconds_asynch = 0xd64bd85c;
static ULONG expected_milliseconds_asynch = 0x88;
static ULONG tolerance_milliseconds_asynch = 20;

static UINT send_unicast = NX_FALSE;
static UINT asynch_unicast_processed = NX_FALSE;

extern void _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);

/* Set up client thread and network resources. */

static NX_PACKET_POOL      client_packet_pool;
static NX_IP               client_ip;
static TX_THREAD           sntp_client_thread;
static TX_THREAD           sntp_server_thread;
static NX_SNTP_CLIENT      sntp_client;
static NX_SNTP_CLIENT      sntp_server; 

#define CLIENT_IP_ADDRESS       IP_ADDRESS(192,168,126,42)
#define SERVER_IP_ADDRESS       IP_ADDRESS(192,168,126,130)
#define SERVER_IP_ADDRESS_2     SERVER_IP_ADDRESS

/* Set up the SNTP network and address index; */
static UINT     iface_index;

static UINT     error_counter;

/* Set up client thread entry point. */
static void sntp_client_thread_entry(ULONG info);
static void sntp_server_thread_entry(ULONG info);
static void inject_sntp_server_reply(char *pkt_data, UINT size);


/* Define what the initial system looks like.  */
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void netx_sntp_request_unicast_test_application_define(void * first_unused_memory)
#endif
{

UINT     status;
UCHAR    *free_memory_pointer;

    error_counter = 0;

    free_memory_pointer = (UCHAR *)first_unused_memory;

    /* Create client packet pool. */
    status =  nx_packet_pool_create(&client_packet_pool, "SNTP Client Packet Pool",
                                    NX_SNTP_CLIENT_PACKET_SIZE, free_memory_pointer, 
                                    NX_SNTP_CLIENT_PACKET_POOL_SIZE);
    free_memory_pointer =  free_memory_pointer + NX_SNTP_CLIENT_PACKET_POOL_SIZE;

    /* Check for errors. */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Initialize the NetX system. */
    nx_system_initialize();


    /* Create Client IP instances */
    status = nx_ip_create(&client_ip, "SNTP IP Instance", CLIENT_IP_ADDRESS, 
                          0xFFFFFF00UL, &client_packet_pool, _nx_ram_network_driver_1500, 
                          free_memory_pointer, 2048, 1);
    free_memory_pointer =  free_memory_pointer + 2048;
    
    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    /* Enable ARP and supply ARP cache memory. */
    status =  nx_arp_enable(&client_ip, (void **) free_memory_pointer, 2048);
    free_memory_pointer = free_memory_pointer + 2048;

    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    
    /* Enable UDP for client. */
    status =  nx_udp_enable(&client_ip);

    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    status = nx_icmp_enable(&client_ip);

    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;


    /* Create the server thread */
    status = tx_thread_create(&sntp_server_thread, "SNTP Server Thread", sntp_server_thread_entry, 
                              (ULONG)(&sntp_server), free_memory_pointer, 2048, 
                              4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    free_memory_pointer = free_memory_pointer + 2048;

    /* Check for errors */
    if (status != TX_SUCCESS)
        error_counter++;

    /* Create the client thread */
    status = tx_thread_create(&sntp_client_thread, "SNTP Client Thread", sntp_client_thread_entry, 
                              (ULONG)(&sntp_client), free_memory_pointer, 2048, 
                              4, 4, TX_NO_TIME_SLICE, TX_DONT_START);
    free_memory_pointer = free_memory_pointer + 2048;

    /* Check for errors */
    if (status != TX_SUCCESS)
        error_counter++;

    /* set the SNTP network interface to the primary interface. */
    iface_index = 0;

    /* Create the SNTP Client to run in broadcast mode.. */
    status =  nx_sntp_client_create(&sntp_client, &client_ip, iface_index, &client_packet_pool,  
                                    NX_NULL, 
                                    NX_NULL, 
                                    NX_NULL /* no random_number_generator callback */);

    /* Check for error. */
    if (status != NX_SUCCESS)
        error_counter++;

    tx_thread_resume(&sntp_client_thread);

    return;
}

/* Define size of buffer to display client's local time. */
#define BUFSIZE 50

/* Define the client thread.  */
void    sntp_client_thread_entry(ULONG info)
{

UINT   status;
UINT   server_status;
CHAR   buffer[BUFSIZE];
ULONG  base_seconds;
ULONG  base_fraction;
ULONG  seconds, milliseconds, microseconds, fraction;

    printf("NetX Test:   NETX SNTP Client Request Unicast Test.....................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Give other threads (IP instance) a chance to initialize. */
    tx_thread_sleep(100); 

    /* Use the IPv4 service to initialize the Client and set the IPv4 SNTP server. */
    status = nx_sntp_client_initialize_unicast(&sntp_client, SERVER_IP_ADDRESS);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    /* Set the base time which is approximately the number of seconds since the turn of the last century. */
    base_seconds =  0xd2c96b90;  /* Jan 24, 2012 UTC */
    base_fraction = 0xa132db1e;

    /* Apply to the SNTP Client local time.  */
    status = nx_sntp_client_set_local_time(&sntp_client, base_seconds, base_fraction);

    /* Check for error. */
    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_sntp_client_run_unicast(&sntp_client);

    if(status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    inject_sntp_server_reply(&pkt_data[0], pkt_size);
    
    /* Set the 'server' thread to wait for next unicast request. */
    tx_thread_resume(&sntp_server_thread);

    do
    {
    
        /* First verify we have a valid SNTP service running. */
        status = nx_sntp_client_receiving_updates(&sntp_client, &server_status);

        tx_thread_sleep(100);
        
    } while (status != NX_SUCCESS);

    /* Server status is good.   */

    /* Tell the server it's ok to 'respond'to next unicast request. */
    send_unicast = NX_TRUE;

    /* Request a unicast update independently of the SNTP Client thread - wait option 5 seconds. */
    status = nx_sntp_client_request_unicast_time(&sntp_client, 500); 

    if (status == NX_SUCCESS)
    {

        asynch_unicast_processed = NX_TRUE;

        status = nx_sntp_client_get_local_time(&sntp_client, &seconds, &fraction, &buffer[0]);

        /* Convert fraction to microseconds. */
        nx_sntp_client_utility_fraction_to_usecs(fraction, &microseconds);

        milliseconds = ((microseconds + 500) / 1000);

        if (status)
        {
        
            error_counter++;
        }
        else if (
            (seconds != expected_seconds_asynch) || 
            (milliseconds < (expected_milliseconds_asynch - tolerance_milliseconds_asynch)) || 
            (milliseconds > (expected_milliseconds_asynch + tolerance_milliseconds_asynch))
           )
        {
        
            error_counter++;
        }
    }

    nx_sntp_client_stop(&sntp_client);

    nx_sntp_client_delete(&sntp_client);

    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }

    return;
}

/* This should emulate a SNTP server. */
void sntp_server_thread_entry(ULONG info)
{


    /* Wait for next unicast request (should be the asynchronous request). */
    while(!send_unicast)
        tx_thread_sleep(10);

    /* Keep sending till the asynch unicast server message is processed. */
    while(!asynch_unicast_processed)
    {
    
        inject_sntp_server_reply(&pkt_data_asynch[0], pkt_size_asynch);
        tx_thread_sleep(10);
    }
}


void inject_sntp_server_reply(char *pkt_data, UINT size)
{

UINT                    status;
NX_PACKET              *my_packet;

    /* Allocate the packet and let the client IP stack receive it.  */
    status =  nx_packet_allocate(client_ip.nx_ip_default_packet_pool, &my_packet, 0,  500);

    /* Check status.  */
    if (status != NX_SUCCESS)
    {
        error_counter++;
        return;
    }

    /* Load the data simulating the server reply */
    my_packet -> nx_packet_length = size - 14;
    memcpy(my_packet -> nx_packet_prepend_ptr + 16, pkt_data + 14, my_packet -> nx_packet_length);
    my_packet -> nx_packet_append_ptr = my_packet -> nx_packet_prepend_ptr + my_packet -> nx_packet_length;

    my_packet -> nx_packet_prepend_ptr += 16;
    my_packet -> nx_packet_append_ptr += 16;

    /* Send to the Client stack*/
    _nx_ip_packet_deferred_receive(&client_ip, my_packet);

}

#else

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_sntp_request_unicast_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Test:   NETX SNTP Client Request Unicast Test.....................N/A\n"); 

    test_control_return(3);  
}      
#endif

