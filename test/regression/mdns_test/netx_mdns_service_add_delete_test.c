#include   "tx_api.h"
#include   "nx_api.h"
#include   <time.h>    
extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_MDNS_DISABLE_SERVER && !defined NX_DISABLE_IPV4
#include   "nxd_mdns.h"

#define     DEMO_STACK_SIZE    2048
#define     BUFFER_SIZE        10240
#define     LOCAL_FULL_SERVICE_COUNT    16
#define     PEER_FULL_SERVICE_COUNT     16
#define     PEER_PARTIAL_SERVICE_COUNT  32

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the NetX MDNS object control blocks.  */

static NX_MDNS                 mdns_0;
static UCHAR                   buffer[BUFFER_SIZE];
static ULONG                   current_buffer_size;
static UCHAR                   mdns_stack[DEMO_STACK_SIZE];

/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_service_add_delete_test(void *first_unused_memory)
#endif
{

UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;
    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 512, pointer, 8192);
    pointer = pointer + 8192;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, 
                          _nx_ram_network_driver, pointer, 2048, 1);
    pointer = pointer + 2048;

    if(status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);

    /* Check UDP enable status.  */
    if(status)
        error_counter++;

    status = nx_igmp_enable(&ip_0);

    /* Check status. */
    if(status)
        error_counter++;
    
    /* Create the test thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, (ULONG)(pointer + DEMO_STACK_SIZE),  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
CHAR      *pointer = (CHAR*)thread_input;

    printf("NetX Test:   MDNS Service Add And Delete Test..........................");

    /* Initialize random. */
    srand((UINT)time(0));

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set pointer. */
    pointer = (CHAR*)thread_input;
    
    /* Initialize the buffer. */
    current_buffer_size = BUFFER_SIZE >> 1;
    memset(buffer, 0xFF, BUFFER_SIZE);

    /* Create a MDNS instance.  */
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, "NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);
    pointer += DEMO_STACK_SIZE;

    /* Check status. */
    if(status)
        error_counter++;
    
    /*********************************************************/
    /* Delete the service when the MDNS function is disable. */
    /*********************************************************/
    
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST1", (UCHAR *)"_ipp._tcp", NX_NULL, "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0); 

    if(status)
        error_counter++;
    
    /* Add duplicate service. */
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST1", (UCHAR *)"_ipp._tcp", NX_NULL, "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0); 

    if(status == NX_SUCCESS)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 5)
        error_counter++;
    
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST2", (UCHAR *)"_ipp._tcp", "_http", "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0);  

    if(status)
        error_counter++;
    
    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 10)
        error_counter++;
    
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST3", (UCHAR *)"_http._tcp", NX_NULL, "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 15)
        error_counter++;
    
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST4", (UCHAR *)"_smb._tcp", NX_NULL, "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 20)
        error_counter++;
    
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST5", (UCHAR *)"_smb._tcp", NX_NULL, "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 24)
        error_counter++;
    
    /* Delete the service when the MDNS function is disable.  */
    status = nx_mdns_service_delete(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST1", (UCHAR *)"_ipp._tcp", NX_NULL);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 20)
        error_counter++;
    
    status = nx_mdns_service_delete(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST2", (UCHAR *)"_ipp._tcp", NX_NULL);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 14)
        error_counter++;
    
    status = nx_mdns_service_delete(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST3", (UCHAR *)"_http._tcp", NX_NULL);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 9)
        error_counter++;
    
    status = nx_mdns_service_delete(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST4", (UCHAR *)"_smb._tcp", NX_NULL);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 5)
        error_counter++;
    
    status = nx_mdns_service_delete(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST5", (UCHAR *)"_smb._tcp", NX_NULL);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 0)
        error_counter++;


    /*********************************************************/
    /* Delete the service when the MDNS function is enable.  */
    /*********************************************************/

    /* Enable the MDNS function.  */    
    nx_mdns_enable(&mdns_0, 0);

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 2)
        error_counter++;

    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST1", (UCHAR *)"_ipp._tcp", NX_NULL, "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0); 

    if(status)
        error_counter++;
        
    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 7)
        error_counter++;

    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST2", (UCHAR *)"_ipp._tcp", "_http", "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 12)
        error_counter++;
    
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST3", (UCHAR *)"_http._tcp", NX_NULL, "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0);

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 17)
        error_counter++;
    
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST4", (UCHAR *)"_smb._tcp", NX_NULL, "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 22)
        error_counter++;
    
    status = nx_mdns_service_add(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST5", (UCHAR *)"_smb._tcp", NX_NULL, "paper=A4;version=01", 120, 0, 0, 8080,  NX_MDNS_RR_SET_UNIQUE, 0);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 26)
        error_counter++;
    
    /* Delete the service when the MDNS function is enable.  */
    status = nx_mdns_service_delete(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST1", (UCHAR *)"_ipp._tcp", NX_NULL);  

    if(status)
        error_counter++;
    
    /* Wait for sending the goodbye.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);    

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 22)
        error_counter++;
        
    status = nx_mdns_service_delete(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST2", (UCHAR *)"_ipp._tcp", NX_NULL);  

    if(status)
        error_counter++;
    
    /* Disable the MDNS function.  */
    nx_mdns_disable(&mdns_0, 0);

    /* Enable the MDNS function.  */
    nx_mdns_enable(&mdns_0, 0);

    /* Wait for sending the goodbye.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);    

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 16)
        error_counter++;
        
    /* Disable the MDNS function.  */
    nx_mdns_disable(&mdns_0, 0);

    status = nx_mdns_service_delete(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST3", (UCHAR *)"_http._tcp", NX_NULL);  

    if(status)
        error_counter++;

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 11)
        error_counter++;
        
    /* Enable the MDNS function.  */
    nx_mdns_enable(&mdns_0, 0);
    
    status = nx_mdns_service_delete(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST4", (UCHAR *)"_smb._tcp", NX_NULL);  

    if(status)
        error_counter++;
    
    /* Wait for sending the goodbye.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE); 

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 7)
        error_counter++;
    
    status = nx_mdns_service_delete(&mdns_0, (UCHAR *)"NETXDUO_MDNS_TEST5", (UCHAR *)"_smb._tcp", NX_NULL);  

    if(status)
        error_counter++;
    
    /* Wait for sending the goodbye.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE); 

    /* Check mdns information. */
    if(mdns_0.nx_mdns_local_rr_count != 2)
        error_counter++;
    
    /* Disable the MDNS function.  */
    nx_mdns_disable(&mdns_0, 0);

    /* Determine if the test was successful.  */
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
}
#else            
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_service_add_delete_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Service Add And Delete Test..........................N/A\n");
    test_control_return(3);
}
#endif

