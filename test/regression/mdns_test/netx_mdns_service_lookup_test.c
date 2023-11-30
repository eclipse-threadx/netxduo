#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_ram_network_driver_test_1500.h"
             
extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_MDNS_DISABLE_CLIENT && !defined NX_DISABLE_IPV4
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
static UCHAR                   type[256];
static UCHAR                   buffer[BUFFER_SIZE];
static ULONG                   current_buffer_size;
static CHAR                    mdns_data[] = {
0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0x00, 0x1e, /* ..^..... */
0x8f, 0xb1, 0x7a, 0xd4, 0x08, 0x00, 0x45, 0x00, /* ..z...E. */
0x00, 0x8b, 0x76, 0xbf, 0x00, 0x00, 0xff, 0x11, /* ..v..... */
0xa2, 0xfa, 0xc0, 0xa8, 0x00, 0x04, 0xe0, 0x00, /* ........ */
0x00, 0xfb, 0x14, 0xe9, 0x14, 0xe9, 0x00, 0x77, /* .......w */
0xe2, 0xa6, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x05, 0x5f, /* ......._ */
0x68, 0x74, 0x74, 0x70, 0x04, 0x5f, 0x74, 0x63, /* http._tc */
0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, /* p.local. */
0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, /* ........ */
0x00, 0x0f, 0x0c, 0x43, 0x61, 0x6e, 0x6f, 0x6e, /* ...Canon */
0x4d, 0x46, 0x34, 0x35, 0x30, 0x30, 0x77, 0xc0, /* MF4500w. */
0x0c, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, /* ..router */
0xc0, 0x17, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, /* ........ */
0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8, 0x00, 0x04, /* .x...... */
0xc0, 0x28, 0x00, 0x21, 0x80, 0x01, 0x00, 0x00, /* .(.!.... */
0x00, 0x78, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, /* .x...... */
0x00, 0x50, 0xc0, 0x37, 0xc0, 0x28, 0x00, 0x10, /* .P.7.(.. */
0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x01, /* ........ */
0x00                                            /* . */
};


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_service_lookup_test(void *first_unused_memory)
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
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(192,168,0,31), 0xFFFFFF00UL, &pool_0, 
                          _nx_ram_network_driver_1500, pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;
    if(status)
        error_counter++;

    /* Enable UDP processing for both IP instances.  */
    status = nx_udp_enable(&ip_0);

    /* Check UDP enable status.  */
    if(status)
        error_counter++;

    /* Create the test thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, NX_NULL,  
                     pointer, DEMO_STACK_SIZE, 
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + DEMO_STACK_SIZE;
}

/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
NX_PACKET *my_packet;
NX_MDNS_SERVICE service;
UINT       i;
ULONG      ipv4_address;

    printf("NetX Test:   MDNS Service Lookup Test..................................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create mDNS. */
    current_buffer_size = (BUFFER_SIZE >> 1);
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, "NETX-MDNS",  
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);
    pointer = pointer + DEMO_STACK_SIZE;

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Enable mDNS.  */
    status = nx_mdns_enable(&mdns_0, 0);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Inject a response packet. */           
    status = nx_packet_allocate(&pool_0, &my_packet, 16, 100);
    status += nx_packet_data_append(my_packet, mdns_data + 14, sizeof(mdns_data) - 14, &pool_0, 100);
    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];
    _nx_ip_packet_deferred_receive(&ip_0, my_packet);

    /* Check status. */
    if(status)
        error_counter++;

    /* The service name is CanonMF4500w._http._tcp.local. */
    if(nx_mdns_service_lookup(&mdns_0, NX_NULL, "_http._tcp", NX_NULL, 0, &service) == NX_SUCCESS)
    {
        if(strcmp(service.service_name, "CanonMF4500w"))
            error_counter++;
        if(strcmp(service.service_type, "_http._tcp"))
            error_counter++;
        if(strcmp(service.service_domain, "local"))
            error_counter++;
    }
    else
        error_counter++;

    /* Look by wrong type. */
    if(nx_mdns_service_lookup(&mdns_0, NX_NULL, "_http1._tcp", NX_NULL, 0, &service) == NX_SUCCESS)
        error_counter++;

    /* Look by wrong index. */
    for(i = 1; i < 1000; i++)
    {
        if(nx_mdns_service_lookup(&mdns_0, NX_NULL, "_http._tcp", NX_NULL, i, &service) == NX_SUCCESS)
            error_counter++;
    }

    /* Look by name and type. */
    if(nx_mdns_service_lookup(&mdns_0, "CanonMF4500w", "_http._tcp", NX_NULL, 0, &service) == NX_SUCCESS)
    {
        if(strcmp(service.service_name, "CanonMF4500w"))
            error_counter++;
        if(strcmp(service.service_type, "_http._tcp"))
            error_counter++;
        if(strcmp(service.service_domain, "local"))
            error_counter++;
    }
    else
        error_counter++;

    /* Look by wrong name. */
    if(nx_mdns_service_lookup(&mdns_0, "CanonMF4500w1", "_http._tcp", NX_NULL, 0, &service) == NX_SUCCESS)
        error_counter++;

    /* Look by wrong index. */
    for(i = 1; i < 1000; i++)
    {
        if(nx_mdns_service_lookup(&mdns_0, "CanonMF4500w", "_http._tcp", NX_NULL, i, &service) == NX_SUCCESS)
            error_counter++;
    }

    /* Look all services. */
    if(nx_mdns_service_lookup(&mdns_0, NX_NULL, NX_NULL, NX_NULL, 0, &service) == NX_SUCCESS)
    {
        if(strcmp(service.service_name, "CanonMF4500w"))
            error_counter++;
        if(strcmp(service.service_type, "_http._tcp"))
            error_counter++;
        if(strcmp(service.service_domain, "local"))
            error_counter++;
    }
    else
        error_counter++;

    /* Look by wrong index. */
    for(i = 1; i < 1000; i++)
    {
        if(nx_mdns_service_lookup(&mdns_0, NX_NULL, NX_NULL, NX_NULL, i, &service) == NX_SUCCESS)
            error_counter++;
    }

    /* Check IPv4 address. */
    if(nx_mdns_host_address_get(&mdns_0, "router.local", &ipv4_address, NX_NULL, NX_NO_WAIT) == NX_SUCCESS)
    {
        if(ipv4_address != IP_ADDRESS(192, 168, 0, 4))
            error_counter++;
    }

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
void           netx_mdns_service_lookup_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Service Lookup Test..................................N/A\n"); 
    test_control_return(3);
}
#endif /* NX_MDNS_DISABLE_CLIENT  */ 
