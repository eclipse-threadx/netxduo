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
static UCHAR                   buffer[BUFFER_SIZE];
static ULONG                   current_buffer_size;
static CHAR                   *txt = "paper=A4;version=01";
static CHAR                    mdns_data[] = {
0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0x00, 0x11, /* ..^..... */
0x22, 0x33, 0x44, 0x57, 0x08, 0x00, 0x45, 0x00, /* "3DW..E. */
0x00, 0xdf, 0x00, 0x07, 0x40, 0x00, 0xff, 0x11, /* ....@... */
0x8f, 0xec, 0x0a, 0x00, 0x00, 0x1f, 0xe0, 0x00, /* ........ */
0x00, 0xfb, 0x14, 0xe9, 0x14, 0xe9, 0x00, 0xcb, /* ........ */
0x81, 0x17, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x41, /* .......A */
0x52, 0x4d, 0x4d, 0x44, 0x4e, 0x53, 0x54, 0x65, /* RMMDNSTe */
0x73, 0x74, 0x05, 0x5f, 0x68, 0x74, 0x74, 0x70, /* st._http */
0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, /* ._tcp.lo */
0x63, 0x61, 0x6c, 0x00, 0x00, 0x21, 0x80, 0x01, /* cal..!.. */
0x00, 0x00, 0x00, 0x64, 0x00, 0x19, 0x00, 0x00, /* ...d.... */
0x00, 0x00, 0x00, 0x50, 0x0b, 0x41, 0x52, 0x4d, /* ...P.ARM */
0x4d, 0x44, 0x4e, 0x53, 0x54, 0x65, 0x73, 0x74, /* MDNSTest */
0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x0b, /* .local.. */
0x41, 0x52, 0x4d, 0x4d, 0x44, 0x4e, 0x53, 0x54, /* ARMMDNST */
0x65, 0x73, 0x74, 0x05, 0x5f, 0x68, 0x74, 0x74, /* est._htt */
0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, /* p._tcp.l */
0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x10, 0x80, /* ocal.... */
0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x14, 0x08, /* ....d... */
0x70, 0x61, 0x70, 0x65, 0x72, 0x3d, 0x41, 0x34, /* paper=A4 */
0x0a, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, /* .version */
0x3d, 0x30, 0x31, 0x05, 0x5f, 0x68, 0x74, 0x74, /* =01._htt */
0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, /* p._tcp.l */
0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, /* ocal.... */
0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x1e, 0x0b, /* ....d... */
0x41, 0x52, 0x4d, 0x4d, 0x44, 0x4e, 0x53, 0x54, /* ARMMDNST */
0x65, 0x73, 0x74, 0x05, 0x5f, 0x68, 0x74, 0x74, /* est._htt */
0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, /* p._tcp.l */
0x6f, 0x63, 0x61, 0x6c, 0x00                    /* ocal. */
};


/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_txt_notation_test(void *first_unused_memory)
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
    
    status = nx_igmp_enable(&ip_0);

    /* Check status. */
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
UINT            status;
ULONG           actual_status;
NX_MDNS_SERVICE service;
NX_PACKET      *my_packet;

    printf("NetX Test:   MDNS TXT Notation Test....................................");

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

    /* Inject a response with TXT. */
    status = nx_packet_allocate(&pool_0, &my_packet, 16, 100);
    status += nx_packet_data_append(my_packet, mdns_data + 14, sizeof(mdns_data) - 14, &pool_0, 100);
    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];
    _nx_ip_packet_deferred_receive(&ip_0, my_packet);

    /* Check status. */
    if(status)
        error_counter++;

    /* Sleep one second. */
    tx_thread_sleep(100);

    /* Lookup service.  */
    status = nx_mdns_service_lookup(&mdns_0, NX_NULL, "_http._tcp", NX_NULL, 0, &service);

    /* Check RR and TXT. */
    if(status)
        error_counter++;
    else if(service.service_text == NX_NULL)
        error_counter++;
    else if(strcmp(service.service_text, txt))
        error_counter++;

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
void           netx_mdns_txt_notation_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS TXT Notation Test....................................N/A\n"); 
    test_control_return(3);
}
#endif /* NX_MDNS_DISABLE_CLIENT  */ 
