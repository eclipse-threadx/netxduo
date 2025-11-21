#include   "tx_api.h"
#include   "nx_api.h"

extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__  && !defined NX_MDNS_DISABLE_CLIENT && !defined NX_DISABLE_IPV4
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

/* Frame (350 bytes) */
static unsigned char response[350] = {
0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0x00, 0x11, /* ..^..... */
0x32, 0x5e, 0x5b, 0x58, 0x08, 0x00, 0x45, 0x00, /* 2^[X..E. */
0x01, 0x50, 0x52, 0x05, 0x40, 0x00, 0xff, 0x11, /* .PR.@... */
0x22, 0xed, 0xc0, 0xa8, 0x64, 0x06, 0xe0, 0x00, /* "...d... */
0x00, 0xfb, 0x14, 0xe9, 0x14, 0xe9, 0x01, 0x3c, /* .......< */
0x54, 0x86, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, /* T....... */
0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x05, 0x5f, /* ......._ */
0x68, 0x74, 0x74, 0x70, 0x04, 0x5f, 0x74, 0x63, /* http._tc */
0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, /* p.local. */
0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, /* ........ */
0x00, 0x0c, 0x09, 0x44, 0x75, 0x6e, 0x63, 0x68, /* ...Dunch */
0x75, 0x61, 0x6e, 0x67, 0xc0, 0x0c, 0xc0, 0x28, /* uang...( */
0x00, 0x10, 0x80, 0x01, 0x00, 0x00, 0x11, 0x94, /* ........ */
0x00, 0xaa, 0x0f, 0x76, 0x65, 0x6e, 0x64, 0x6f, /* ...vendo */
0x72, 0x3d, 0x53, 0x79, 0x6e, 0x6f, 0x6c, 0x6f, /* r=Synolo */
0x67, 0x79, 0x0c, 0x6d, 0x6f, 0x64, 0x65, 0x6c, /* gy.model */
0x3d, 0x44, 0x53, 0x32, 0x31, 0x36, 0x6a, 0x14, /* =DS216j. */
0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x3d, 0x31, /* serial=1 */
0x36, 0x36, 0x30, 0x4e, 0x4e, 0x4e, 0x35, 0x34, /* 660NNN54 */
0x34, 0x34, 0x30, 0x33, 0x0f, 0x76, 0x65, 0x72, /* 4403.ver */
0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x61, 0x6a, /* sion_maj */
0x6f, 0x72, 0x3d, 0x36, 0x0f, 0x76, 0x65, 0x72, /* or=6.ver */
0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x69, 0x6e, /* sion_min */
0x6f, 0x72, 0x3d, 0x30, 0x12, 0x76, 0x65, 0x72, /* or=0.ver */
0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x62, 0x75, 0x69, /* sion_bui */
0x6c, 0x64, 0x3d, 0x37, 0x33, 0x39, 0x33, 0x0f, /* ld=7393. */
0x61, 0x64, 0x6d, 0x69, 0x6e, 0x5f, 0x70, 0x6f, /* admin_po */
0x72, 0x74, 0x3d, 0x35, 0x30, 0x30, 0x30, 0x16, /* rt=5000. */
0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x5f, 0x61, /* secure_a */
0x64, 0x6d, 0x69, 0x6e, 0x5f, 0x70, 0x6f, 0x72, /* dmin_por */
0x74, 0x3d, 0x35, 0x30, 0x30, 0x31, 0x1d, 0x6d, /* t=5001.m */
0x61, 0x63, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, /* ac_addre */
0x73, 0x73, 0x3d, 0x30, 0x30, 0x3a, 0x31, 0x31, /* ss=00:11 */
0x3a, 0x33, 0x32, 0x3a, 0x35, 0x65, 0x3a, 0x35, /* :32:5e:5 */
0x62, 0x3a, 0x35, 0x38, 0xc0, 0x28, 0x00, 0x21, /* b:58.(.! */
0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x12, /* .....x.. */
0x00, 0x00, 0x00, 0x00, 0x13, 0x88, 0x09, 0x44, /* .......D */
0x75, 0x6e, 0x63, 0x68, 0x75, 0x61, 0x6e, 0x67, /* unchuang */
0xc0, 0x17, 0xc0, 0xfc, 0x00, 0x1c, 0x80, 0x01, /* ........ */
0x00, 0x00, 0x00, 0x78, 0x00, 0x10, 0x20, 0x01, /* ...x.. . */
0x04, 0x70, 0xf4, 0xde, 0x30, 0x00, 0x02, 0x11, /* .p..0... */
0x32, 0xff, 0xfe, 0x5e, 0x5b, 0x58, 0xc0, 0xfc, /* 2..^[X.. */
0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, /* .......x */
0x00, 0x04, 0xc0, 0xa8, 0x64, 0x06              /* ....d. */
};
/* Define the counters used in the test application...  */

static ULONG                   error_counter;
static CHAR                   *pointer;
static CHAR                    host_registered = NX_FALSE;
static CHAR                    serivce_received = 0;
static CHAR                    serivce_updated = 0;
static CHAR                    serivce_deleted = 0;

/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern VOID    _nx_ram_network_driver_1500(NX_IP_DRIVER *driver_req_ptr);
static VOID    probing_notify(struct NX_MDNS_STRUCT *mdns_ptr, UCHAR *name, UINT state);
static VOID    service_change_notify(NX_MDNS *mdns_ptr, NX_MDNS_SERVICE *service_ptr, UINT state);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_peer_service_change_notify_test(void *first_unused_memory)
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
UINT       status;
ULONG      actual_status;
NX_PACKET *my_packet;
NX_MDNS_SERVICE service_instance;

    NX_PARAMETER_NOT_USED(thread_input);
    
    printf("NetX Test:   MDNS Peer Service Change Notify Test......................");

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
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",  
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

    /* Inject mDNS response to primary interface of ip_0. */
    status = nx_packet_allocate(&pool_0, &my_packet, 16, NX_NO_WAIT);

    /* Check status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(my_packet, response + 14, sizeof(response) - 14, &pool_0, NX_NO_WAIT);

    /* Check status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];
    _nx_ip_packet_receive(&ip_0, my_packet);

    /* Sleep 1s.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Check the flag.  */
    if ((serivce_received != 0) || (serivce_updated !=0) || (serivce_deleted !=0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Service lookup.  */
    status = nx_mdns_service_lookup(&mdns_0, NX_NULL, (UCHAR *)"_http._tcp", NX_NULL, 0, &service_instance);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the service info.  */
    if ((strcmp((const char*)service_instance.service_name, (const char*)"Dunchuang")) ||
        (strcmp((const char*)service_instance.service_type, (const char*)"_http._tcp"))||
        (strcmp((const char*)service_instance.service_domain, (const char*)"local"))||
        (strcmp((const char*)service_instance.service_host, (const char*)"Dunchuang.local"))||
        (service_instance.service_text_valid != 1) ||
        (service_instance.service_port != 5000) ||
        (service_instance.service_weight != 0) ||
        (service_instance.service_priority != 0) ||
        (service_instance.service_ipv4 != 0xc0a86406) ||
        (service_instance.service_ipv6[0][0] != 0x20010470) ||
        (service_instance.service_ipv6[0][1] != 0xf4de3000) ||
        (service_instance.service_ipv6[0][2] != 0x021132ff) ||
        (service_instance.service_ipv6[0][3] != 0xfe5e5b58))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Clear the cache.  */
    status = nx_mdns_peer_cache_clear(&mdns_0);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Set the serivce change notify for _http.  */
    status = nx_mdns_service_notify_set(&mdns_0, 0x02, service_change_notify); 

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Inject mDNS response to primary interface of ip_0. */
    status = nx_packet_allocate(&pool_0, &my_packet, 16, NX_NO_WAIT);

    /* Check status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = nx_packet_data_append(my_packet, response + 14, sizeof(response) - 14, &pool_0, NX_NO_WAIT);

    /* Check status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    my_packet -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];
    _nx_ip_packet_receive(&ip_0, my_packet);

    /* Check the flag.  */
    if ((serivce_received == 0) || (serivce_updated == 0) || (serivce_deleted != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Service lookup.  */
    status = nx_mdns_service_lookup(&mdns_0, NX_NULL, (UCHAR *)"_http._tcp", NX_NULL, 0, &service_instance);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the service info.  */
    if ((strcmp((const char*)service_instance.service_name, (const char*)"Dunchuang")) ||
        (strcmp((const char*)service_instance.service_type, (const char*)"_http._tcp"))||
        (strcmp((const char*)service_instance.service_domain, (const char*)"local"))||
        (strcmp((const char*)service_instance.service_host, (const char*)"Dunchuang.local"))||
        (service_instance.service_text_valid != 1) ||
        (service_instance.service_port != 5000) ||
        (service_instance.service_weight != 0) ||
        (service_instance.service_priority != 0) ||
        (service_instance.service_ipv4 != 0xc0a86406) ||
        (service_instance.service_ipv6[0][0] != 0x20010470) ||
        (service_instance.service_ipv6[0][1] != 0xf4de3000) ||
        (service_instance.service_ipv6[0][2] != 0x021132ff) ||
        (service_instance.service_ipv6[0][3] != 0xfe5e5b58))
    {
        printf("ERROR!\n");
        test_control_return(1);
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

static VOID  service_change_notify(NX_MDNS *mdns_ptr, NX_MDNS_SERVICE *service_ptr, UINT state)
{

    NX_PARAMETER_NOT_USED(mdns_ptr);
    NX_PARAMETER_NOT_USED(service_ptr);

    switch(state)
    {
        case NX_MDNS_PEER_SERVICE_RECEIVED:
        {
            serivce_received++;
            break;
        }
        case NX_MDNS_PEER_SERVICE_UPDATED:
        {
            serivce_updated++;
            break;
        }
        case NX_MDNS_PEER_SERVICE_DELETED:
        {              
            serivce_deleted++;
            break;
        } 
    }
}
#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_peer_service_change_notify_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS Peer Service Change Notify Test......................N/A\n");
    test_control_return(3);
}
#endif
