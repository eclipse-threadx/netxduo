#include   "tx_api.h"
#include   "nx_api.h"
#include   <time.h>

extern void    test_control_return(UINT status);

#if defined __PRODUCT_NETXDUO__ && !defined NX_DISABLE_IPV4 && !defined NX_MDNS_DISABLE_CLIENT && defined NX_MDNS_ENABLE_IPV6
#include   "nxd_mdns.h"
#define     DEMO_STACK_SIZE    2048
#define     BUFFER_SIZE        10240

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
extern UINT    _nx_mdns_cache_add_string(NX_MDNS *mdns_ptr, UINT cache_type, VOID *string_ptr, UINT string_len, VOID **insert_ptr, UCHAR find_string, UCHAR add_name);
extern VOID    _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);
extern UINT    _nx_mdns_cache_delete_resource_record(NX_MDNS *mdns_ptr, UINT cache_type, NX_MDNS_RR *record_ptr);

/* Frame (185 bytes) */
static unsigned char response1[185] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0xfb, 0x00, 0x1e, /* 33...... */
0x8f, 0xb1, 0x7a, 0xd4, 0x86, 0xdd, 0x60, 0x00, /* ..z...`. */
0x00, 0x00, 0x00, 0x83, 0x11, 0x40, 0xfe, 0x80, /* .....@.. */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x1e, /* ........ */
0x8f, 0xff, 0xfe, 0xb1, 0x7a, 0xd4, 0xff, 0x02, /* ....z... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x14, 0xe9, /* ........ */
0x14, 0xe9, 0x00, 0x83, 0x30, 0x75, 0x00, 0x00, /* ....0u.. */
0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, /* ........ */
0x00, 0x03, 0x05, 0x5f, 0x68, 0x74, 0x74, 0x70, /* ..._http */
0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, /* ._tcp.lo */
0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01, /* cal..... */
0x00, 0x00, 0x11, 0x94, 0x00, 0x0f, 0x0c, 0x43, /* .......C */
0x61, 0x6e, 0x6f, 0x6e, 0x4d, 0x46, 0x34, 0x35, /* anonMF45 */
0x30, 0x30, 0x77, 0xc0, 0x0c, 0x06, 0x72, 0x6f, /* 00w...ro */
0x75, 0x74, 0x65, 0x72, 0xc0, 0x17, 0x00, 0x1c, /* uter.... */
0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10, /* .....x.. */
0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x02, 0x1e, 0x8f, 0xff, 0xfe, 0xb1, 0x7a, 0xd4, /* ......z. */
0xc0, 0x28, 0x00, 0x21, 0x80, 0x01, 0x00, 0x00, /* .(.!.... */
0x00, 0x78, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, /* .x...... */
0x00, 0x50, 0xc0, 0x37, 0xc0, 0x28, 0x00, 0x10, /* .P.7.(.. */
0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x01, /* ........ */
0x00                                            /* . */
};

/* Frame (126 bytes) */
static unsigned char response2[126] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0xfb, 0x00, 0x15, /* 33...... */
0x5d, 0x64, 0x17, 0x05, 0x86, 0xdd, 0x60, 0x02, /* ]d....`. */
0xe9, 0x46, 0x00, 0x48, 0x11, 0xff, 0x20, 0x01, /* .F.H.. . */
0x04, 0x70, 0xf4, 0xde, 0x30, 0x00, 0x00, 0x00, /* .p..0... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x14, 0xe9, /* ........ */
0x14, 0xe9, 0x00, 0x48, 0x63, 0xa9, 0x00, 0x00, /* ...Hc... */
0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, /* ..._serv */
0x69, 0x63, 0x65, 0x73, 0x07, 0x5f, 0x64, 0x6e, /* ices._dn */
0x73, 0x2d, 0x73, 0x64, 0x04, 0x5f, 0x75, 0x64, /* s-sd._ud */
0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, /* p.local. */
0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, /* ........ */
0x00, 0x0c, 0x04, 0x5f, 0x73, 0x6d, 0x62, 0x04, /* ..._smb. */
0x5f, 0x74, 0x63, 0x70, 0xc0, 0x23              /* _tcp.# */
};

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_ipv6_string_test(void *first_unused_memory)
#endif
{

UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;
    error_counter = 0;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
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

    status = nxd_ipv6_enable(&ip_0);

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
UINT        status;
ULONG       actual_status;
NX_MDNS_RR  *p;
ULONG       *head;
ULONG       *tail;
ULONG       temp_tail;
NX_PACKET   *my_packet1;
NX_PACKET   *my_packet2;
NX_MDNS_RR  *ptr = NX_NULL;
NX_MDNS_RR  *aaaa = NX_NULL;
NX_MDNS_RR  *srv = NX_NULL;
NX_MDNS_RR  *txt = NX_NULL;
NX_MDNS_RR  *dns_sd_ptr = NX_NULL;
UINT        dns_sd_ptr_string_len = 0;


    printf("NetX Test:   MDNS IPv6 String Test.....................................");
    
    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, 100);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set link local address.  */
    status = nx_ip_interface_physical_address_set(&ip_0, 0, 0x00000011, 0x22334456, NX_TRUE);
    status += nxd_ipv6_address_set(&ip_0, 0, NX_NULL, 10, NX_NULL);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Create a MDNS instance.  */
    current_buffer_size = 2048;
    status = nx_mdns_create(&mdns_0, &ip_0, &pool_0, 2, pointer, DEMO_STACK_SIZE, (UCHAR *)"NETX-MDNS",
                            buffer, current_buffer_size, buffer + current_buffer_size, current_buffer_size, NX_NULL);
    pointer += DEMO_STACK_SIZE;

    /* Enable mDNS.  */
    status = nx_mdns_enable(&mdns_0, 0);

    /* Check status. */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Wait for probing and announcing.  */
    tx_thread_sleep(5 * NX_IP_PERIODIC_RATE);

    /* Inject two packet to store the response in peer cache.
       If the IPv6 address is added into cache as string, 
       The logic for deleting string in _nx_mdns_cache_delete_string() is incorrect.
       For example,
       Step1. Add ipv6_address_string (0x000080fe, ...). into cache.
       Step2. Add string1 into cache.The strings in cache are string1, ipv6_address_string.
       Step3. Delete string1 from cache.
       After step3, the ipv6_address_string may also be deleted in some case since string_len = strlen(string_ptr), cnt are 0.  */

    /* Inject mDNS response1 to primary interface of ip_0. */
    status = nx_packet_allocate(&pool_0, &my_packet1, 16, NX_NO_WAIT);

    /* Check status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Append the data.  */
    status = nx_packet_data_append(my_packet1, response1 + 14, sizeof(response1) - 14, &pool_0, NX_NO_WAIT);

    /* Check status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the interface and receive the packet.  */
    my_packet1 -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];
    _nx_ip_packet_receive(&ip_0, my_packet1);

    /* After process this packet, the IPv6 address string in cache is the last string .  */


    /* Inject mDNS response2 to primary interface of ip_0. */
    status = nx_packet_allocate(&pool_0, &my_packet2, 16, NX_NO_WAIT);

    /* Check status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Append the data.  */
    status = nx_packet_data_append(my_packet2, response2 + 14, sizeof(response2) - 14, &pool_0, NX_NO_WAIT);

    /* Check status.  */
    if(status != NX_SUCCESS)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Set the interface and receive the packet.  */
    my_packet2 -> nx_packet_ip_interface = &ip_0.nx_ip_interface[0];
    _nx_ip_packet_receive(&ip_0, my_packet2);

    /* After process this packet, the dns PTR string in cache is after IPv6 address string.  */


    /* Wait for process response.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    head = (ULONG*)mdns_0.nx_mdns_peer_service_cache;
    tail = (ULONG*)(*head);

    /* Delete TXT resource record.  */
    for (p = (NX_MDNS_RR*)(head + 1); (ULONG*)p < tail; p++)
    {

        /* Check the entry type.  */  
        if (p -> nx_mdns_rr_state == NX_MDNS_RR_STATE_INVALID)
            continue;

        /* Check the type.  */
        if (p -> nx_mdns_rr_type == NX_MDNS_RR_TYPE_PTR)
        {
            if (memcmp(p -> nx_mdns_rr_name, "_services._dns-sd._udp.local", strlen("_services._dns-sd._udp.local")))
                ptr = p;
            else
                dns_sd_ptr = p;
        }
        else if (p -> nx_mdns_rr_type == NX_MDNS_RR_TYPE_AAAA)
            aaaa = p;
        else if (p -> nx_mdns_rr_type == NX_MDNS_RR_TYPE_SRV)
            srv = p;
        else if (p -> nx_mdns_rr_type == NX_MDNS_RR_TYPE_TXT)
            txt = p;
    }

    /* Check the rr count (PTR, AAAA, SRV, TXT, dns-sd PTR).  */
    if ((mdns_0.nx_mdns_peer_rr_count != 5) ||
        (ptr == NX_NULL) ||
        (aaaa == NX_NULL) ||
        (srv == NX_NULL) ||
        (txt == NX_NULL) ||
        (dns_sd_ptr == NX_NULL))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check dns PTR info.  */
    if ((memcmp(dns_sd_ptr -> nx_mdns_rr_name, "_services._dns-sd._udp.local", strlen("_services._dns-sd._udp.local"))) ||
        (memcmp(dns_sd_ptr -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_ptr.nx_mdns_rr_ptr_name, "_smb._tcp.local", strlen("_smb._tcp.local"))))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the string tail info.  */
    tail = (ULONG*)mdns_0.nx_mdns_peer_service_cache + (mdns_0.nx_mdns_peer_service_cache_size >> 2) - 1;
    temp_tail = (ULONG)(*tail);

    /* The tail should be dns-sd PTR string.  */
    if (dns_sd_ptr -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_ptr.nx_mdns_rr_ptr_name != (UCHAR*)(*tail))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Compute the string length.  */
    dns_sd_ptr_string_len = ((strlen((const char*)dns_sd_ptr -> nx_mdns_rr_name) & 0xFFFFFFFC) + 8) & 0xFFFFFFFF;    
    dns_sd_ptr_string_len += ((strlen((const char*)dns_sd_ptr -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_ptr.nx_mdns_rr_ptr_name) & 0xFFFFFFFC) + 8) & 0xFFFFFFFF;

    /* Check the string length.  */
    if (dns_sd_ptr_string_len != 56)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check the TXT info.  */
    if (memcmp(txt -> nx_mdns_rr_name, "CanonMF4500w._http._tcp.local", strlen("CanonMF4500w._http._tcp.local")))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check SRV info.  */
    if ((memcmp(srv -> nx_mdns_rr_name, "CanonMF4500w._http._tcp.local", strlen("CanonMF4500w._http._tcp.local"))) ||
        (memcmp(srv -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_srv.nx_mdns_rr_srv_target, "router.local", strlen("router.local"))) ||
        (srv -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_srv.nx_mdns_rr_srv_port != 80) ||
        (srv -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_srv.nx_mdns_rr_srv_priority != 0) ||
        (srv -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_srv.nx_mdns_rr_srv_weights != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check AAAA info.  */
    if ((memcmp(aaaa -> nx_mdns_rr_name, "router.local", strlen("router.local"))) ||
        (aaaa -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_aaaa.nx_mdns_rr_aaaa_address[0] != 0xfe800000) ||
        (aaaa -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_aaaa.nx_mdns_rr_aaaa_address[1] != 0x00000000) ||
        (aaaa -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_aaaa.nx_mdns_rr_aaaa_address[2] != 0x021e8fff)||
        (aaaa -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_aaaa.nx_mdns_rr_aaaa_address[3] != 0xfeb17ad4))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Check PTR info.  */
    if ((memcmp(ptr -> nx_mdns_rr_name, "_http._tcp.local", strlen("_http._tcp.local"))) ||
        (memcmp(ptr -> nx_mdns_rr_rdata.nx_mdns_rr_rdata_ptr.nx_mdns_rr_ptr_name, "CanonMF4500w._http._tcp.local", strlen("CanonMF4500w._http._tcp.local"))))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Delete dns-sd PTR record.  */
    _nx_mdns_cache_delete_resource_record(&mdns_0, NX_MDNS_CACHE_TYPE_PEER, dns_sd_ptr);

    /* Check the string tail info.  */
    tail = (ULONG*)mdns_0.nx_mdns_peer_service_cache + (mdns_0.nx_mdns_peer_service_cache_size >> 2) - 1;    

    /* The tail should be dns PTR string.  */
    if (*tail != temp_tail + dns_sd_ptr_string_len)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Determine if the test was successful.  */
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

#else
#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_mdns_ipv6_string_test(void *first_unused_memory)
#endif
{
    printf("NetX Test:   MDNS IPv6 String Test.....................................N/A\n");
    test_control_return(3);
}
#endif
