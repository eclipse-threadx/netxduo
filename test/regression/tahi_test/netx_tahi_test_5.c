#include    "tx_api.h"
#include    "nx_api.h"
#include    "netx_tahi.h"
#if defined(FEATURE_NX_IPV6) && defined(NX_TAHI_ENABLE)
#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"
#include    "nx_icmpv6.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;


static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;

static NXD_ADDRESS             ipv6_address_1;


/* Define thread prototypes.  */
static void         thread_0_entry(ULONG thread_input);
extern void         test_control_return(UINT status);
extern void         _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define the test threads.  */

extern TAHI_TEST_SEQ tahi_05_002[];
extern TAHI_TEST_SEQ tahi_05_003[];
extern TAHI_TEST_SEQ tahi_05_004[];
extern TAHI_TEST_SEQ tahi_05_005[];
extern TAHI_TEST_SEQ tahi_05_006[];
extern TAHI_TEST_SEQ tahi_05_007[];
extern TAHI_TEST_SEQ tahi_05_008[];
extern TAHI_TEST_SEQ tahi_05_009[];
extern TAHI_TEST_SEQ tahi_05_010[];
extern TAHI_TEST_SEQ tahi_05_012[];
extern TAHI_TEST_SEQ tahi_05_013[];
extern TAHI_TEST_SEQ tahi_05_014[];
extern TAHI_TEST_SEQ tahi_05_015[];
extern TAHI_TEST_SEQ tahi_05_017[];
extern TAHI_TEST_SEQ tahi_05_018[];
extern TAHI_TEST_SEQ tahi_05_020[];
extern TAHI_TEST_SEQ tahi_05_021[];
extern TAHI_TEST_SEQ tahi_05_022[];
extern TAHI_TEST_SEQ tahi_05_024[];
extern TAHI_TEST_SEQ tahi_05_025[];

extern int tahi_05_002_size;
extern int tahi_05_003_size;
extern int tahi_05_004_size;
extern int tahi_05_005_size;
extern int tahi_05_006_size;
extern int tahi_05_007_size;
extern int tahi_05_008_size;
extern int tahi_05_009_size;
extern int tahi_05_010_size;
extern int tahi_05_012_size;
extern int tahi_05_013_size;
extern int tahi_05_014_size;
extern int tahi_05_015_size;
extern int tahi_05_017_size;
extern int tahi_05_018_size;
extern int tahi_05_020_size;
extern int tahi_05_021_size;
extern int tahi_05_022_size;
extern int tahi_05_024_size;
extern int tahi_05_025_size;


static TAHI_TEST_SUITE test_suite[20];
static void build_test_suite(void)
{
    test_suite[0].test_case = &tahi_05_002[0];test_suite[0].test_case_size = tahi_05_002_size;
    test_suite[1].test_case = &tahi_05_003[0];test_suite[1].test_case_size = tahi_05_003_size;
    test_suite[2].test_case = &tahi_05_004[0];test_suite[2].test_case_size = tahi_05_004_size;
    test_suite[3].test_case = &tahi_05_005[0];test_suite[3].test_case_size = tahi_05_005_size;
    test_suite[4].test_case = &tahi_05_006[0];test_suite[4].test_case_size = tahi_05_006_size;
    test_suite[5].test_case = &tahi_05_007[0];test_suite[5].test_case_size = tahi_05_007_size;
    test_suite[6].test_case = &tahi_05_008[0];test_suite[6].test_case_size = tahi_05_008_size;
    test_suite[7].test_case = &tahi_05_009[0];test_suite[7].test_case_size = tahi_05_009_size;
    test_suite[8].test_case = &tahi_05_010[0];test_suite[8].test_case_size = tahi_05_010_size;
    test_suite[9].test_case = &tahi_05_012[0];test_suite[9].test_case_size = tahi_05_012_size;
    test_suite[10].test_case = &tahi_05_013[0];test_suite[10].test_case_size = tahi_05_013_size;
    test_suite[11].test_case = &tahi_05_014[0];test_suite[11].test_case_size = tahi_05_014_size;
    test_suite[12].test_case = &tahi_05_015[0];test_suite[12].test_case_size = tahi_05_015_size;
    test_suite[13].test_case = &tahi_05_017[0];test_suite[13].test_case_size = tahi_05_017_size;
    test_suite[14].test_case = &tahi_05_018[0];test_suite[14].test_case_size = tahi_05_018_size;
    test_suite[15].test_case = &tahi_05_020[0];test_suite[15].test_case_size = tahi_05_020_size;
    test_suite[16].test_case = &tahi_05_021[0];test_suite[16].test_case_size = tahi_05_021_size;
    test_suite[17].test_case = &tahi_05_022[0];test_suite[17].test_case_size = tahi_05_022_size;
    test_suite[18].test_case = &tahi_05_024[0];test_suite[18].test_case_size = tahi_05_024_size;
    test_suite[19].test_case = &tahi_05_025[0];test_suite[19].test_case_size = tahi_05_025_size;
}


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tahi_test_5_define(void *first_unused_memory)
#endif
{
    CHAR       *pointer;
    UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;
    memset(&test_suite, 0, sizeof(test_suite));

    build_test_suite();

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
        pointer, DEMO_STACK_SIZE, 
        4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, 1536*16);
    pointer = pointer + 1536*16;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1,2,3,4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
        pointer, 2048, 1);
    pointer = pointer + 2048;


    /* Set ipv6 version and address.  */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0xfe800000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x021122ff;
    ipv6_address_1.nxd_ip_address.v6[3] = 0xfe334456;

    /* Enable IPv6 */
    status = nxd_ipv6_enable(&ip_0);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check ARP enable status.  */
    if(status)
        error_counter++;

    /* Enable fragment processing for IP Instance 0.  */
    status = nx_ip_fragment_enable(&ip_0);

    /* Check fragment enable status.  */
    if(status)
        error_counter++;

    /* Enable fragment processing for IP Instance 0.  */
    status = nx_udp_enable(&ip_0);

    /* Check fragment enable status.  */
    if(status)
        error_counter++;

    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1,64, NX_NULL);

    if(status)
        error_counter++;
}


static void    thread_0_entry(ULONG thread_input)
{
    int                    num_suite;
    int                    i;


    num_suite = sizeof(test_suite) / sizeof(TAHI_TEST_SUITE);

    for(i = 0; i < num_suite; i++)
    {
        if(test_suite[i].test_case)
            netx_tahi_run_test_case(&ip_0, test_suite[i].test_case, test_suite[i].test_case_size);
    }

    test_control_return(0xdeadbeef);

    /* Clear the flags. */

}

#endif
