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
extern TAHI_TEST_SEQ tahi_01_001[];
extern TAHI_TEST_SEQ tahi_01_002[];
extern TAHI_TEST_SEQ tahi_01_003[];
extern TAHI_TEST_SEQ tahi_01_004[];
extern TAHI_TEST_SEQ tahi_01_005[];
extern TAHI_TEST_SEQ tahi_01_006[];
extern TAHI_TEST_SEQ tahi_01_007[];
extern TAHI_TEST_SEQ tahi_01_008[];
extern TAHI_TEST_SEQ tahi_01_009[];
extern TAHI_TEST_SEQ tahi_01_010[];
extern TAHI_TEST_SEQ tahi_01_011[];
extern TAHI_TEST_SEQ tahi_01_012[];
extern TAHI_TEST_SEQ tahi_01_013[];
extern TAHI_TEST_SEQ tahi_01_014[];
extern TAHI_TEST_SEQ tahi_01_015[];
extern TAHI_TEST_SEQ tahi_01_016[];
extern TAHI_TEST_SEQ tahi_01_017[];
extern TAHI_TEST_SEQ tahi_01_018[];
extern TAHI_TEST_SEQ tahi_01_019[];
extern TAHI_TEST_SEQ tahi_01_020[];
extern TAHI_TEST_SEQ tahi_01_021[];
extern TAHI_TEST_SEQ tahi_01_022[];
extern TAHI_TEST_SEQ tahi_01_023[];
extern TAHI_TEST_SEQ tahi_01_024[];
extern TAHI_TEST_SEQ tahi_01_025[];
extern TAHI_TEST_SEQ tahi_01_026[];
extern TAHI_TEST_SEQ tahi_01_027[];
extern TAHI_TEST_SEQ tahi_01_028[];
extern TAHI_TEST_SEQ tahi_01_029[];
extern TAHI_TEST_SEQ tahi_01_030[];
extern TAHI_TEST_SEQ tahi_01_031[];
extern TAHI_TEST_SEQ tahi_01_032[];
extern TAHI_TEST_SEQ tahi_01_033[];
extern TAHI_TEST_SEQ tahi_01_034[];
extern TAHI_TEST_SEQ tahi_01_035[];
extern TAHI_TEST_SEQ tahi_01_036[];
extern TAHI_TEST_SEQ tahi_01_037[];
extern TAHI_TEST_SEQ tahi_01_038[];
extern TAHI_TEST_SEQ tahi_01_039[];
extern TAHI_TEST_SEQ tahi_01_040[];
extern TAHI_TEST_SEQ tahi_01_041[];
extern TAHI_TEST_SEQ tahi_01_042[];
extern TAHI_TEST_SEQ tahi_01_043[];
extern TAHI_TEST_SEQ tahi_01_044[];
extern TAHI_TEST_SEQ tahi_01_045[];
extern TAHI_TEST_SEQ tahi_01_046[];
extern TAHI_TEST_SEQ tahi_01_047[];
extern TAHI_TEST_SEQ tahi_01_048[];
extern TAHI_TEST_SEQ tahi_01_049[];
extern TAHI_TEST_SEQ tahi_01_050[];
extern TAHI_TEST_SEQ tahi_01_051[];
extern TAHI_TEST_SEQ tahi_01_052[];
extern TAHI_TEST_SEQ tahi_01_053[];
extern TAHI_TEST_SEQ tahi_01_054[];

extern int tahi_01_001_size;
extern int tahi_01_002_size;
extern int tahi_01_003_size;
extern int tahi_01_004_size;
extern int tahi_01_005_size;
extern int tahi_01_006_size;
extern int tahi_01_007_size;
extern int tahi_01_008_size;
extern int tahi_01_009_size;
extern int tahi_01_010_size;
extern int tahi_01_011_size;
extern int tahi_01_012_size;
extern int tahi_01_013_size;
extern int tahi_01_014_size;
extern int tahi_01_015_size;
extern int tahi_01_016_size;
extern int tahi_01_017_size;
extern int tahi_01_018_size;
extern int tahi_01_019_size;
extern int tahi_01_020_size;
extern int tahi_01_021_size;
extern int tahi_01_022_size;
extern int tahi_01_023_size;
extern int tahi_01_024_size;
extern int tahi_01_025_size;
extern int tahi_01_026_size;
extern int tahi_01_027_size;
extern int tahi_01_028_size;
extern int tahi_01_029_size;
extern int tahi_01_030_size;
extern int tahi_01_031_size;
extern int tahi_01_032_size;
extern int tahi_01_033_size;
extern int tahi_01_034_size;
extern int tahi_01_035_size;
extern int tahi_01_036_size;
extern int tahi_01_037_size;
extern int tahi_01_038_size;
extern int tahi_01_039_size;
extern int tahi_01_040_size;
extern int tahi_01_041_size;
extern int tahi_01_042_size;
extern int tahi_01_043_size;
extern int tahi_01_044_size;
extern int tahi_01_045_size;
extern int tahi_01_046_size;
extern int tahi_01_047_size;
extern int tahi_01_048_size;
extern int tahi_01_049_size;
extern int tahi_01_050_size;
extern int tahi_01_051_size;
extern int tahi_01_052_size;
extern int tahi_01_053_size;
extern int tahi_01_054_size;

static TAHI_TEST_SUITE test_suite[54];
static void build_test_suite(void)
{

#if 1
    test_suite[0].test_case = &tahi_01_001[0]; test_suite[0].test_case_size = tahi_01_001_size;
    test_suite[1].test_case = &tahi_01_002[0]; test_suite[1].test_case_size = tahi_01_002_size;
    test_suite[2].test_case = &tahi_01_003[0]; test_suite[2].test_case_size = tahi_01_003_size;
    test_suite[3].test_case = &tahi_01_004[0]; test_suite[3].test_case_size = tahi_01_004_size;
    test_suite[4].test_case = &tahi_01_005[0]; test_suite[4].test_case_size = tahi_01_005_size;   
    test_suite[5].test_case = &tahi_01_006[0]; test_suite[5].test_case_size = tahi_01_006_size;
    test_suite[6].test_case = &tahi_01_007[0]; test_suite[6].test_case_size = tahi_01_007_size;  
    test_suite[7].test_case = &tahi_01_008[0]; test_suite[7].test_case_size = tahi_01_008_size;
    test_suite[8].test_case = &tahi_01_009[0]; test_suite[8].test_case_size = tahi_01_009_size;
    test_suite[9].test_case = &tahi_01_010[0]; test_suite[9].test_case_size = tahi_01_010_size;
    test_suite[10].test_case = &tahi_01_011[0]; test_suite[10].test_case_size = tahi_01_011_size;
    test_suite[11].test_case = &tahi_01_012[0]; test_suite[11].test_case_size = tahi_01_012_size;
#endif
    test_suite[12].test_case = &tahi_01_013[0]; test_suite[12].test_case_size = tahi_01_013_size;
    test_suite[13].test_case = &tahi_01_014[0]; test_suite[13].test_case_size = tahi_01_014_size;
    test_suite[14].test_case = &tahi_01_015[0]; test_suite[14].test_case_size = tahi_01_015_size;
    test_suite[15].test_case = &tahi_01_016[0]; test_suite[15].test_case_size = tahi_01_016_size;
    test_suite[16].test_case = &tahi_01_017[0]; test_suite[16].test_case_size = tahi_01_017_size;
    test_suite[17].test_case = &tahi_01_018[0]; test_suite[17].test_case_size = tahi_01_018_size;
    test_suite[18].test_case = &tahi_01_019[0]; test_suite[18].test_case_size = tahi_01_019_size;
    test_suite[19].test_case = &tahi_01_020[0]; test_suite[19].test_case_size = tahi_01_020_size;
    test_suite[20].test_case = &tahi_01_021[0]; test_suite[20].test_case_size = tahi_01_021_size;
    test_suite[21].test_case = &tahi_01_022[0]; test_suite[21].test_case_size = tahi_01_022_size;
    test_suite[22].test_case = &tahi_01_023[0]; test_suite[22].test_case_size = tahi_01_023_size;
    test_suite[23].test_case = &tahi_01_024[0]; test_suite[23].test_case_size = tahi_01_024_size;
    test_suite[24].test_case = &tahi_01_025[0]; test_suite[24].test_case_size = tahi_01_025_size;
    test_suite[25].test_case = &tahi_01_026[0]; test_suite[25].test_case_size = tahi_01_026_size;
    test_suite[26].test_case = &tahi_01_027[0]; test_suite[26].test_case_size = tahi_01_027_size;
    test_suite[27].test_case = &tahi_01_028[0]; test_suite[27].test_case_size = tahi_01_028_size;
    test_suite[28].test_case = &tahi_01_029[0]; test_suite[28].test_case_size = tahi_01_029_size;   
    test_suite[29].test_case = &tahi_01_030[0]; test_suite[29].test_case_size = tahi_01_030_size;
    test_suite[30].test_case = &tahi_01_031[0]; test_suite[30].test_case_size = tahi_01_031_size;
    test_suite[31].test_case = &tahi_01_032[0]; test_suite[31].test_case_size = tahi_01_032_size;
    test_suite[32].test_case = &tahi_01_033[0]; test_suite[32].test_case_size = tahi_01_033_size;
    test_suite[33].test_case = &tahi_01_034[0]; test_suite[33].test_case_size = tahi_01_034_size;
    test_suite[34].test_case = &tahi_01_035[0]; test_suite[34].test_case_size = tahi_01_035_size;
    test_suite[35].test_case = &tahi_01_036[0]; test_suite[35].test_case_size = tahi_01_036_size;
    test_suite[36].test_case = &tahi_01_037[0]; test_suite[36].test_case_size = tahi_01_037_size;
    test_suite[37].test_case = &tahi_01_038[0]; test_suite[37].test_case_size = tahi_01_038_size;
    test_suite[38].test_case = &tahi_01_039[0]; test_suite[38].test_case_size = tahi_01_039_size;
    test_suite[39].test_case = &tahi_01_040[0]; test_suite[39].test_case_size = tahi_01_040_size;
    test_suite[40].test_case = &tahi_01_041[0]; test_suite[40].test_case_size = tahi_01_041_size;
    test_suite[41].test_case = &tahi_01_042[0]; test_suite[41].test_case_size = tahi_01_042_size;
    test_suite[42].test_case = &tahi_01_043[0]; test_suite[42].test_case_size = tahi_01_043_size;
    test_suite[43].test_case = &tahi_01_044[0]; test_suite[43].test_case_size = tahi_01_044_size;
    test_suite[44].test_case = &tahi_01_045[0]; test_suite[44].test_case_size = tahi_01_045_size;
    test_suite[45].test_case = &tahi_01_046[0]; test_suite[45].test_case_size = tahi_01_046_size;
    test_suite[46].test_case = &tahi_01_047[0]; test_suite[46].test_case_size = tahi_01_047_size;
    test_suite[47].test_case = &tahi_01_048[0]; test_suite[47].test_case_size = tahi_01_048_size;
    test_suite[48].test_case = &tahi_01_049[0]; test_suite[48].test_case_size = tahi_01_049_size;
    test_suite[49].test_case = &tahi_01_050[0]; test_suite[49].test_case_size = tahi_01_050_size;
    test_suite[50].test_case = &tahi_01_051[0]; test_suite[50].test_case_size = tahi_01_051_size;
    test_suite[51].test_case = &tahi_01_052[0]; test_suite[51].test_case_size = tahi_01_052_size;
    test_suite[52].test_case = &tahi_01_053[0]; test_suite[52].test_case_size = tahi_01_053_size;
    test_suite[53].test_case = &tahi_01_054[0]; test_suite[53].test_case_size = tahi_01_054_size;
}


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tahi_test_1_define(void *first_unused_memory)
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
