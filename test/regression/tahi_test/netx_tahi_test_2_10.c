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
extern TAHI_TEST_SEQ tahi_02_135[];
extern TAHI_TEST_SEQ tahi_02_136[];
extern TAHI_TEST_SEQ tahi_02_137[];
extern TAHI_TEST_SEQ tahi_02_138[];
extern TAHI_TEST_SEQ tahi_02_139[];
extern TAHI_TEST_SEQ tahi_02_140[];
extern TAHI_TEST_SEQ tahi_02_141[];
extern TAHI_TEST_SEQ tahi_02_142[];
extern TAHI_TEST_SEQ tahi_02_143[];
extern TAHI_TEST_SEQ tahi_02_144[];
extern TAHI_TEST_SEQ tahi_02_145[];
extern TAHI_TEST_SEQ tahi_02_146[];
extern TAHI_TEST_SEQ tahi_02_147[];
extern TAHI_TEST_SEQ tahi_02_148[];
extern TAHI_TEST_SEQ tahi_02_149[];
extern TAHI_TEST_SEQ tahi_02_150[];
extern TAHI_TEST_SEQ tahi_02_151[];
extern TAHI_TEST_SEQ tahi_02_152[];
extern TAHI_TEST_SEQ tahi_02_153[];
extern TAHI_TEST_SEQ tahi_02_154[];
extern TAHI_TEST_SEQ tahi_02_155[];
extern TAHI_TEST_SEQ tahi_02_156[];
extern TAHI_TEST_SEQ tahi_02_157[];
extern TAHI_TEST_SEQ tahi_02_158[];
extern TAHI_TEST_SEQ tahi_02_159[];
extern TAHI_TEST_SEQ tahi_02_160[];
extern TAHI_TEST_SEQ tahi_02_161[];
extern TAHI_TEST_SEQ tahi_02_162[];
extern TAHI_TEST_SEQ tahi_02_163[];
extern TAHI_TEST_SEQ tahi_02_164[];
extern TAHI_TEST_SEQ tahi_02_165[];
extern TAHI_TEST_SEQ tahi_02_166[];
extern TAHI_TEST_SEQ tahi_02_167[];

extern int tahi_02_135_size;
extern int tahi_02_136_size;
extern int tahi_02_137_size;
extern int tahi_02_138_size;
extern int tahi_02_139_size;
extern int tahi_02_140_size;
extern int tahi_02_141_size;
extern int tahi_02_142_size;
extern int tahi_02_143_size;
extern int tahi_02_144_size;
extern int tahi_02_145_size;
extern int tahi_02_146_size;
extern int tahi_02_147_size;
extern int tahi_02_148_size;
extern int tahi_02_149_size;
extern int tahi_02_150_size;
extern int tahi_02_151_size;
extern int tahi_02_152_size;
extern int tahi_02_153_size;
extern int tahi_02_154_size;
extern int tahi_02_155_size;
extern int tahi_02_156_size;
extern int tahi_02_157_size;
extern int tahi_02_158_size;
extern int tahi_02_159_size;
extern int tahi_02_160_size;
extern int tahi_02_161_size;
extern int tahi_02_162_size;
extern int tahi_02_163_size;
extern int tahi_02_164_size;
extern int tahi_02_165_size;
extern int tahi_02_166_size;
extern int tahi_02_167_size;


static TAHI_TEST_SUITE test_suite[33];
static void build_test_suite(void)
{
    test_suite[0].test_case = &tahi_02_135[0]; test_suite[0].test_case_size = tahi_02_135_size;
    test_suite[1].test_case = &tahi_02_136[0]; test_suite[1].test_case_size = tahi_02_136_size;
    test_suite[2].test_case = &tahi_02_137[0]; test_suite[2].test_case_size = tahi_02_137_size;
    test_suite[3].test_case = &tahi_02_138[0]; test_suite[3].test_case_size = tahi_02_138_size;
    test_suite[4].test_case = &tahi_02_139[0]; test_suite[4].test_case_size = tahi_02_139_size;
    test_suite[5].test_case = &tahi_02_140[0]; test_suite[5].test_case_size = tahi_02_140_size;
    test_suite[6].test_case = &tahi_02_141[0]; test_suite[6].test_case_size = tahi_02_141_size;
    test_suite[7].test_case = &tahi_02_142[0]; test_suite[7].test_case_size = tahi_02_142_size;
    test_suite[8].test_case = &tahi_02_143[0]; test_suite[8].test_case_size = tahi_02_143_size;
    test_suite[9].test_case = &tahi_02_144[0]; test_suite[9].test_case_size = tahi_02_144_size;
    test_suite[10].test_case = &tahi_02_145[0]; test_suite[10].test_case_size = tahi_02_145_size;
    test_suite[11].test_case = &tahi_02_146[0]; test_suite[11].test_case_size = tahi_02_146_size;
    test_suite[12].test_case = &tahi_02_147[0]; test_suite[12].test_case_size = tahi_02_147_size; /* line:620 */
    test_suite[13].test_case = &tahi_02_148[0]; test_suite[13].test_case_size = tahi_02_148_size;
    test_suite[14].test_case = &tahi_02_149[0]; test_suite[14].test_case_size = tahi_02_149_size;
    test_suite[15].test_case = &tahi_02_150[0]; test_suite[15].test_case_size = tahi_02_150_size;
    test_suite[16].test_case = &tahi_02_151[0]; test_suite[16].test_case_size = tahi_02_151_size;  /* line:102 */
    test_suite[17].test_case = &tahi_02_152[0]; test_suite[17].test_case_size = tahi_02_152_size;
    test_suite[18].test_case = &tahi_02_153[0]; test_suite[18].test_case_size = tahi_02_153_size;
    test_suite[19].test_case = &tahi_02_154[0]; test_suite[19].test_case_size = tahi_02_154_size;
    test_suite[20].test_case = &tahi_02_155[0]; test_suite[20].test_case_size = tahi_02_155_size;
    test_suite[21].test_case = &tahi_02_156[0]; test_suite[21].test_case_size = tahi_02_156_size;
    test_suite[22].test_case = &tahi_02_157[0]; test_suite[22].test_case_size = tahi_02_157_size;
    test_suite[23].test_case = &tahi_02_158[0]; test_suite[23].test_case_size = tahi_02_158_size;
    test_suite[24].test_case = &tahi_02_159[0]; test_suite[24].test_case_size = tahi_02_159_size;
    test_suite[25].test_case = &tahi_02_160[0]; test_suite[25].test_case_size = tahi_02_160_size;
    test_suite[26].test_case = &tahi_02_161[0]; test_suite[26].test_case_size = tahi_02_161_size;
    test_suite[27].test_case = &tahi_02_162[0]; test_suite[27].test_case_size = tahi_02_162_size;
    test_suite[28].test_case = &tahi_02_163[0]; test_suite[28].test_case_size = tahi_02_163_size;
    test_suite[29].test_case = &tahi_02_164[0]; test_suite[29].test_case_size = tahi_02_164_size;
    test_suite[30].test_case = &tahi_02_165[0]; test_suite[30].test_case_size = tahi_02_165_size;
    test_suite[31].test_case = &tahi_02_166[0]; test_suite[31].test_case_size = tahi_02_166_size;
    test_suite[32].test_case = &tahi_02_167[0]; test_suite[32].test_case_size = tahi_02_167_size;  //line:142
}

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tahi_test_2_10_define(void *first_unused_memory)
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
    
    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1,64, NX_NULL);
    
    if(status)
        error_counter++;

    
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
    
    /* Clear the flags. */
    test_control_return(0xdeadbeef);

}


#endif
