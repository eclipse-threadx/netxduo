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
extern TAHI_TEST_SEQ tahi_02_168[];
extern TAHI_TEST_SEQ tahi_02_169[];
extern TAHI_TEST_SEQ tahi_02_170[];
extern TAHI_TEST_SEQ tahi_02_171[];
extern TAHI_TEST_SEQ tahi_02_172[];
extern TAHI_TEST_SEQ tahi_02_173[];
extern TAHI_TEST_SEQ tahi_02_174[];
extern TAHI_TEST_SEQ tahi_02_175[];
extern TAHI_TEST_SEQ tahi_02_176[];
extern TAHI_TEST_SEQ tahi_02_177[];
extern TAHI_TEST_SEQ tahi_02_178[];
extern TAHI_TEST_SEQ tahi_02_179[];
extern TAHI_TEST_SEQ tahi_02_180[];
extern TAHI_TEST_SEQ tahi_02_181[];
extern TAHI_TEST_SEQ tahi_02_182[];
extern TAHI_TEST_SEQ tahi_02_183[];
extern TAHI_TEST_SEQ tahi_02_184[];
extern TAHI_TEST_SEQ tahi_02_185[];
extern TAHI_TEST_SEQ tahi_02_186[];
extern TAHI_TEST_SEQ tahi_02_187[];
extern TAHI_TEST_SEQ tahi_02_188[];
extern TAHI_TEST_SEQ tahi_02_189[];
extern TAHI_TEST_SEQ tahi_02_190[];
extern TAHI_TEST_SEQ tahi_02_191[];
extern TAHI_TEST_SEQ tahi_02_192[];
extern TAHI_TEST_SEQ tahi_02_193[];
extern TAHI_TEST_SEQ tahi_02_194[];
extern TAHI_TEST_SEQ tahi_02_195[];
extern TAHI_TEST_SEQ tahi_02_196[];
extern TAHI_TEST_SEQ tahi_02_197[];
extern TAHI_TEST_SEQ tahi_02_198[];
extern TAHI_TEST_SEQ tahi_02_199[];
extern TAHI_TEST_SEQ tahi_02_200[];
extern TAHI_TEST_SEQ tahi_02_201[];
extern TAHI_TEST_SEQ tahi_02_202[];
extern TAHI_TEST_SEQ tahi_02_203[];
extern TAHI_TEST_SEQ tahi_02_204[];
extern TAHI_TEST_SEQ tahi_02_205[];
extern TAHI_TEST_SEQ tahi_02_206[];
extern TAHI_TEST_SEQ tahi_02_207[];
extern TAHI_TEST_SEQ tahi_02_208[];
extern TAHI_TEST_SEQ tahi_02_209[];
extern TAHI_TEST_SEQ tahi_02_210[];
extern TAHI_TEST_SEQ tahi_02_211[];
extern TAHI_TEST_SEQ tahi_02_212[];
extern TAHI_TEST_SEQ tahi_02_213[];
extern TAHI_TEST_SEQ tahi_02_214[];
extern TAHI_TEST_SEQ tahi_02_215[];
extern TAHI_TEST_SEQ tahi_02_216[];
extern TAHI_TEST_SEQ tahi_02_217[];
extern TAHI_TEST_SEQ tahi_02_218[];
extern TAHI_TEST_SEQ tahi_02_219[];
extern TAHI_TEST_SEQ tahi_02_220[];
extern TAHI_TEST_SEQ tahi_02_221[];
extern TAHI_TEST_SEQ tahi_02_222[];
extern TAHI_TEST_SEQ tahi_02_223[];
extern TAHI_TEST_SEQ tahi_02_224[];
extern TAHI_TEST_SEQ tahi_02_225[];
extern TAHI_TEST_SEQ tahi_02_226[];
extern TAHI_TEST_SEQ tahi_02_227[];
extern TAHI_TEST_SEQ tahi_02_228[];
extern TAHI_TEST_SEQ tahi_02_229[];

extern TAHI_TEST_SEQ tahi_02_230[];
extern TAHI_TEST_SEQ tahi_02_231[];
extern TAHI_TEST_SEQ tahi_02_232[];
extern TAHI_TEST_SEQ tahi_02_233[];
extern TAHI_TEST_SEQ tahi_02_234[];
extern TAHI_TEST_SEQ tahi_02_235[];
extern TAHI_TEST_SEQ tahi_02_236[];

extern int tahi_02_168_size;
extern int tahi_02_169_size;
extern int tahi_02_170_size;
extern int tahi_02_171_size;
extern int tahi_02_172_size;
extern int tahi_02_173_size;
extern int tahi_02_174_size;
extern int tahi_02_175_size;
extern int tahi_02_176_size;
extern int tahi_02_177_size;
extern int tahi_02_178_size;
extern int tahi_02_179_size;
extern int tahi_02_180_size;
extern int tahi_02_181_size;
extern int tahi_02_182_size;
extern int tahi_02_183_size;
extern int tahi_02_184_size;
extern int tahi_02_185_size;
extern int tahi_02_186_size;
extern int tahi_02_187_size;
extern int tahi_02_188_size;
extern int tahi_02_189_size;
extern int tahi_02_190_size;
extern int tahi_02_191_size;
extern int tahi_02_192_size;
extern int tahi_02_193_size;
extern int tahi_02_194_size;
extern int tahi_02_195_size;
extern int tahi_02_196_size;
extern int tahi_02_197_size;
extern int tahi_02_198_size;
extern int tahi_02_199_size;
extern int tahi_02_200_size;
extern int tahi_02_201_size;
extern int tahi_02_202_size;
extern int tahi_02_203_size;
extern int tahi_02_204_size;
extern int tahi_02_205_size;
extern int tahi_02_206_size;
extern int tahi_02_207_size;
extern int tahi_02_208_size;
extern int tahi_02_209_size;
extern int tahi_02_210_size;
extern int tahi_02_211_size;
extern int tahi_02_212_size;
extern int tahi_02_213_size;
extern int tahi_02_214_size;
extern int tahi_02_215_size;
extern int tahi_02_216_size;
extern int tahi_02_217_size;
extern int tahi_02_218_size;
extern int tahi_02_219_size;

extern int tahi_02_220_size;
extern int tahi_02_221_size;
extern int tahi_02_222_size;
extern int tahi_02_223_size;
extern int tahi_02_224_size;
extern int tahi_02_225_size;
extern int tahi_02_226_size;
extern int tahi_02_227_size;
extern int tahi_02_228_size;
extern int tahi_02_229_size;

extern int tahi_02_230_size;
extern int tahi_02_231_size;
extern int tahi_02_232_size;
extern int tahi_02_233_size;
extern int tahi_02_234_size;
extern int tahi_02_235_size;
extern int tahi_02_236_size;

static TAHI_TEST_SUITE test_suite[69];
static void build_test_suite(void)
{
    test_suite[0].test_case = &tahi_02_168[0]; test_suite[0].test_case_size = tahi_02_168_size;
    test_suite[1].test_case = &tahi_02_169[0]; test_suite[1].test_case_size = tahi_02_169_size;
    test_suite[2].test_case = &tahi_02_170[0]; test_suite[2].test_case_size = tahi_02_170_size;
    test_suite[3].test_case = &tahi_02_171[0]; test_suite[3].test_case_size = tahi_02_171_size;
    test_suite[4].test_case = &tahi_02_172[0]; test_suite[4].test_case_size = tahi_02_172_size;
    test_suite[5].test_case = &tahi_02_173[0]; test_suite[5].test_case_size = tahi_02_173_size;
    test_suite[6].test_case = &tahi_02_174[0]; test_suite[6].test_case_size = tahi_02_174_size;
    test_suite[7].test_case = &tahi_02_175[0]; test_suite[7].test_case_size = tahi_02_175_size;
    test_suite[8].test_case = &tahi_02_176[0]; test_suite[8].test_case_size = tahi_02_176_size;
    test_suite[9].test_case = &tahi_02_177[0]; test_suite[9].test_case_size = tahi_02_177_size;
    test_suite[10].test_case = &tahi_02_178[0]; test_suite[10].test_case_size = tahi_02_178_size;
    test_suite[11].test_case = &tahi_02_179[0]; test_suite[11].test_case_size = tahi_02_179_size;
    test_suite[12].test_case = &tahi_02_180[0]; test_suite[12].test_case_size = tahi_02_180_size;
    test_suite[13].test_case = &tahi_02_181[0]; test_suite[13].test_case_size = tahi_02_181_size;
    test_suite[14].test_case = &tahi_02_182[0]; test_suite[14].test_case_size = tahi_02_182_size;
    test_suite[15].test_case = &tahi_02_183[0]; test_suite[15].test_case_size = tahi_02_183_size;
    test_suite[16].test_case = &tahi_02_184[0]; test_suite[16].test_case_size = tahi_02_184_size;
    test_suite[17].test_case = &tahi_02_185[0]; test_suite[17].test_case_size = tahi_02_185_size;
    test_suite[18].test_case = &tahi_02_186[0]; test_suite[18].test_case_size = tahi_02_186_size;
    test_suite[19].test_case = &tahi_02_187[0]; test_suite[19].test_case_size = tahi_02_187_size;
    test_suite[20].test_case = &tahi_02_188[0]; test_suite[20].test_case_size = tahi_02_188_size;
    test_suite[21].test_case = &tahi_02_189[0]; test_suite[21].test_case_size = tahi_02_189_size;
    test_suite[22].test_case = &tahi_02_190[0]; test_suite[22].test_case_size = tahi_02_190_size;
    test_suite[23].test_case = &tahi_02_191[0]; test_suite[23].test_case_size = tahi_02_191_size;
    test_suite[24].test_case = &tahi_02_192[0]; test_suite[24].test_case_size = tahi_02_192_size;
    test_suite[25].test_case = &tahi_02_193[0]; test_suite[25].test_case_size = tahi_02_193_size;
    test_suite[26].test_case = &tahi_02_194[0]; test_suite[26].test_case_size = tahi_02_194_size;
    test_suite[27].test_case = &tahi_02_195[0]; test_suite[27].test_case_size = tahi_02_195_size;
    test_suite[28].test_case = &tahi_02_196[0]; test_suite[28].test_case_size = tahi_02_196_size;
    test_suite[29].test_case = &tahi_02_197[0]; test_suite[29].test_case_size = tahi_02_197_size;
    test_suite[30].test_case = &tahi_02_198[0]; test_suite[30].test_case_size = tahi_02_198_size;
    test_suite[31].test_case = &tahi_02_199[0]; test_suite[31].test_case_size = tahi_02_199_size;
    test_suite[32].test_case = &tahi_02_200[0]; test_suite[32].test_case_size = tahi_02_200_size;
    test_suite[33].test_case = &tahi_02_201[0]; test_suite[33].test_case_size = tahi_02_201_size;
    test_suite[34].test_case = &tahi_02_202[0]; test_suite[34].test_case_size = tahi_02_202_size;
    test_suite[35].test_case = &tahi_02_203[0]; test_suite[35].test_case_size = tahi_02_203_size;
    test_suite[36].test_case = &tahi_02_204[0]; test_suite[36].test_case_size = tahi_02_204_size;
    test_suite[37].test_case = &tahi_02_205[0]; test_suite[37].test_case_size = tahi_02_205_size; 
    test_suite[38].test_case = &tahi_02_206[0]; test_suite[38].test_case_size = tahi_02_206_size;
    test_suite[39].test_case = &tahi_02_207[0]; test_suite[39].test_case_size = tahi_02_207_size;
    test_suite[40].test_case = &tahi_02_208[0]; test_suite[40].test_case_size = tahi_02_208_size;
    test_suite[41].test_case = &tahi_02_209[0]; test_suite[41].test_case_size = tahi_02_209_size;
    test_suite[42].test_case = &tahi_02_210[0]; test_suite[42].test_case_size = tahi_02_210_size;
    test_suite[43].test_case = &tahi_02_211[0]; test_suite[43].test_case_size = tahi_02_211_size;
    test_suite[44].test_case = &tahi_02_212[0]; test_suite[44].test_case_size = tahi_02_212_size;
    test_suite[45].test_case = &tahi_02_213[0]; test_suite[45].test_case_size = tahi_02_213_size;
    test_suite[46].test_case = &tahi_02_214[0]; test_suite[46].test_case_size = tahi_02_214_size;
    test_suite[47].test_case = &tahi_02_215[0]; test_suite[47].test_case_size = tahi_02_215_size; 
    test_suite[48].test_case = &tahi_02_216[0]; test_suite[48].test_case_size = tahi_02_216_size;
    test_suite[49].test_case = &tahi_02_217[0]; test_suite[49].test_case_size = tahi_02_217_size;
    test_suite[50].test_case = &tahi_02_218[0]; test_suite[50].test_case_size = tahi_02_218_size;
    test_suite[51].test_case = &tahi_02_219[0]; test_suite[51].test_case_size = tahi_02_219_size;
    test_suite[52].test_case = &tahi_02_220[0]; test_suite[52].test_case_size = tahi_02_220_size;
    test_suite[53].test_case = &tahi_02_221[0]; test_suite[53].test_case_size = tahi_02_221_size;
    test_suite[54].test_case = &tahi_02_222[0]; test_suite[54].test_case_size = tahi_02_222_size;
    test_suite[55].test_case = &tahi_02_223[0]; test_suite[55].test_case_size = tahi_02_223_size;
    test_suite[56].test_case = &tahi_02_224[0]; test_suite[56].test_case_size = tahi_02_224_size;
    test_suite[57].test_case = &tahi_02_225[0]; test_suite[57].test_case_size = tahi_02_225_size; 
    test_suite[58].test_case = &tahi_02_226[0]; test_suite[58].test_case_size = tahi_02_226_size;
    test_suite[59].test_case = &tahi_02_227[0]; test_suite[59].test_case_size = tahi_02_227_size;
    test_suite[60].test_case = &tahi_02_228[0]; test_suite[60].test_case_size = tahi_02_228_size;  
    test_suite[61].test_case = &tahi_02_229[0]; test_suite[61].test_case_size = tahi_02_229_size;
    test_suite[62].test_case = &tahi_02_230[0]; test_suite[62].test_case_size = tahi_02_230_size;
    test_suite[63].test_case = &tahi_02_231[0]; test_suite[63].test_case_size = tahi_02_231_size;
    test_suite[64].test_case = &tahi_02_232[0]; test_suite[64].test_case_size = tahi_02_232_size;
    test_suite[65].test_case = &tahi_02_233[0]; test_suite[65].test_case_size = tahi_02_233_size;
    test_suite[66].test_case = &tahi_02_234[0]; test_suite[66].test_case_size = tahi_02_234_size;
    test_suite[67].test_case = &tahi_02_235[0]; test_suite[67].test_case_size = tahi_02_235_size; 
    test_suite[68].test_case = &tahi_02_236[0]; test_suite[68].test_case_size = tahi_02_236_size;
}


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tahi_test_2_11_define(void *first_unused_memory)
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
