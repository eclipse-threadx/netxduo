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
extern TAHI_TEST_SEQ tahi_02_001[];
extern TAHI_TEST_SEQ tahi_02_002[];
extern TAHI_TEST_SEQ tahi_02_003[];
extern TAHI_TEST_SEQ tahi_02_004[];
extern TAHI_TEST_SEQ tahi_02_005[];
extern TAHI_TEST_SEQ tahi_02_006[];
extern TAHI_TEST_SEQ tahi_02_007[];
extern TAHI_TEST_SEQ tahi_02_008[];
extern TAHI_TEST_SEQ tahi_02_009[];
extern TAHI_TEST_SEQ tahi_02_010[];
extern TAHI_TEST_SEQ tahi_02_011[];
extern TAHI_TEST_SEQ tahi_02_012[];
extern TAHI_TEST_SEQ tahi_02_013[];
extern TAHI_TEST_SEQ tahi_02_014[];
extern TAHI_TEST_SEQ tahi_02_015[];
extern TAHI_TEST_SEQ tahi_02_016[];
extern TAHI_TEST_SEQ tahi_02_017[];
extern TAHI_TEST_SEQ tahi_02_018[];
extern TAHI_TEST_SEQ tahi_02_019[];
extern TAHI_TEST_SEQ tahi_02_020[];
extern TAHI_TEST_SEQ tahi_02_021[];
extern TAHI_TEST_SEQ tahi_02_022[];
extern TAHI_TEST_SEQ tahi_02_023[];
extern TAHI_TEST_SEQ tahi_02_024[];
extern TAHI_TEST_SEQ tahi_02_025[];
extern TAHI_TEST_SEQ tahi_02_026[];
extern TAHI_TEST_SEQ tahi_02_027[];
extern TAHI_TEST_SEQ tahi_02_028[];
extern TAHI_TEST_SEQ tahi_02_029[];
extern TAHI_TEST_SEQ tahi_02_030[];
extern TAHI_TEST_SEQ tahi_02_031[];
extern TAHI_TEST_SEQ tahi_02_032[];
extern TAHI_TEST_SEQ tahi_02_033[];
extern TAHI_TEST_SEQ tahi_02_034[];
extern TAHI_TEST_SEQ tahi_02_035[];
extern TAHI_TEST_SEQ tahi_02_036[];
extern TAHI_TEST_SEQ tahi_02_037[];
extern TAHI_TEST_SEQ tahi_02_038[];
extern TAHI_TEST_SEQ tahi_02_039[];
extern TAHI_TEST_SEQ tahi_02_040[];
extern TAHI_TEST_SEQ tahi_02_041[];
extern TAHI_TEST_SEQ tahi_02_042[];
extern TAHI_TEST_SEQ tahi_02_043[];
extern TAHI_TEST_SEQ tahi_02_044[];
extern TAHI_TEST_SEQ tahi_02_045[];
extern TAHI_TEST_SEQ tahi_02_046[];
extern TAHI_TEST_SEQ tahi_02_047[];
extern TAHI_TEST_SEQ tahi_02_048[];
extern TAHI_TEST_SEQ tahi_02_049[];
extern TAHI_TEST_SEQ tahi_02_050[];
extern TAHI_TEST_SEQ tahi_02_051[];
extern TAHI_TEST_SEQ tahi_02_052[];
extern TAHI_TEST_SEQ tahi_02_053[];
extern TAHI_TEST_SEQ tahi_02_054[];
extern TAHI_TEST_SEQ tahi_02_055[];
extern TAHI_TEST_SEQ tahi_02_056[];
extern TAHI_TEST_SEQ tahi_02_057[];
extern TAHI_TEST_SEQ tahi_02_058[];
extern TAHI_TEST_SEQ tahi_02_059[];
extern TAHI_TEST_SEQ tahi_02_060[];
extern TAHI_TEST_SEQ tahi_02_061[];
extern TAHI_TEST_SEQ tahi_02_062[];
extern TAHI_TEST_SEQ tahi_02_063[];
extern TAHI_TEST_SEQ tahi_02_064[];
extern TAHI_TEST_SEQ tahi_02_065[];
extern TAHI_TEST_SEQ tahi_02_066[];
extern TAHI_TEST_SEQ tahi_02_067[];
extern TAHI_TEST_SEQ tahi_02_068[];
extern TAHI_TEST_SEQ tahi_02_069[];
extern TAHI_TEST_SEQ tahi_02_070[];
extern TAHI_TEST_SEQ tahi_02_071[];
extern TAHI_TEST_SEQ tahi_02_072[];
extern TAHI_TEST_SEQ tahi_02_073[];
extern TAHI_TEST_SEQ tahi_02_074[];
extern TAHI_TEST_SEQ tahi_02_075[];
extern TAHI_TEST_SEQ tahi_02_076[];
extern TAHI_TEST_SEQ tahi_02_077[];
extern TAHI_TEST_SEQ tahi_02_078[];
extern TAHI_TEST_SEQ tahi_02_079[];
extern TAHI_TEST_SEQ tahi_02_080[];
extern TAHI_TEST_SEQ tahi_02_081[];
extern TAHI_TEST_SEQ tahi_02_082[];
extern TAHI_TEST_SEQ tahi_02_083[];
extern TAHI_TEST_SEQ tahi_02_084[];
extern TAHI_TEST_SEQ tahi_02_085[];
extern TAHI_TEST_SEQ tahi_02_086[];
extern TAHI_TEST_SEQ tahi_02_087[];
extern TAHI_TEST_SEQ tahi_02_088[];
extern TAHI_TEST_SEQ tahi_02_089[];
extern TAHI_TEST_SEQ tahi_02_090[];
extern TAHI_TEST_SEQ tahi_02_091[];
extern TAHI_TEST_SEQ tahi_02_092[];
extern TAHI_TEST_SEQ tahi_02_093[];
extern TAHI_TEST_SEQ tahi_02_094[];
extern TAHI_TEST_SEQ tahi_02_095[];
extern TAHI_TEST_SEQ tahi_02_096[];
extern TAHI_TEST_SEQ tahi_02_097[];
extern TAHI_TEST_SEQ tahi_02_098[];
extern TAHI_TEST_SEQ tahi_02_099[];

extern TAHI_TEST_SEQ tahi_02_100[];
extern TAHI_TEST_SEQ tahi_02_101[];
extern TAHI_TEST_SEQ tahi_02_102[];
extern TAHI_TEST_SEQ tahi_02_103[];
extern TAHI_TEST_SEQ tahi_02_104[];
extern TAHI_TEST_SEQ tahi_02_105[];
extern TAHI_TEST_SEQ tahi_02_106[];
extern TAHI_TEST_SEQ tahi_02_107[];
extern TAHI_TEST_SEQ tahi_02_108[];
extern TAHI_TEST_SEQ tahi_02_109[];
extern TAHI_TEST_SEQ tahi_02_110[];
extern TAHI_TEST_SEQ tahi_02_111[];
extern TAHI_TEST_SEQ tahi_02_112[];
extern TAHI_TEST_SEQ tahi_02_113[];
extern TAHI_TEST_SEQ tahi_02_114[];
extern TAHI_TEST_SEQ tahi_02_115[];
extern TAHI_TEST_SEQ tahi_02_116[];
extern TAHI_TEST_SEQ tahi_02_117[];
extern TAHI_TEST_SEQ tahi_02_118[];
extern TAHI_TEST_SEQ tahi_02_119[];
extern TAHI_TEST_SEQ tahi_02_120[];
extern TAHI_TEST_SEQ tahi_02_121[];
extern TAHI_TEST_SEQ tahi_02_122[];
extern TAHI_TEST_SEQ tahi_02_123[];
extern TAHI_TEST_SEQ tahi_02_124[];
extern TAHI_TEST_SEQ tahi_02_125[];
extern TAHI_TEST_SEQ tahi_02_126[];

extern int tahi_02_001_size;
extern int tahi_02_002_size;
extern int tahi_02_003_size;
extern int tahi_02_004_size;
extern int tahi_02_005_size;
extern int tahi_02_006_size;
extern int tahi_02_007_size;
extern int tahi_02_008_size;
extern int tahi_02_009_size;
extern int tahi_02_010_size;
extern int tahi_02_011_size;
extern int tahi_02_012_size;
extern int tahi_02_013_size;
extern int tahi_02_014_size;
extern int tahi_02_015_size;
extern int tahi_02_016_size;
extern int tahi_02_017_size;
extern int tahi_02_018_size;
extern int tahi_02_019_size;
extern int tahi_02_020_size;
extern int tahi_02_021_size;
extern int tahi_02_022_size;
extern int tahi_02_023_size;
extern int tahi_02_024_size;
extern int tahi_02_025_size;
extern int tahi_02_026_size;
extern int tahi_02_027_size;
extern int tahi_02_028_size;
extern int tahi_02_029_size;
extern int tahi_02_030_size;
extern int tahi_02_031_size;
extern int tahi_02_032_size;
extern int tahi_02_033_size;
extern int tahi_02_034_size;
extern int tahi_02_035_size;
extern int tahi_02_036_size;
extern int tahi_02_037_size;
extern int tahi_02_038_size;
extern int tahi_02_039_size;
extern int tahi_02_040_size;
extern int tahi_02_041_size;
extern int tahi_02_042_size;
extern int tahi_02_043_size;
extern int tahi_02_044_size;
extern int tahi_02_045_size;
extern int tahi_02_046_size;
extern int tahi_02_047_size;
extern int tahi_02_048_size;
extern int tahi_02_049_size;
extern int tahi_02_050_size;
extern int tahi_02_051_size;
extern int tahi_02_052_size;
extern int tahi_02_053_size;
extern int tahi_02_054_size;
extern int tahi_02_055_size;
extern int tahi_02_056_size;
extern int tahi_02_057_size;
extern int tahi_02_058_size;
extern int tahi_02_059_size;
extern int tahi_02_060_size;
extern int tahi_02_061_size;
extern int tahi_02_062_size;
extern int tahi_02_063_size;
extern int tahi_02_064_size;
extern int tahi_02_065_size;
extern int tahi_02_066_size;
extern int tahi_02_067_size;
extern int tahi_02_068_size;
extern int tahi_02_069_size;
extern int tahi_02_070_size;
extern int tahi_02_071_size;
extern int tahi_02_072_size;
extern int tahi_02_073_size;
extern int tahi_02_074_size;
extern int tahi_02_075_size;
extern int tahi_02_076_size;
extern int tahi_02_077_size;
extern int tahi_02_078_size;
extern int tahi_02_079_size;
extern int tahi_02_080_size;
extern int tahi_02_081_size;
extern int tahi_02_082_size;
extern int tahi_02_083_size;
extern int tahi_02_084_size;
extern int tahi_02_085_size;
extern int tahi_02_086_size;
extern int tahi_02_087_size;
extern int tahi_02_088_size;
extern int tahi_02_089_size;
extern int tahi_02_090_size;
extern int tahi_02_091_size;
extern int tahi_02_092_size;
extern int tahi_02_093_size;
extern int tahi_02_094_size;
extern int tahi_02_095_size;
extern int tahi_02_096_size;
extern int tahi_02_097_size;
extern int tahi_02_098_size;
extern int tahi_02_099_size;

extern int tahi_02_100_size;
extern int tahi_02_101_size;
extern int tahi_02_102_size;
extern int tahi_02_103_size;
extern int tahi_02_104_size;
extern int tahi_02_105_size;
extern int tahi_02_106_size;
extern int tahi_02_107_size;
extern int tahi_02_108_size;
extern int tahi_02_109_size;
extern int tahi_02_110_size;
extern int tahi_02_111_size;
extern int tahi_02_112_size;
extern int tahi_02_113_size;
extern int tahi_02_114_size;
extern int tahi_02_115_size;
extern int tahi_02_116_size;
extern int tahi_02_117_size;
extern int tahi_02_118_size;
extern int tahi_02_119_size;
extern int tahi_02_120_size;
extern int tahi_02_121_size;
extern int tahi_02_122_size;
extern int tahi_02_123_size;
extern int tahi_02_124_size;
extern int tahi_02_125_size;
extern int tahi_02_126_size;

static TAHI_TEST_SUITE test_suite[126];
static void build_test_suite(void)
{

    test_suite[0].test_case = &tahi_02_001[0]; test_suite[0].test_case_size = tahi_02_001_size;
    test_suite[1].test_case = &tahi_02_002[0]; test_suite[1].test_case_size = tahi_02_002_size;
    test_suite[2].test_case = &tahi_02_003[0]; test_suite[2].test_case_size = tahi_02_003_size;
    test_suite[3].test_case = &tahi_02_004[0]; test_suite[3].test_case_size = tahi_02_004_size;
    test_suite[4].test_case = &tahi_02_005[0]; test_suite[4].test_case_size = tahi_02_005_size;   
    test_suite[5].test_case = &tahi_02_006[0]; test_suite[5].test_case_size = tahi_02_006_size;
    test_suite[6].test_case = &tahi_02_007[0]; test_suite[6].test_case_size = tahi_02_007_size;  
    test_suite[7].test_case = &tahi_02_008[0]; test_suite[7].test_case_size = tahi_02_008_size;
    test_suite[8].test_case = &tahi_02_009[0]; test_suite[8].test_case_size = tahi_02_009_size;
    test_suite[9].test_case = &tahi_02_010[0]; test_suite[9].test_case_size = tahi_02_010_size;
    test_suite[10].test_case = &tahi_02_011[0]; test_suite[10].test_case_size = tahi_02_011_size;
    test_suite[11].test_case = &tahi_02_012[0]; test_suite[11].test_case_size = tahi_02_012_size;
    test_suite[12].test_case = &tahi_02_013[0]; test_suite[12].test_case_size = tahi_02_013_size;
    test_suite[13].test_case = &tahi_02_014[0]; test_suite[13].test_case_size = tahi_02_014_size;
    test_suite[14].test_case = &tahi_02_015[0]; test_suite[14].test_case_size = tahi_02_015_size;
    test_suite[15].test_case = &tahi_02_016[0]; test_suite[15].test_case_size = tahi_02_016_size;
    test_suite[16].test_case = &tahi_02_017[0]; test_suite[16].test_case_size = tahi_02_017_size;
    test_suite[17].test_case = &tahi_02_018[0]; test_suite[17].test_case_size = tahi_02_018_size;
    test_suite[18].test_case = &tahi_02_019[0]; test_suite[18].test_case_size = tahi_02_019_size;
    test_suite[19].test_case = &tahi_02_020[0]; test_suite[19].test_case_size = tahi_02_020_size;
    test_suite[20].test_case = &tahi_02_021[0]; test_suite[20].test_case_size = tahi_02_021_size;
    test_suite[21].test_case = &tahi_02_022[0]; test_suite[21].test_case_size = tahi_02_022_size;
    test_suite[22].test_case = &tahi_02_023[0]; test_suite[22].test_case_size = tahi_02_023_size;
    test_suite[23].test_case = &tahi_02_024[0]; test_suite[23].test_case_size = tahi_02_024_size;
    test_suite[24].test_case = &tahi_02_025[0]; test_suite[24].test_case_size = tahi_02_025_size;
    test_suite[25].test_case = &tahi_02_026[0]; test_suite[25].test_case_size = tahi_02_026_size;
    test_suite[26].test_case = &tahi_02_027[0]; test_suite[26].test_case_size = tahi_02_027_size;
    test_suite[27].test_case = &tahi_02_028[0]; test_suite[27].test_case_size = tahi_02_028_size;
    test_suite[28].test_case = &tahi_02_029[0]; test_suite[28].test_case_size = tahi_02_029_size; 
    test_suite[29].test_case = &tahi_02_030[0]; test_suite[29].test_case_size = tahi_02_030_size;
    test_suite[30].test_case = &tahi_02_031[0]; test_suite[30].test_case_size = tahi_02_031_size;
    test_suite[31].test_case = &tahi_02_032[0]; test_suite[31].test_case_size = tahi_02_032_size;
    test_suite[32].test_case = &tahi_02_033[0]; test_suite[32].test_case_size = tahi_02_033_size;
    test_suite[33].test_case = &tahi_02_034[0]; test_suite[33].test_case_size = tahi_02_034_size;
    test_suite[34].test_case = &tahi_02_035[0]; test_suite[34].test_case_size = tahi_02_035_size;
    test_suite[35].test_case = &tahi_02_036[0]; test_suite[35].test_case_size = tahi_02_036_size;
    test_suite[36].test_case = &tahi_02_037[0]; test_suite[36].test_case_size = tahi_02_037_size;
    test_suite[37].test_case = &tahi_02_038[0]; test_suite[37].test_case_size = tahi_02_038_size;
    test_suite[38].test_case = &tahi_02_039[0]; test_suite[38].test_case_size = tahi_02_039_size;
    test_suite[39].test_case = &tahi_02_040[0]; test_suite[39].test_case_size = tahi_02_040_size;
    test_suite[40].test_case = &tahi_02_041[0]; test_suite[40].test_case_size = tahi_02_041_size;
    test_suite[41].test_case = &tahi_02_042[0]; test_suite[41].test_case_size = tahi_02_042_size;
    test_suite[42].test_case = &tahi_02_043[0]; test_suite[42].test_case_size = tahi_02_043_size;
    test_suite[43].test_case = &tahi_02_044[0]; test_suite[43].test_case_size = tahi_02_044_size;
    test_suite[44].test_case = &tahi_02_045[0]; test_suite[44].test_case_size = tahi_02_045_size;
    test_suite[45].test_case = &tahi_02_046[0]; test_suite[45].test_case_size = tahi_02_046_size;
    test_suite[46].test_case = &tahi_02_047[0]; test_suite[46].test_case_size = tahi_02_047_size;
    test_suite[47].test_case = &tahi_02_048[0]; test_suite[47].test_case_size = tahi_02_048_size;
    test_suite[48].test_case = &tahi_02_049[0]; test_suite[48].test_case_size = tahi_02_049_size;
    test_suite[49].test_case = &tahi_02_050[0]; test_suite[49].test_case_size = tahi_02_050_size;
    test_suite[50].test_case = &tahi_02_051[0]; test_suite[50].test_case_size = tahi_02_051_size;
    test_suite[51].test_case = &tahi_02_052[0]; test_suite[51].test_case_size = tahi_02_052_size;
    test_suite[52].test_case = &tahi_02_053[0]; test_suite[52].test_case_size = tahi_02_053_size;
    test_suite[53].test_case = &tahi_02_054[0]; test_suite[53].test_case_size = tahi_02_054_size;
    test_suite[54].test_case = &tahi_02_055[0]; test_suite[54].test_case_size = tahi_02_055_size;
    test_suite[55].test_case = &tahi_02_056[0]; test_suite[55].test_case_size = tahi_02_056_size;
    test_suite[56].test_case = &tahi_02_057[0]; test_suite[56].test_case_size = tahi_02_057_size;
    test_suite[57].test_case = &tahi_02_058[0]; test_suite[57].test_case_size = tahi_02_058_size;
    test_suite[58].test_case = &tahi_02_059[0]; test_suite[58].test_case_size = tahi_02_059_size;
    test_suite[59].test_case = &tahi_02_060[0]; test_suite[59].test_case_size = tahi_02_060_size;
    test_suite[60].test_case = &tahi_02_061[0]; test_suite[60].test_case_size = tahi_02_061_size;
    test_suite[61].test_case = &tahi_02_062[0]; test_suite[61].test_case_size = tahi_02_062_size;
    test_suite[62].test_case = &tahi_02_063[0]; test_suite[62].test_case_size = tahi_02_063_size;
    test_suite[63].test_case = &tahi_02_064[0]; test_suite[63].test_case_size = tahi_02_064_size;
    test_suite[64].test_case = &tahi_02_065[0]; test_suite[64].test_case_size = tahi_02_065_size;
    test_suite[65].test_case = &tahi_02_066[0]; test_suite[65].test_case_size = tahi_02_066_size;
    test_suite[66].test_case = &tahi_02_067[0]; test_suite[66].test_case_size = tahi_02_067_size;
    test_suite[67].test_case = &tahi_02_068[0]; test_suite[67].test_case_size = tahi_02_068_size;
    test_suite[68].test_case = &tahi_02_069[0]; test_suite[68].test_case_size = tahi_02_069_size;
    test_suite[69].test_case = &tahi_02_070[0]; test_suite[69].test_case_size = tahi_02_070_size;
    test_suite[70].test_case = &tahi_02_071[0]; test_suite[70].test_case_size = tahi_02_071_size;
    test_suite[71].test_case = &tahi_02_072[0]; test_suite[71].test_case_size = tahi_02_072_size;
    test_suite[72].test_case = &tahi_02_073[0]; test_suite[72].test_case_size = tahi_02_073_size;
    test_suite[73].test_case = &tahi_02_074[0]; test_suite[73].test_case_size = tahi_02_074_size;
    test_suite[74].test_case = &tahi_02_075[0]; test_suite[74].test_case_size = tahi_02_075_size;
    test_suite[75].test_case = &tahi_02_076[0]; test_suite[75].test_case_size = tahi_02_076_size;
    test_suite[76].test_case = &tahi_02_077[0]; test_suite[76].test_case_size = tahi_02_077_size;
    test_suite[77].test_case = &tahi_02_078[0]; test_suite[77].test_case_size = tahi_02_078_size;
    test_suite[78].test_case = &tahi_02_079[0]; test_suite[78].test_case_size = tahi_02_079_size;
    test_suite[79].test_case = &tahi_02_080[0]; test_suite[79].test_case_size = tahi_02_080_size;
    test_suite[80].test_case = &tahi_02_081[0]; test_suite[80].test_case_size = tahi_02_081_size;
    test_suite[81].test_case = &tahi_02_082[0]; test_suite[81].test_case_size = tahi_02_082_size;
    test_suite[82].test_case = &tahi_02_083[0]; test_suite[82].test_case_size = tahi_02_083_size;
    test_suite[83].test_case = &tahi_02_084[0]; test_suite[83].test_case_size = tahi_02_084_size;
    test_suite[84].test_case = &tahi_02_085[0]; test_suite[84].test_case_size = tahi_02_085_size;
    test_suite[85].test_case = &tahi_02_086[0]; test_suite[85].test_case_size = tahi_02_086_size;
    test_suite[86].test_case = &tahi_02_087[0]; test_suite[86].test_case_size = tahi_02_087_size;
    test_suite[87].test_case = &tahi_02_088[0]; test_suite[87].test_case_size = tahi_02_088_size;
    test_suite[88].test_case = &tahi_02_089[0]; test_suite[88].test_case_size = tahi_02_089_size;
    test_suite[89].test_case = &tahi_02_090[0]; test_suite[89].test_case_size = tahi_02_090_size;
    test_suite[90].test_case = &tahi_02_091[0]; test_suite[90].test_case_size = tahi_02_091_size;
    test_suite[91].test_case = &tahi_02_092[0]; test_suite[91].test_case_size = tahi_02_092_size;
    test_suite[92].test_case = &tahi_02_093[0]; test_suite[92].test_case_size = tahi_02_093_size;
    test_suite[93].test_case = &tahi_02_094[0]; test_suite[93].test_case_size = tahi_02_094_size;
    test_suite[94].test_case = &tahi_02_095[0]; test_suite[94].test_case_size = tahi_02_095_size;
    test_suite[95].test_case = &tahi_02_096[0]; test_suite[95].test_case_size = tahi_02_096_size;
    test_suite[96].test_case = &tahi_02_097[0]; test_suite[96].test_case_size = tahi_02_097_size;
    test_suite[97].test_case = &tahi_02_098[0]; test_suite[97].test_case_size = tahi_02_098_size;
    test_suite[98].test_case = &tahi_02_099[0]; test_suite[98].test_case_size = tahi_02_099_size;
    test_suite[99].test_case = &tahi_02_100[0]; test_suite[99].test_case_size = tahi_02_100_size;
    test_suite[100].test_case = &tahi_02_101[0]; test_suite[100].test_case_size = tahi_02_101_size;
    test_suite[101].test_case = &tahi_02_102[0]; test_suite[101].test_case_size = tahi_02_102_size;
    test_suite[102].test_case = &tahi_02_103[0]; test_suite[102].test_case_size = tahi_02_103_size;
    test_suite[103].test_case = &tahi_02_104[0]; test_suite[103].test_case_size = tahi_02_104_size;
    test_suite[104].test_case = &tahi_02_105[0]; test_suite[104].test_case_size = tahi_02_105_size;
    test_suite[105].test_case = &tahi_02_106[0]; test_suite[105].test_case_size = tahi_02_106_size;
    test_suite[106].test_case = &tahi_02_107[0]; test_suite[106].test_case_size = tahi_02_107_size;
    test_suite[107].test_case = &tahi_02_108[0]; test_suite[107].test_case_size = tahi_02_108_size;
    test_suite[108].test_case = &tahi_02_109[0]; test_suite[108].test_case_size = tahi_02_109_size;
    test_suite[109].test_case = &tahi_02_110[0]; test_suite[109].test_case_size = tahi_02_110_size;
    test_suite[110].test_case = &tahi_02_111[0]; test_suite[110].test_case_size = tahi_02_111_size;
    test_suite[111].test_case = &tahi_02_112[0]; test_suite[111].test_case_size = tahi_02_112_size;
    test_suite[112].test_case = &tahi_02_113[0]; test_suite[112].test_case_size = tahi_02_113_size;
    test_suite[113].test_case = &tahi_02_114[0]; test_suite[113].test_case_size = tahi_02_114_size;
    test_suite[114].test_case = &tahi_02_115[0]; test_suite[114].test_case_size = tahi_02_115_size;
    test_suite[115].test_case = &tahi_02_116[0]; test_suite[115].test_case_size = tahi_02_116_size;
    test_suite[116].test_case = &tahi_02_117[0]; test_suite[116].test_case_size = tahi_02_117_size;
    test_suite[117].test_case = &tahi_02_118[0]; test_suite[117].test_case_size = tahi_02_118_size;
    test_suite[118].test_case = &tahi_02_119[0]; test_suite[118].test_case_size = tahi_02_119_size;
    test_suite[119].test_case = &tahi_02_120[0]; test_suite[119].test_case_size = tahi_02_120_size;
    test_suite[120].test_case = &tahi_02_121[0]; test_suite[120].test_case_size = tahi_02_121_size;
    test_suite[121].test_case = &tahi_02_122[0]; test_suite[121].test_case_size = tahi_02_122_size;
    test_suite[122].test_case = &tahi_02_123[0]; test_suite[122].test_case_size = tahi_02_123_size;
    test_suite[123].test_case = &tahi_02_124[0]; test_suite[123].test_case_size = tahi_02_124_size;
    test_suite[124].test_case = &tahi_02_125[0]; test_suite[124].test_case_size = tahi_02_125_size;
    test_suite[125].test_case = &tahi_02_126[0]; test_suite[125].test_case_size = tahi_02_126_size;
}


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tahi_test_2_1_define(void *first_unused_memory)
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

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check ARP enable status.  */
    if(status)
        error_counter++;


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

    test_control_return(0xdeadbeef);

    /* Clear the flags. */

}
#endif
