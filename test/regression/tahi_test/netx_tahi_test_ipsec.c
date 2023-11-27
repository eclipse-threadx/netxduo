#include    "tx_api.h"
#include    "nx_api.h"
#include    "netx_tahi.h"

#if defined FEATURE_NX_IPV6 && defined NX_IPSEC_ENABLE && defined NX_TAHI_ENABLE

#include    "nx_tcp.h"
#include    "nx_ip.h"
#include    "nx_ipv6.h"
#include    "nx_icmpv6.h"
#include    "nx_ipsec.h"
#include    "nx_crypto.h"
#include    "nx_crypto_3des.h"
#include    "nx_crypto_aes.h"
#include    "nx_crypto_des.h"
#include    "nx_crypto_dh.h"
#include    "nx_crypto_hmac_md5.h"
#include    "nx_crypto_hmac_sha1.h"
#include    "nx_crypto_md5.h"
#include    "nx_crypto_null.h"
#include    "nx_crypto_sha1.h"

#define     DEMO_STACK_SIZE    2048
#define     TEST_INTERFACE     0
#define     IPSEC_MAX_END_NODE 10
#define     IPSEC_SA_LIFETIME  5000

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               thread_0;


static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;

/* Define the counters used in the demo application...  */

static ULONG                   error_counter;
static NXD_ADDRESS             ipv6_address_1;
static NXD_ADDRESS             ipv6_address_2;

/* Define IPSEC related data. */

static NX_IPSEC_SELECTOR   ingress_selectors[IPSEC_MAX_END_NODE];
static NX_IPSEC_SELECTOR   egress_selectors[IPSEC_MAX_END_NODE];
static NX_IPSEC_SA         ingress_sa[IPSEC_MAX_END_NODE];
static NX_IPSEC_SA         egress_sa[IPSEC_MAX_END_NODE];
static UCHAR               ingress_hmac_sha1[IPSEC_MAX_END_NODE][20];
static UCHAR               ingress_3des_cbc[IPSEC_MAX_END_NODE][24];
static UCHAR               ingress_aes_cbc[IPSEC_MAX_END_NODE][32];
static UCHAR               egress_hmac_sha1[IPSEC_MAX_END_NODE][20];
static UCHAR               egress_3des_cbc[IPSEC_MAX_END_NODE][24];
static UCHAR               egress_aes_cbc[IPSEC_MAX_END_NODE][32];
static UCHAR               egress_aes_xcbc_mac[32];
static UCHAR               ingress_aes_xcbc_mac[32];
static ULONG               egress_spi[IPSEC_MAX_END_NODE];
static ULONG               ingress_spi[IPSEC_MAX_END_NODE];
static UCHAR               ingress_aes_ctr[32];
static UCHAR               egress_aes_ctr[32];

/* Define the Crypto Method */

static NX_CRYPTO_3DES egress_3des[IPSEC_MAX_END_NODE];
static NX_CRYPTO_3DES ingress_3des[IPSEC_MAX_END_NODE];
static NX_SHA1_HMAC   metadata_egress_hmac_sha1[IPSEC_MAX_END_NODE];
static NX_SHA1_HMAC   metadata_ingress_hmac_sha1[IPSEC_MAX_END_NODE];


/* 3DES, encrypt */
static NX_CRYPTO_METHOD crypto_method_t_des =  
{
    NX_CRYPTO_ENCRYPTION_3DES_CBC,             /* 3DES-CBC crypto algorithm               */
    NX_CRYPTO_3DES_KEY_LEN_IN_BITS,            /* Key size in bits                        */
    NX_CRYPTO_3DES_IV_LEN_IN_BITS,             /* IV size in bits                         */
    0,                                         /* ICV size in bits, not used              */
    (NX_CRYPTO_3DES_BLOCK_SIZE_IN_BITS>>3),    /* Block size in bytes                     */
    sizeof(NX_CRYPTO_3DES), /* 768 */          /* Metadata size in bytes                  */
    _nx_ipsec_crypto_method_3des_init,         /* 3DES-CBC initialization routine.        */
    NX_NULL,                                   /* 3DES-CBC cleanup routine, not used      */
    _nx_ipsec_crypto_method_3des_operation     /* 3DES-CBC operation                      */
};

/* HMAC SHA1 */
static NX_CRYPTO_METHOD crypto_method_hmac_sha1 = 
{
    NX_CRYPTO_AUTHENTICATION_HMAC_SHA1_96,        /* HMAC SHA1 algorithm                   */
    NX_CRYPTO_HMAC_SHA1_KEY_LEN_IN_BITS,          /* Key size in bits                      */ 
    0,                                            /* IV size in bits, not used             */
    NX_CRYPTO_AUTHENTICATION_ICV_TRUNC_BITS,      /* Transmitted ICV size in bits          */
    0,                                            /* Block size in bytes, not used         */
    0,                                            /* Metadata size in bytes                */
    NX_NULL,                                      /* Initialization routine, not used      */
    NX_NULL,                                      /* Cleanup routine, not used             */
    _nx_ipsec_crypto_method_hmac_sha1_operation   /* HMAC SHA1 operation                   */
};

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    test_control_return(UINT status);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);
extern UINT    (*packet_process_callback)(NX_IP *ip_ptr, NX_PACKET *packet_ptr);
static void    init_para();
static UINT    clean_sa();
static VOID    sa_timeout_process(NX_IP *ip_ptr, NX_IPSEC_SA *sa);

static UINT    create_sa(UINT index, UCHAR sa_mode,
                         NX_CRYPTO_METHOD* sa_encryption_method_ingress, NX_CRYPTO_METHOD* sa_encryption_method_egress,
                         UCHAR *sa_encryption_key_ingress, UCHAR *sa_encryption_key_egress, 
                         UINT sa_encryption_key_len_in_bits,
                         NX_CRYPTO_METHOD* sa_integrity_method, 
                         UCHAR *sa_integrity_key_ingress, UCHAR *sa_integrity_key_egress, 
                         UINT sa_integrity_key_len_in_bits, 
                         VOID *crypto_metadata_area_ingress, VOID *crypto_metadata_area_egress, ULONG crypto_metadata_size,
                         VOID *authentication_metadata_area_ingress, VOID *authentication_metadata_area_egress, ULONG authentication_metadata_size);

/* Define the test threads.  */
extern TAHI_TEST_SEQ tahi_ipsec_001[];
extern TAHI_TEST_SEQ tahi_ipsec_002[];
extern TAHI_TEST_SEQ tahi_ipsec_003[];
extern TAHI_TEST_SEQ tahi_ipsec_004[];
extern TAHI_TEST_SEQ tahi_ipsec_005[];

extern int tahi_ipsec_001_size;
extern int tahi_ipsec_002_size;
extern int tahi_ipsec_003_size;
extern int tahi_ipsec_004_size;
extern int tahi_ipsec_005_size;

static TAHI_TEST_SUITE test_suite[10];

static void build_test_suite(void)
{
    test_suite[0].test_case = &tahi_ipsec_001[0]; test_suite[0].test_case_size = tahi_ipsec_001_size;
    test_suite[1].test_case = &tahi_ipsec_002[0]; test_suite[1].test_case_size = tahi_ipsec_002_size;
    test_suite[2].test_case = &tahi_ipsec_003[0]; test_suite[2].test_case_size = tahi_ipsec_003_size;
    test_suite[3].test_case = &tahi_ipsec_004[0]; test_suite[3].test_case_size = tahi_ipsec_004_size;
    test_suite[4].test_case = &tahi_ipsec_005[0]; test_suite[4].test_case_size = tahi_ipsec_005_size;
}


/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void           netx_tahi_test_ipsec_define(void *first_unused_memory)
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

    /* Check IP create status.  */
    if(status)
        error_counter++;

    pointer = pointer + 2048;

    /* Enable ICMP for IP Instance 0 and 1.  */
    status = nxd_icmp_enable(&ip_0);

    /* Check ARP enable status.  */
    if(status)
        error_counter++;


    /* Enable IPv6 */
    status += nxd_ipv6_enable(&ip_0);

    /* Enable IPv6 */
    status += nx_ipsec_enable(&ip_0);

    /* Enable UDP   */
    status += nx_udp_enable(&ip_0);

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status += nx_arp_enable(&ip_0, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable fragment processing for IP Instance 0.  */
    status = nx_ip_fragment_enable(&ip_0);

    /* Set ipv6 version and address.  */
    ipv6_address_1.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_1.nxd_ip_address.v6[0] = 0xfe800000;
    ipv6_address_1.nxd_ip_address.v6[1] = 0x00000000;
    ipv6_address_1.nxd_ip_address.v6[2] = 0x021122ff;
    ipv6_address_1.nxd_ip_address.v6[3] = 0xfe334456;

    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_1, 64, NX_NULL);

    /* Set ipv6 version and address.  */
    ipv6_address_2.nxd_ip_version = NX_IP_VERSION_V6;
    ipv6_address_2.nxd_ip_address.v6[0] = 0x3ffe0501;
    ipv6_address_2.nxd_ip_address.v6[1] = 0xffff0000;
    ipv6_address_2.nxd_ip_address.v6[2] = 0x021122ff;
    ipv6_address_2.nxd_ip_address.v6[3] = 0xfe334456;

    status += nxd_ipv6_address_set(&ip_0, 0, &ipv6_address_2, 64, NX_NULL);

    /* Check fragment enable status.  */
    if(status)
        error_counter++;
}

static void    thread_0_entry(ULONG thread_input)
{

    init_para();

    netx_tahi_run_test_case(&ip_0, test_suite[0].test_case, test_suite[0].test_case_size);


    create_sa(0,NX_IPSEC_TRANSPORT_MODE,
            &crypto_method_t_des,&crypto_method_t_des,
            ingress_3des_cbc[0], egress_3des_cbc[0], 
            NX_CRYPTO_3DES_KEY_LEN_IN_BITS, 
            &crypto_method_hmac_sha1,
            ingress_hmac_sha1[0], egress_hmac_sha1[0],
            NX_CRYPTO_HMAC_SHA1_KEY_LEN_IN_BITS,
            &ingress_3des[0], &egress_3des[0], sizeof(NX_CRYPTO_3DES),
            &metadata_ingress_hmac_sha1[0], &metadata_egress_hmac_sha1[0], sizeof(NX_SHA1_HMAC));
    create_sa(1,NX_IPSEC_TRANSPORT_MODE,
            &crypto_method_t_des,&crypto_method_t_des,
            ingress_3des_cbc[1], egress_3des_cbc[1], 
            NX_CRYPTO_3DES_KEY_LEN_IN_BITS, 
            &crypto_method_hmac_sha1,
            ingress_hmac_sha1[1], egress_hmac_sha1[1],
            NX_CRYPTO_HMAC_SHA1_KEY_LEN_IN_BITS,
            &ingress_3des[1], &egress_3des[1], sizeof(NX_CRYPTO_3DES),
            &metadata_ingress_hmac_sha1[1], &metadata_egress_hmac_sha1[1], sizeof(NX_SHA1_HMAC));
    netx_tahi_run_test_case(&ip_0, test_suite[1].test_case, test_suite[1].test_case_size);


    clean_sa();
    create_sa(2,NX_IPSEC_TRANSPORT_MODE,
            &crypto_method_t_des,&crypto_method_t_des,
            ingress_3des_cbc[2], egress_3des_cbc[2],
            NX_CRYPTO_3DES_KEY_LEN_IN_BITS, 
            &crypto_method_hmac_sha1,
            ingress_hmac_sha1[2], egress_hmac_sha1[2],
            NX_CRYPTO_HMAC_SHA1_KEY_LEN_IN_BITS,
            &ingress_3des[2], &egress_3des[2], sizeof(NX_CRYPTO_3DES),
            &metadata_ingress_hmac_sha1[2], &metadata_egress_hmac_sha1[2], sizeof(NX_SHA1_HMAC));
    create_sa(3,NX_IPSEC_TRANSPORT_MODE,
            &crypto_method_t_des,&crypto_method_t_des,
            ingress_3des_cbc[3], egress_3des_cbc[3],
            NX_CRYPTO_3DES_KEY_LEN_IN_BITS, 
            &crypto_method_hmac_sha1,
            ingress_hmac_sha1[3], egress_hmac_sha1[3],
            NX_CRYPTO_HMAC_SHA1_KEY_LEN_IN_BITS,
            &ingress_3des[3], &egress_3des[3], sizeof(NX_CRYPTO_3DES),
            &metadata_ingress_hmac_sha1[3], &metadata_egress_hmac_sha1[3], sizeof(NX_SHA1_HMAC));

    netx_tahi_run_test_case(&ip_0, test_suite[2].test_case, test_suite[2].test_case_size);


    clean_sa();
    create_sa(0,NX_IPSEC_TRANSPORT_MODE,
            &crypto_method_t_des,&crypto_method_t_des,
            ingress_3des_cbc[0], egress_3des_cbc[0], 
            NX_CRYPTO_3DES_KEY_LEN_IN_BITS, 
            &crypto_method_hmac_sha1,
            ingress_hmac_sha1[0], egress_hmac_sha1[0],
            NX_CRYPTO_HMAC_SHA1_KEY_LEN_IN_BITS,
            &ingress_3des[0], &egress_3des[0], sizeof(NX_CRYPTO_3DES),
            &metadata_ingress_hmac_sha1[0], &metadata_egress_hmac_sha1[0], sizeof(NX_SHA1_HMAC));
    netx_tahi_run_test_case(&ip_0, test_suite[3].test_case, test_suite[3].test_case_size);

#if 0
    clean_sa();
    create_sa(0,NX_IPSEC_TRANSPORT_MODE,
            &crypto_method_t_des,&crypto_method_t_des,
            ingress_3des_cbc[0], egress_3des_cbc[0], 
            NX_CRYPTO_3DES_KEY_LEN_IN_BITS, 
            &crypto_method_hmac_sha1,
            ingress_hmac_sha1[0], egress_hmac_sha1[0],
            NX_CRYPTO_HMAC_SHA1_KEY_LEN_IN_BITS,
            &ingress_3des[0], &egress_3des[0], sizeof(NX_CRYPTO_3DES),
            &metadata_ingress_hmac_sha1[0], &metadata_egress_hmac_sha1[0], sizeof(NX_SHA1_HMAC));
    netx_tahi_run_test_case(&ip_0, test_suite[4].test_case, test_suite[4].test_case_size);
#endif

    test_control_return(0xdeadbeef);

    /* Clear the flags. */

}

/* Initialize parameters for IPSec. */
static void    init_para()
{
    UINT i;

    /* Setup addresses of selectors. */
    for(i = 0; i < IPSEC_MAX_END_NODE; i++)
    {        
        egress_selectors[i].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_version = NX_IP_VERSION_V6;
        egress_selectors[i].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_address.v6[0] = 0x3ffe0501;
        egress_selectors[i].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_address.v6[1] = 0xffff0000;
        egress_selectors[i].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_address.v6[2] = 0x021122ff;
        egress_selectors[i].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_address.v6[3] = 0xfe334456;
        memcpy(&egress_selectors[i].nx_ipsec_selector_address.nx_selector_src_address_end, 
            &egress_selectors[i].nx_ipsec_selector_address.nx_selector_src_address_start, sizeof(NXD_ADDRESS));

        memcpy(&ingress_selectors[i].nx_ipsec_selector_address.nx_selector_dst_address_start, 
            &egress_selectors[i].nx_ipsec_selector_address.nx_selector_src_address_start, sizeof(NXD_ADDRESS));
        memcpy(&ingress_selectors[i].nx_ipsec_selector_address.nx_selector_dst_address_end, 
            &egress_selectors[i].nx_ipsec_selector_address.nx_selector_src_address_start, sizeof(NXD_ADDRESS));

        ingress_selectors[i].nx_ipsec_selector_next_layer_protocol_id = NX_NULL;
        egress_selectors[i].nx_ipsec_selector_next_layer_protocol_id = NX_NULL;
        ingress_selectors[i].nx_ipsec_selector_policy = NX_IPSEC_TRAFFIC_PROTECT;
        egress_selectors[i].nx_ipsec_selector_policy = NX_IPSEC_TRAFFIC_PROTECT;
    }

    /*Setup destination IP address. */
    egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6[0] = 0x3ffe0501;
    egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6[1] = 0xffff0001;
    egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6[2] = 0x00000000;
    egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6[3] = 0x00000001;
    memcpy(&egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_end, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));

    memcpy(&ingress_selectors[0].nx_ipsec_selector_address.nx_selector_src_address_start, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[0].nx_ipsec_selector_address.nx_selector_src_address_end, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));

    memcpy(&egress_selectors[1].nx_ipsec_selector_address.nx_selector_dst_address_start, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    egress_selectors[1].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6[3] = 0x00000002;
    memcpy(&egress_selectors[1].nx_ipsec_selector_address.nx_selector_dst_address_end, 
        &egress_selectors[1].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[1].nx_ipsec_selector_address.nx_selector_src_address_start, 
        &egress_selectors[1].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[1].nx_ipsec_selector_address.nx_selector_src_address_end, 
        &egress_selectors[1].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));

    memcpy(&egress_selectors[2].nx_ipsec_selector_address.nx_selector_dst_address_start, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&egress_selectors[2].nx_ipsec_selector_address.nx_selector_dst_address_end, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[2].nx_ipsec_selector_address.nx_selector_src_address_start, 
        &egress_selectors[2].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[2].nx_ipsec_selector_address.nx_selector_src_address_end, 
        &egress_selectors[2].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));

    memcpy(&egress_selectors[3].nx_ipsec_selector_address.nx_selector_dst_address_start, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&egress_selectors[3].nx_ipsec_selector_address.nx_selector_dst_address_end, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[3].nx_ipsec_selector_address.nx_selector_src_address_start, 
        &egress_selectors[3].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[3].nx_ipsec_selector_address.nx_selector_src_address_end, 
        &egress_selectors[3].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));

    /* Used by test case 8-2 */
    memset(&egress_selectors[4].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_address.v6, 0, 16);
    memset(&egress_selectors[4].nx_ipsec_selector_address.nx_selector_src_address_end.nxd_ip_address.v6, 0xFF, 16);
    memset(&egress_selectors[4].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6, 0, 16);
    memset(&egress_selectors[4].nx_ipsec_selector_address.nx_selector_dst_address_end.nxd_ip_address.v6, 0xFF, 16);
    memset(&ingress_selectors[4].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_address.v6, 0, 16);
    memset(&ingress_selectors[4].nx_ipsec_selector_address.nx_selector_src_address_end.nxd_ip_address.v6, 0xFF, 16);
    memset(&ingress_selectors[4].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6, 0, 16);
    memset(&ingress_selectors[4].nx_ipsec_selector_address.nx_selector_dst_address_end.nxd_ip_address.v6, 0xFF, 16);
    egress_selectors[4].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    egress_selectors[4].nx_ipsec_selector_address.nx_selector_src_address_end.nxd_ip_version = NX_IP_VERSION_V6;
    egress_selectors[4].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    egress_selectors[4].nx_ipsec_selector_address.nx_selector_dst_address_end.nxd_ip_version = NX_IP_VERSION_V6;
    ingress_selectors[4].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    ingress_selectors[4].nx_ipsec_selector_address.nx_selector_src_address_end.nxd_ip_version = NX_IP_VERSION_V6;
    ingress_selectors[4].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    ingress_selectors[4].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    ingress_selectors[4].nx_ipsec_selector_policy = NX_IPSEC_TRAFFIC_BYPASS;
    egress_selectors[4].nx_ipsec_selector_policy = NX_IPSEC_TRAFFIC_BYPASS;

    /* Used by test case 9-2 */

    memset(&egress_selectors[5].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_address.v6, 0, 16);
    memset(&egress_selectors[5].nx_ipsec_selector_address.nx_selector_src_address_end.nxd_ip_address.v6, 0xFF, 16);
    memset(&egress_selectors[5].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6, 0, 16);
    memset(&egress_selectors[5].nx_ipsec_selector_address.nx_selector_dst_address_end.nxd_ip_address.v6, 0xFF, 16);
    memset(&ingress_selectors[5].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_address.v6, 0, 16);
    memset(&ingress_selectors[5].nx_ipsec_selector_address.nx_selector_src_address_end.nxd_ip_address.v6, 0xFF, 16);
    memset(&ingress_selectors[5].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6, 0, 16);
    memset(&ingress_selectors[5].nx_ipsec_selector_address.nx_selector_dst_address_end.nxd_ip_address.v6, 0xFF, 16);
    egress_selectors[5].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    egress_selectors[5].nx_ipsec_selector_address.nx_selector_src_address_end.nxd_ip_version = NX_IP_VERSION_V6;
    egress_selectors[5].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    egress_selectors[5].nx_ipsec_selector_address.nx_selector_dst_address_end.nxd_ip_version = NX_IP_VERSION_V6;
    ingress_selectors[5].nx_ipsec_selector_address.nx_selector_src_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    ingress_selectors[5].nx_ipsec_selector_address.nx_selector_src_address_end.nxd_ip_version = NX_IP_VERSION_V6;
    ingress_selectors[5].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    ingress_selectors[5].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_version = NX_IP_VERSION_V6;
    ingress_selectors[5].nx_ipsec_selector_policy = NX_IPSEC_TRAFFIC_DROP;
    egress_selectors[5].nx_ipsec_selector_policy = NX_IPSEC_TRAFFIC_DROP;

    /* Used by test case 22 */
    memcpy(&egress_selectors[6].nx_ipsec_selector_address.nx_selector_dst_address_start, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&egress_selectors[6].nx_ipsec_selector_address.nx_selector_dst_address_end, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[6].nx_ipsec_selector_address.nx_selector_src_address_start, 
        &egress_selectors[6].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[6].nx_ipsec_selector_address.nx_selector_src_address_end, 
        &egress_selectors[6].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));

    /* Used by test case 23 */
    memcpy(&egress_selectors[7].nx_ipsec_selector_address.nx_selector_dst_address_start, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    egress_selectors[7].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6[1] = 0xffff0002;
    egress_selectors[7].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6[2] = 0x00000000;
    egress_selectors[7].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6[3] = 0x00000000;
    memcpy(&egress_selectors[7].nx_ipsec_selector_address.nx_selector_dst_address_end, 
        &egress_selectors[7].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    egress_selectors[7].nx_ipsec_selector_address.nx_selector_dst_address_end.nxd_ip_address.v6[2] = 0xFFFFFFFF;
    egress_selectors[7].nx_ipsec_selector_address.nx_selector_dst_address_end.nxd_ip_address.v6[3] = 0xFFFFFFFF;
    memcpy(&ingress_selectors[7].nx_ipsec_selector_address.nx_selector_src_address_start, 
        &egress_selectors[7].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[7].nx_ipsec_selector_address.nx_selector_src_address_end, 
        &egress_selectors[7].nx_ipsec_selector_address.nx_selector_dst_address_end, sizeof(NXD_ADDRESS));

    /* Used by test case 24-1 */
    memcpy(&egress_selectors[8].nx_ipsec_selector_address.nx_selector_dst_address_start, 
        &egress_selectors[0].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    egress_selectors[8].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6[1] = 0xffff0002;
    memcpy(&egress_selectors[8].nx_ipsec_selector_address.nx_selector_dst_address_end, 
        &egress_selectors[8].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[8].nx_ipsec_selector_address.nx_selector_src_address_start, 
        &egress_selectors[8].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[8].nx_ipsec_selector_address.nx_selector_src_address_end, 
        &egress_selectors[8].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));

    /* Used by test case 24-2 */
    memcpy(&egress_selectors[9].nx_ipsec_selector_address.nx_selector_dst_address_start, 
        &egress_selectors[8].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    egress_selectors[9].nx_ipsec_selector_address.nx_selector_dst_address_start.nxd_ip_address.v6[3] = 0x00000002;
    memcpy(&egress_selectors[9].nx_ipsec_selector_address.nx_selector_dst_address_end, 
        &egress_selectors[9].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[9].nx_ipsec_selector_address.nx_selector_src_address_start, 
        &egress_selectors[9].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));
    memcpy(&ingress_selectors[9].nx_ipsec_selector_address.nx_selector_src_address_end, 
        &egress_selectors[9].nx_ipsec_selector_address.nx_selector_dst_address_start, sizeof(NXD_ADDRESS));


    /* Setup SPI. */
    ingress_spi[0] = 0x1000;
    egress_spi[0] = 0x2000;
    ingress_spi[1] = 0x3000;
    egress_spi[1] = 0x4000;
    ingress_spi[2] = 0x1000;
    egress_spi[2] = 0x2000;
    ingress_spi[3] = 0x1000;
    egress_spi[3] = 0x3000;
    ingress_spi[4] = 0x1000;
    egress_spi[4] = 0x2000;
    ingress_spi[5] = 0x1000;
    egress_spi[5] = 0x2000;
    ingress_spi[6] = 0x1000;
    egress_spi[6] = 0x2000;
    ingress_spi[7] = 0x1000;
    egress_spi[7] = 0x2000;
    ingress_spi[8] = 0x1000;
    egress_spi[8] = 0x2000;
    ingress_spi[9] = 0x3000;
    egress_spi[9] = 0x4000;

    /* Setup encryption key. */
    memcpy(&ingress_3des_cbc[0], "ipv6readylogo3descbcin01", 24);
    memcpy(&ingress_hmac_sha1[0], "ipv6readylogsha1in01", 20);
    memcpy(&egress_3des_cbc[0], "ipv6readylogo3descbcout1", 24);
    memcpy(&egress_hmac_sha1[0], "ipv6readylogsha1out1", 20);

    memcpy(&ingress_3des_cbc[1], "ipv6readylogo3descbcin02", 24);
    memcpy(&ingress_hmac_sha1[1], "ipv6readylogsha1in02", 20);
    memcpy(&egress_3des_cbc[1], "ipv6readylogo3descbcout2", 24);
    memcpy(&egress_hmac_sha1[1], "ipv6readylogsha1out2", 20);

    memcpy(&ingress_3des_cbc[2], "ipv6readylogo3descbcin01", 24);
    memcpy(&ingress_hmac_sha1[2], "ipv6readylogsha1in01", 20);
    memcpy(&egress_3des_cbc[2], "ipv6readylogo3descbcout2", 24);
    memcpy(&egress_hmac_sha1[2], "ipv6readylogsha1out2", 20);

    memcpy(&ingress_3des_cbc[3], "ipv6readylogo3descbcin01", 24);
    memcpy(&ingress_hmac_sha1[3], "ipv6readylogsha1in01", 20);
    memcpy(&egress_3des_cbc[3], "ipv6readylogo3descbcout3", 24);
    memcpy(&egress_hmac_sha1[3], "ipv6readylogsha1out3", 20);

    memcpy(&ingress_aes_cbc[0], "ipv6readaescin01", 16);
    memcpy(&egress_aes_cbc[0], "ipv6readaescout1", 16);

    memcpy(&ingress_aes_ctr, "ipv6readylogaescin01", 20);
    memcpy(&egress_aes_ctr, "ipv6readylogaescout1", 20);

    memcpy(&ingress_3des_cbc[9], "ipv6readylogo3descbcin02", 24);
    memcpy(&ingress_hmac_sha1[9], "ipv6readylogsha1in02", 20);
    memcpy(&egress_3des_cbc[9], "ipv6readylogo3descbcout2", 24);
    memcpy(&egress_hmac_sha1[9], "ipv6readylogsha1out2", 20);

    memcpy(&ingress_aes_xcbc_mac, "ipv6readaesxin01", 16);
    memcpy(&egress_aes_xcbc_mac, "ipv6readaesxout1", 16);

    /* Setup selectors. */    
    ingress_selectors[2].nx_ipsec_selector_next_layer_protocol_id = NX_PROTOCOL_ICMPV6;
    ingress_selectors[2].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_type_start = 128;
    ingress_selectors[2].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_type_end = 128;
    ingress_selectors[2].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_code_start = 0;
    ingress_selectors[2].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_code_end = 0;

    egress_selectors[2].nx_ipsec_selector_next_layer_protocol_id = NX_PROTOCOL_ICMPV6;
    egress_selectors[2].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_type_start = 129;
    egress_selectors[2].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_type_end = 129;
    egress_selectors[2].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_code_start = 0;
    egress_selectors[2].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_code_end = 0;

    ingress_selectors[3].nx_ipsec_selector_next_layer_protocol_id = NX_PROTOCOL_ICMPV6;
    ingress_selectors[3].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_type_start = 128;
    ingress_selectors[3].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_type_end = 128;
    ingress_selectors[3].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_code_start = 0;
    ingress_selectors[3].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_code_end = 0;

    egress_selectors[3].nx_ipsec_selector_next_layer_protocol_id = NX_PROTOCOL_ICMPV6;
    egress_selectors[3].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_type_start = 1;
    egress_selectors[3].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_type_end = 1;
    egress_selectors[3].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_code_start = 4;
    egress_selectors[3].nx_ipsec_selector_next_layer_protocol.nx_ipsec_selector_icmp.nx_selector_icmp_code_end = 4;

}


/* Clean SA for IPSec. */
static UINT    clean_sa()
{

    UINT status = 0, i;

    for(i = 0; i < IPSEC_MAX_END_NODE; i++)
    {
        if(ingress_sa[i].nx_ipsec_sa_id)        
            status = _nxe_ipsec_sa_delete(&ingress_sa[i]);
        if(egress_sa[i].nx_ipsec_sa_id)
            status += _nxe_ipsec_sa_delete(&egress_sa[i]);

    }

    return status;
}

static VOID    sa_timeout_process(NX_IP *ip_ptr, NX_IPSEC_SA *sa)
{
    nx_ipsec_sa_update(sa, sa->nx_ipsec_sa_spi, NX_IPSEC_SA_MATURE, IPSEC_SA_LIFETIME, (IPSEC_SA_LIFETIME - 3),
                        sa->nx_ipsec_sa_encrypt_key_string, sa->nx_ipsec_sa_encryption_method -> nx_crypto_key_size_in_bits,
                        sa->nx_ipsec_sa_integrity_key_string, sa->nx_ipsec_sa_integrity_method -> nx_crypto_key_size_in_bits);
    return;
}

/* Create SA for IPSec. */
UINT    create_sa(UINT index, UCHAR sa_mode,
                  NX_CRYPTO_METHOD* sa_encryption_method_ingress, NX_CRYPTO_METHOD* sa_encryption_method_egress,
                  UCHAR *sa_encryption_key_ingress, UCHAR *sa_encryption_key_egress, 
                  UINT sa_encryption_key_len_in_bits,
                  NX_CRYPTO_METHOD* sa_integrity_method, 
                  UCHAR *sa_integrity_key_ingress, UCHAR *sa_integrity_key_egress, 
                  UINT sa_integrity_key_len_in_bits, 
                  VOID *crypto_metadata_area_ingress, VOID *crypto_metadata_area_egress, ULONG crypto_metadata_size,
                  VOID *authentication_metadata_area_ingress, VOID *authentication_metadata_area_egress, ULONG authentication_metadata_size)
{

    UINT    status;

    status = _nx_ipsec_sa_create(&ip_0, &ingress_sa[index], sa_mode, NX_PROTOCOL_NEXT_HEADER_ENCAP_SECURITY, 
        NX_IPSEC_MANUAL_KEY, NX_IPSEC_SA_INGRESS, &ingress_selectors[index], IPSEC_SA_LIFETIME, 
        (IPSEC_SA_LIFETIME) - 3, sa_timeout_process, 0, ingress_spi[index], 
        sa_encryption_method_ingress, crypto_metadata_area_ingress, crypto_metadata_size,
        sa_encryption_key_ingress, sa_encryption_key_len_in_bits, 
        sa_integrity_method, authentication_metadata_area_ingress, authentication_metadata_size,
        sa_integrity_key_ingress, sa_integrity_key_len_in_bits);

    if (status)
        error_counter++;                               

    status += _nx_ipsec_sa_create(&ip_0, &egress_sa[index], sa_mode, NX_PROTOCOL_NEXT_HEADER_ENCAP_SECURITY, 
        NX_IPSEC_MANUAL_KEY, NX_IPSEC_SA_EGRESS, &egress_selectors[index], IPSEC_SA_LIFETIME, 
        (IPSEC_SA_LIFETIME) - 3, sa_timeout_process, 0, egress_spi[index], 
        sa_encryption_method_egress, crypto_metadata_area_egress, crypto_metadata_size,
        sa_encryption_key_egress, sa_encryption_key_len_in_bits,
        sa_integrity_method, authentication_metadata_area_egress, authentication_metadata_size,
        sa_integrity_key_egress, sa_integrity_key_len_in_bits);
    if (status)
        error_counter++;

    return status;
}

#endif
