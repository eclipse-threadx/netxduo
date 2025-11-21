#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"

extern void    test_control_return(UINT status);

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
#define __LINUX__

#define     DEMO_STACK_SIZE  4096 //  (3 * 1024 / sizeof(ULONG))

/* Define the IP thread's stack area.  */
#define IP_STACK_SIZE 4096 //(2 * 1024 / sizeof(ULONG))

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_BYTES  ((1536 + sizeof(NX_PACKET)) * 20)
#define NX_PACKET_POOL_SIZE (NX_PACKET_POOL_BYTES/sizeof(ULONG) + 64 / sizeof(ULONG))

/* Define the ARP cache area.  */
#define ARP_AREA_SIZE 1024 // (512 / sizeof(ULONG))

#define TOTAL_STACK_SPACE (2 * (DEMO_STACK_SIZE + IP_STACK_SIZE + NX_PACKET_POOL_SIZE + ARP_AREA_SIZE))


/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_TCP_SOCKET           client_socket;
static NX_SECURE_TLS_SESSION   tls_session;



/*  Cryptographic routines. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
extern NX_CRYPTO_METHOD crypto_method_aes_ccm_8;

#ifndef __LINUX__
ULONG test_stack_area[TOTAL_STACK_SPACE + 2000];
#endif


static ULONG pool_area[2][NX_PACKET_POOL_SIZE];

/* Define the counters used in the demo application...  */
static ULONG error_counter;


static NX_SECURE_TLS_CIPHERSUITE_INFO test_ciphersuite = {TLS_PSK_WITH_AES_128_CCM_8, NX_NULL, NX_NULL, &crypto_method_aes_ccm_8, 16, 16, NX_NULL, 0, NX_NULL};
static UCHAR record_data[16];
static UCHAR test_iv[128];
static UCHAR test_key[128];
static UCHAR test_metadata[4000];


/* Define thread prototypes.  */

static void ntest_0_entry(ULONG thread_input);
extern void _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */
#ifndef __LINUX__
void tx_application_define(void *first_unused_memory)
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_record_length_test_application_define(void *first_unused_memory)
#endif
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
#ifndef __LINUX__
    pointer = (CHAR*)test_stack_area;
#else
    pointer = (CHAR *) first_unused_memory;
#endif

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pool_area[0], sizeof(pool_area[0]));

    if(status)
    {
        printf("Error in function nx_packet_pool_create: 0x%x\n", status);
        error_counter++;
    }


    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, IP_STACK_SIZE, 1);
    pointer = pointer + IP_STACK_SIZE;

    if(status)
    {
        printf("Error in function nx_ip_create: 0x%x\n", status);
        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, ARP_AREA_SIZE);
    pointer = pointer + ARP_AREA_SIZE;

    /* Check ARP enable status.  */
    if(status)
    {
        printf("Error in function nx_arp_enable: 0x%x\n", status);
        error_counter++;
    }

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if(status)
    {
        printf("Error in function tcp_enable: 0x%x\n", status);
        error_counter++;
    }

    nx_secure_tls_initialize();
}


/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
UINT       record_length;
NX_PACKET *test_packet;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Record Length Test.............................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
    {
        printf("Error in function nx_ip_status_check: 0x%x\n", status);
        error_counter++;
    }

    tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    tls_session.nx_secure_tls_key_material.nx_secure_tls_client_iv = test_iv;
    tls_session.nx_secure_session_cipher_metadata_area_client = test_metadata;
    tls_session.nx_secure_session_cipher_metadata_size = sizeof(test_metadata);
    tls_session.nx_secure_tls_key_material.nx_secure_tls_client_write_key = test_key;

    status = nx_packet_allocate(&pool_0, &test_packet, NX_IPv4_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_packet_data_append(test_packet, record_data, sizeof(record_data), &pool_0, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_tls_record_payload_encrypt(&tls_session, test_packet,
                                                   tls_session.nx_secure_tls_remote_sequence_number, 0);
    EXPECT_EQ(NX_SUCCESS, status);

    nx_packet_release(test_packet);


    /* Test to make sure when the record length is too small, the decryption function would not crash. */
    record_length = 6;

    status = _nx_secure_tls_record_payload_decrypt(&tls_session, test_packet, 0, 6, &test_packet,
                                                   tls_session.nx_secure_tls_remote_sequence_number, 0, 0);
    EXPECT_EQ(NX_SECURE_TLS_AEAD_DECRYPT_FAIL, status);

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
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID nx_secure_tls_record_length_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Record Length Test.............................N/A\n");
    test_control_return(3);
}
#endif
