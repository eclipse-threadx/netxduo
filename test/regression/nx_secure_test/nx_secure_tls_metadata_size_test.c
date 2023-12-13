/* TLS metadata size test
   Make sure the value calculated by nx_secure_tls_metadata_size_calculate is the minimal value
   required by nx_secure_tls_session_create.
  */

#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"

extern void    test_control_return(UINT status);

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;
static NX_SECURE_TLS_SESSION   tls_session;

static UCHAR packet_buffer[4000];
static CHAR crypto_metadata[20000];

/*  Cryptographic routines. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

#define DEMO_STACK_SIZE  4096 //  (3 * 1024 / sizeof(ULONG))

/* Define the IP thread's stack area.  */
#define IP_STACK_SIZE 4096 //(2 * 1024 / sizeof(ULONG))

/* Define packet pool for the demonstration.  */
#define NX_PACKET_POOL_BYTES  ((1536 + sizeof(NX_PACKET)) * 20)
#define NX_PACKET_POOL_SIZE (NX_PACKET_POOL_BYTES/sizeof(ULONG) + 64 / sizeof(ULONG))

/* Define the ARP cache area.  */
#define ARP_AREA_SIZE 1024 // (512 / sizeof(ULONG))

/* Define the counters used in the demo application...  */
ULONG                   error_counter;


/* Define thread prototypes.  */

static void    ntest_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT *driver_req);

/* Define what the initial system looks like.  */
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void           nx_secure_tls_metadata_size_application_define(void *first_unused_memory)
#endif
{
CHAR       *pointer;
UINT       status;

    /* Setup the working pointer.  */
    pointer = (CHAR *) first_unused_memory;

    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer = pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536, pointer, NX_PACKET_POOL_BYTES);
    pointer = pointer + NX_PACKET_POOL_BYTES;

    if(status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_1500,
                          pointer, IP_STACK_SIZE, 1);
    pointer = pointer + IP_STACK_SIZE;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, ARP_AREA_SIZE);
    pointer = pointer + ARP_AREA_SIZE;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if(status)
        error_counter++;

    nx_secure_tls_initialize();
}

/* Define the test threads.  */
static void    ntest_0_entry(ULONG thread_input)
{
UINT       status;
ULONG      actual_status;
ULONG      metadata_size;
NX_SECURE_TLS_CRYPTO test_ciphers;
NX_CRYPTO_METHOD test_crypto_method_sha256;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Metadata Size Test.............................");

    /* Check for earlier error.  */
    if(error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if(status)
        error_counter++;

    status =  nx_secure_tls_metadata_size_calculate(&nx_crypto_tls_ciphers, &metadata_size);

    /* Check for error.  */
    if(status)
        error_counter++;

    /* Create a TLS session with metadata_size less than required value.  */
    status =  nx_secure_tls_session_create(&tls_session,
                                           &nx_crypto_tls_ciphers,
                                           crypto_metadata,
                                           (metadata_size - 1));

    /* Check for error.  */
    if(status == NX_SECURE_TLS_SUCCESS)
        error_counter++;

    /* Create a TLS session with metadata_size equal to required value.  */
    status =  nx_secure_tls_session_create(&tls_session,
                                           &nx_crypto_tls_ciphers,
                                           crypto_metadata,
                                           metadata_size);

    /* Check for error.  */
    if(status)
        error_counter++;

    memcpy(&test_ciphers, &nx_crypto_tls_ciphers, sizeof(NX_SECURE_TLS_CRYPTO));
    memcpy(&test_crypto_method_sha256, nx_crypto_tls_ciphers.nx_secure_tls_handshake_hash_sha256_method, sizeof(NX_CRYPTO_METHOD));
    test_crypto_method_sha256.nx_crypto_metadata_area_size = 4096;
    test_ciphers.nx_secure_tls_handshake_hash_sha256_method = &test_crypto_method_sha256;
    status =  nx_secure_tls_metadata_size_calculate(&test_ciphers, &metadata_size);
    EXPECT_EQ(NX_SUCCESS, status);

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
