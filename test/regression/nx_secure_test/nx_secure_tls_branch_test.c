#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"
extern void    test_control_return(UINT status);

#include "tx_thread.h"
#include "nx_secure_tls.h"
#define     DEMO_STACK_SIZE         2048
#define ARP_AREA_SIZE 1024 // (512 / sizeof(ULONG))

/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               thread_0;
#ifndef NX_DISABLE_ASSERT
static TX_THREAD               thread_for_assert;
static UINT                    assert_count = 0;
static NX_PACKET_POOL          pool_0;
static NX_IP                   ip_0;


/* Define the counters used in the demo application...  */
static ULONG                   error_counter =     0;
static CHAR                    *pointer;


/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);
extern void    _nx_ram_network_driver_256(struct NX_IP_DRIVER_STRUCT *driver_req);
static void    thread_for_assert_entry(ULONG thread_input);

/* Define what the initial system looks like.  */
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void    nx_secure_tls_branch_test_application_define(void *first_unused_memory)
#endif
{
UINT    status;
    
    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;
    error_counter = 0;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 256, pointer, 8192);
    pointer = pointer + 8192;

    if (status)
        error_counter++;

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver_256,
                    pointer, 2048, 1);
    pointer =  pointer + 2048;

    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status = nx_arp_enable(&ip_0, (void *) pointer, ARP_AREA_SIZE);
    pointer = pointer + ARP_AREA_SIZE;

    /* Enable TCP processing for both IP instances.  */
    status = nx_tcp_enable(&ip_0);

    /* Check TCP enable status.  */
    if(status)
    {
        printf("Failed nx_tcp_enable with error: 0x%0x\n", status);
        error_counter++;
    }
    
    nx_secure_tls_initialize();
}

/* Define the test threads.  */

static void    thread_0_entry(ULONG thread_input)
{

    /* Print out some test information banners.  */
    printf("NetX Secure Test:   TLS Branch Test....................................");

    /* Check for earlier error.  */
    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test _nx_secure_tls_record_hash_update. */
    /* Hit NX_ASSERT(authentication_method -> nx_crypto_operation != NX_NULL) */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);


    /* Test _nx_secure_tls_record_hash_calculate. */
    /* Hit NX_ASSERT(authentication_method -> nx_crypto_operation != NX_NULL) */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);


    /* Test _nx_secure_tls_record_hash_initialize. */
    /* Hit NX_ASSERT(authentication_method -> nx_crypto_operation != NX_NULL) */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);


    /* Test _nx_secure_tls_record_payload_encrypt. */
    /* Hit NX_ASSERT(block_size <= NX_SECURE_TLS_MAX_CIPHER_BLOCK_SIZE) */
    tx_thread_create(&thread_for_assert, "Assert Test thread", thread_for_assert_entry, 0,  
                     pointer, DEMO_STACK_SIZE, 
                     5, 5, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Let test thread run.  */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

    /* Terminate the test thread.  */
    tx_thread_terminate(&thread_for_assert);
    tx_thread_delete(&thread_for_assert);


    /* Check status.  */
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

/* Lookup table used to map ciphersuites to cryptographic routines. */
static NX_SECURE_TLS_CIPHERSUITE_INFO test_ciphersuite = {TLS_NULL_WITH_NULL_NULL, NX_NULL, NX_NULL, NX_NULL, 0, 0, NX_NULL, 0, NX_NULL};

/* Define the object we can pass into TLS. */
static NX_SECURE_TLS_CRYPTO test_crypto_table =
{
    /* Ciphersuite lookup table and size. */
    &test_ciphersuite,
    1,
#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    NX_NULL,
    0,
#endif
    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    NX_NULL,
    NX_NULL,
    NX_NULL,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    NX_NULL,
    NX_NULL,
#endif
};
static NX_SECURE_TLS_SESSION _tls_session;
static NX_CRYPTO_METHOD _crypto_method;

/* Define the test threads.  */
static void    thread_for_assert_entry(ULONG thread_input)
{
    _tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    _tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    test_ciphersuite.nx_secure_tls_hash = &_crypto_method;
    _crypto_method.nx_crypto_operation = NX_NULL;

    /* Check the count.  */
    if (assert_count == 0)
    {
        /* Update the count.  */
        assert_count ++;
        _nx_secure_tls_record_hash_update(&_tls_session, NX_NULL, 0);
    }
    else if (assert_count == 1)
    {
        /* Update the count.  */
        assert_count ++;
        _nx_secure_tls_record_hash_calculate(&_tls_session, NX_NULL, 0);
    }
    else if (assert_count == 2)
    {
        /* Update the count.  */
        assert_count ++;
        _nx_secure_tls_record_hash_initialize(&_tls_session, NX_NULL, NX_NULL, 0, NX_NULL, NX_NULL);
    }
    else if (assert_count == 3)
    {
        /* Update the count.  */
        assert_count ++;
        test_ciphersuite.nx_secure_tls_session_cipher = &_crypto_method;
        _crypto_method.nx_crypto_block_size_in_bytes = NX_SECURE_TLS_MAX_CIPHER_BLOCK_SIZE + 1;
        _nx_secure_tls_record_payload_encrypt(&_tls_session, NX_NULL, NX_NULL, 0);
    }
}
#else    
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void    nx_secure_tls_branch_test_application_define(void *first_unused_memory)
#endif
{                                                                        

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Branch Test....................................N/A\n");
    
    test_control_return(3);
}
#endif
