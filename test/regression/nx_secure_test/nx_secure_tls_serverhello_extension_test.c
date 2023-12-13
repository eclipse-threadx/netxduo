#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_DISABLE_X509)
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
static NX_TCP_SOCKET           server_socket;
static NX_SECURE_TLS_SESSION   client_tls_session;


static UCHAR server_packet_buffer[4000];
static UCHAR client_packet_buffer[4000];

static CHAR server_crypto_metadata[16000];
static CHAR client_crypto_metadata[16000];

/*  Cryptographic routines. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

#ifndef __LINUX__
ULONG test_stack_area[TOTAL_STACK_SPACE + 2000];
#endif


static ULONG pool_area[2][NX_PACKET_POOL_SIZE];

/* Define the counters used in the demo application...  */
static ULONG error_counter;

/* ServerHello message with 40 extensions. */
static UCHAR serverhello_ext[] = {
  0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x69, 0x98, 0x3c, 0x64, 0x73, 0x48,
  0x33, 0x66, 0x51, 0xdc, 0xb0, 0x74, 0xff, 0x5c, 0x49, 0x19, 0x4a, 0x94,
  0xe8, 0x2a, 0xec, 0x58, 0x55, 0x62, 0x29, 0x1f, 0x8e, 0x23, 0x00, 0x00,
  0x3d, 0x00, 0x00, 0xc8, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
  0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
  0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
  0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
  0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
  0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
  0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
  0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
  0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
  0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
  0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
  0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
  0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
  0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00
};


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
void nx_secure_tls_serverhello_extension_test_application_define(void *first_unused_memory)
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


    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS ServerHello Extension Test.....................");

    /* Ensure the IP instance has been initialized.  */
    status = nx_ip_status_check(&ip_0, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check for error.  */
    if (status)
    {
        printf("Error in function nx_ip_status_check: 0x%x\n", status);
        error_counter++;
    }

    client_tls_session.nx_secure_tls_crypto_table = (NX_SECURE_TLS_CRYPTO *)&nx_crypto_tls_ciphers;
    status = _nx_secure_tls_process_serverhello(&client_tls_session, serverhello_ext, sizeof(serverhello_ext));
    EXPECT_EQ(NX_SUCCESS, status);

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
VOID nx_secure_tls_serverhello_extension_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS ServerHello Extension Test.....................N/A\n");
    test_control_return(3);
}
#endif
