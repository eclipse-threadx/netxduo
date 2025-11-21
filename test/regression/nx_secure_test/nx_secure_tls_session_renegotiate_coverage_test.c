#include <stdio.h>

#include "nx_secure_tls_api.h"
#include "nx_crypto.h"
#include "tls_test_utility.h"
#include "test_device_cert.c"

extern void    test_control_return(UINT status);

static NX_SECURE_TLS_SESSION   tls_session;
#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
static void  NX_Secure_TLS_session_renegotiate_coverage(void);
#endif
/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_session_renegotiate_coverage_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Session Regegotiate Coverage Test..............");

#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_DISABLE_X509)
    NX_Secure_TLS_session_renegotiate_coverage();

    printf("SUCCESS!\n");
#else
    printf("N/A\n");
#endif
    test_control_return(0);

}

#if !defined(NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION) && !defined(NX_SECURE_DISABLE_X509)
extern VOID    _nx_ram_network_driver_1500(struct NX_IP_DRIVER_STRUCT* driver_req);
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
extern NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table[];
#define THREAD_STACK_SIZE    1024
/* Force a small packet size so line 168 _nx_secure_tls_send_clienthello would fail.*/
#define PACKET_SIZE           128
#define PACKET_SIZE_SMALL      40  
#define NUM_PACKETS             3
#define PACKET_POOL_SIZE        ((PACKET_SIZE + sizeof(NX_PACKET)) * 3)
static ULONG                    ip_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static NX_SECURE_TLS_SESSION    tls_session;
static ULONG                    pool_0_memory[PACKET_POOL_SIZE / sizeof(ULONG)];
static NX_PACKET_POOL           pool_0;
static NX_IP                    ip_0;
static NX_TCP_SOCKET            tcp_socket;
static NX_SECURE_X509_CERT      device_certificate;

TEST(NX_Secure_TLS, session_renegotiate_coverage)
{


UINT   status;
NX_SECURE_X509_CERTIFICATE_STORE *store;


    nx_secure_tls_initialize();

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE_SMALL,
                                    pool_0_memory, PACKET_POOL_SIZE);
    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL,
                          &pool_0, _nx_ram_network_driver_1500,
                          ip_0_stack, sizeof(ip_0_stack), 1);

    tls_session.nx_secure_tls_packet_pool = &pool_0;

    /* Cover line 118 */
    tls_session.nx_secure_tls_remote_session_active = NX_FALSE;
    tls_session.nx_secure_tls_local_session_active = NX_FALSE;
    status = _nx_secure_tls_session_renegotiate(&tls_session, NX_NO_WAIT);
    //EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_SESSION_INACTIVE, status);

    tls_session.nx_secure_tls_remote_session_active = NX_TRUE;
    tls_session.nx_secure_tls_local_session_active = NX_FALSE;
    status = _nx_secure_tls_session_renegotiate(&tls_session, NX_NO_WAIT);
    //EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_SESSION_INACTIVE, status);

    tls_session.nx_secure_tls_remote_session_active = NX_FALSE;
    tls_session.nx_secure_tls_local_session_active = NX_TRUE;
    status = _nx_secure_tls_session_renegotiate(&tls_session, NX_NO_WAIT);
    //EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_SESSION_INACTIVE, status);


    /* Cover line 134 - 137 */
    tls_session.nx_secure_tls_remote_session_active = NX_TRUE;
    tls_session.nx_secure_tls_local_session_active = NX_TRUE;
    tls_session.nx_secure_tls_secure_renegotiation = NX_FALSE;
    status = _nx_secure_tls_session_renegotiate(&tls_session, NX_NO_WAIT);
    //EXPECT_EQ(NX_SECURE_TLS_RENEGOTIATION_FAILURE, status);
    
    /* Cover line 148 */
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    tls_session.nx_secure_tls_tcp_socket = &tcp_socket;
    tls_session.nx_secure_tls_secure_renegotiation = NX_TRUE;
    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    status = _nx_secure_tls_session_renegotiate(&tls_session, NX_NO_WAIT);
    //EXPECT_EQ(NX_SECURE_TLS_ALLOCATE_PACKET_FAILED, status);    
    
    nx_packet_pool_delete(&pool_0);
 
    /* Initializes valid packet pool for TLS */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE,
                                    pool_0_memory, PACKET_POOL_SIZE);    

    tls_session.nx_secure_tls_session_ciphersuite = &_nx_crypto_ciphersuite_lookup_table[3];
    tls_session.nx_secure_tls_crypto_table = &nx_crypto_tls_ciphers;
    tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;

    /* Cover line 239 */
    status = _nx_secure_tls_session_renegotiate(&tls_session, NX_NO_WAIT);
    //EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

#ifndef NX_SECURE_DISABLE_X509
    nx_secure_x509_certificate_initialize(&device_certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    device_certificate.nx_secure_x509_user_allocated_cert = 1;
    store = &(tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store);
    /* Force a duplicate into the free list inside the store, so the certificate free would fail. */
    _nx_secure_x509_certificate_list_add(&store -> nx_secure_x509_free_certificates, &device_certificate, 1);
    _nx_secure_x509_certificate_list_add(&store -> nx_secure_x509_remote_certificates, &device_certificate, 1);

    /* Cover line 168 */
    status = _nx_secure_tls_session_renegotiate(&tls_session, NX_NO_WAIT);
    //EXPECT_EQ(NX_INVALID_PARAMETERS, status);
#endif
}
#endif

