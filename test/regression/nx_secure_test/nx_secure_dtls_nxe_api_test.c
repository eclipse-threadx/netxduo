/* Test DTLS APIs */

#include   "nx_api.h"
#include   "tls_test_utility.h"
#include   "nx_secure_dtls_api.h"

extern void    test_control_return(UINT status);

#if !defined(NX_DISABLE_ERROR_CHECKING)

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD thread_0;
static NX_PACKET_POOL             pool_0;
static NX_PACKET                  test_packet;
static NX_PACKET   *test_packet_recv = NX_NULL;
static NX_SECURE_X509_CERT certificate;
static NX_UDP_SOCKET udp_socket;

static VOID thread_0_entry(ULONG thread_input);

#ifdef NX_SECURE_ENABLE_DTLS
#define EXPECT_STATUS NX_PTR_ERROR
#else
#define EXPECT_STATUS NX_NOT_SUPPORTED
#endif 

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_dtls_nxe_api_test_application_define(void *first_unused_memory)
#endif
{
    tx_thread_create(&thread_0, "Thread 0", thread_0_entry, 0,
                     first_unused_memory, 4096,
                     16, 16, 4, TX_AUTO_START);
}

static VOID thread_0_entry(ULONG thread_input)
{

UINT        status;
NXD_ADDRESS address;
UINT local_port, client_port;

static NX_SECURE_DTLS_SESSION      dtls_uninitialized_session;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS NXE API Test..................................");

    nx_secure_dtls_initialize();

    /*****************************************************************/
    /* Test the nxe uninitialized session checking                   */
    /*****************************************************************/
#ifdef NX_SECURE_ENABLE_DTLS
    status = _nxe_secure_dtls_client_protocol_version_override(&dtls_uninitialized_session, NX_SECURE_DTLS_VERSION_1_2);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_client_session_start(&dtls_uninitialized_session, &udp_socket, &address, 1234, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_packet_allocate(&dtls_uninitialized_session, &pool_0, &test_packet_recv, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_psk_add(&dtls_uninitialized_session, "psk", 3, "psk id", 5, "hint", 4);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_server_session_send(&dtls_uninitialized_session, &test_packet);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_server_session_start(&dtls_uninitialized_session, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_session_client_info_get(&dtls_uninitialized_session, &address, &client_port, &local_port);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_session_end(&dtls_uninitialized_session, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_session_local_certificate_add(&dtls_uninitialized_session, &certificate, 1);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_session_local_certificate_remove(&dtls_uninitialized_session, "common name", strlen("common name"), 1);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_session_receive(&dtls_uninitialized_session, &test_packet_recv, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_session_reset(&dtls_uninitialized_session);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_session_send(&dtls_uninitialized_session, &test_packet, &address, 1234);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_session_start(&dtls_uninitialized_session, &udp_socket, 0, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_session_trusted_certificate_add(&dtls_uninitialized_session, &certificate, 1);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_dtls_session_trusted_certificate_remove(&dtls_uninitialized_session, "common name", strlen("common name"), 1);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);
#endif

    /******************************************************************/
    /* Test the _nxe_secure_dtls_client_protocol_version_override api */
    /******************************************************************/
    status = nx_secure_dtls_client_protocol_version_override(NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_client_session_start api             */
    /******************************************************************/
    status = nx_secure_dtls_client_session_start(NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_packet_allocate api                  */
    /******************************************************************/
    status = nx_secure_dtls_packet_allocate(NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_create api                    */
    /******************************************************************/
    status = nx_secure_dtls_server_create(NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL,
                                          NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL,
                                          NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_delete api                    */
    /******************************************************************/
    status = nx_secure_dtls_server_delete(NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_local_certificate_add api     */
    /******************************************************************/
    status = nx_secure_dtls_server_local_certificate_add(NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_local_certificate_remove api  */
    /******************************************************************/
    status = nx_secure_dtls_server_local_certificate_remove(NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_server_notify_set api         */
    /******************************************************************/
    status = nx_secure_dtls_server_notify_set(NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_protocol_version_override api */
    /******************************************************************/
    status = nx_secure_dtls_server_protocol_version_override(NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

#if defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES) || defined(NX_SECURE_ENABLE_ECJPAKE_CIPHERSUITE)
    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_psk_add api                   */
    /******************************************************************/
    status = nx_secure_dtls_server_psk_add(NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_psk_add api                          */
    /******************************************************************/
    status = nx_secure_dtls_psk_add(NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);
#endif

    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_session_send api              */
    /******************************************************************/
    status = nx_secure_dtls_server_session_send(NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_session_start api             */
    /******************************************************************/
    status = nx_secure_dtls_server_session_start(NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_start api                     */
    /******************************************************************/
    status = nx_secure_dtls_server_start(NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_server_stop api                      */
    /******************************************************************/
    status = nx_secure_dtls_server_stop(NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_server_trusted_certificate_add api        */
    /******************************************************************/
    status = nx_secure_dtls_server_trusted_certificate_add(NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /*******************************************************************/
    /* Test the _nxe_secure_dtls_server_trusted_certificate_remove api */
    /*******************************************************************/
    status = nx_secure_dtls_server_trusted_certificate_remove(NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /*********************************************************************/
    /* Test the _nxe_secure_dtls_server_x509_client_verify_configure api */
    /*********************************************************************/
    status = nx_secure_dtls_server_x509_client_verify_configure(NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /*******************************************************************/
    /* Test the _nxe_secure_dtls_server_x509_client_verify_disable api */
    /*******************************************************************/
    status = nx_secure_dtls_server_x509_client_verify_disable(NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_client_info_get api          */
    /******************************************************************/
    status = nx_secure_dtls_session_client_info_get(NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_create api                   */
    /******************************************************************/
    status = nx_secure_dtls_session_create(NX_NULL, NX_NULL, NX_NULL, NX_NULL, NX_NULL,
                                           NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_delete api                   */
    /******************************************************************/
    status = nx_secure_dtls_session_delete(NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_end api                      */
    /******************************************************************/
    status = nx_secure_dtls_session_end(NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_local_certificate_add api    */
    /******************************************************************/
    status = nx_secure_dtls_session_local_certificate_add(NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_local_certificate_remove api */
    /******************************************************************/
    status = nx_secure_dtls_session_local_certificate_remove(NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_receive api                  */
    /******************************************************************/
    status = nx_secure_dtls_session_receive(NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_reset api                    */
    /******************************************************************/
    status = nx_secure_dtls_session_reset(NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_send api                     */
    /******************************************************************/
    status = nx_secure_dtls_session_send(NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_start api                    */
    /******************************************************************/
    status = nx_secure_dtls_session_start(NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /******************************************************************/
    /* Test the _nxe_secure_dtls_session_trusted_certificate_add api  */
    /******************************************************************/
    status = nx_secure_dtls_session_trusted_certificate_add(NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /********************************************************************/
    /* Test the _nxe_secure_dtls_session_trusted_certificate_remove api */
    /********************************************************************/
    status = nx_secure_dtls_session_trusted_certificate_remove(NX_NULL, NX_NULL, NX_NULL, NX_NULL);
    EXPECT_EQ(EXPECT_STATUS, status);

    /* Output success.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID nx_secure_dtls_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DTLS NXE API Test..................................N/A\n");
    test_control_return(3);
}
#endif
