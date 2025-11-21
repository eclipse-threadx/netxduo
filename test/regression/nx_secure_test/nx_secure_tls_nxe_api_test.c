/* 14.19 TCP MUST include an SWS avoidance algorithm in the receiver when effective send MSS < (1/ 2)*RCV_BUFF.  */

/*  Procedure
    1.Connection successfully  
    2.First Client sends 40 data to Server, then check if the last_sent changed
    3.Then Client sends more 20 data to Server, also check if the last_sent changed
    4.If the last_sent changed, the SWS avoidance algorithm has not been used.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"
#include   "test_ca_cert.c"
#include   "test_device_cert.c"
#include   "test_ca.crl.der.c"

extern void    test_control_return(UINT status);

#ifndef NX_DISABLE_ERROR_CHECKING

#define METADATA_SIZE               16000

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD thread_0;
static NX_SECURE_TLS_SESSION      tls_client_session_0;
static NX_SECURE_TLS_SESSION      tls_uninitialized_session;
static NX_PACKET_POOL             pool_0;
static NX_PACKET                  test_packet;
static NX_TCP_SOCKET              client_socket_0;
static UCHAR                      client_metadata[METADATA_SIZE];
static NX_SECURE_X509_CERT        certificate;
static NX_SECURE_X509_CERT        client_remote_cert;
static UCHAR                      client_cert_buffer[2048];
static UCHAR                      too_small_client_cert_buffer1[sizeof(NX_SECURE_X509_CERT) - 2];
static UCHAR                      too_small_client_cert_buffer2[sizeof(NX_SECURE_X509_CERT) + NX_SECURE_TLS_MINIMUM_CERTIFICATE_SIZE - 2];
static NX_SECURE_X509_CERTIFICATE_STORE cert_store;
static NX_SECURE_X509_DNS_NAME    dns_name;

extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
const CHAR *dns_tld = "NX Secure Device Certificate";

static VOID thread_0_entry(ULONG thread_input);

static ULONG _test_time_func(VOID)
{
    return(0);
}

static ULONG _renegotiate_callback(NX_SECURE_TLS_SESSION *tls_session)
{
    return(0);
}

static ULONG _certificate_callback(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_X509_CERT *certificate)
{
    return(0);
}

static ULONG _client_callback(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION *extension, UINT num_extensions)
{
    return(0);
}

static ULONG _server_callback(NX_SECURE_TLS_SESSION *tls_session, NX_SECURE_TLS_HELLO_EXTENSION *extensions, UINT num_extensions)
{
    return(0);
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_nxe_api_test_application_define(void *first_unused_memory)
#endif
{
    tx_thread_create(&thread_0, "Thread 0", thread_0_entry, 0,
        first_unused_memory, 4096,
        16, 16, 4, TX_AUTO_START);
}

static VOID thread_0_entry(ULONG thread_input)
{

UINT        status;
ULONG       metadata_size;
NX_PACKET   *test_packet_recv = NX_NULL;
NX_SECURE_TLS_HELLO_EXTENSION hello_extension;
USHORT      keyusage_bitfield;
NX_SECURE_X509_EXTENSION extension;
NX_SECURE_X509_CERT *cert_ptr;
NX_TCP_SOCKET tcp_socket;
UINT       alert_value, alert_level;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS NXE API Test...................................");

    /*****************************************************************/
    /* Test the nxe uninitialized session checking                   */
    /*****************************************************************/
    status = _nxe_secure_tls_active_certificate_set(&tls_uninitialized_session, &certificate);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    status = _nxe_secure_tls_client_psk_set(&tls_uninitialized_session, "psk", 3, "psk id", 5, "hint", 4);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_psk_add(&tls_uninitialized_session, "psk", 3, "psk id", 5, "hint", 4);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);
#endif

    status = _nxe_secure_tls_local_certificate_add(&tls_uninitialized_session, &certificate);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_local_certificate_find(&tls_uninitialized_session, &cert_ptr, "common name", strlen("common name"));
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_local_certificate_remove(&tls_uninitialized_session, "common name", strlen("common name"));
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_packet_allocate(&tls_uninitialized_session, &pool_0, &test_packet_recv, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_remote_certificate_allocate(&tls_uninitialized_session, &certificate, client_cert_buffer, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_remote_certificate_buffer_allocate(&tls_uninitialized_session, 1, client_cert_buffer, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_remote_certificate_free_all(&tls_uninitialized_session);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_server_certificate_add(&tls_uninitialized_session, &certificate, 1);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_server_certificate_find(&tls_uninitialized_session, &cert_ptr, 1);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_server_certificate_remove(&tls_uninitialized_session, 1);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_alert_value_get(&tls_uninitialized_session, &alert_level, &alert_value);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_certificate_callback_set(&tls_uninitialized_session, _certificate_callback);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_client_callback_set(&tls_uninitialized_session, _client_callback);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_client_verify_disable(&tls_uninitialized_session);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_client_verify_enable(&tls_uninitialized_session);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_end(&tls_uninitialized_session, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_packet_buffer_set(&tls_uninitialized_session, client_metadata, sizeof(client_metadata));
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_packet_pool_set(&tls_uninitialized_session, &pool_0);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_protocol_version_override(&tls_uninitialized_session, NX_SECURE_TLS_VERSION_TLS_1_2);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_receive(&tls_uninitialized_session, &test_packet_recv, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
    status = _nxe_secure_tls_session_renegotiate(&tls_uninitialized_session, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_renegotiate_callback_set(&tls_uninitialized_session, _renegotiate_callback);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);
#endif /* NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION */

    status = _nxe_secure_tls_session_send(&tls_uninitialized_session, &test_packet, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_server_callback_set(&tls_uninitialized_session, _server_callback);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_sni_extension_parse(&tls_uninitialized_session, &hello_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_sni_extension_set(&tls_uninitialized_session, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_start(&tls_uninitialized_session, &client_socket_0, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_time_function_set(&tls_uninitialized_session, _test_time_func);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_session_x509_client_verify_configure(&tls_uninitialized_session, 1, client_cert_buffer, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_trusted_certificate_add(&tls_uninitialized_session, &certificate);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    status = _nxe_secure_tls_trusted_certificate_remove(&tls_uninitialized_session, "common name", strlen("common name"));
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);


    /*****************************************************************/
    /* Initialize TLS session for following tests.                   */
    /*****************************************************************/
    tls_client_session_0.nx_secure_tls_id = NX_SECURE_TLS_ID;

    /*****************************************************************/
    /* Test the nxe_secure_tls_session_protocol_version_override api */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_protocol_version_override(NX_NULL, NX_SECURE_TLS_VERSION_TLS_1_1);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test unknown TLS version. */
    status = nx_secure_tls_session_protocol_version_override(&tls_client_session_0, 0);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_TLS_VERSION, status);

    /* Test unsupported TLS version. */
    status = nx_secure_tls_session_protocol_version_override(&tls_client_session_0, NX_SECURE_TLS_VERSION_SSL_3_0);
    EXPECT_EQ(NX_SECURE_TLS_UNSUPPORTED_TLS_VERSION, status);


    /*****************************************************************/
    /* Test the nxe_secure_tls_packet_allocate api                   */
    /*****************************************************************/

    /* Test uninitialized session. */
    status = nx_secure_tls_packet_allocate(&tls_client_session_0, &pool_0, &test_packet_recv, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    /* Unestablished tcp connection. */
    tls_client_session_0.nx_secure_tls_tcp_socket = &tcp_socket;
    tcp_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V6;
    tcp_socket.nx_tcp_socket_state = 0xff;
    status = nx_secure_tls_packet_allocate(&tls_client_session_0, &pool_0, &test_packet_recv, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);
    tls_client_session_0.nx_secure_tls_tcp_socket = NX_NULL;

    /*****************************************************************/
    /* Test the nxe_secure_tls_session_packet_buffer_set api         */
    /*****************************************************************/

    /* Test null buffer pointer. */
    status = nx_secure_tls_session_packet_buffer_set(&tls_client_session_0, NX_NULL, NX_SECURE_TLS_MINIMUM_MESSAGE_BUFFER_SIZE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test buffer too small. */
    status = nx_secure_tls_session_packet_buffer_set(&tls_client_session_0, client_metadata, NX_SECURE_TLS_MINIMUM_MESSAGE_BUFFER_SIZE - 1);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);


    /*****************************************************************/
    /* Test the nxe_secure_tls_session_packet_pool_set api         */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_packet_pool_set(NX_NULL, &pool_0);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the nxe_secure_tls_session_send api                      */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_send(NX_NULL, &test_packet, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL packet */
    status = nx_secure_tls_session_send(&tls_client_session_0, NX_NULL, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test uninitialized session */
    status = nx_secure_tls_session_send(&tls_client_session_0, &test_packet, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);

    /* Test plaintext length overflow */
    tls_client_session_0.nx_secure_tls_tcp_socket = &tcp_socket;
    test_packet.nx_packet_length = 65000;
    status = nx_secure_tls_session_send(&tls_client_session_0, &test_packet, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_RECORD_OVERFLOW, status);
    tls_client_session_0.nx_secure_tls_tcp_socket = NX_NULL;


    /*****************************************************************/
    /* Test the nxe_secure_tls_session_receive api                   */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_receive(NX_NULL, &test_packet_recv, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL packet */
    status = nx_secure_tls_session_receive(&tls_client_session_0, NX_NULL, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test uninitialized session */
    status = nx_secure_tls_session_receive(&tls_client_session_0, &test_packet_recv, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_SECURE_TLS_SESSION_UNINITIALIZED, status);


    /*****************************************************************/
    /* Test the nxe_secure_tls_session_create api                    */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_create(NX_NULL, &nx_crypto_tls_ciphers, client_metadata, sizeof(client_metadata));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL cipher table. */
    status = nx_secure_tls_session_create(&tls_client_session_0, NX_NULL, client_metadata, sizeof(client_metadata));
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the nxe_secure_tls_session_start api                     */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_start(NX_NULL, &client_socket_0, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL cipher table. */
    status = nx_secure_tls_session_start(&tls_client_session_0, NX_NULL, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the nxe_secure_tls_session_end api                       */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_end(NX_NULL, NX_IP_PERIODIC_RATE);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the nxe_secure_tls_session_delete api                    */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_delete(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the nxe_secure_tls_session_reset api                     */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_reset(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_session_client_verify_enable api     */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_client_verify_enable(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_session_client_verify_disable api    */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_client_verify_disable(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

     /****************************************************************/
    /* Test the _nxe_secure_tls_session_alert_value_get api          */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_alert_value_get(NX_NULL, &alert_level, &alert_value);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL alert level parameter. */
    status = nx_secure_tls_session_alert_value_get(&tls_client_session_0, NX_NULL, &alert_value);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL alert value parameter. */
    status = nx_secure_tls_session_alert_value_get(&tls_client_session_0, &alert_level, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /*****************************************************************/
    /* Test the nxe_secure_x509_certificate_initialize api           */
    /*****************************************************************/

    /* Test NULL certificate. */
    status = nx_secure_x509_certificate_initialize(NX_NULL, test_ca_cert_der, test_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL certificate data. */
    status = nx_secure_x509_certificate_initialize(&certificate, NX_NULL, test_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test 0 certificate data length. */
    status = nx_secure_x509_certificate_initialize(&certificate, test_ca_cert_der, 0, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the nxe_secure_tls_local_certificate_add api             */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_local_certificate_add(NX_NULL, &certificate);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL certificate. */
    status = nx_secure_tls_local_certificate_add(&tls_client_session_0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /*****************************************************************/
    /* Test the nxe_secure_tls_local_certificate_find api            */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_local_certificate_find(NX_NULL, &cert_ptr, "none", 4);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL certificate. */
    status = nx_secure_tls_local_certificate_find(&tls_client_session_0, NX_NULL, "none", 4);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL common_name. */
    status = nx_secure_tls_local_certificate_find(&tls_client_session_0, &cert_ptr, NX_NULL, 4);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_local_certificate_remove api         */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_local_certificate_remove(NX_NULL, "c", 1);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL string. */
    status = nx_secure_tls_local_certificate_remove(&tls_client_session_0, NX_NULL, 1);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test 0 common name length. */
    status = nx_secure_tls_local_certificate_remove(&tls_client_session_0, "", 0);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_trusted_certificate_add api          */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_trusted_certificate_add(NX_NULL, &certificate);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL certificate. */
    status = nx_secure_tls_trusted_certificate_add(&tls_client_session_0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_trusted_certificate_remove api       */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_trusted_certificate_remove(NX_NULL, "c", 1);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL string. */
    status = nx_secure_tls_trusted_certificate_remove(&tls_client_session_0, NX_NULL, 1);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test 0 common name length. */
    status = nx_secure_tls_trusted_certificate_remove(&tls_client_session_0, "", 0);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*********************************************************************/
    /* Test the _nxe_secure_tls_remote_certificate_buffer_allocate api   */
    /*********************************************************************/

    /* TLS session NULL. */
    status = _nxe_secure_tls_remote_certificate_buffer_allocate(NX_NULL, 2, client_cert_buffer, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Buffer NULL. */
    status = _nxe_secure_tls_remote_certificate_buffer_allocate(&tls_client_session_0, 2, NX_NULL, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Number of certs 0. */
    status = _nxe_secure_tls_remote_certificate_buffer_allocate(&tls_client_session_0, 0, client_cert_buffer, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Buffer size 0. */
    status = _nxe_secure_tls_remote_certificate_buffer_allocate(&tls_client_session_0, 2, client_cert_buffer, 0);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

#ifndef NX_SECURE_DISABLE_X509
    /* Buffer size smaller than sizeof(NX_SECURE_X509_CERT). */
    status = _nxe_secure_tls_remote_certificate_buffer_allocate(&tls_client_session_0, 1, too_small_client_cert_buffer1,
    																		       sizeof(too_small_client_cert_buffer1));
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Buffer size smaller than NX_SECURE_TLS_MINIMUM_CERTIFICATE_SIZE. */
    status = _nxe_secure_tls_remote_certificate_buffer_allocate(&tls_client_session_0, 1, too_small_client_cert_buffer2,
    																		       sizeof(too_small_client_cert_buffer2));
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);
#endif

    /*****************************************************************/
    /* Test the _nxe_secure_tls_remote_certificate_allocate api      */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_remote_certificate_allocate(NX_NULL, &client_remote_cert, client_cert_buffer, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL certificate. */
    status = nx_secure_tls_remote_certificate_allocate(&tls_client_session_0, NX_NULL, client_cert_buffer, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL certificate buffer. */
    status = nx_secure_tls_remote_certificate_allocate(&tls_client_session_0, &client_remote_cert, NX_NULL, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test 0 buffer length. */
    status = nx_secure_tls_remote_certificate_allocate(&tls_client_session_0, &client_remote_cert, client_cert_buffer, 0);
    EXPECT_EQ(NX_SECURE_TLS_INSUFFICIENT_CERT_SPACE, status);

    /*********************************************************************/
    /* Test the _nxe_secure_tls_session_client_x509_verify_configure api */
    /*********************************************************************/

    /* TLS session NULL. */
    status = _nxe_secure_tls_session_x509_client_verify_configure(NX_NULL, 2, client_cert_buffer, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Buffer NULL but non-zero buffer size. */
    status = _nxe_secure_tls_session_x509_client_verify_configure(&tls_client_session_0, 2, NX_NULL, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Number of certs 0. */
    status = _nxe_secure_tls_session_x509_client_verify_configure(&tls_client_session_0, 0, client_cert_buffer, sizeof(client_cert_buffer));
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Buffer size 0 with non-null buffer. */
    status = _nxe_secure_tls_session_x509_client_verify_configure(&tls_client_session_0, 2, client_cert_buffer, 0);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Buffer size smaller than sizeof(NX_SECURE_X509_CERT). */
    status = _nxe_secure_tls_session_x509_client_verify_configure(&tls_client_session_0, 1, too_small_client_cert_buffer1,
    																		       sizeof(too_small_client_cert_buffer1));
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Buffer size smaller than NX_SECURE_TLS_MINIMUM_CERTIFICATE_SIZE. */
    status = _nxe_secure_tls_session_x509_client_verify_configure(&tls_client_session_0, 1, too_small_client_cert_buffer2,
    																		       sizeof(too_small_client_cert_buffer2));
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);


    /*****************************************************************/
    /* Test the _nxe_secure_x509_common_name_dns_check api           */
    /*****************************************************************/

    /* Test NULL certificate. */
    status = nx_secure_x509_common_name_dns_check(NX_NULL, dns_tld, strlen(dns_tld));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL dns_tld. */
    status = nx_secure_x509_common_name_dns_check(&certificate, NX_NULL, strlen(dns_tld));
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test 0 dns_tld length. */
    status = nx_secure_x509_common_name_dns_check(&certificate, dns_tld, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the _nxe_secure_x509_crl_revocation_check api            */
    /*****************************************************************/

    /* Test NULL certificate. */
    status = nx_secure_x509_crl_revocation_check(test_ca_crl_der, test_ca_crl_der_len, &cert_store, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL crl data. */
    status = nx_secure_x509_crl_revocation_check(NX_NULL, test_ca_crl_der_len, &cert_store, &certificate);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL store. */
    status = nx_secure_x509_crl_revocation_check(test_ca_crl_der, test_ca_crl_der_len, NX_NULL, &certificate);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test 0 crl length. */
    status = nx_secure_x509_crl_revocation_check(test_ca_crl_der, 0, &cert_store, &certificate);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_session_sni_extension_set api        */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_sni_extension_set(NX_NULL, &dns_name);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL dns name. */
    status = nx_secure_tls_session_sni_extension_set(&tls_client_session_0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_session_time_function_set api        */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_time_function_set(NX_NULL, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL time function pointer. */
    status = nx_secure_tls_session_time_function_set(&tls_client_session_0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_session_time_function_set(&tls_client_session_0, _test_time_func);
    EXPECT_EQ(NX_SUCCESS, status);

#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
    /*****************************************************************/
    /* Test the _nxe_secure_tls_session_renegotiate_callback_set api */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_renegotiate_callback_set(NX_NULL, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL callback function pointer. */
    status = nx_secure_tls_session_renegotiate_callback_set(&tls_client_session_0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_session_renegotiate_callback_set(&tls_client_session_0, _renegotiate_callback);
    EXPECT_EQ(NX_SUCCESS, status);
#endif /* NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION */


    /*****************************************************************/
    /* Test the _nxe_secure_tls_session_certificate_callback_set api */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_certificate_callback_set(NX_NULL, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL callback function pointer. */
    status = nx_secure_tls_session_certificate_callback_set(&tls_client_session_0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_session_certificate_callback_set(&tls_client_session_0, _certificate_callback);
    EXPECT_EQ(NX_SUCCESS, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_session_client_callback_set api      */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_client_callback_set(NX_NULL, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL callback function pointer. */
    status = nx_secure_tls_session_client_callback_set(&tls_client_session_0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_session_client_callback_set(&tls_client_session_0, _client_callback);
    EXPECT_EQ(NX_SUCCESS, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_session_server_callback_set api      */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_server_callback_set(NX_NULL, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL callback function pointer. */
    status = nx_secure_tls_session_server_callback_set(&tls_client_session_0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_session_server_callback_set(&tls_client_session_0, _client_callback);
    EXPECT_EQ(NX_SUCCESS, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_session_sni_extension_parse api      */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_session_sni_extension_parse(NX_NULL, NX_NULL, 0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL extension. */
    status = nx_secure_tls_session_sni_extension_parse(&tls_client_session_0, NX_NULL, 0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_session_sni_extension_parse(&tls_client_session_0, &hello_extension, 0, NX_NULL);
    EXPECT_EQ(NX_SECURE_TLS_EXTENSION_NOT_FOUND, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_metadata_size_calculate api          */
    /*****************************************************************/

    /* Test NULL cipher table. */
    status = nx_secure_tls_metadata_size_calculate(NX_NULL, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL value return pointer. */
    status = nx_secure_tls_metadata_size_calculate(&nx_crypto_tls_ciphers, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_metadata_size_calculate(&nx_crypto_tls_ciphers, &metadata_size);
    EXPECT_EQ(NX_SUCCESS, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_server_certificate_add api           */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_server_certificate_add(NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL certificate. */
    status = nx_secure_tls_server_certificate_add(&tls_client_session_0, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_server_certificate_add(&tls_client_session_0, &certificate, 0);
    EXPECT_EQ(NX_SECURE_TLS_CERT_ID_INVALID, status);

#ifndef NX_SECURE_DISABLE_X509

    /*****************************************************************/
    /* Test the _nxe_secure_tls_active_certificate_set api           */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_active_certificate_set(NX_NULL, &certificate);
    EXPECT_EQ(NX_PTR_ERROR, status);

    /* Test NULL certificate. */
    status = nx_secure_tls_active_certificate_set(&tls_client_session_0, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_active_certificate_set(&tls_client_session_0, &certificate);
    EXPECT_EQ(NX_SUCCESS, status);

    /*****************************************************************/
    /* Test the _nxe_secure_tls_server_certificate_find api          */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_server_certificate_find(NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_server_certificate_find(&tls_client_session_0, NX_NULL, 0);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    /*****************************************************************/
    /* Test the _nxe_secure_tls_server_certificate_remove api        */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_server_certificate_remove(NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_server_certificate_remove(&tls_client_session_0, 0);
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);


    /*****************************************************************/
    /* Test the _nxe_secure_tls_remote_certificate_free_all api      */
    /*****************************************************************/

    /* Test NULL session. */
    status = nx_secure_tls_remote_certificate_free_all(NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_remote_certificate_free_all(&tls_client_session_0);
    EXPECT_EQ(NX_SUCCESS, status);


    /*****************************************************************/
    /* Test the _nxe_secure_x509_extension_find api                  */
    /*****************************************************************/

    /* Test NULL pointers. */
    status = nx_secure_x509_extension_find(NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_x509_extension_find(&certificate, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_x509_extension_find(&certificate, &extension, 0);
    EXPECT_EQ(NX_SECURE_X509_EXTENSION_NOT_FOUND, status);
#endif

    /*****************************************************************/
    /* Other apis.                                                   */
    /*****************************************************************/
    nx_secure_tls_initialize();

    status = nx_secure_tls_local_certificate_remove(&tls_client_session_0, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_remote_certificate_allocate(&tls_client_session_0, NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_session_client_verify_disable(&tls_client_session_0);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_secure_tls_session_client_verify_enable(&tls_client_session_0);
    EXPECT_EQ(NX_SUCCESS, status);

#ifndef NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION
    status = nx_secure_tls_session_renegotiate(NX_NULL, NX_NO_WAIT);
    EXPECT_EQ(NX_PTR_ERROR, status);
#endif /* NX_SECURE_TLS_DISABLE_SECURE_RENEGOTIATION */

    status = nx_secure_x509_extended_key_usage_extension_parse(NX_NULL, NX_SECURE_TLS_X509_TYPE_PKIX_KP_TIME_STAMPING);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_x509_key_usage_extension_parse(NX_NULL, &keyusage_bitfield);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_x509_key_usage_extension_parse(&certificate, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_x509_dns_name_initialize(NX_NULL, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    status = nx_secure_tls_psk_add(&tls_client_session_0, NX_NULL, 0, NX_NULL, 0, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = nx_secure_tls_client_psk_set(&tls_client_session_0, NX_NULL, 0, NX_NULL, 0, NX_NULL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);
#endif

    /* Output success.  */
    printf("SUCCESS!\n");
    test_control_return(0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID nx_secure_tls_nxe_api_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS NXE API Test...................................N/A\n");
    test_control_return(3);
}
#endif
