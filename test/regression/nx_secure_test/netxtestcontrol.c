/* This is the test control routine the NetX TCP/IP stack.  All tests are dispatched from this routine.  */

#include "tx_api.h"
#include "nx_api.h"
#include "nx_secure_tls.h"
#include <stdio.h>
#include <stdlib.h>
#include "nx_secure_tls.h"
#include "nx_ram_network_driver_test_1500.h"

/* Check version definitions. */
#ifndef __PRODUCT_NETX_SECURE__
#error "__PRODUCT_NETX_SECURE__ is not defined."
#endif /* __PRODUCT_NETX_SECURE__ */

#if defined(EXPECTED_MAJOR_VERSION) && ( !defined(__NETX_SECURE_MAJOR_VERSION__) || (__NETX_SECURE_MAJOR_VERSION__ != EXPECTED_MAJOR_VERSION))
#error "__NETX_SECURE_MAJOR_VERSION__"
#endif /* EXPECTED_MAJOR_VERSION */

#if defined(EXPECTED_MINOR_VERSION) && ( !defined(__NETX_SECURE_MINOR_VERSION__) || (__NETX_SECURE_MINOR_VERSION__ != EXPECTED_MINOR_VERSION))
#error "__NETX_SECURE_MINOR_VERSION__"
#endif /* EXPECTED_MINOR_VERSION */

#if defined(__linux__) && defined(USE_FORK)
#undef __suseconds_t_defined
#undef _STRUCT_TIMEVAL
#undef _SYS_SELECT_H
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/poll.h>

void fork_child();
#endif

/*
#define NETXTEST_TIMEOUT_DISABLE
*/

 FILE *stream;

#define TEST_STACK_SIZE         4096

/* 1 minute. */
#define TEST_TIMEOUT_LOW        (60 * NX_IP_PERIODIC_RATE)
/* 15 minutes. */
#define TEST_TIMEOUT_MID        (900 * NX_IP_PERIODIC_RATE)
/* 120 minutes. */
#define TEST_TIMEOUT_HIGH       (7200 * NX_IP_PERIODIC_RATE)

/* Define the test control ThreadX objects...  */

TX_THREAD       test_control_thread;
#ifndef NETXTEST_TIMEOUT_DISABLE
TX_SEMAPHORE    test_control_sema;
#endif

/* Define the test control global variables.   */

ULONG           test_control_return_status;
ULONG           test_control_successful_tests;
ULONG           test_control_failed_tests;
ULONG           test_control_warning_tests;
ULONG           test_control_na_tests;

/* Remember the start of free memory.  */

UCHAR           *test_free_memory_ptr;

extern volatile UINT   _tx_thread_preempt_disable;

/* Define test entry pointer type.  */

typedef  struct TEST_ENTRY_STRUCT
{
    VOID        (*test_entry)(void *);
    UINT        timeout;
} TEST_ENTRY;


/* Define the prototypes for the test entry points.  */
VOID nx_secure_tls_session_receive_coverage_test_application_define(void *);
VOID nx_secure_tls_send_record_coverage_test_application_define(void *);
void nx_secure_tls_client_handshake_coverage_test_application_define(void *);
void nx_secure_tls_finished_hash_coverage_test_application_define(void *);
void nx_secure_tls_generate_key_coverage_test_application_define(void *);
void nx_secure_tls_generate_premaster_coverage_test_application_define(void *);
void nx_secure_tls_handshake_hash_coverage_test_application_define(void *);
void nx_secure_tls_ecc_generate_keys_coverage_test_application_define(void *);
void nx_secure_tls_session_renegotiate_coverage_test_application_define(void*);
void nx_secure_tls_session_keys_set_coverage_test_application_define(void*);
void nx_secure_tls_newest_supported_version_test_application_define(void *);
void nx_secure_tls_verify_mac_test_application_define(void*);
void nx_secure_sha224_test_application_define(void *);
void nx_secure_sha256_test_application_define(void *);
void nx_secure_sha256_rfc_test_application_define(void *);
void nx_secure_sha384_test_application_define(void *);
void nx_secure_sha512_test_application_define(void *);
void nx_secure_hmac_md5_test_application_define(void *);
void nx_secure_hmac_sha1_test_application_define(void *);
void nx_secure_hmac_sha224_test_application_define(void *);
void nx_secure_hmac_sha256_test_application_define(void *);
void nx_secure_hmac_sha384_test_application_define(void *);
void nx_secure_hmac_sha512_test_application_define(void *);
void nx_secure_x509_certificate_initialize_test_application_define(void *first_unused_memory);
void nx_secure_x509_certificate_verify_test_application_define(void *first_unused_memory);
void nx_secure_x509_crl_verify_test_application_define(void *first_unused_memory);
void nx_secure_x509_parse_test_application_define(void *);
void nx_secure_x509_list_test_application_define(void *);
void nx_secure_x509_store_test_application_define(void *);
void nx_secure_x509_name_check_test_application_define(void *);
void nx_secure_x509_crl_test_application_define(void *);
void nx_secure_x509_error_checking_test_application_define(void *first_unused_memory);
void nx_secure_x509_expiration_check_test_application_define(void *);
void nx_secure_x509_key_usage_test_application_define(void *first_unused_memory);
void nx_secure_x509_pkcs7_decode_coverage_test_application_define(void *);
void nx_secure_rsa_test_application_define(void *);
void nx_secure_aes_test_application_define(void *first_unused_memory);
void nx_secure_aes_ccm_test_application_define(void *first_unused_memory);
void nx_secure_des_test_application_define(void *first_unused_memory);
void nx_secure_3des_test_application_define(void *first_unused_memory);
void nx_secure_tls_handshake_header_test_application_define(void *);
void nx_secure_tls_header_test_application_define(void *);
void nx_secure_phash_prf_test_application_define(void *);
void nx_secure_tls_two_way_test_application_define(void *first_unused_memory);
void nx_secure_tls_two_way_test_version_1_1_application_define(void *first_unused_memory);
void nx_secure_tls_ciphersuites_test_application_define(void *);
void nx_secure_tls_cert_verify_test_application_define(void *first_unused_memory);
void nx_secure_tls_session_sni_extension_test_application_define(void*);
void nx_secure_tls_certificate_coverage_test_application_define(void *);
void nx_secure_tls_no_remote_certs_allocated_test_application_define(void *first_unused_memory);
void nx_secure_tls_partial_remote_certs_allocated_test_application_define(void *first_unused_memory);
void nx_secure_tls_process_certificate_verify_test_application_define(void *first_unused_memory);
void nx_secure_tls_client_handshake_test_application_define(void *first_unused_memory);
void nx_secure_tls_clienthello_extension_test_application_define(void *first_unused_memory);
void nx_secure_tls_coverage_test_application_define(void *first_unused_memory);
void nx_secure_tls_coverage_2_test_application_define(void *first_unused_memory);
void nx_secure_tls_coverage_3_test_application_define(void *first_unused_memory);
void nx_secure_tls_alert_test_application_define(void *first_unused_memory);
void nx_secure_tls_error_checking_test_application_define(void *first_unused_memory);
void nx_secure_tls_error_checking_2_test_application_define(void *first_unused_memory);
void nx_secure_tls_tcp_fragment_test_application_define(void *first_unused_memory);
void nx_secure_tls_user_defined_key_test_application_define(void *first_unused_memory);
void nx_secure_tls_no_client_cert_test_application_define(void *first_unused_memory);
void nx_secure_tls_hash_coverage_test_application_define(void *);
void nx_secure_tls_handshake_fail_test_application_define(void *first_unused_memory);
void nx_secure_tls_handshake_fragmentation_test_application_define(void *first_unused_memory);
void nx_secure_tls_handshake_fragmentation_ecc_test_application_define(void *first_unused_memory);
void nx_secure_tls_packet_chain_test_application_define(void *first_unused_memory);
void nx_secure_tls_receive_alert_test_application_define(void *first_unused_memory);
void nx_secure_tls_receive_test_application_define(void *first_unused_memory);
void nx_secure_tls_record_decrypt_coverage_test_application_define(void *);
void nx_secure_tls_record_encrypt_coverage_test_application_define(void *);
void nx_secure_tls_record_layer_version_test_application_define(void *first_unused_memory);
void nx_secure_tls_record_length_test_application_define(void *first_unused_memory);
void nx_secure_tls_server_key_exchange_coverage_test_application_define(void *);
void nx_secure_tls_serverhello_coverage_test_application_define(void *);
void nx_secure_tls_serverhello_extension_test_application_define(void *first_unused_memory);
void nx_secure_tls_metadata_size_application_define(void *first_unused_memory);
void nx_secure_tls_multiple_handshake_msg_test_application_define(void *first_unused_memory);
void nx_secure_tls_multithread_test_application_define(void *first_unused_memory);
void nx_secure_tls_unrecognized_ciphersuite_test_application_define(void *first_unused_memory);
void nx_secure_tls_unsupported_ciphersuites_test_application_define(void *first_unused_memory);
void nx_secure_tls_non_blocking_test_application_define(void *first_unused_memory);
void nx_secure_tls_ecc_basic_test_application_define(void *first_unused_memory);
void nx_secure_tls_ecc_protocol_version_test_application_define(void *first_unused_memory);
void nx_secure_tls_ecc_client_cert_test_application_define(void *first_unused_memory);
void nx_secure_tls_ecc_ciphersuites_test_application_define(void *first_unused_memory);
void nx_secure_tls_ecc_curves_test_application_define(void *first_unused_memory);
void nx_secure_tls_ecc_crl_test_application_define(void *first_unused_memory);
void nx_secure_tls_ecc_packet_chain_test_application_define(void *first_unused_memory);
void nx_secure_tls_ecc_point_format_test_application_define(void *first_unused_memory);
void nx_secure_tls_shutdown_test_application_define(void *first_unused_memory);
void nx_secure_distingushed_name_compare_test_application_define(void *first_unused_memory);
void nx_secure_dtls_nxe_api_test_application_define(void *);
void nx_secure_dtls_basic_test_application_define(void *);
void nx_secure_dtls_error_checking_test_application_define(void *first_unused_memory);
void nx_secure_dtls_sliding_window_test_application_define(void *first_unused_memory);
void nx_secure_dtls_retransmit_test_application_define(void *);
void nx_secure_dtls_retransmit_interval_test_application_define(void *);
void nx_secure_dtls_retransmit_change_cipher_spec_test_application_define(void *);
void nx_secure_dtls_handshake_fail_test_application_define(void *first_unused_memory);
void nx_secure_dtls_ciphersuites_test_application_define(void *);
void nx_secure_dtls_ecjpake_test_application_define(void *);
void nx_secure_dtls_multiple_sessions_receive_test_application_define(void *);
void nx_secure_dtls_multiple_sessions_connect_test_application_define(void *);
void nx_secure_dtls_multiple_sessions_reuse_test_application_define(void *);
void nx_secure_dtls_multiple_sessions_connect_fail_test_application_define(void *);
void nx_secure_dtls_multiple_sessions_send_test_application_define(void *);
void nx_secure_dtls_multiple_sessions_retransmit_test_application_define(void *);
void nx_secure_dtls_multiple_sessions_ecjpake_test_application_define(void *);
void nx_secure_dtls_multiple_ip_address_test_application_define(void *);
void nx_secure_dtls_no_free_sessions_test_application_define(void *);
void nx_secure_dtls_concurrent_sessions_test_application_define(void *);
void nx_secure_dtls_concurrent_sessions_retransmit_test_application_define(void *);
void nx_secure_dtls_abort_waiting_test_application_define(void *);
void nx_secure_dtls_fragment_test_application_define(void *);
void nx_secure_dtls_abnormal_test_application_define(void *);
void nx_secure_dtls_out_of_order_test_application_define(void *);
void nx_secure_dtls_version_1_0_test_application_define(void *);
void nx_secure_dtls_ecc_basic_test_application_define(void *);
void nx_secure_dtls_ecc_ciphersuites_test_application_define(void *);
void nx_secure_dtls_ecc_curves_test_application_define(void *);
void nx_secure_dtls_ecc_client_cert_test_application_define(void *);
void nx_secure_ec_test_application_define(void *first_unused_memory);
void nx_secure_ecjpake_self_test_application_define(void *first_unused_memory);
void nx_secure_ecdh_self_test_application_define(void *first_unused_memory);
void nx_secure_ecdh_test_application_define(void *first_unused_memory);
void nx_secure_ecdsa_test_application_define(void *first_unused_memory);
void nx_secure_tls_nxe_api_test_application_define(void *first_unused_memory);
void nx_secure_tls_server_handshake_test_application_define(void *first_unused_memory);
void nx_secure_tls_cert_callback_fail_test_application_define(void *first_unused_memory);
void nx_secure_tls_send_and_receive_record_test_application_define(void *first_unused_memory);
void nx_secure_tls_branch_test_application_define(void *first_unused_memory);
void nx_secure_crypto_self_test_application_define(void *first_unused_memory);
void nx_secure_crypto_cleanup_test_application_define(void *first_unused_memory);
void nx_secure_crypto_method_cleanup_test_application_define(void *first_unused_memory);
void nx_secure_tls_certificate_verify_test_application_define(void *first_unused_memory);
void nx_secure_tls_rsa_4096_test_application_define(void *first_unused_memory);
void nx_secure_tls_rsa_private_key_test_application_define(void *first_unused_memory);
void nx_secure_tls_serverhello_session_id_test_application_define(void *first_unused_memory);
void nx_secure_hkdf_test_application_define(void *first_unused_memory);
void nx_secure_tls_1_3_before_key_generation_test_application_define(void *first_unused_memory);
void nx_secure_tls_1_3_ciphersuites_test_application_define(void *);
void nx_secure_tls_1_3_clienthello_length_checking_test_application_define(void *first_unused_memory);
void nx_secure_tls_1_3_handshake_fail_test_application_define(void *);
void nx_secure_tls_1_3_hello_retry_cookie_test_application_define(void *);
void nx_secure_tls_1_3_invalid_client_state_test_application_define(void *first_unused_memory);
void nx_secure_tls_1_3_key_share_test_application_define(void *);
void nx_secure_tls_1_3_provisioned_psk_test_application_define(void *);
void nx_secure_tls_1_3_receive_invalid_server_handshake_message_test_application_define(void *);
void nx_secure_tls_1_3_serverhello_length_checking_test_application_define(void *first_unused_memory);
void nx_secure_tls_1_3_session_create_ext_test_application_define(void *first_unused_memory);
void nx_secure_tls_1_3_version_negotiation_test_application_define(void *);
void nx_secure_tls_client_ca_select_test_application_define(void *);
void nx_secure_tls_send_plaintext_alert_after_key_generation_test_application_define(void *first_unused_memory);
void nx_secure_tls_session_create_ext_test_application_define(void *first_unused_memory);
void nx_secure_tls_empty_clienthello_extension_test_application_define(void *first_unused_memory);
void nx_secure_tls_packet_trim_test_application_define(void *first_unused_memory);
void nx_secure_tls_payload_size_test_application_define(void *first_unused_memory);
void nx_secure_tls_process_changecipherspec_test_application_define(void *first_unused_memory);
void nx_secure_tls_process_certificate_request_test_application_define(void *first_unused_memory);
void nx_secure_tls_process_finished_test_application_define(void *first_unused_memory);
void nx_secure_tls_process_record_test_application_define(void *first_unused_memory);
void nx_secure_tls_send_certificate_test_application_define(void *first_unused_memory);
void nx_secure_tls_send_client_hello_test_application_define(void *first_unused_memory);
void nx_secure_tls_server_cipher_priority_test_application_define(void *first_unused_memory);
void nx_secure_tls_session_delete_test_application_define(void *first_unused_memory);
void nx_secure_tls_session_start_test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory);
void nx_secure_tls_hash_record_coverage_test_application_define(void *first_unused_memory);


#define INCLUDE_TWO_WAY_TEST 1

#ifdef NX_SECURE_TLS_CLIENT_DISABLED
#undef INCLUDE_TWO_WAY_TEST
#define INCLUDE_TWO_WAY_TEST 0
#endif

#ifdef NX_SECURE_TLS_SERVER_DISABLED
#undef INCLUDE_TWO_WAY_TEST
#define INCLUDE_TWO_WAY_TEST 0
#endif

/* Define the array of test entry points.  */

TEST_ENTRY  test_control_tests[] =
{

#ifdef CTEST
    {test_application_define, TEST_TIMEOUT_HIGH},
#else /* ifdef CTEST */
    {nx_secure_tls_session_receive_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_send_record_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_client_handshake_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_handshake_hash_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_generate_premaster_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_generate_key_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_finished_hash_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_ecc_generate_keys_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_session_renegotiate_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_session_keys_set_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_newest_supported_version_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_verify_mac_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_hash_record_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_branch_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_error_checking_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_error_checking_2_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_two_way_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_no_client_cert_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_two_way_test_version_1_1_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_distingushed_name_compare_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_cert_callback_fail_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_certificate_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_ciphersuites_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_server_cipher_priority_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_client_handshake_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_tls_clienthello_extension_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_session_sni_extension_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_tls_coverage_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_tls_coverage_2_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_tls_coverage_3_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_tls_server_handshake_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_tls_tcp_fragment_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_user_defined_key_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_alert_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_hash_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_handshake_header_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_header_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_handshake_fail_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_packet_chain_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_receive_alert_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_receive_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_record_decrypt_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_record_encrypt_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_record_layer_version_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_record_length_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_server_key_exchange_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_serverhello_coverage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_serverhello_extension_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_send_and_receive_record_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_certificate_verify_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_no_remote_certs_allocated_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_partial_remote_certs_allocated_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_process_certificate_verify_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_rsa_4096_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_rsa_private_key_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_send_plaintext_alert_after_key_generation_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_serverhello_session_id_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_metadata_size_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_multiple_handshake_msg_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_multithread_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_unrecognized_ciphersuite_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_unsupported_ciphersuites_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_non_blocking_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_ecc_basic_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_ecc_protocol_version_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_ecc_client_cert_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_ecc_ciphersuites_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_ecc_curves_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_ecc_crl_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_ecc_packet_chain_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_ecc_point_format_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_empty_clienthello_extension_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_handshake_fragmentation_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_before_key_generation_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_ciphersuites_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_clienthello_length_checking_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_handshake_fail_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_hello_retry_cookie_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_invalid_client_state_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_key_share_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_serverhello_length_checking_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_session_create_ext_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_provisioned_psk_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_receive_invalid_server_handshake_message_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_1_3_version_negotiation_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_cert_verify_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_client_ca_select_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_packet_trim_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_process_changecipherspec_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_process_certificate_request_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_process_finished_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_process_record_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_session_create_ext_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_shutdown_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_send_certificate_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_send_client_hello_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_session_delete_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_session_start_test_application_define, TEST_TIMEOUT_LOW},   
    {nx_secure_x509_certificate_initialize_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_certificate_verify_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_crl_verify_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_parse_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_list_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_store_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_name_check_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_crl_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_error_checking_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_expiration_check_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_key_usage_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_x509_pkcs7_decode_coverage_test_application_define, TEST_TIMEOUT_LOW},

#ifndef CERT_BUILD
    {nx_secure_dtls_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_basic_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_error_checking_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_sliding_window_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_retransmit_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_retransmit_interval_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_retransmit_change_cipher_spec_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_ciphersuites_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_handshake_fail_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_ecjpake_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_multiple_sessions_receive_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_multiple_sessions_connect_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_multiple_sessions_connect_fail_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_multiple_sessions_send_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_multiple_sessions_retransmit_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_multiple_sessions_ecjpake_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_multiple_ip_address_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_no_free_sessions_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_concurrent_sessions_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_concurrent_sessions_retransmit_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_abort_waiting_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_fragment_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_abnormal_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_dtls_out_of_order_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_version_1_0_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_multiple_sessions_reuse_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_ecc_basic_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_ecc_ciphersuites_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_ecc_curves_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_dtls_ecc_client_cert_test_application_define, TEST_TIMEOUT_MID},
#endif /* CERT_BUILD */
    {nx_secure_tls_nxe_api_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_crypto_self_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_crypto_cleanup_test_application_define, TEST_TIMEOUT_LOW},
    /* Crypto test. */
    {nx_secure_hkdf_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_sha224_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_sha256_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_sha256_rfc_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_sha384_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_sha512_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_md5_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_sha1_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_sha224_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_sha256_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_sha384_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_hmac_sha512_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_rsa_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_aes_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_aes_ccm_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_des_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_3des_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_phash_prf_test_application_define, TEST_TIMEOUT_LOW},
#ifndef CERT_BUILD
    {nx_secure_ec_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_ecjpake_self_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_ecdh_self_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_ecdh_test_application_define, TEST_TIMEOUT_MID},
    {nx_secure_ecdsa_test_application_define, TEST_TIMEOUT_MID},
#endif /* CERT_BUILD */
    {nx_secure_crypto_method_cleanup_test_application_define, TEST_TIMEOUT_LOW},
    {nx_secure_tls_payload_size_test_application_define, TEST_TIMEOUT_LOW},
#endif /* ifdef CTEST */
    {TX_NULL, TEST_TIMEOUT_LOW},
};

/* Define thread prototypes.  */

void  test_control_thread_entry(ULONG thread_input);
void  test_control_return(UINT status);
void  test_control_cleanup(void);
void  _nx_ram_network_driver_reset(void);

/* Define necessary external references.  */

#ifdef __ghs
extern TX_MUTEX                 __ghLockMutex;
#endif

extern TX_TIMER                 *_tx_timer_created_ptr;
extern ULONG                    _tx_timer_created_count;
#ifndef TX_TIMER_PROCESS_IN_ISR
extern TX_THREAD                _tx_timer_thread;
#endif
extern TX_THREAD                *_tx_thread_created_ptr;
extern ULONG                    _tx_thread_created_count;
extern TX_SEMAPHORE             *_tx_semaphore_created_ptr;
extern ULONG                    _tx_semaphore_created_count;
extern TX_QUEUE                 *_tx_queue_created_ptr;
extern ULONG                    _tx_queue_created_count;
extern TX_MUTEX                 *_tx_mutex_created_ptr;
extern ULONG                    _tx_mutex_created_count;
extern TX_EVENT_FLAGS_GROUP     *_tx_event_flags_created_ptr;
extern ULONG                    _tx_event_flags_created_count;
extern TX_BYTE_POOL             *_tx_byte_pool_created_ptr;
extern ULONG                    _tx_byte_pool_created_count;
extern TX_BLOCK_POOL            *_tx_block_pool_created_ptr;
extern ULONG                    _tx_block_pool_created_count;

extern NX_PACKET_POOL *         _nx_packet_pool_created_ptr;
extern ULONG                    _nx_packet_pool_created_count;
extern NX_IP *                  _nx_ip_created_ptr;
extern ULONG                    _nx_ip_created_count;

/* Define main entry point.  */
#define __NETX_SECURE_SP_VERSION__ 1
int main()
{

#ifdef NX_CRYPTO_SELF_TEST
    nx_crypto_initialize();

    _nx_crypto_method_self_test(0);
#endif

#if 0
    /* Reassign "stdout" to "freopen.out": */
    stream = freopen( "test_result.txt", "w", stdout );
#endif
    /* Print out some test information banners.  */
    printf("%s\n", _nx_secure_version_id);
    printf("NetX Secure Version %d.%d\n", __NETX_SECURE_MAJOR_VERSION__,
           __NETX_SECURE_MINOR_VERSION__);
    printf("Tested on %s %s\n", __DATE__, __TIME__);

    fflush(stdout);

#if defined(__linux__) && defined(USE_FORK)
    fork_child();
#else
    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
#endif

    return 0;
}


#if defined(__linux__) && defined(USE_FORK)
static pid_t child_pid = -1;
static UINT test_index = 0;
static int result_fd[2];

void kill_child(int sig)
{
CHAR data[4]={0, 1, 0, 0};

    printf("ERROR! Kill child process\n");
    fflush(stdout);
    write(result_fd[1], data, sizeof(data));
    exit(1);
}

void fork_child()
{
INT status;
CHAR data[4];
struct pollfd fds;

    while (test_control_tests[test_index].test_entry != TX_NULL)
    {

        /* Create pipe for communicating. */
        pipe(result_fd);
        fds.fd = result_fd[0];
        fds.events=POLLIN | POLLOUT | POLLERR;

        /* Fork test process. */
        child_pid = fork();
        if (child_pid > 0)
        {
            wait(&status);
            poll(&fds, 1, 0);
            if (fds.revents & POLLIN)
            {
                read(result_fd[0], data, sizeof(data));
                test_control_successful_tests += (ULONG)data[0];
                test_control_failed_tests += (ULONG)data[1];
                test_control_warning_tests += (ULONG)data[2];
                test_control_na_tests += (ULONG)data[3];
            }
            else
            {

                /* The child process crashes. */
                printf("ERROR! Child process crashed\n");
                test_control_failed_tests++;
            }

            fflush(stdout);

            test_index++;
        }
        else
        {

            /* Setup SIGALRM callback function. */
            signal(SIGALRM, (void (*)(int))kill_child);

            /* Initialize the results. */
            test_control_successful_tests = 0;
            test_control_failed_tests = 0;
            test_control_warning_tests = 0;
            test_control_na_tests = 0;

            /* Setup timeout alarm. */
            alarm(test_control_tests[test_index].timeout / NX_IP_PERIODIC_RATE);

            /* Enter the ThreadX kernel.  */
            tx_kernel_enter();
            return;
        }
    }

    /* Finished with all tests, print results and return!  */
    printf("**** Testing Complete ****\n");
    printf("**** Test Summary:  Tests Passed:  %lu   Tests Warning:  %lu   Tests Failed:  %lu\n", test_control_successful_tests, test_control_warning_tests, test_control_failed_tests);
#ifdef BATCH_TEST
    exit(test_control_failed_tests);
#endif
}

/* Define what the initial system looks like.  */

void    tx_application_define(void *first_unused_memory)
{

    /* Dispatch the test.  */
    (test_control_tests[test_index].test_entry)(first_unused_memory);
}

void  test_control_return(UINT status)
{
UINT    old_posture = TX_INT_ENABLE;
INT     exit_code = status;
CHAR    data[4];

    fflush(stdout);

    /* Initialize result through pipe. */
    data[0] = (CHAR)test_control_successful_tests;
    data[1] = (CHAR)test_control_failed_tests;
    data[2] = (CHAR)test_control_warning_tests;
    data[3] = (CHAR)test_control_na_tests;

    /* Save the status in a global.  */
    test_control_return_status = status;

    /* Ensure interrupts are enabled.  */
    old_posture = tx_interrupt_control(TX_INT_ENABLE);

    /* Determine if it was successful or not.  */
    if((status == 1) || (_tx_thread_preempt_disable) || (old_posture == TX_INT_DISABLE))
    {
        data[1]++;
        exit_code = 1;
    }
    else if(status == 2)
    {
        data[2]++;
        exit_code = 2;
    }
    else if(status == 0)
    {
        data[0]++;
        exit_code = 0;
    }
    else if(status == 3)
    {
        data[3]++;
        exit_code = 3;
    }

    /* Send result through pipe. */
    write(result_fd[1], data, sizeof(data));
    exit(exit_code);
}

#else
/* Define what the initial system looks like.  */

void    tx_application_define(void *first_unused_memory)
{
    UCHAR    *pointer;

    /* Setup a pointer to the first unused memory.  */
    pointer = (UCHAR *)   first_unused_memory;

    /* Create the test control thread.  */
    tx_thread_create(&test_control_thread, "test control thread", test_control_thread_entry, 0,
        pointer, TEST_STACK_SIZE,
        0, 0, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer = pointer + TEST_STACK_SIZE;

#ifndef NETXTEST_TIMEOUT_DISABLE
    /* Create the test control semaphore.  */
    tx_semaphore_create(&test_control_sema, "Test control semaphore", 0);
#endif

    /* Remember the free memory pointer.  */
    test_free_memory_ptr = pointer;
}

/* Define the test control thread.  This thread is responsible for dispatching all of the
tests in the ThreadX test suite.  */

void  test_control_thread_entry(ULONG thread_input)
{
    UINT    i;

    /* Loop to process all tests...  */
    i = 0;
    while (test_control_tests[i].test_entry != TX_NULL)
    {

        /* Dispatch the test.  */
        (test_control_tests[i++].test_entry)(test_free_memory_ptr);

        if (test_control_return_status != 3)
        {

#ifdef NETXTEST_TIMEOUT_DISABLE
            /* Suspend control test to allow test to run.  */
            tx_thread_suspend(&test_control_thread);
#else
            if(tx_semaphore_get(&test_control_sema, test_control_tests[i - 1].timeout))
            {

                /* Test case timeouts. */
                printf("ERROR! Test case timeout\n");
                test_control_failed_tests++;

            }
#endif
        }
        else
            test_control_return_status = 0;

        /* Test finished, cleanup in preparation for the next test.  */
        test_control_cleanup();
        fflush(stdout);
    }

    /* Finished with all tests, print results and return!  */
    printf("**** Testing Complete ****\n");
    printf("**** Test Summary:  Tests Passed:  %lu   Tests Warning:  %lu   Tests Failed:  %lu\n", test_control_successful_tests, test_control_warning_tests, test_control_failed_tests);
#if 0
    fclose(stream);
#endif
#ifdef BATCH_TEST
    exit(test_control_failed_tests);
#endif

}

void  test_control_return(UINT status)
{
    UINT    old_posture = TX_INT_ENABLE;

    /* Save the status in a global.  */
    test_control_return_status = status;

    /* Ensure interrupts are enabled.  */
    old_posture = tx_interrupt_control(TX_INT_ENABLE);

    /* Determine if it was successful or not.  */
    if((status == 1) || (_tx_thread_preempt_disable) || (old_posture == TX_INT_DISABLE))
        test_control_failed_tests++;
    else if(status == 2)
        test_control_warning_tests++;
    else if(status == 0)
        test_control_successful_tests++;
    else if(status == 3)
        test_control_na_tests++;

#ifdef NETXTEST_TIMEOUT_DISABLE
    /* Resume the control thread to fully exit the test.  */
    tx_thread_resume(&test_control_thread);
#else
    if(test_control_return_status != 3)
        tx_semaphore_put(&test_control_sema);
#endif
}

void  test_control_cleanup(void)
{
    TX_MUTEX        *mutex_ptr;
    TX_THREAD       *thread_ptr;

    /* Clean timer used by RAM driver. */
    _nx_ram_network_driver_timer_clean();

    /* Delete all IP instances.   */
    while (_nx_ip_created_ptr)
    {

        /* Delete all UDP sockets.  */
        while (_nx_ip_created_ptr -> nx_ip_udp_created_sockets_ptr)
        {

            /* Make sure the UDP socket is unbound.  */
            nx_udp_socket_unbind(_nx_ip_created_ptr -> nx_ip_udp_created_sockets_ptr);

            /* Delete the UDP socket.  */
            nx_udp_socket_delete(_nx_ip_created_ptr -> nx_ip_udp_created_sockets_ptr);
        }

        /* Delete all TCP sockets.  */
        while (_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr)
        {

            /* Disconnect.  */
            nx_tcp_socket_disconnect(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr, NX_NO_WAIT);

            /* Make sure the TCP client socket is unbound.  */
            nx_tcp_client_socket_unbind(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr);

            /* Make sure the TCP server socket is unaccepted.  */
            nx_tcp_server_socket_unaccept(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr);

            /* Delete the TCP socket.  */
            nx_tcp_socket_delete(_nx_ip_created_ptr -> nx_ip_tcp_created_sockets_ptr);
        }

        /* Clear all listen requests.  */
        while (_nx_ip_created_ptr -> nx_ip_tcp_active_listen_requests)
        {

            /* Make sure the TCP server socket is unlistened.  */
            nx_tcp_server_socket_unlisten(_nx_ip_created_ptr, (_nx_ip_created_ptr -> nx_ip_tcp_active_listen_requests) -> nx_tcp_listen_port);
        }

        /* Delete the IP instance.  */
        nx_ip_delete(_nx_ip_created_ptr);
    }

    /* Delete all the packet pools.  */
    while (_nx_packet_pool_created_ptr)
    {
        nx_packet_pool_delete(_nx_packet_pool_created_ptr);
    }

    /* Reset the RAM driver.  */
    _nx_ram_network_driver_reset();

    /* Delete all queues.  */
    while(_tx_queue_created_ptr)
    {

        /* Delete queue.  */
        tx_queue_delete(_tx_queue_created_ptr);
    }

    /* Delete all semaphores.  */
    while(_tx_semaphore_created_ptr)
    {
#ifndef NETXTEST_TIMEOUT_DISABLE
        if(_tx_semaphore_created_ptr != &test_control_sema)
        {

            /* Delete semaphore.  */
            tx_semaphore_delete(_tx_semaphore_created_ptr);
        }
        else if(_tx_semaphore_created_count == 1)
            break;
        else
        {
            /* Delete semaphore.  */
            tx_semaphore_delete(_tx_semaphore_created_ptr -> tx_semaphore_created_next);
        }
#else
        /* Delete semaphore.  */
        tx_semaphore_delete(_tx_semaphore_created_ptr);
#endif
    }

    /* Delete all event flag groups.  */
    while(_tx_event_flags_created_ptr)
    {

        /* Delete event flag group.  */
        tx_event_flags_delete(_tx_event_flags_created_ptr);
    }

    /* Delete all byte pools.  */
    while(_tx_byte_pool_created_ptr)
    {

        /* Delete byte pool.  */
        tx_byte_pool_delete(_tx_byte_pool_created_ptr);
    }

    /* Delete all block pools.  */
    while(_tx_block_pool_created_ptr)
    {

        /* Delete block pool.  */
        tx_block_pool_delete(_tx_block_pool_created_ptr);
    }

    /* Delete all timers.  */
    while(_tx_timer_created_ptr)
    {

        /* Deactivate timer.  */
        tx_timer_deactivate(_tx_timer_created_ptr);

        /* Delete timer.  */
        tx_timer_delete(_tx_timer_created_ptr);
    }

    /* Delete all mutexes (except for system mutex).  */
    while(_tx_mutex_created_ptr)
    {

        /* Setup working mutex pointer.  */
        mutex_ptr = _tx_mutex_created_ptr;

#ifdef __ghs

        /* Determine if the mutex is the GHS system mutex.  If so, don't delete!  */
        if(mutex_ptr == &__ghLockMutex)
        {

            /* Move to next mutex.  */
            mutex_ptr = mutex_ptr -> tx_mutex_created_next;
        }

        /* Determine if there are no more mutexes to delete.  */
        if(_tx_mutex_created_count == 1)
            break;
#endif

        /* Delete mutex.  */
        tx_mutex_delete(mutex_ptr);
    }

    /* Delete all threads, except for timer thread, and test control thread.  */
    while (_tx_thread_created_ptr)
    {

        /* Setup working pointer.  */
        thread_ptr = _tx_thread_created_ptr;

#ifdef TX_TIMER_PROCESS_IN_ISR

        /* Determine if there are more threads to delete.  */
        if(_tx_thread_created_count == 1)
            break;

        /* Determine if this thread is the test control thread.  */
        if(thread_ptr == &test_control_thread)
        {

            /* Move to the next thread pointer.  */
            thread_ptr = thread_ptr -> tx_thread_created_next;
        }
#else

        /* Determine if there are more threads to delete.  */
        if(_tx_thread_created_count == 2)
            break;

        /* Move to the thread not protected.  */
        while ((thread_ptr == &_tx_timer_thread) || (thread_ptr == &test_control_thread))
        {

            /* Yes, move to the next thread.  */
            thread_ptr = thread_ptr -> tx_thread_created_next;
        }
#endif

        /* First terminate the thread to ensure it is ready for deletion.  */
        tx_thread_terminate(thread_ptr);

        /* Delete the thread.  */
        tx_thread_delete(thread_ptr);
    }

    /* At this point, only the test control thread and the system timer thread and/or mutex should still be
    in the system.  */

#ifdef NX_PCAP_ENABLE
    /* Close the pcap file.  */
    close_pcap_file();
#endif
}
#endif
