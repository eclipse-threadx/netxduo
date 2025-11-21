#ifndef __NX_SECURE_TLS_TEST_INIT_FUNCTIONS_H
#define __NX_SECURE_TLS_TEST_INIT_FUNCTIONS_H


static void nx_secure_tls_test_init_functions(NX_SECURE_TLS_SESSION *tls_session)
{
    tls_session->nx_secure_generate_premaster_secret = _nx_secure_generate_premaster_secret;
    tls_session->nx_secure_generate_master_secret = _nx_secure_generate_master_secret;
    tls_session->nx_secure_generate_session_keys = _nx_secure_generate_session_keys;
    tls_session->nx_secure_session_keys_set = _nx_secure_session_keys_set;
#ifndef NX_SECURE_TLS_CLIENT_DISABLED
    tls_session->nx_secure_process_server_key_exchange = _nx_secure_process_server_key_exchange;
    tls_session->nx_secure_generate_client_key_exchange = _nx_secure_generate_client_key_exchange;
#endif
#ifndef NX_SECURE_TLS_SERVER_DISABLED
    tls_session->nx_secure_process_client_key_exchange = _nx_secure_process_client_key_exchange;
    tls_session->nx_secure_generate_server_key_exchange = _nx_secure_generate_server_key_exchange;
#endif
    tls_session->nx_secure_verify_mac = _nx_secure_verify_mac;
    tls_session->nx_secure_remote_certificate_verify = _nx_secure_remote_certificate_verify;
    tls_session->nx_secure_trusted_certificate_add = _nx_secure_trusted_certificate_add;
}
#endif