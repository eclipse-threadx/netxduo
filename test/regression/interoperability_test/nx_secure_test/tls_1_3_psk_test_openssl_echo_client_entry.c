#include "tls_test_frame.h"

extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;

/* Openssl echo client entry. */
INT openssl_echo_client_entry(TLS_TEST_INSTANCE* instance_ptr)
{

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && (NX_SECURE_TLS_TLS_1_3_ENABLED) && defined(NX_SECURE_ENABLE_PSK_CIPHERSUITES)


INT status, exit_status;

/* Added -curves prime256v1 to avoid hello retry. */
CHAR* external_cmd[] = { "openssl_1_1_echo_client.sh", TLS_TEST_IP_ADDRESS_STRING, DEVICE_SERVER_PORT_STRING, "-curves", "prime256v1",
                         "-psk", "112233445566",
                         "-psk_identity", "psk_test",
                         (CHAR*)NULL};

    tls_test_semaphore_wait(semaphore_echo_server_prepared);
    tls_test_sleep(1);

    /* Call an external program to connect to tls server. */
    status = tls_test_launch_external_test_process(&exit_status, external_cmd);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Check for exit_status. */
    return_value_if_fail(0 == exit_status, TLS_TEST_INSTANCE_FAILED);

    return TLS_TEST_SUCCESS;

#else

    return TLS_TEST_NOT_AVAILABLE;

#endif

}