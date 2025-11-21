#include "tls_test_frame.h"

/* Global semaphore. */
extern TLS_TEST_SEMAPHORE* semaphore_server_prepared;

/* Instance two test entry. */
INT dtls_client_entry( TLS_TEST_INSTANCE* instance_ptr)
{

#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_DTLS)

/* Just use DTLSv1.2 */
CHAR* external_cmd[] = { "openssl_echo_client.sh", TLS_TEST_IP_ADDRESS_STRING, DEVICE_SERVER_PORT_STRING, "-cipher", "AES256-SHA256", "-dtls1_2", (CHAR*)NULL};
INT status, exit_status, instance_status = TLS_TEST_SUCCESS;

    print_error_message("Client waiting for semaphore.\n");
    tls_test_semaphore_wait(semaphore_server_prepared);
    tls_test_sleep(1);
    print_error_message("Client get semaphore. Launch a external test program.\n");

    /* Call an external program to connect to DTLS server. */
    status = tls_test_launch_external_test_process(&exit_status, external_cmd);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Check for exit_status. */
    return_value_if_fail(0 == exit_status, TLS_TEST_INSTANCE_FAILED);
    return TLS_TEST_SUCCESS;

#else /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

    return TLS_TEST_NOT_AVAILABLE;

#endif /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

}
