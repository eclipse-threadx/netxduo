#include "tls_test_frame.h"

/* Global demo emaphore. */
extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;

/* Instance two test entry. */
INT openssl_echo_client_entry( TLS_TEST_INSTANCE* instance_ptr)
{

#ifndef NX_SECURE_TLS_SERVER_DISABLED

/* Just use TLSv1.2 */
CHAR* external_cmd[] = { "openssl_echo_client.sh", TLS_TEST_IP_ADDRESS_STRING, DEVICE_SERVER_PORT_STRING, "-cipher", "AES128-SHA256", (CHAR*)NULL};
INT status, exit_status, instance_status = TLS_TEST_SUCCESS, i = 0;

    print_error_message("Connection %d: waiting for semaphore.\n", i);
    tls_test_semaphore_wait(semaphore_echo_server_prepared);
    tls_test_sleep(1);
    print_error_message("Connection %d: client get semaphore. Launch a external test program.\n", i);

    /* Call an external program to connect to tls server. */
    status = tls_test_launch_external_test_process(&exit_status, external_cmd);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Check for exit_status. */
    return_value_if_fail(0 == exit_status, TLS_TEST_INSTANCE_FAILED);
    return TLS_TEST_SUCCESS;

#else /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

    return TLS_TEST_NOT_AVAILABLE;

#endif /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

}
