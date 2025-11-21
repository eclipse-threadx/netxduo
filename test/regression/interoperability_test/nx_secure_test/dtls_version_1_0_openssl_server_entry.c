#include "tls_test_frame.h"

extern TLS_TEST_SEMAPHORE* semaphore_server_prepared;
/* Openssl echo server entry. */
INT dtls_server_entry(TLS_TEST_INSTANCE* instance_ptr)
{

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && defined(NX_SECURE_ENABLE_DTLS) && (NX_SECURE_TLS_TLS_1_1_ENABLED)

INT status, exit_status;
CHAR* external_cmd[] = { "openssl_echo_server.sh", "../key.pem", "../cert.pem", "-port", DEVICE_SERVER_PORT_STRING, "-dtls1", (CHAR*)NULL};

    /* Post the semaphore to notify that the reverse echo server is prepared. */
    tls_test_semaphore_post(semaphore_server_prepared);

    /* Launch the openssl server. */
    tls_test_launch_external_test_process(&exit_status, external_cmd);

#if 0 /* openssl exit with 0 no matter TLS session is established or not. */
    /* Check for the exit status of external program. */
    return_value_if_fail(0 == exit_status, TLS_TEST_INSTANCE_EXTERNAL_PROGRAM_FAILED);
#endif
    return TLS_TEST_SUCCESS;

#else /* ifndef NX_SECURE_TLS_CLIENT_DISABLED */

    return TLS_TEST_NOT_AVAILABLE;

#endif /* ifndef NX_SECURE_TLS_CLIENT_DISABLED */

}
