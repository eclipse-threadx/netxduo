#include "mqtt_interoperability_test.h"

#ifdef NXD_MQTT_REQUIRE_TLS
INT mqtt_server_entry(TLS_TEST_INSTANCE* instance_ptr)
{
    return TLS_TEST_NOT_AVAILABLE;
}
#else
/* Global semaphore address. */
extern TLS_TEST_SEMAPHORE* semaphore_mqtt_server_prepared;
extern TLS_TEST_SEMAPHORE* semaphore_mqtt_test_finished;

INT mqtt_server_entry(TLS_TEST_INSTANCE* instance_ptr)
{
CHAR* name;
CHAR* external_cmd[] = { "no_tls_server.sh", "-p", STRING(MQTT_PORT), NULL};
INT status, exit_status;
TLS_TEST_EXTERNAL_TEST_PROCESS external_test_process;

    /* Get the name of the test instance. */
    status = tls_test_instance_get_name(instance_ptr, &name);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Launch the mqtt server in background. */
    status = tls_test_launch_external_test_process_in_background(&external_test_process, external_cmd);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Post the semaphore to indicate that mqtt server is prepared. */
    tls_test_sleep(2);
    print_error_message("Instance %s: post semaphore_mqtt_server_prepared.\n", name);
    tls_test_semaphore_post(semaphore_mqtt_server_prepared);

    /* Wait for the termination of the test. */
    print_error_message("Instance %s: wait for semaphore_mqtt_test_finished.\n", name);
    tls_test_semaphore_wait(semaphore_mqtt_test_finished);

    /* Kill the mqtt server by SIGTERM. */
    status = tls_test_kill_external_test_process(&external_test_process);
    status += tls_test_wait_external_test_process(&external_test_process, &exit_status);
    return_value_if_fail(TLS_TEST_SUCCESS == status, TLS_TEST_UNKNOWN_TYPE_ERROR);

    /* Make sure that the mqtt server is killed by SIGTERM. */
    /* For a shell process killed by signal, the return value must be (128 + signal number). */
    return_value_if_fail(128 + SIGTERM == exit_status, TLS_TEST_INSTANCE_FAILED);
    return 0;
}
#endif
