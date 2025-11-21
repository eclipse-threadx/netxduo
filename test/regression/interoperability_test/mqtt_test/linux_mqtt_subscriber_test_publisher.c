#include "mqtt_interoperability_test.h"

/* Global semaphore address. */
extern TLS_TEST_SEMAPHORE* semaphore_mqtt_topic_subscribed;
extern TLS_TEST_SEMAPHORE* semaphore_mqtt_message_published;

INT mqtt_publisher_entry(TLS_TEST_INSTANCE* instance_ptr)
{
CHAR* name;
/* Publish a messge to the test topic. */
CHAR* external_cmd[] = { "no_tls_pub.sh","-p", STRING(MQTT_PORT), "-t", "test", "-m", "hello", NULL};
INT status, exit_status;

    /* Get the name of the test instance. */
    status = tls_test_instance_get_name(instance_ptr, &name);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Wait for the subscriber. */
    tls_test_semaphore_wait(semaphore_mqtt_topic_subscribed);

    /* Wait for subscriber for one seconds. */
    tls_test_sleep(1);
    print_error_message("Instance %s: get semaphore_mqtt_topic_subscribed.\n", name);

    /* Call an external script in the directory prepared_test_program. */
    status = tls_test_launch_external_test_process(&exit_status, external_cmd);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Post the semaphore to indicate that one message is published. */
    tls_test_sleep(1);
    tls_test_semaphore_post(semaphore_mqtt_message_published);

    /* Check for exit status of the external script. */
    return_value_if_fail(0 == exit_status, TLS_TEST_INSTANCE_FAILED);
    return 0;
};
