#include "tls_test_frame.h"

/* Declare the test entries of test instances. */
INT mqtt_server_entry(TLS_TEST_INSTANCE* instance_ptr);
INT mqtt_publisher_entry(TLS_TEST_INSTANCE* instance_ptr);
INT mqtt_subscriber_entry(TLS_TEST_INSTANCE* instance_ptr);

/* Declare semaphores. */
TLS_TEST_SEMAPHORE* semaphore_mqtt_server_prepared;
TLS_TEST_SEMAPHORE* semaphore_mqtt_topic_subscribed;
TLS_TEST_SEMAPHORE* semaphore_mqtt_message_published;
TLS_TEST_SEMAPHORE* semaphore_mqtt_test_finished;

INT main(INT argc, CHAR* argv[])
{
INT status;
TLS_TEST_INSTANCE *ins0, *ins1, *ins2;
TLS_TEST_DIRECTOR *director;
INT exit_status[3];

    /* Create three test instances. */
    status = tls_test_instance_create(&ins0,                          /* test instance ptr */
                                      "mqtt_server",                  /* instance name */
                                      mqtt_server_entry,              /* test entry */
                                      0,                              /* delay(seconds) */
                                      20,                             /* timeout(seconds) */
                                      1024,                           /* shared buffer size */
                                      NULL);                          /* reserved */
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_create(&ins1, 
                                      "mqtt_subscriber",
                                      mqtt_subscriber_entry,
                                      0,
                                      20,
                                      1024,
                                      NULL);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    status = tls_test_instance_create(&ins2, 
                                      "mqtt_publisher",
                                      mqtt_publisher_entry,
                                      0,
                                      20,
                                      1024,
                                      NULL);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Create test semaphores whose value will be initialized as zero. */
    status = tls_test_semaphore_create(&semaphore_mqtt_server_prepared, 0);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);
    status = tls_test_semaphore_create(&semaphore_mqtt_message_published, 0);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);
    status = tls_test_semaphore_create(&semaphore_mqtt_topic_subscribed, 0);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);
    status = tls_test_semaphore_create(&semaphore_mqtt_test_finished, 0);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Create the test director. */
    status = tls_test_director_create(&director, NULL /* reserved */);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Register test instances to the director. */
    status = tls_test_director_register_test_instance(director, ins0);
    status += tls_test_director_register_test_instance(director, ins1);
    status += tls_test_director_register_test_instance(director, ins2);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Launch test. */
    status = tls_test_director_test_start(director);
    return_value_if_fail(TLS_TEST_SUCCESS == status, status);

    /* Show test results. */
    tls_test_instance_show_exit_status(ins0);
    tls_test_instance_show_exit_status(ins1);
    tls_test_instance_show_exit_status(ins2);

    /* Collect exit code. */
    tls_test_instance_get_exit_status(ins0, &(exit_status[0]));
    tls_test_instance_get_exit_status(ins1, &(exit_status[1]));
    tls_test_instance_get_exit_status(ins1, &(exit_status[2]));

    /* Destroy all created instances. */
    tls_test_director_clean_all(director);

    /* Destroy the semaphore. */
    tls_test_semaphore_destroy(semaphore_mqtt_server_prepared);
    tls_test_semaphore_destroy(semaphore_mqtt_topic_subscribed);
    tls_test_semaphore_destroy(semaphore_mqtt_message_published);
    tls_test_semaphore_destroy(semaphore_mqtt_test_finished);

    /* Check the exit codes of two instances. */
    return_value_if_fail((TLS_TEST_NOT_AVAILABLE != exit_status[0]) && (TLS_TEST_NOT_AVAILABLE != exit_status[1]) && (TLS_TEST_NOT_AVAILABLE != exit_status[2]), TLS_TEST_NOT_AVAILABLE);
    return_value_if_fail((0 == exit_status[0]) && (0 == exit_status[1]) && (0 == exit_status[2]), TLS_TEST_UNKNOWN_TYPE_ERROR);
    return TLS_TEST_SUCCESS;
}
