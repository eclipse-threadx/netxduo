#Describe test points.
list( APPEND REGRESSION_TEST_LIST demo_semaphore_test)
set( demo_semaphore_test_FILE_LIST
demo_semaphore_test.c
)

list( APPEND REGRESSION_TEST_LIST demo_shared_buffer_test)
set( demo_shared_buffer_test_FILE_LIST
demo_shared_buffer_test.c
)

list( APPEND REGRESSION_TEST_LIST demo_background_test_process_test)
set( demo_background_test_process_test_FILE_LIST
demo_background_test_process_test.c
)

list( APPEND REGRESSION_TEST_LIST demo_timeout_test)
set( demo_timeout_test_FILE_LIST
demo_timeout_test.c
)

list( APPEND REGRESSION_TEST_LIST demo_background_test_process_group_test)
set( demo_background_test_process_group_test_FILE_LIST
demo_background_test_process_group_test.c
)
