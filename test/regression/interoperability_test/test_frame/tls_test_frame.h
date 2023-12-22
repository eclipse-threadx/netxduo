#ifndef __TLS_TEST_FRAME__
#define __TLS_TEST_FRAME__

/* System headers. */
#include <fcntl.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

/* The compile definition of TEST_FOR_FRAME means that the current test program is only for the interoperability itself. */
#ifndef TEST_FOR_FRAME

/* Product headers. */
#include "tx_api.h"
#include "nx_api.h"
#include "nx_crypto.h"
#include "nx_secure_tls_api.h"
#include "nx_secure_dtls_api.h"
#include "nx_secure_x509.h"

#else /* ! TEST_FOR_FRAME */

typedef int INT;
typedef unsigned int UINT;
typedef void VOID;
typedef long LONG;
typedef unsigned long ULONG;
typedef char CHAR;
typedef unsigned char UCHAR;

#endif /* TEST_FOR_FRAME */

/* Type of test instance structure. */
typedef struct _TLS_TEST_INSTANCE TLS_TEST_INSTANCE;

/* Test entry function. */
typedef INT ( *InstanceTestEntryFunc)( TLS_TEST_INSTANCE* instance_ptr);

/* Test instance structure. */
struct _TLS_TEST_INSTANCE
{

    /* Members related to shared memory. */
    UINT    tls_test_shared_buffer_size;                /* The size of shared buffer. */
    UINT    tls_test_shared_buffer_offset;              /* The location of the variable of current shared buffer offset. */
    VOID*   tls_test_shared_buffer;                     /* The location of user's shared buffer. */

    /* Other attributes. */
    CHAR*   tls_test_instance_name;                     /* Instance name. */
    UINT    tls_test_timeout;                           /* Timeout before reciving SIGRECV. */
    UINT    tls_test_delay;                             /* Delay after last test process started. */
    UINT    tls_test_instance_identify;                 /* The location in director's registry table. */
    UINT    tls_test_instance_status;                   /* The indication of test instance status. */
    InstanceTestEntryFunc tls_test_entry;               /* The test entry of this test instance. */
    pid_t   tls_test_instance_current_pid;              /* The process id of test process. */
    TLS_TEST_INSTANCE* tls_test_next_instance_ptr;      /* The pointer to the next test instance. */
    INT     tls_test_instance_exit_status;              /* The return code of the test process.(A negative value -N indicate that the test process wat terminated by signal N). */
};

/* Test director structure. */
typedef struct _TLS_TEST_DIRECTOR
{
    UINT    tls_test_registered_test_instances;
    TLS_TEST_INSTANCE* tls_test_first_instance_ptr;
} TLS_TEST_DIRECTOR;

typedef sem_t TLS_TEST_SEMAPHORE;

typedef struct _TLS_TEST_EXTERNAL_TEST_PROCESS
{
    INT     tls_test_external_test_process_id;
} TLS_TEST_EXTERNAL_TEST_PROCESS;

/* Test instance methods. */
INT tls_test_instance_append( TLS_TEST_INSTANCE* instance_ptr, TLS_TEST_INSTANCE* next_instance_ptr);
INT tls_test_instance_create( TLS_TEST_INSTANCE** instance_ptr_ptr, CHAR* instance_name, InstanceTestEntryFunc test_entry, UINT delay, UINT timeout, UINT shared_buffer_size, VOID* reserved);
INT tls_test_instance_destroy( TLS_TEST_INSTANCE* instance_ptr);
INT tls_test_instance_find_next( TLS_TEST_INSTANCE* instance_ptr, TLS_TEST_INSTANCE** next_instance_ptr_ptr);
INT tls_test_instance_get_exit_status( TLS_TEST_INSTANCE* instance_ptr, INT* exit_status_ptr);
INT tls_test_instance_get_name( TLS_TEST_INSTANCE* instance_ptr, CHAR** name_ptr);
INT tls_test_instance_show_exit_status(TLS_TEST_INSTANCE* instance_ptr);
INT tls_test_instance_set_exit_status( TLS_TEST_INSTANCE* instance_ptr, INT exit_status);
INT tls_test_instance_set_exit_status( TLS_TEST_INSTANCE* instance_ptr, INT exit_status);

/* Test director methods. */
INT tls_test_director_create( TLS_TEST_DIRECTOR** director_ptr, VOID* description);
INT tls_test_director_register_test_instance( TLS_TEST_DIRECTOR* director_ptr, TLS_TEST_INSTANCE* instance_ptr);
INT tls_test_director_cleanup_registered_instances( TLS_TEST_DIRECTOR* director_ptr);
INT tls_test_director_destroy( TLS_TEST_DIRECTOR* director_ptr);
INT tls_test_director_clean_all( TLS_TEST_DIRECTOR* director_ptr);
INT tls_test_director_test_start( TLS_TEST_DIRECTOR* director_ptr);

/* Shared buffer manipulation. */
INT tls_test_instance_get_shared_buffer( TLS_TEST_INSTANCE* instance_ptr, VOID** shared_buffer_ptr);
INT tls_test_instance_get_shared_buffer_offset( TLS_TEST_INSTANCE* instance_ptr, UINT* offset);
INT tls_test_instance_set_shared_buffer_offset( TLS_TEST_INSTANCE* instance_ptr, UINT offset);
INT tls_test_instance_append_data_to_shared_buffer( TLS_TEST_INSTANCE* instance_ptr, VOID* data, UINT* length);

/* Semaphore methods. */
INT tls_test_semaphore_create( TLS_TEST_SEMAPHORE** semaphore_ptr_ptr, UINT initial_value);
INT tls_test_semaphore_post( TLS_TEST_SEMAPHORE* semaphore_ptr);
INT tls_test_semaphore_wait( TLS_TEST_SEMAPHORE* semaphore_ptr);
INT tls_test_semaphore_destroy( TLS_TEST_SEMAPHORE* semaphore_ptr);

/* External programs calling. */
INT tls_test_get_external_test_process_output( INT* exit_status_ptr, CHAR* argv[], VOID* output_buffer, ULONG* length_ptr);
INT tls_test_launch_external_test_process( INT* exit_status_ptr, CHAR* argv[]);
INT tls_test_launch_external_test_process_in_background( TLS_TEST_EXTERNAL_TEST_PROCESS* test_process_ptr, CHAR* argv[]);
INT tls_test_kill_external_test_process( TLS_TEST_EXTERNAL_TEST_PROCESS* test_process_ptr);
INT tls_test_wait_all_child_process( void* reserved_ptr);
INT tls_test_wait_external_test_process( TLS_TEST_EXTERNAL_TEST_PROCESS* test_process_ptr, INT* exit_status_ptr);
INT tls_test_instance_append_external_program_output_to_shared_buffer( TLS_TEST_INSTANCE* instance_ptr, INT* exit_status_ptr, CHAR* argv[]);
INT tls_test_uninterruptable_wait( pid_t* pid_ptr, INT* exit_status_ptr);
#define tls_test_sleep( secs) sleep( secs)

/* Return code macros. */
#define TLS_TEST_SUCCESS                                    0
#define TLS_TEST_UNABLE_TO_CREATE_SHARED_MEMORY             1
#define TLS_TEST_INVALID_POINTER                            2
#define TLS_TEST_TOO_MANY_TEST_INSTANCES                    3
#define TLS_TEST_UNKNOWN_TYPE_ERROR                         4
#define TLS_TEST_ALREADY_REGISTERED                         5
#define TLS_TEST_NO_REGISTERED_INSTANCE                     6
#define TLS_TEST_INSTANCE_UNINITIALIZED                     7
#define TLS_TEST_UNABLE_TO_CREATE_TEST_PROCESS              8
#define TLS_TEST_ILLEGAL_SHARED_BUFFER_ACCESS               9
#define TLS_TEST_UNABLE_TO_REDIRECT_EXTERNAL_PROGRAM_OUTPUT 10
#define TLS_TEST_SYSTEM_CALL_FAILED                         11
#define TLS_TEST_INSTANCE_EXTERNAL_PROGRAM_FAILED           12
#define TLS_TEST_INSTANTIATION_FAILED                       13
#define TLS_TEST_ENTRY_FUNCTION_FAILED                      14
#define TLS_TEST_INSTANCE_UNEXITED                          15
#define TLS_TEST_INSTANCE_FAILED                            16
#define TLS_TEST_INSTANCE_NO_TIME_LEFT                      17
#define TLS_TEST_NOT_AVAILABLE                              233

/* Test instance status */
#define TLS_TEST_INSTANCE_STATUS_INITIALIZED                0x1
#define TLS_TEST_INSTANCE_STATUS_REGISTERED                 0x10
#define TLS_TEST_INSTANCE_STATUS_RUNNING                    0x100
#define TLS_TEST_INSTANCE_STATUS_EXITED                     0x1000
#define TLS_TEST_INSTANCE_STATUS_SIGNALED                   0x10000

/* Default timeout for every test process. */
#define TLS_TEST_PROCESS_DEFAULT_TIMEOUT                    (60*15)

/* Maximum of instances registered in a director instance. */
#define TLS_TEST_MAX_TEST_INSTANCE_NUMBER                   10

/* The buffer size for pipe data. */
#define TLS_TEST_PIPE_BUFFER_SIZE                           1024

/* The maximum of external program parameters. */
#define TLS_TEST_MAXIMUM_EXTERNAL_PROGRAM_PARAMETERS        1024

/* Take use of two levels of macros to stringize the result of expansison of a macro argument. */
#define xstr(s) str(s)
#define str(s) #s

/* Specify the ipv4 address of the test device. */
#if defined(TLS_TEST_IP_BYTE_0) || defined(TLS_TEST_IP_BYTE_1) || defined(TLS_TEST_IP_BYTE_2) || defined(TLS_TEST_IP_BYTE_3)
#define TLS_TEST_IP_ADDRESS_STRING xstr(TLS_TEST_IP_BYTE_0)"."xstr(TLS_TEST_IP_BYTE_1)"."xstr(TLS_TEST_IP_BYTE_2)"."xstr(TLS_TEST_IP_BYTE_3)
#define TLS_TEST_IP_ADDRESS_NUMBER  IP_ADDRESS( TLS_TEST_IP_BYTE_0, TLS_TEST_IP_BYTE_1, TLS_TEST_IP_BYTE_2, TLS_TEST_IP_BYTE_3)
#endif /* defined() && defined() && defined() && defined() */

/* TLS_TEST_IP_ADDRESS_STRING */
#ifndef TLS_TEST_IP_ADDRESS_STRING
#define TLS_TEST_IP_ADDRESS_STRING                          "10.0.0.1"
#endif /* ifndef TLS_TEST_IP_ADDRESS_STRING */

#ifndef TLS_TEST_IP_ADDRESS_NUMBER
#define TLS_TEST_IP_ADDRESS_NUMBER                          IP_ADDRESS( 10, 0, 0, 1)
#endif /* ifndef TLS_TEST_IP_ADDRESS_NUMBER */

/* Specify the ipv4 address of the remote device. */
#if defined(REMOTE_IP_BYTE_0) || defined(REMOTE_IP_BYTE_1) || defined(REMOTE_IP_BYTE_2) || defined(REMOTE_IP_BYTE_3)
#define REMOTE_IP_ADDRESS_STRING xstr(REMOTE_IP_BYTE_0)"."xstr(REMOTE_IP_BYTE_1)"."xstr(REMOTE_IP_BYTE_2)"."xstr(REMOTE_IP_BYTE_3)
#define REMOTE_IP_ADDRESS_NUMBER  IP_ADDRESS( REMOTE_IP_BYTE_0, REMOTE_IP_BYTE_1, REMOTE_IP_BYTE_2, REMOTE_IP_BYTE_3)
#endif /* defined() && defined() && defined() && defined() */

#ifndef REMOTE_IP_ADDRESS_STRING
#define REMOTE_IP_ADDRESS_STRING                            "10.0.0.2"
#endif /* ifndef REMOTE_IP_ADDRESS_STRING */

#ifndef REMOTE_IP_ADDRESS_NUMBER
#define REMOTE_IP_ADDRESS_NUMBER                            IP_ADDRESS( 10, 0, 0, 2)
#endif /* ifndef REMOTE_IP_ADDRESS_NUMBER */


/* For parallel processing, all ports are using in arrangement. */
#ifdef INTEROPERABILITY_TEST_ENABLE_PARALLEL_PROCESSING

#ifndef DEVICE_SERVER_PORT
#define DEVICE_SERVER_PORT 4433
#endif /* DEVICE_SERVER_PORT */

/* the string for DEVICE_SERVER_PORT */
#define DEVICE_SERVER_PORT_STRING xstr(DEVICE_SERVER_PORT)

#ifndef LOCAL_CLIENT_PORT
#define LOCAL_CLIENT_PORT 30024
#endif /* LOCAL_CLIENT_PORT */

/* the string for LOCAL_CLIENT_PORT */
#define LOCAL_CLIENT_PORT_STRING xstr(LOCAL_CLIENT_PORT)

#endif /* INTEROPERABILITY_TEST_ENABLE_PARALLEL_PROCESSING */


/* Output error message to stderr. */
#define print_error_message( format, ...) printf( format, ##__VA_ARGS__) 

#define return_value_if_fail( p, val) if(!(p)){print_error_message("Error! %s:%d, "#p" failed.\n", __func__, __LINE__);return(val);}

#define exit_if_fail( p, val) if(!(p)){print_error_message("Error! %s:%d, "#p" failed.\n", __func__, __LINE__);exit(val);}

#define show_error_message_if_fail( p) if(!(p)){print_error_message("Error! %s:%d, "#p" failed.\n", __func__, __LINE__);}

#define add_error_counter_if_fail( p, counter) if(!(p)){print_error_message("Error! %s:%d, "#p" failed.\n", __func__, __LINE__);counter++;}

#endif /* __TLS_TEST_FRAME__ */
