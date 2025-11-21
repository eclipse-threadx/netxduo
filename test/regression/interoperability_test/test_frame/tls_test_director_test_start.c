#include "tls_test_frame.h"

static void signal_handler_wait_all( int signum)
{
    /* Wait for all processes in current process group. */
    while ( -1 != wait(NULL));

    /* Raise the same signal to kill itself. */
    raise( signum);
}

static void signal_handler_kill_process_group( int signum)
{
    /* Install an one shot signal handler. */
    struct sigaction sig_act;
    sig_act.sa_handler = signal_handler_wait_all;
    sig_act.sa_flags = SA_RESETHAND;
    sigaction( signum, &sig_act, NULL);

    /* Send received signal to every process in current process group. */
    kill( 0, signum);
}

/* Run test programs. */
INT tls_test_director_test_start( TLS_TEST_DIRECTOR* director_ptr)
{
pid_t pid;
TLS_TEST_INSTANCE* iter, *iter_term, *iter_wait;
INT status = TLS_TEST_SUCCESS, exit_status = 0;
int err = 0;

    /* Check parameters. */
    return_value_if_fail( NULL != director_ptr, TLS_TEST_INVALID_POINTER);
    return_value_if_fail( 0 != director_ptr -> tls_test_registered_test_instances, TLS_TEST_NO_REGISTERED_INSTANCE);

    /* Get the first instance. */
    iter = director_ptr -> tls_test_first_instance_ptr;

    /* Loop to launch all test instances. */
    while ( NULL != iter)
    {

        /* Launch next test instance after given seconds. */
        if ( iter -> tls_test_delay)
        {
            sleep(iter -> tls_test_delay);
        }

        pid = fork();

        /* Error handle. */
        show_error_message_if_fail( -1 != pid);
        if ( -1 == pid)
        {
            /* Cleanup all running test process if fail to fork a new process for the new instance. */
            for ( iter_term = director_ptr -> tls_test_first_instance_ptr; iter_term != iter; tls_test_instance_find_next( iter_term, &iter_term))
            {
                /* Kill the process group of the test instance. */
                status = kill( - iter_term -> tls_test_instance_current_pid, SIGTERM);
                show_error_message_if_fail( -1 != status);
                if ( -1 == status)
                    continue;

                /* Get exit status of test instances. */
                status = waitpid( iter_term -> tls_test_instance_current_pid, &exit_status, 0);
                show_error_message_if_fail( -1 != status);
                if ( -1 == status)
                    continue;

                status = tls_test_instance_set_exit_status( iter_term, exit_status);
                return_value_if_fail( TLS_TEST_SUCCESS == status, status);

            } /* for iter_term */

            return TLS_TEST_UNABLE_TO_CREATE_TEST_PROCESS;
        } /* if -1 == pid */

        /* Child process. */
        else if (0 == pid)
        {

            /* Create a new process group. */
            setpgid( 0, 0);

            /* Install signal handler for SIGALRM and SIGTERM. */
            struct sigaction sig_act;
            sig_act.sa_handler = signal_handler_kill_process_group;    /* Specify signal handler. */
            sig_act.sa_flags = SA_RESETHAND;                /* Set the signal handler as a one shot handler. */
            status = sigaction( SIGALRM, &sig_act, NULL);
            return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);
            status = sigaction( SIGTERM, &sig_act, NULL);
            return_value_if_fail( -1 != status, TLS_TEST_SYSTEM_CALL_FAILED);

            /* Set timeer for the test process. */
            alarm( iter -> tls_test_timeout);

            /* Enter test entry. */
            status = iter -> tls_test_entry( iter); 

            /* Wait until all child process terminated. */
            tls_test_wait_all_child_process( NULL);

            exit( status);
        }
        /* Parent process. */
        else
        {
            /* Set the gid of the child process again. */
            setpgid( pid, pid);

            iter -> tls_test_instance_current_pid = pid;
            iter -> tls_test_instance_status |= TLS_TEST_INSTANCE_STATUS_RUNNING;
            tls_test_instance_find_next( iter, &iter);
        }
    } /* NULL != iter */

    /* Wait for all test instances. */
    iter_wait = director_ptr -> tls_test_first_instance_ptr;
    while (iter_wait != NULL && TLS_TEST_SUCCESS == ( status = tls_test_uninterruptable_wait( &pid, &exit_status)))
    {
        iter = director_ptr -> tls_test_first_instance_ptr;
        while ( NULL != iter)
        {
            if (iter -> tls_test_instance_current_pid == pid)
            {
                status = tls_test_instance_set_exit_status( iter, exit_status);
                show_error_message_if_fail( TLS_TEST_SUCCESS == status);
                if (iter -> tls_test_instance_exit_status != TLS_TEST_SUCCESS)
                {
                    err = 1;
                }

                break; /* NULL != iter */
            } /* if iter -> tls_test_instance_current_pid == pid */

            tls_test_instance_find_next( iter, &iter);
        } /* NULL != iter */

        if (err == 1)
        {
            for (iter_term = director_ptr -> tls_test_first_instance_ptr; iter_term != NULL;)
            {
                if (iter != iter_term)
                {
                    /* Kill the process group of the test instance. */
                    status = kill(-iter_term -> tls_test_instance_current_pid, SIGTERM);
                    show_error_message_if_fail(-1 != status);
                    if (-1 != status)
                    {

                        /* Get exit status of test instances. */
                        status = waitpid(iter_term -> tls_test_instance_current_pid, &exit_status, 0);
                        show_error_message_if_fail(-1 != status);
                        if (-1 != status)
                        {
                            status = tls_test_instance_set_exit_status(iter_term, exit_status);
                            return_value_if_fail(TLS_TEST_SUCCESS == status, status);
                        }
                    }
                }
                tls_test_instance_find_next( iter_term, &iter_term);
            }
            break;
        }
        tls_test_instance_find_next(iter_wait, &iter_wait);
    } /* while exited_test_intances < director_ptr -> tls_tset_registered_test_instances */

    return TLS_TEST_SUCCESS;
}
