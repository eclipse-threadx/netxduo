#include "tls_test_frame.h"

typedef struct
{
    UINT sig_alg_index;
    UINT session_succ;
} OPENSSLTEST;

static CHAR *signature_algorithms[] = 
{
    "RSA+SHA256",
    "RSA+SHA384",
    "RSA+SHA512",
    "RSA+SHA1",
    "ECDSA+SHA256",
    "ECDSA+SHA384",
    "ECDSA+SHA512",
    "ECDSA+SHA1",
};

OPENSSLTEST tests[] =
{

    /* Test RSA. */
    {0, NX_TRUE},
    {1, NX_TRUE},
    {2, NX_TRUE},
    {3, NX_TRUE},

    /* Test ECDSA. */
    {4, NX_TRUE},
    {5, NX_TRUE},
    {6, NX_TRUE},
    {7, NX_TRUE},

    /* Noa shared signature algorithms. */
    {5, NX_FALSE},
};

extern TLS_TEST_SEMAPHORE* semaphore_echo_server_prepared;
INT openssl_echo_client_entry( TLS_TEST_INSTANCE* instance_ptr)
{

#if !defined(NX_SECURE_TLS_SERVER_DISABLED) && defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)

/* Just use TLSv1.2 */
CHAR* external_cmd[] = { "openssl_echo_client.sh", TLS_TEST_IP_ADDRESS_STRING, DEVICE_SERVER_PORT_STRING,
                         "-sigalgs", "", (CHAR*)NULL};
INT status, exit_status, instance_status = TLS_TEST_SUCCESS, i = 0;

    for ( ; i < sizeof(tests) / sizeof(OPENSSLTEST); i++)
    {

        print_error_message("Connection %d: waiting for semaphore.\n", i);
        tls_test_semaphore_wait(semaphore_echo_server_prepared);
        tls_test_sleep(1);
        print_error_message("Connection %d: client get semaphore. Launch a external test program.\n", i);


        /* Call an external program to connect to tls server. */
        external_cmd[4] = signature_algorithms[tests[i].sig_alg_index];
        status = tls_test_launch_external_test_process(&exit_status, external_cmd);
        return_value_if_fail(TLS_TEST_SUCCESS == status, status);

        /* Check for exit_status. */
        if ((exit_status && tests[i].session_succ) ||
            (!exit_status && !tests[i].session_succ))
        {

            /* Record errors. */
            instance_status = TLS_TEST_INSTANCE_EXTERNAL_PROGRAM_FAILED;
        }
    }
    return instance_status;

#else /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

    return TLS_TEST_NOT_AVAILABLE;

#endif /* ifndef NX_SECURE_TLS_SERVER_DISABLED */

}
