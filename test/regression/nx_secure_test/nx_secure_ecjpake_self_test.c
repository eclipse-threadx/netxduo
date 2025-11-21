
#include <stdio.h>
#include <time.h>
#include "nx_crypto_ecjpake.h"
#include "nx_crypto_ec.h"
#include "nx_crypto_sha2.h"
#include "tls_test_utility.h"
#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif

#define LOOP 100

/* Declare a crypto method for ECJ-PAKE. */
NX_CRYPTO_METHOD crypto_method_ecjpake =
{
    NX_CRYPTO_KEY_EXCHANGE_ECJPAKE,           /* ECJ-PAKE placeholder                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_ECJPAKE),                /* Metadata size in bytes                 */
    _nx_crypto_method_ecjpake_init,           /* Initialization routine.                */
    _nx_crypto_method_ecjpake_cleanup,        /* Cleanup routine, not used.             */
    _nx_crypto_method_ecjpake_operation,      /* Operation                              */
};

/* Define software SHA256 method. */
static NX_CRYPTO_METHOD crypto_method_sha256 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256,   /* SHA crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    256,                                      /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_SHA256),                        /* Metadata size in bytes                 */
    NX_CRYPTO_NULL,                           /* SHA initialization routine.            */
    NX_CRYPTO_NULL,                           /* SHA cleanup routine, not used.         */
    _nx_crypto_method_sha256_operation,       /* SHA operation                          */
};

extern NX_CRYPTO_METHOD crypto_method_ec_secp192;
extern NX_CRYPTO_METHOD crypto_method_ec_secp224;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;

/* ECJPAKE context. */
static NX_CRYPTO_ECJPAKE ecjpake_ctx_client;
static NX_CRYPTO_ECJPAKE ecjpake_ctx_server;

/* SHA context. */
static NX_SHA256 sha256_ctx;


static UCHAR psk_data[32];


/* Output. */
static UCHAR client_hello[330];
static UCHAR server_hello[330];
static UCHAR client_ke[165];
static UCHAR server_ke[165];
static UCHAR client_pms[32];
static UCHAR server_pms[32];

static NX_CRYPTO_METHOD *ecc_methods[] =
{
    /* FIXME: Due to hard coded length, only secp256 is supported. */
#if 0
    &crypto_method_ec_secp192,
    &crypto_method_ec_secp224,
#endif
    &crypto_method_ec_secp256,
#if 0
    &crypto_method_ec_secp384,
    &crypto_method_ec_secp521
#endif
};


#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_ecjpake_self_test_application_define(void *first_unused_memory)
#endif
{
#ifndef NX_CRYPTO_STANDALONE_ENABLE
    tx_thread_create(&thread_0, "Thread 0", thread_0_entry, 0,
                     first_unused_memory, 4096,
                     16, 16, 4, TX_AUTO_START);
#else
    thread_0_entry(0);
#endif
}

static VOID thread_0_entry(ULONG thread_input)
{
UINT i, j;
UINT psk_len;
UINT status;
NX_CRYPTO_METHOD *ecc_method;
NX_CRYPTO_EXTENDED_OUTPUT extended_output[2];
UCHAR buffer[32];

    /* Print out test information banner.  */
    printf("NetX Secure Test:   ECJPAKE Self Test..................................");

    srand(time(0));

    for (i = 0; i < LOOP; i++)
    {

        memset(client_pms, 0xFF, sizeof(client_pms));
        memset(server_pms, 0, sizeof(server_pms));

        memset(&ecjpake_ctx_client, 0, sizeof(ecjpake_ctx_client));
        memset(&ecjpake_ctx_server, 0, sizeof(ecjpake_ctx_server));

        psk_len = rand() & 0x1F;
        if (psk_len == 0)
        {
            psk_len = 1;
        }
        for (j = 0; j < psk_len; j++)
        {
            psk_data[j] = 1 + (rand() % 254);
        }

        ecc_method = ecc_methods[i % (sizeof(ecc_methods) / sizeof(NX_CRYPTO_METHOD *))];

        status = crypto_method_ecjpake.nx_crypto_init(&crypto_method_ecjpake,
                                                      psk_data,
                                                      (USHORT)(psk_len << 3),
                                                      NX_CRYPTO_NULL,
                                                      &ecjpake_ctx_client,
                                                      sizeof(ecjpake_ctx_client));
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_HASH_METHOD_SET,
                                                          NX_CRYPTO_NULL,
                                                          &crypto_method_ecjpake,
                                                          NX_CRYPTO_NULL,
                                                          (USHORT)(sizeof(NX_SHA256) << 3),
                                                          (UCHAR *)&crypto_method_sha256,
                                                          sizeof(NX_CRYPTO_METHOD),
                                                          NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0,
                                                          &ecjpake_ctx_client,
                                                          sizeof(ecjpake_ctx_client),
                                                          NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_CURVE_SET,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL, 0,
                                                           (UCHAR *)ecc_method,
                                                           sizeof(NX_CRYPTO_METHOD),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0,
                                                           &ecjpake_ctx_client,
                                                           sizeof(ecjpake_ctx_client),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecjpake.nx_crypto_init(&crypto_method_ecjpake,
                                                      psk_data,
                                                      (USHORT)(psk_len << 3),
                                                      NX_CRYPTO_NULL,
                                                      &ecjpake_ctx_server,
                                                      sizeof(ecjpake_ctx_server));
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_HASH_METHOD_SET,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL,
                                                           (USHORT)(sizeof(NX_SHA256) << 3),
                                                           (UCHAR *)&crypto_method_sha256,
                                                           sizeof(NX_CRYPTO_METHOD),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0,
                                                           &ecjpake_ctx_server,
                                                           sizeof(ecjpake_ctx_server),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_CURVE_SET,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL, 0,
                                                           (UCHAR *)ecc_method,
                                                           sizeof(NX_CRYPTO_METHOD),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0,
                                                           &ecjpake_ctx_server,
                                                           sizeof(ecjpake_ctx_server),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);


        extended_output[0].nx_crypto_extended_output_data = client_hello;
        extended_output[0].nx_crypto_extended_output_length_in_byte = sizeof(client_hello);
        extended_output[0].nx_crypto_extended_output_actual_size = 0;
        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_CLIENT_HELLO_GENERATE,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL, 0,
                                                           NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL,
                                                           (UCHAR *)&extended_output[0],
                                                           sizeof(extended_output[0]),
                                                           &ecjpake_ctx_client,
                                                           sizeof(ecjpake_ctx_client),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        extended_output[1].nx_crypto_extended_output_data = server_hello;
        extended_output[1].nx_crypto_extended_output_length_in_byte = sizeof(server_hello);
        extended_output[1].nx_crypto_extended_output_actual_size = 0;
        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_SERVER_HELLO_GENERATE,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL, 0,
                                                           NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL,
                                                           (UCHAR *)&extended_output[1],
                                                           sizeof(extended_output[1]),
                                                           &ecjpake_ctx_server,
                                                           sizeof(ecjpake_ctx_server),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);


        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_SERVER_HELLO_PROCESS,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL, 0,
                                                           server_hello,
                                                           extended_output[1].nx_crypto_extended_output_actual_size,
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0,
                                                           &ecjpake_ctx_client,
                                                           sizeof(ecjpake_ctx_client),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_CLIENT_HELLO_PROCESS,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL, 0,
                                                           client_hello,
                                                           extended_output[0].nx_crypto_extended_output_actual_size,
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0,
                                                           &ecjpake_ctx_server,
                                                           sizeof(ecjpake_ctx_server),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);


        extended_output[0].nx_crypto_extended_output_data = client_ke;
        extended_output[0].nx_crypto_extended_output_length_in_byte = sizeof(client_ke);
        extended_output[0].nx_crypto_extended_output_actual_size = 0;
        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_CLIENT_KEY_EXCHANGE_GENERATE,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL, 0,
                                                           NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL,
                                                           (UCHAR *)&extended_output[0],
                                                           sizeof(extended_output[0]),
                                                           &ecjpake_ctx_client,
                                                           sizeof(ecjpake_ctx_client),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        extended_output[1].nx_crypto_extended_output_data = server_ke;
        extended_output[1].nx_crypto_extended_output_length_in_byte = sizeof(server_ke);
        extended_output[1].nx_crypto_extended_output_actual_size = 0;
        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_SERVER_KEY_EXCHANGE_GENERATE,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL, 0,
                                                           NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL,
                                                           (UCHAR *)&extended_output[1],
                                                           sizeof(extended_output[1]),
                                                           &ecjpake_ctx_server,
                                                           sizeof(ecjpake_ctx_server),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);


        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_SERVER_KEY_EXCHANGE_PROCESS,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL, 0,
                                                           server_ke,
                                                           extended_output[1].nx_crypto_extended_output_actual_size,
                                                           NX_CRYPTO_NULL,
                                                           client_pms,
                                                           sizeof(client_pms),
                                                           &ecjpake_ctx_client,
                                                           sizeof(ecjpake_ctx_client),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

        status = crypto_method_ecjpake.nx_crypto_operation(NX_CRYPTO_ECJPAKE_CLIENT_KEY_EXCHANGE_PROCESS,
                                                           NX_CRYPTO_NULL,
                                                           &crypto_method_ecjpake,
                                                           NX_CRYPTO_NULL, 0,
                                                           client_ke,
                                                           extended_output[0].nx_crypto_extended_output_actual_size,
                                                           NX_CRYPTO_NULL,
                                                           server_pms,
                                                           sizeof(server_pms),
                                                           &ecjpake_ctx_server,
                                                           sizeof(ecjpake_ctx_server),
                                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(NX_CRYPTO_SUCCESS, status);
        EXPECT_EQ(0, memcmp(client_pms, server_pms, sizeof(server_pms)));

    }

    /* PSK length is zero. */
    status = _nx_crypto_method_ecjpake_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_ecjpake_init(NX_CRYPTO_NULL, NX_CRYPTO_NULL, 1, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL key pointer. */
    status = _nx_crypto_method_ecjpake_init(&crypto_method_ecjpake, NX_CRYPTO_NULL, 1, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_ecjpake_init(&crypto_method_ecjpake, (VOID *)0x04, 1, NX_CRYPTO_NULL, NX_CRYPTO_NULL, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_ecjpake_init(&crypto_method_ecjpake, (VOID *)0x04, 1, NX_CRYPTO_NULL, (VOID *)0x03, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_ecjpake_init(&crypto_method_ecjpake, (VOID *)0x04, 1, NX_CRYPTO_NULL, (VOID *)0x04, 0);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* An NULL character is in the psk key. */
    buffer[0] = 0;
    status = _nx_crypto_method_ecjpake_init(&crypto_method_ecjpake, buffer, 32, NX_CRYPTO_NULL, &ecjpake_ctx_server, sizeof(ecjpake_ctx_server));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    /* Invoke crypto_method_cleanup. */
    status = _nx_crypto_method_ecjpake_cleanup(&ecjpake_ctx_server);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_ecjpake_cleanup(NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    /* NULL method pointer. */
    status = _nx_crypto_method_ecjpake_operation(0, NX_CRYPTO_NULL,
                                                 NX_CRYPTO_NULL, /* method */
                                                 NX_CRYPTO_NULL, 0, /* key */
                                                 NX_CRYPTO_NULL, 0, /* input */
                                                 NX_CRYPTO_NULL, /* iv */
                                                 NX_CRYPTO_NULL, 0, /* output */
                                                 NX_CRYPTO_NULL, 0, /* crypto metadata */
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* NULL metadata pointer. */
    status = _nx_crypto_method_ecjpake_operation(0, NX_CRYPTO_NULL,
                                                 &crypto_method_ecjpake, /* method */
                                                 NX_CRYPTO_NULL, 0, /* key */
                                                 NX_CRYPTO_NULL, 0, /* input */
                                                 NX_CRYPTO_NULL, /* iv */
                                                 NX_CRYPTO_NULL, 0, /* output */
                                                 NX_CRYPTO_NULL, 0, /* crypto metadata */
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata address is not 4-byte aligned. */
    status = _nx_crypto_method_ecjpake_operation(0, NX_CRYPTO_NULL,
                                                 &crypto_method_ecjpake, /* method */
                                                 NX_CRYPTO_NULL, 0, /* key */
                                                 NX_CRYPTO_NULL, 0, /* input */
                                                 NX_CRYPTO_NULL, /* iv */
                                                 NX_CRYPTO_NULL, 0, /* output */
                                                 (VOID *)0x03, 0, /* crypto metadata */
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Metadata size is not enough. */
    status = _nx_crypto_method_ecjpake_operation(0, NX_CRYPTO_NULL,
                                                 &crypto_method_ecjpake, /* method */
                                                 NX_CRYPTO_NULL, 0, /* key */
                                                 NX_CRYPTO_NULL, 0, /* input */
                                                 NX_CRYPTO_NULL, /* iv */
                                                 NX_CRYPTO_NULL, 0, /* output */
                                                 (VOID *)0x04, 0, /* crypto metadata */
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    /* Invalid op parameter. */
    status = _nx_crypto_method_ecjpake_operation(0, NX_CRYPTO_NULL,
                                                 &crypto_method_ecjpake, /* method */
                                                 NX_CRYPTO_NULL, 0, /* key */
                                                 NX_CRYPTO_NULL, 0, /* input */
                                                 NX_CRYPTO_NULL, /* iv */
                                                 NX_CRYPTO_NULL, 0, /* output */
                                                 &ecjpake_ctx_server, sizeof(ecjpake_ctx_server), /* crypto metadata */
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);

    ecjpake_ctx_server.nx_crypto_ecjpake_curve = (NX_CRYPTO_EC *)&_nx_crypto_ec_secp192r1;
    status = _nx_crypto_method_ecjpake_operation(NX_CRYPTO_ECJPAKE_HASH_METHOD_SET, NX_CRYPTO_NULL,
                                                 &crypto_method_ecjpake, /* method */
                                                 NX_CRYPTO_NULL, 0, /* key */
                                                 NX_CRYPTO_NULL, 0, /* input */
                                                 NX_CRYPTO_NULL, /* iv */
                                                 NX_CRYPTO_NULL, 0, /* output */
                                                 &ecjpake_ctx_server, sizeof(ecjpake_ctx_server), /* crypto metadata */
                                                 NX_CRYPTO_NULL, NX_CRYPTO_NULL);
    EXPECT_EQ(NX_CRYPTO_SUCCESS, status);

    printf("SUCCESS!\n");
    test_control_return(0);
}
