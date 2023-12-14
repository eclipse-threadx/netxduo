
#include <stdio.h>
#include "nx_crypto_rsa.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h" 
#endif
#include "tls_test_utility.h"

#define MAXIMUM_KEY_BITS 2048

#include "nx_secure_rsa_test_data.c"

/* Define software RSA method. */
static NX_CRYPTO_METHOD test_crypto_method_rsa =
{
    NX_CRYPTO_KEY_EXCHANGE_RSA,               /* RSA crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_RSA),                    /* Metadata size in bytes                 */
    _nx_crypto_method_rsa_init,               /* RSA initialization routine.            */
    NX_CRYPTO_NULL,                           /* RSA cleanup routine, not used.         */
    _nx_crypto_method_rsa_operation           /* RSA operation                          */

};

/* RSA context. */
static NX_CRYPTO_RSA rsa_ctx;

/* Output. */
static ULONG output[MAXIMUM_KEY_BITS >> 5];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_rsa_test_application_define(void *first_unused_memory)
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
UINT i, status, backup;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   RSA Test...........................................");

    for (i = 0; i < sizeof(rsa_data) / sizeof(RSA_DATA); i++)
    {

        /* Encryption. */
        memset(output, 0xFF, sizeof(output));
        test_crypto_method_rsa.nx_crypto_init(&test_crypto_method_rsa,
                                              rsa_data[i].m,
                                              (rsa_data[i].m_len << 3),
                                               NX_CRYPTO_NULL,
                                               &rsa_ctx,
                                               sizeof(rsa_ctx));

        test_crypto_method_rsa.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_rsa,
                                                   rsa_data[i].pub_e,
                                                   (rsa_data[i].pub_e_len << 3),
                                                   rsa_data[i].plain,
                                                   rsa_data[i].plain_len,
                                                   NX_CRYPTO_NULL,
                                                   (UCHAR *)output,
                                                   sizeof(output),
                                                   &rsa_ctx,
                                                   sizeof(rsa_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, rsa_data[i].secret, rsa_data[i].secret_len));

        /* Decryption. */
        memset(output, 0xFF, sizeof(output));
        test_crypto_method_rsa.nx_crypto_init(&test_crypto_method_rsa,
                                              rsa_data[i].m,
                                              (rsa_data[i].m_len << 3),
                                               NX_CRYPTO_NULL,
                                               &rsa_ctx,
                                               sizeof(rsa_ctx));

        test_crypto_method_rsa.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_rsa,
                                                   rsa_data[i].pri_e,
                                                   (rsa_data[i].pri_e_len << 3),
                                                   rsa_data[i].secret,
                                                   rsa_data[i].secret_len,
                                                   NX_CRYPTO_NULL,
                                                   (UCHAR *)output,
                                                   sizeof(output),
                                                   &rsa_ctx,
                                                   sizeof(rsa_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, rsa_data[i].plain, rsa_data[i].plain_len));

        /* Decryption by CRT. */
        memset(output, 0xFF, sizeof(output));
        test_crypto_method_rsa.nx_crypto_init(&test_crypto_method_rsa,
                                              rsa_data[i].m,
                                              (rsa_data[i].m_len << 3),
                                               NX_CRYPTO_NULL,
                                               &rsa_ctx,
                                               sizeof(rsa_ctx));

        test_crypto_method_rsa.nx_crypto_operation(NX_CRYPTO_SET_PRIME_P,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_rsa,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   rsa_data[i].p,
                                                   rsa_data[i].p_len,
                                                   NX_CRYPTO_NULL,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   &rsa_ctx,
                                                   sizeof(rsa_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        test_crypto_method_rsa.nx_crypto_operation(NX_CRYPTO_SET_PRIME_Q,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_rsa,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   rsa_data[i].q,
                                                   rsa_data[i].q_len,
                                                   NX_CRYPTO_NULL,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   &rsa_ctx,
                                                   sizeof(rsa_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        test_crypto_method_rsa.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_rsa,
                                                   rsa_data[i].pri_e,
                                                   (rsa_data[i].pri_e_len << 3),
                                                   rsa_data[i].secret,
                                                   rsa_data[i].secret_len,
                                                   NX_CRYPTO_NULL,
                                                   (UCHAR *)output,
                                                   sizeof(output),
                                                   &rsa_ctx,
                                                   sizeof(rsa_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, rsa_data[i].plain, rsa_data[i].plain_len));
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
