
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "nx_crypto_des.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif
#include "tls_test_utility.h"

#define MAXIMUM_KEY_BITS 256

/* Define software DES method. */
static NX_CRYPTO_METHOD test_crypto_method_des =
{
    NX_CRYPTO_ENCRYPTION_DES_CBC,             /* DES crypto algorithm filled at runtime*/
    0,                                        /* Key size in bits                       */
    NX_CRYPTO_DES_IV_LEN_IN_BITS,             /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS,         /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_DES),                    /* Metadata size in bytes                 */
    _nx_crypto_method_des_init,               /* DES initialization routine.            */
    NX_CRYPTO_NULL,                           /* DES cleanup routine, not used.         */
    _nx_crypto_method_des_operation           /* DES operation                          */

};

/* DES context. */
static NX_CRYPTO_DES _des_ctx;

/* Input to hold plain plus nonce. */
static UCHAR key[8];

/* IV. */
static UCHAR iv[8] = {0, 1, 2, 3, 4, 5, 6, 7};


#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_des_test_application_define(void *first_unused_memory)
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

#define TEST_TEXT_LENGTH 32

static VOID thread_0_entry(ULONG thread_input)
{
UINT i, status, backup;
UCHAR input[TEST_TEXT_LENGTH];
UCHAR output[TEST_TEXT_LENGTH];
UCHAR expected[TEST_TEXT_LENGTH];
VOID *handle;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   DES Test...........................................");


    /* Encryption. */
    memset(output, 0xFF, sizeof(output));

    /* Set key and IV. */
    for (i = 0; i < 8; i++)
    {
        key[i] = i;
        input[i] = i;
    }

    test_crypto_method_des.nx_crypto_init(&test_crypto_method_des,
                                          (UCHAR *)key,
                                          (NX_CRYPTO_DES_KEY_LEN_IN_BITS),
                                          &handle,
                                          &_des_ctx,
                                          sizeof(_des_ctx));

    test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_des,
                                               (UCHAR *)key,
                                               (NX_CRYPTO_DES_KEY_LEN_IN_BITS),
                                               input,
                                               sizeof(input),
                                               (UCHAR *)iv,
                                               (UCHAR *)output,
                                               sizeof(output),
                                               &_des_ctx,
                                               sizeof(_des_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    /* Decryption. */
    test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_des,
                                               (UCHAR *)key,
                                               (NX_CRYPTO_DES_KEY_LEN_IN_BITS),                                               
                                               (UCHAR *)output,
                                               sizeof(output),
                                               (UCHAR *)iv,
                                               (UCHAR *)output,
                                               sizeof(output),
                                               &_des_ctx,
                                               sizeof(_des_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, input, sizeof(input)));


    /* Test the support of filling plain text in several updates. */
    EXPECT_TRUE(TEST_TEXT_LENGTH > (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3));

    /* Generate test data. */
    srand(time(NULL));

    for (i = 0; i < TEST_TEXT_LENGTH; i++)
    {
        input[i] = (UCHAR)rand();
    }

    /* Encryption. */

    memset(output, 0xFF, sizeof(output));
    memset(expected, 0xFF, sizeof(expected));

    /* Calculate the expected result. */
    test_crypto_method_des.nx_crypto_init(&test_crypto_method_des,
                                          (UCHAR *)key,
                                          (NX_CRYPTO_DES_KEY_LEN_IN_BITS),
                                          &handle,
                                          &_des_ctx,
                                          sizeof(_des_ctx));

    test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_des,
                                               (UCHAR *)key,
                                               (NX_CRYPTO_DES_KEY_LEN_IN_BITS),
                                               input,
                                               TEST_TEXT_LENGTH,
                                               (UCHAR *)iv,
                                               (UCHAR *)expected,
                                               sizeof(expected),
                                               &_des_ctx,
                                               sizeof(_des_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    /* Fill plain text in several times. */
    test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_ENCRYPT_INITIALIZE,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_des,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               0,
                                               (UCHAR *)iv,
                                               NX_CRYPTO_NULL,
                                               0,
                                               &_des_ctx,
                                               sizeof(_des_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_ENCRYPT_UPDATE,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_des,
                                               NX_CRYPTO_NULL,
                                               0,
                                               input,
                                               (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3),
                                               NX_CRYPTO_NULL,
                                               (UCHAR *)output,
                                               sizeof(output),
                                               &_des_ctx,
                                               sizeof(_des_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_ENCRYPT_UPDATE,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_des,
                                               NX_CRYPTO_NULL,
                                               0,
                                               (UCHAR *)input + (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3),
                                               TEST_TEXT_LENGTH - (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3),
                                               NX_CRYPTO_NULL,
                                               (UCHAR *)output + (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3),
                                               sizeof(output) - (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3),
                                               &_des_ctx,
                                               sizeof(_des_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, expected, sizeof(expected)));

    /* Decryption. */

    /* Calculate the expected result. */
    test_crypto_method_des.nx_crypto_init(&test_crypto_method_des,
                                          (UCHAR *)key,
                                          (NX_CRYPTO_DES_KEY_LEN_IN_BITS),
                                          &handle,
                                          &_des_ctx,
                                          sizeof(_des_ctx));

    test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_des,
                                               (UCHAR *)key,
                                               (NX_CRYPTO_DES_KEY_LEN_IN_BITS),                                               
                                               (UCHAR *)expected,
                                               TEST_TEXT_LENGTH,
                                               (UCHAR *)iv,
                                               (UCHAR *)expected,
                                               sizeof(expected),
                                               &_des_ctx,
                                               sizeof(_des_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    /* Fill cipher text in several times. */
    test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_DECRYPT_INITIALIZE,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_des,
                                               NX_CRYPTO_NULL,
                                               0,
                                               NX_CRYPTO_NULL,
                                               0,
                                               (UCHAR *)iv,
                                               NX_CRYPTO_NULL,
                                               sizeof(output),
                                               &_des_ctx,
                                               sizeof(_des_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_DECRYPT_UPDATE,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_des,
                                               NX_CRYPTO_NULL,
                                               0,
                                               output,
                                               (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3),
                                               NX_CRYPTO_NULL,
                                               (UCHAR *)output,
                                               sizeof(output),
                                               &_des_ctx,
                                               sizeof(_des_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_des.nx_crypto_operation(NX_CRYPTO_DECRYPT_UPDATE,
                                               NX_CRYPTO_NULL,
                                               &test_crypto_method_des,
                                               NX_CRYPTO_NULL,
                                               0,
                                               (UCHAR *)output + (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3),
                                               TEST_TEXT_LENGTH - (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3),
                                               NX_CRYPTO_NULL,
                                               (UCHAR *)output + (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3),
                                               sizeof(output) - (NX_CRYPTO_DES_BLOCK_SIZE_IN_BITS >> 3),
                                               &_des_ctx,
                                               sizeof(_des_ctx),
                                               NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, expected, TEST_TEXT_LENGTH));

    printf("SUCCESS!\n");
    test_control_return(0);
}
