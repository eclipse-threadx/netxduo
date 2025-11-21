
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "nx_crypto_aes.h"

#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h"
#endif
#include "tls_test_utility.h"

#define MAXIMUM_KEY_BITS 256

#include "nx_secure_aes_test_data.c"

/* Define software AES method. */
NX_CRYPTO_METHOD test_crypto_method_aes =
{
    0,                                        /* AES crypto algorithm filled at runtime */
    0,                                        /* Key size in bits                       */
    NX_CRYPTO_AES_IV_LEN_IN_BITS,             /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS >> 3,    /* Block size in bytes.                   */
    sizeof(NX_AES),                           /* Metadata size in bytes                 */
    _nx_crypto_method_aes_init,               /* AES initialization routine.            */
    NX_CRYPTO_NULL,                           /* AES cleanup routine, not used.         */
    _nx_crypto_method_aes_operation           /* AES operation                          */

};

/* AES context. */
static NX_CRYPTO_AES aes_ctx;

/* Input to hold plain plus nonce. */
static ULONG key[(MAXIMUM_KEY_BITS >> 5) + 1];

/* IV. */
static ULONG iv[4];

#define TEST_TEXT_LENGTH (NX_CRYPTO_AES_BLOCK_SIZE * 3)

/* Output. */
static ULONG output[TEST_TEXT_LENGTH >> 2];

/* Buffers for packet chain tests. */
static UCHAR plain_text_buffer[TEST_TEXT_LENGTH];
static UCHAR cipher_text_buffer[TEST_TEXT_LENGTH];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_aes_test_application_define(void *first_unused_memory)
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
UINT i, j, status;
UCHAR *nonce;
UINT nonce_len;
NX_CRYPTO_METHOD test_method;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   AES Test...........................................");

    for (i = 0; i < sizeof(aes_data) / sizeof(AES_DATA); i++)
    {

        /* Encryption. */
        memset(output, 0xFF, sizeof(output));

        /* Conjunction of key and nonce for CTR mode. */
        /* It does not affect CBC mode. */
        memcpy(key, aes_data[i].key, aes_data[i].key_len);
        memcpy(key + (aes_data[i].key_len >> 2), aes_data[i].iv, 4);

        if (aes_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CBC)
        {
            memcpy(iv, aes_data[i].iv, sizeof(iv));
        }
        else
        {
            memcpy(iv, aes_data[i].iv + 4, 8);
        }

        /* Set crypto algorithm. */
        test_crypto_method_aes.nx_crypto_algorithm = aes_data[i].algorithm;

        test_crypto_method_aes.nx_crypto_init(&test_crypto_method_aes,
                                              (UCHAR *)key,
                                              (aes_data[i].key_len << 3),
                                              NX_CRYPTO_NULL,
                                              &aes_ctx,
                                              sizeof(aes_ctx));

        test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes,
                                                   (UCHAR *)key,
                                                   (aes_data[i].key_len << 3),
                                                   aes_data[i].plain,
                                                   aes_data[i].plain_len,
                                                   (UCHAR *)iv,
                                                   (UCHAR *)output,
                                                   sizeof(output),
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, aes_data[i].secret, aes_data[i].secret_len));

        /* Decryption. */
        test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes,
                                                   (UCHAR *)key,
                                                   (aes_data[i].key_len << 3),
                                                   aes_data[i].secret,
                                                   aes_data[i].secret_len,
                                                   (UCHAR *)iv,
                                                   (UCHAR *)output,
                                                   sizeof(output),
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, aes_data[i].plain, aes_data[i].plain_len));
    }

    srand(time(NULL));

    /* Tests for NX_CRYPTO_ENCRYPT_UPDATE and NX_CRYPTO_DECRYPT_UPDATE. */
    for (i = 0; i < sizeof(aes_data) / sizeof(AES_DATA); i++)
    {

        /* Conjunction of key and nonce for CTR mode. */
        /* It does not affect CBC mode. */
        memcpy(key, aes_data[i].key, aes_data[i].key_len);
        memcpy(key + (aes_data[i].key_len >> 2), aes_data[i].iv, 4);

        if (aes_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CBC)
        {
            memcpy(iv, aes_data[i].iv, sizeof(iv));
            nonce = NX_CRYPTO_NULL;
            nonce_len = 0;
        }
        else
        {
            memcpy(iv, aes_data[i].iv + 4, 8);
            nonce = (UCHAR *)key + aes_data[i].key_len;
            nonce_len = 4;
        }

        /* Set crypto algorithm. */
        test_crypto_method_aes.nx_crypto_algorithm = aes_data[i].algorithm;

        /* Generate test data. */
        for (j = 0; j < TEST_TEXT_LENGTH; j++)
        {
            plain_text_buffer[j] = (UCHAR)rand();
        }

        test_crypto_method_aes.nx_crypto_init(&test_crypto_method_aes,
                                              (UCHAR *)key,
                                              (aes_data[i].key_len << 3),
                                              NX_CRYPTO_NULL,
                                              &aes_ctx,
                                              sizeof(aes_ctx));

        test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes,
                                                   (UCHAR *)key,
                                                   (aes_data[i].key_len << 3),
                                                   plain_text_buffer,
                                                   TEST_TEXT_LENGTH,
                                                   (UCHAR *)iv,
                                                   cipher_text_buffer,
                                                   sizeof(cipher_text_buffer),
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Tests for NX_CRYPTO_ENCRYPT_UPDATE and NX_CRYPTO_DECRYPT_UPDATE. */

        /* Encryption. */
        memset(output, 0xFF, sizeof(output));

        /* Initialize the context. */
        test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_ENCRYPT_INITIALIZE,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   nonce,
                                                   nonce_len,
                                                   (UCHAR *)iv,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Update one block of input. */
        test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_ENCRYPT_UPDATE,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   plain_text_buffer,
                                                   NX_CRYPTO_AES_BLOCK_SIZE,
                                                   NX_CRYPTO_NULL,
                                                   (UCHAR *)output,
                                                   sizeof(output),
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Update the rest. */
        test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_ENCRYPT_UPDATE,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   plain_text_buffer + NX_CRYPTO_AES_BLOCK_SIZE,
                                                   TEST_TEXT_LENGTH - NX_CRYPTO_AES_BLOCK_SIZE,
                                                   NX_CRYPTO_NULL,
                                                   (UCHAR *)output + NX_CRYPTO_AES_BLOCK_SIZE,
                                                   sizeof(output) - NX_CRYPTO_AES_BLOCK_SIZE,
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, cipher_text_buffer, TEST_TEXT_LENGTH));

        /* Decryption. */
        memset(output, 0xFF, sizeof(output));

        /* Initialize the context. */
        test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_DECRYPT_INITIALIZE,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   nonce,
                                                   nonce_len,
                                                   (UCHAR *)iv,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Update one block of input. */
        test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_DECRYPT_UPDATE,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   cipher_text_buffer,
                                                   NX_CRYPTO_AES_BLOCK_SIZE,
                                                   NX_CRYPTO_NULL,
                                                   (UCHAR *)output,
                                                   sizeof(output),
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Update the rest. */
        test_crypto_method_aes.nx_crypto_operation(NX_CRYPTO_DECRYPT_UPDATE,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   cipher_text_buffer + NX_CRYPTO_AES_BLOCK_SIZE,
                                                   TEST_TEXT_LENGTH - NX_CRYPTO_AES_BLOCK_SIZE,
                                                   NX_CRYPTO_NULL,
                                                   (UCHAR *)output + NX_CRYPTO_AES_BLOCK_SIZE,
                                                   sizeof(output) - NX_CRYPTO_AES_BLOCK_SIZE,
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, plain_text_buffer, TEST_TEXT_LENGTH));
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
