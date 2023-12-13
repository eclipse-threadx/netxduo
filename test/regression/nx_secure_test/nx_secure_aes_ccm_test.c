
#include <stdio.h>
#include <time.h>

#include "nx_crypto_aes.h"
#include "tls_test_utility.h"
#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls.h" 
#endif

#define MAXIMUM_KEY_BITS 256
#define TEST_ADDITIONAL_DATA_LENGTH 8
#define TEST_DATA_LENGTH 48
#define TEST_MAXIMUM_TAG_LENGTH 32

#include "nx_secure_aes_ccm_test_data.c"

/* Define software AES method. */
NX_CRYPTO_METHOD test_crypto_method_aes_ccm =
{
    0,                                        /* AES crypto algorithm filled at runtime */
    0,                                        /* Key size in bits                       */
    NX_CRYPTO_AES_IV_LEN_IN_BITS,             /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    NX_CRYPTO_AES_BLOCK_SIZE_IN_BITS,         /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_AES),                    /* Metadata size in bytes                 */
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

/* Output. */
static ULONG output[(TEST_ADDITIONAL_DATA_LENGTH + TEST_DATA_LENGTH + TEST_MAXIMUM_TAG_LENGTH) >> 2];

/* Buffer for packet chain tests. */
static UCHAR plain_text_buffer[TEST_ADDITIONAL_DATA_LENGTH + TEST_DATA_LENGTH];
static UCHAR cipher_text_and_tag_buffer[TEST_ADDITIONAL_DATA_LENGTH + TEST_DATA_LENGTH + TEST_MAXIMUM_TAG_LENGTH];

#ifndef NX_CRYPTO_STANDALONE_ENABLE
static TX_THREAD thread_0;
#endif

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_aes_ccm_test_application_define(void *first_unused_memory)
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
UINT status, i, j, offset = 0;
UINT data_len = 0, additional_len = 0;
NX_CRYPTO_EXTENDED_OUTPUT extended_output;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   AES CCM Test.......................................");

    for (i = 0; i < sizeof(aes_ccm_data) / sizeof(AES_DATA); i++)
    {

        /* Encryption. */
        memset(output, 0xFF, sizeof(output));

        memcpy(key, aes_ccm_data[i].key, aes_ccm_data[i].key_len);

        memcpy(iv, aes_ccm_data[i].iv, sizeof(iv));

        if (aes_ccm_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CCM_8)
        {
            test_crypto_method_aes_ccm.nx_crypto_ICV_size_in_bits = 64;
        }
        else if (aes_ccm_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CCM_12)
        {
            test_crypto_method_aes_ccm.nx_crypto_ICV_size_in_bits = 96;
        }
        else if (aes_ccm_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CCM_16)
        {
            test_crypto_method_aes_ccm.nx_crypto_ICV_size_in_bits = 128;
        }

        /* Set crypto algorithm. */
        test_crypto_method_aes_ccm.nx_crypto_algorithm = aes_ccm_data[i].algorithm;

        test_crypto_method_aes_ccm.nx_crypto_init(&test_crypto_method_aes_ccm,
                                              (UCHAR *)key,
                                              (aes_ccm_data[i].key_len << 3),
                                              NX_CRYPTO_NULL,
                                              &aes_ctx,
                                              sizeof(aes_ctx));

        /* Encryption. */
        data_len = ((UCHAR *)iv)[10];
        additional_len = aes_ccm_data[i].plain_len - data_len;
        memcpy(output, aes_ccm_data[i].plain, additional_len);

        /* Set additional data pointer and length. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_SET_ADDITIONAL_DATA,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes_ccm,
                                                   (UCHAR *)key,
                                                   (aes_ccm_data[i].key_len << 3),
                                                   aes_ccm_data[i].plain,
                                                   additional_len,
                                                   (UCHAR *)iv,
                                                   (UCHAR *)output,
                                                   sizeof(output),
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes_ccm,
                                                   (UCHAR *)key,
                                                   (aes_ccm_data[i].key_len << 3),
                                                   aes_ccm_data[i].plain + additional_len,
                                                   data_len,
                                                   (UCHAR *)iv,
                                                   (UCHAR *)output + additional_len,
                                                   sizeof(output) - additional_len,
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, aes_ccm_data[i].secret, aes_ccm_data[i].secret_len));

        ((UCHAR*)iv)[10] = data_len + (test_crypto_method_aes_ccm.nx_crypto_ICV_size_in_bits >> 3);

        /* Decryption. */
        data_len = ((UCHAR *)iv)[10];
        additional_len = aes_ccm_data[i].secret_len - data_len;
        memcpy(output, aes_ccm_data[i].secret, additional_len);

        /* Set additional data pointer and length. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_SET_ADDITIONAL_DATA,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes_ccm,
                                                   (UCHAR *)key,
                                                   (aes_ccm_data[i].key_len << 3),
                                                   aes_ccm_data[i].secret,
                                                   additional_len,
                                                   (UCHAR *)iv,
                                                   (UCHAR *)output,
                                                   sizeof(output),
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        status = test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                                                NX_CRYPTO_NULL,
                                                                &test_crypto_method_aes_ccm,
                                                                (UCHAR *)key,
                                                                (aes_ccm_data[i].key_len << 3),
                                                                aes_ccm_data[i].secret + additional_len,
                                                                data_len,
                                                                (UCHAR *)iv,
                                                                (UCHAR *)output + additional_len,
                                                                sizeof(output) - additional_len,
                                                                &aes_ctx,
                                                                sizeof(aes_ctx),
                                                                NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, aes_ccm_data[i].plain, aes_ccm_data[i].plain_len));
        EXPECT_EQ(0, status);
    }

    /* Set randam seed for generating test data. */
    srand(time(NULL));

    /* Tests for filling input encryption and decryption in several updates. */
    for (i = 0; i < sizeof(aes_ccm_data) / sizeof(AES_DATA); i++)
    {

        memcpy(key, aes_ccm_data[i].key, aes_ccm_data[i].key_len);

        memcpy(iv, aes_ccm_data[i].iv, sizeof(iv));

        if (aes_ccm_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CCM_8)
        {
            test_crypto_method_aes_ccm.nx_crypto_ICV_size_in_bits = 64;
        }
        else if (aes_ccm_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CCM_12)
        {
            test_crypto_method_aes_ccm.nx_crypto_ICV_size_in_bits = 96;
        }
        else if (aes_ccm_data[i].algorithm == NX_CRYPTO_ENCRYPTION_AES_CCM_16)
        {
            test_crypto_method_aes_ccm.nx_crypto_ICV_size_in_bits = 128;
        }

        /* Set crypto algorithm. */
        test_crypto_method_aes_ccm.nx_crypto_algorithm = aes_ccm_data[i].algorithm;

        /* Generate test data. */
        for (j = 0; j < TEST_ADDITIONAL_DATA_LENGTH + TEST_DATA_LENGTH; j++)
        {
            plain_text_buffer[j] = (UCHAR)rand();
        }

        ((UCHAR *)iv)[10] = TEST_DATA_LENGTH;

        test_crypto_method_aes_ccm.nx_crypto_init(&test_crypto_method_aes_ccm,
                                                  (UCHAR *)key,
                                                  (aes_ccm_data[i].key_len << 3),
                                                  NX_CRYPTO_NULL,
                                                  &aes_ctx,
                                                  sizeof(aes_ctx));

        memcpy(cipher_text_and_tag_buffer, plain_text_buffer, TEST_ADDITIONAL_DATA_LENGTH);

        /* Set additional data pointer and length. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_SET_ADDITIONAL_DATA,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_aes_ccm,
                                                       (UCHAR *)key,
                                                       (aes_ccm_data[i].key_len << 3),
                                                       plain_text_buffer,
                                                       TEST_ADDITIONAL_DATA_LENGTH,
                                                       (UCHAR *)iv,
                                                       (UCHAR *)cipher_text_and_tag_buffer,
                                                       sizeof(cipher_text_and_tag_buffer),
                                                       &aes_ctx,
                                                       sizeof(aes_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Encrypt data in plain_text_buffer by verified crypto_method. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_ENCRYPT,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_aes_ccm,
                                                       (UCHAR *)key,
                                                       (aes_ccm_data[i].key_len << 3),
                                                       &plain_text_buffer[TEST_ADDITIONAL_DATA_LENGTH],
                                                       TEST_DATA_LENGTH,
                                                       (UCHAR *)iv,
                                                       &cipher_text_and_tag_buffer[TEST_ADDITIONAL_DATA_LENGTH],
                                                       sizeof(cipher_text_and_tag_buffer) - TEST_ADDITIONAL_DATA_LENGTH,
                                                       &aes_ctx,
                                                       sizeof(aes_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        /* Data generation finished. */


        /* Tests for updating input in several time. */

        /* Encryption. */

        memset(output, 0xFF, sizeof(output));

        test_crypto_method_aes_ccm.nx_crypto_init(&test_crypto_method_aes_ccm,
                                                  (UCHAR *)key,
                                                  (aes_ccm_data[i].key_len << 3),
                                                  NX_CRYPTO_NULL,
                                                  &aes_ctx,
                                                  sizeof(aes_ctx));

        memcpy(output, plain_text_buffer, TEST_ADDITIONAL_DATA_LENGTH);

        /* Set additional data pointer and length. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_ENCRYPT_INITIALIZE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_aes_ccm,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       plain_text_buffer,
                                                       TEST_ADDITIONAL_DATA_LENGTH,
                                                       (UCHAR *)iv,
                                                       NX_CRYPTO_NULL,
                                                       TEST_DATA_LENGTH,
                                                       &aes_ctx,
                                                       sizeof(aes_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Update one block of plain text. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_ENCRYPT_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_aes_ccm,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       plain_text_buffer + TEST_ADDITIONAL_DATA_LENGTH,
                                                       NX_CRYPTO_AES_BLOCK_SIZE,
                                                       NX_CRYPTO_NULL,
                                                       (UCHAR *)output + TEST_ADDITIONAL_DATA_LENGTH,
                                                       sizeof(output) - TEST_ADDITIONAL_DATA_LENGTH,
                                                       &aes_ctx,
                                                       sizeof(aes_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Update the rest of plain text. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_ENCRYPT_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_aes_ccm,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       plain_text_buffer + TEST_ADDITIONAL_DATA_LENGTH + NX_CRYPTO_AES_BLOCK_SIZE,
                                                       TEST_DATA_LENGTH - NX_CRYPTO_AES_BLOCK_SIZE,
                                                       NX_CRYPTO_NULL,
                                                       (UCHAR *)output + TEST_ADDITIONAL_DATA_LENGTH + NX_CRYPTO_AES_BLOCK_SIZE,
                                                       sizeof(output) - TEST_ADDITIONAL_DATA_LENGTH - NX_CRYPTO_AES_BLOCK_SIZE,
                                                       &aes_ctx,
                                                       sizeof(aes_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Calculate the tag. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_ENCRYPT_CALCULATE,
                                                   NX_CRYPTO_NULL,
                                                   &test_crypto_method_aes_ccm,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   NX_CRYPTO_NULL,
                                                   0,
                                                   NX_CRYPTO_NULL,
                                                   (UCHAR *)output + TEST_ADDITIONAL_DATA_LENGTH + TEST_DATA_LENGTH,
                                                   sizeof(output) - TEST_ADDITIONAL_DATA_LENGTH - TEST_DATA_LENGTH,
                                                   &aes_ctx,
                                                   sizeof(aes_ctx),
                                                   NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        /* Verify the cipher text and tag. */
        EXPECT_EQ(0, memcmp(output, cipher_text_and_tag_buffer, TEST_ADDITIONAL_DATA_LENGTH + TEST_DATA_LENGTH + (test_crypto_method_aes_ccm.nx_crypto_ICV_size_in_bits >> 3)));

        /* Decryption. */

        memset(output, 0xFF, sizeof(output));

        ((UCHAR *)iv)[10] = TEST_DATA_LENGTH;
        memcpy(output, cipher_text_and_tag_buffer, TEST_ADDITIONAL_DATA_LENGTH);

        /* Set additional data pointer and length. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_ENCRYPT_INITIALIZE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_aes_ccm,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       cipher_text_and_tag_buffer,
                                                       TEST_ADDITIONAL_DATA_LENGTH,
                                                       (UCHAR *)iv,
                                                       NX_CRYPTO_NULL,
                                                       TEST_DATA_LENGTH,
                                                       &aes_ctx,
                                                       sizeof(aes_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Update one block of cipher text. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_DECRYPT_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_aes_ccm,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &cipher_text_and_tag_buffer[TEST_ADDITIONAL_DATA_LENGTH],
                                                       NX_CRYPTO_AES_BLOCK_SIZE,
                                                       NX_CRYPTO_NULL,
                                                       (UCHAR *)output + TEST_ADDITIONAL_DATA_LENGTH,
                                                       sizeof(output) - TEST_ADDITIONAL_DATA_LENGTH,
                                                       &aes_ctx,
                                                       sizeof(aes_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        /* Update the rest of cipher text. */
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_DECRYPT_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_aes_ccm,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &cipher_text_and_tag_buffer[TEST_ADDITIONAL_DATA_LENGTH + NX_CRYPTO_AES_BLOCK_SIZE],
                                                       TEST_DATA_LENGTH - NX_CRYPTO_AES_BLOCK_SIZE,
                                                       NX_CRYPTO_NULL,
                                                       (UCHAR *)output + TEST_ADDITIONAL_DATA_LENGTH + NX_CRYPTO_AES_BLOCK_SIZE,
                                                       sizeof(output) - TEST_ADDITIONAL_DATA_LENGTH - NX_CRYPTO_AES_BLOCK_SIZE,
                                                       &aes_ctx,
                                                       sizeof(aes_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        EXPECT_EQ(0, memcmp(output, plain_text_buffer, TEST_ADDITIONAL_DATA_LENGTH + TEST_DATA_LENGTH));

        /* Validate the tag. */
        status = 
        test_crypto_method_aes_ccm.nx_crypto_operation(NX_CRYPTO_DECRYPT_CALCULATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_aes_ccm,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &cipher_text_and_tag_buffer[TEST_ADDITIONAL_DATA_LENGTH + TEST_DATA_LENGTH],
                                                       test_crypto_method_aes_ccm.nx_crypto_ICV_size_in_bits << 3,
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &aes_ctx,
                                                       sizeof(aes_ctx),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        EXPECT_EQ(0, status);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}
