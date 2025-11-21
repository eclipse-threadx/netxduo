#include <stdio.h>

#include "nx_crypto_hmac_sha2.h"

#include "tls_test_utility.h"

extern void    test_control_return(UINT status);


void NX_SECURE_SHA256_HMAC_Test1();
void NX_SECURE_SHA256_HMAC_Test2();
void NX_SECURE_SHA256_HMAC_Test3();
void NX_SECURE_SHA256_HMAC_Test4();
void NX_SECURE_SHA256_HMAC_Test5();
void NX_SECURE_SHA256_HMAC_Test6();
void NX_SECURE_SHA256_HMAC_Test7();

/* Define software SHA256 method. */
static NX_CRYPTO_METHOD test_crypto_method_hmac_sha256 =
{
    NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256,   /* SHA crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    256,                                      /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_SHA256_HMAC),                   /* Metadata size in bytes                 */
    NX_CRYPTO_NULL,                           /* SHA initialization routine.            */
    NX_CRYPTO_NULL,                           /* SHA cleanup routine, not used.         */
    _nx_crypto_method_hmac_sha256_operation,  /* SHA operation                          */
};

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_sha256_rfc_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   SHA-256 RFC Test...................................");

    NX_SECURE_SHA256_HMAC_Test1();
    NX_SECURE_SHA256_HMAC_Test2();
    NX_SECURE_SHA256_HMAC_Test3();
    NX_SECURE_SHA256_HMAC_Test4();
    NX_SECURE_SHA256_HMAC_Test5();
    NX_SECURE_SHA256_HMAC_Test6();
    NX_SECURE_SHA256_HMAC_Test7();

    printf("SUCCESS!\n");
    test_control_return(0);

}


TEST(NX_SECURE_SHA256_HMAC, Test1)
{
/* 4.2.  Test Case 1 */

UCHAR test_key[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b }; // 20 bytes
UCHAR test_data[] = "Hi There";

UCHAR expected[] = { 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                     0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7 };

UCHAR output[32];
NX_SHA256_HMAC context;

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       test_data,
                                                       strlen((const char*)test_data),
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, expected, 32));

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       test_data,
                                                       strlen((const char*)test_data),
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

     EXPECT_EQ(0, memcmp(output, expected, 32));
}

TEST(NX_SECURE_SHA256_HMAC, Test2)
{

/* 4.3.  Test Case 2 - Test with a key shorter than the length of the HMAC output. */

UCHAR test_key[] = "Jefe";
UCHAR test_data[] = "what do ya want for nothing?";

UCHAR expected[] = { 0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
                     0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43 };

UCHAR output[32];
NX_SHA256_HMAC context;

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (strlen((const char*)test_key) << 3),
                                                       test_data,
                                                       strlen((const char*)test_data),
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, expected, 32));

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (strlen((const char*)test_key) << 3),
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       test_data,
                                                       strlen((const char*)test_data),
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

     EXPECT_EQ(0, memcmp(output, expected, 32));
}

TEST(NX_SECURE_SHA256_HMAC, Test3)
{

/* 4.4.  Test Case 3

   Test with a combined length of key and data that is larger than 64
   bytes (= block-size of SHA-224 and SHA-256).
*/

UCHAR test_key[] =  { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                      0xaa, 0xaa, 0xaa, 0xaa }; //                          (20 bytes)
UCHAR test_data[] = { 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                      0xdd, 0xdd }; //   (50 bytes)

UCHAR expected[] = { 0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
                     0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe };

UCHAR output[32];
NX_SHA256_HMAC context;

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       test_data,
                                                       sizeof(test_data),
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, expected, 32));

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       test_data,
                                                       sizeof(test_data),
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

     EXPECT_EQ(0, memcmp(output, expected, 32));
}

TEST(NX_SECURE_SHA256_HMAC, Test4)
{

/* 4.5.  Test Case 4

Test with a combined length of key and data that is larger than 64
bytes (= block-size of SHA-224 and SHA-256).
*/

UCHAR test_key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19}; //                (25 bytes)
UCHAR test_data[] = { 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd }; //                              (50 bytes)

UCHAR expected[] = { 0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
                     0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b };

UCHAR output[32];
NX_SHA256_HMAC context;

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       test_data,
                                                       sizeof(test_data),
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, expected, 32));

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       test_data,
                                                       sizeof(test_data),
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

     EXPECT_EQ(0, memcmp(output, expected, 32));
}

TEST(NX_SECURE_SHA256_HMAC, Test5)
{

/* 4.6.  Test Case 5

Test with a truncation of output to 128 bits.
*/
UCHAR test_key[] = { 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
                    0x0c, 0x0c, 0x0c, 0x0c }; //                          (20 bytes)
UCHAR test_data[] = "Test With Truncation";

UCHAR expected[] = { 0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0, 0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b };

UCHAR output[32];
NX_SHA256_HMAC context;

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       test_data,
                                                       strlen((const char*)test_data),
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, expected, 16));

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       test_data,
                                                       strlen((const char*)test_data),
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

     EXPECT_EQ(0, memcmp(output, expected, 16));
}

TEST(NX_SECURE_SHA256_HMAC, Test6)
{

/*4.7.  Test Case 6

Test with a key larger than 128 bytes (= block-size of SHA-384 and
SHA-512).
*/
UCHAR test_key[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                    0xaa, 0xaa, 0xaa  }; //                           (131 bytes)
UCHAR test_data[] = "Test Using Larger Than Block-Size Key - Hash Key First";

UCHAR expected[] = { 0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
                    0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54 };

UCHAR output[32];
NX_SHA256_HMAC context;

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       test_data,
                                                       strlen((const char*)test_data),
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, expected, 32));

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       test_data,
                                                       strlen((const char*)test_data),
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

     EXPECT_EQ(0, memcmp(output, expected, 32));
}

TEST(NX_SECURE_SHA256_HMAC, Test7)
{

/*4.8.  Test Case 7

Test with a key and data that is larger than 128 bytes (= block-size
of SHA-384 and SHA-512).
*/
UCHAR test_key[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                     0xaa, 0xaa, 0xaa }; //                           (131 bytes)

UCHAR test_data[] = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

UCHAR expected[] = { 0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
                     0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2 };

UCHAR output[32];
NX_SHA256_HMAC context;

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       test_data,
                                                       strlen((const char*)test_data),
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    EXPECT_EQ(0, memcmp(output, expected, 32));

    memset(output, 0xFF, sizeof(output));

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_INITIALIZE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       test_key,
                                                       (sizeof(test_key) << 3),
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_UPDATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       test_data,
                                                       strlen((const char*)test_data),
                                                       NX_CRYPTO_NULL,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

    test_crypto_method_hmac_sha256.nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                                       NX_CRYPTO_NULL,
                                                       &test_crypto_method_hmac_sha256,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       0,
                                                       NX_CRYPTO_NULL,
                                                       output,
                                                       sizeof(output),
                                                       &context,
                                                       sizeof(context),
                                                       NX_CRYPTO_NULL, NX_CRYPTO_NULL);

     EXPECT_EQ(0, memcmp(output, expected, 32));
}

