#include <stdio.h>

#include "nx_secure_tls_api.h"

#include "tls_test_utility.h"

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"
#include   "nx_crypto_rsa.h"
#include   "nx_crypto_ecdsa.h"
#include   "nx_crypto_sha1.h"
#include   "nx_crypto_sha2.h"
#include   "nx_crypto_const.h"
#include   "ecc_certs.c"

extern void    test_control_return(UINT status);

void NX_Secure_TLS_SendCertificateVerifyTest_Test_1();

void NX_Secure_TLS_SendCertificateVerifyTest_Test_2();

void NX_Secure_TLS_SendCertificateVerifyTest_Test_3();

void NX_Secure_TLS_SendCertificateVerifyTest_Test_4();

void NX_Secure_TLS_SendCertificateVerifyTest_Test_ECC();

void NX_Secure_TLS_SendClientKeyExchangeTest();

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_cert_verify_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Certificate Verify Test.......................");

    NX_Secure_TLS_SendCertificateVerifyTest_Test_1();

    NX_Secure_TLS_SendCertificateVerifyTest_Test_2();

    NX_Secure_TLS_SendCertificateVerifyTest_Test_3();

    NX_Secure_TLS_SendCertificateVerifyTest_Test_4();

    NX_Secure_TLS_SendCertificateVerifyTest_Test_ECC();

    printf("SUCCESS!\n");

    printf("NetX Secure Test:   TLS Send ClientKeyExchange Test.......................");

    NX_Secure_TLS_SendClientKeyExchangeTest();

    printf("SUCCESS!\n");

    test_control_return(0);

}

#ifndef NX_SECURE_DISABLE_X509

static UCHAR server_packet_buffer[2000];

static NX_PACKET_POOL    pool_0;

#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 32)

static ULONG             packet_pool_area[NX_PACKET_POOL_SIZE/sizeof(ULONG) + 64 / sizeof(ULONG)];

/*  Cryptographic routines. */
extern NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

/* Server certificate. */
static unsigned char test_device_cert_der[] = {
  0x30, 0x82, 0x03, 0xd2, 0x30, 0x82, 0x02, 0xba, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x01, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x7a, 0x31, 0x0b, 0x30,
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b,
  0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x43, 0x41, 0x31,
  0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x09, 0x53, 0x61,
  0x6e, 0x20, 0x44, 0x69, 0x65, 0x67, 0x6f, 0x31, 0x16, 0x30, 0x14, 0x06,
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0d, 0x45, 0x78, 0x70, 0x72, 0x65, 0x73,
  0x73, 0x20, 0x4c, 0x6f, 0x67, 0x69, 0x63, 0x31, 0x14, 0x30, 0x12, 0x06,
  0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0b, 0x4e, 0x65, 0x74, 0x58, 0x20, 0x53,
  0x65, 0x63, 0x75, 0x72, 0x65, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55,
  0x04, 0x03, 0x0c, 0x13, 0x4e, 0x65, 0x74, 0x58, 0x20, 0x53, 0x65, 0x63,
  0x75, 0x72, 0x65, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30,
  0x1e, 0x17, 0x0d, 0x31, 0x36, 0x31, 0x31, 0x31, 0x31, 0x31, 0x39, 0x35,
  0x31, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x30, 0x39,
  0x31, 0x39, 0x35, 0x31, 0x30, 0x30, 0x5a, 0x30, 0x62, 0x31, 0x0b, 0x30,
  0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b,
  0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x43, 0x41, 0x31,
  0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0d, 0x45, 0x78,
  0x70, 0x72, 0x65, 0x73, 0x73, 0x20, 0x4c, 0x6f, 0x67, 0x69, 0x63, 0x31,
  0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0b, 0x4e, 0x65,
  0x74, 0x58, 0x20, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x31, 0x18, 0x30,
  0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x77, 0x77, 0x77, 0x2e,
  0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30,
  0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
  0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30,
  0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xae, 0x03, 0x2c, 0xec,
  0xa2, 0x79, 0xd1, 0x15, 0x20, 0x88, 0x4d, 0xcd, 0xa2, 0x1b, 0x05, 0xe3,
  0xbd, 0x55, 0xad, 0xc6, 0x1f, 0x64, 0xe8, 0xb5, 0xc5, 0x0d, 0x67, 0xfc,
  0x7e, 0xda, 0xfb, 0x70, 0xf6, 0xc9, 0x47, 0x87, 0x3a, 0xaa, 0x88, 0x00,
  0xf1, 0xa7, 0xf7, 0xe1, 0xf5, 0x2c, 0x54, 0x0e, 0x33, 0xda, 0xbe, 0x9c,
  0x66, 0x30, 0xd9, 0x40, 0xeb, 0x1d, 0xce, 0xe1, 0x55, 0x15, 0x2b, 0x11,
  0x47, 0x6c, 0x7e, 0x88, 0xc6, 0x24, 0xcf, 0x87, 0x1b, 0xb5, 0x1f, 0x47,
  0xb9, 0xef, 0xad, 0x29, 0xd3, 0x2e, 0x43, 0xee, 0x39, 0xdd, 0x09, 0x54,
  0xba, 0xfc, 0xed, 0xbc, 0x2e, 0x0e, 0x53, 0x15, 0x37, 0xcb, 0xc5, 0xf5,
  0xee, 0x70, 0x2a, 0xe8, 0x01, 0x6d, 0xb1, 0x39, 0x94, 0x5a, 0xc2, 0x8a,
  0x00, 0x04, 0xa9, 0xff, 0xea, 0x56, 0xf7, 0xd7, 0xa8, 0x1b, 0xa4, 0x26,
  0xcd, 0x28, 0xaf, 0xfa, 0x52, 0x85, 0x1c, 0x26, 0x3e, 0x5e, 0x01, 0xf7,
  0xe1, 0x66, 0xff, 0xac, 0xad, 0x9c, 0x98, 0x2f, 0xe0, 0x7e, 0x9f, 0xf1,
  0x33, 0x31, 0xc3, 0x7f, 0xe6, 0x58, 0x5d, 0xd8, 0x5f, 0x7d, 0x2b, 0x5a,
  0x55, 0xcf, 0xb1, 0x91, 0x53, 0x41, 0x04, 0xac, 0x86, 0x5e, 0x01, 0x35,
  0x2b, 0x74, 0x8d, 0x46, 0x4d, 0x48, 0xc0, 0x5f, 0x83, 0x67, 0xb5, 0x6d,
  0x52, 0x3f, 0x3e, 0xe6, 0xec, 0xf8, 0x2e, 0x10, 0x28, 0xdb, 0x69, 0xa6,
  0x9d, 0x4b, 0xde, 0x19, 0x2e, 0xd2, 0x5f, 0xc8, 0xa9, 0x3b, 0x52, 0xe9,
  0xb2, 0xcd, 0x6e, 0x19, 0x22, 0xf9, 0x99, 0xa6, 0xcc, 0xf5, 0xd3, 0xec,
  0xff, 0x0c, 0x77, 0x6f, 0x25, 0x92, 0x07, 0x4c, 0x64, 0x7d, 0x34, 0x49,
  0x6f, 0xff, 0x0a, 0xa8, 0x15, 0x64, 0x72, 0x2d, 0x4f, 0x42, 0x05, 0xe8,
  0x2b, 0x01, 0xf1, 0xe3, 0x65, 0x94, 0x23, 0xd9, 0xdf, 0x5e, 0x3b, 0xb5,
  0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x7b, 0x30, 0x79, 0x30, 0x09, 0x06,
  0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x2c, 0x06, 0x09,
  0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x0d, 0x04, 0x1f, 0x16,
  0x1d, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x4c, 0x20, 0x47, 0x65, 0x6e,
  0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69,
  0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
  0x0e, 0x04, 0x16, 0x04, 0x14, 0x8d, 0xb0, 0xee, 0x8f, 0x6b, 0x43, 0x52,
  0x29, 0xf4, 0x25, 0xff, 0x3c, 0xda, 0x5f, 0xb3, 0xce, 0x9b, 0x7b, 0x75,
  0xe1, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
  0x80, 0x14, 0x1b, 0x8d, 0x06, 0xd9, 0x6b, 0xad, 0xee, 0x82, 0x24, 0x26,
  0x55, 0x9a, 0x1b, 0x03, 0x44, 0x92, 0x0a, 0x06, 0x92, 0x48, 0x30, 0x0d,
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
  0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x75, 0x83, 0x89, 0xab, 0x84, 0x52,
  0x5f, 0xa4, 0x9e, 0x98, 0xca, 0xa3, 0xf9, 0xab, 0xd4, 0x04, 0x32, 0xa4,
  0x8c, 0x96, 0x90, 0x39, 0x88, 0x92, 0xc3, 0xcd, 0x51, 0xc3, 0x01, 0x35,
  0x03, 0x78, 0xfa, 0x0d, 0x1e, 0x7b, 0x79, 0xe9, 0x7d, 0xd8, 0x68, 0x7a,
  0x65, 0xc6, 0x00, 0x7c, 0xa1, 0x7a, 0x52, 0xc9, 0xa3, 0xf4, 0x0b, 0xbd,
  0x76, 0x24, 0xdf, 0xde, 0x22, 0x2d, 0x95, 0xc5, 0xb6, 0x54, 0xb1, 0xac,
  0xb6, 0x9a, 0xe4, 0x68, 0x0f, 0x97, 0x4a, 0x44, 0xa2, 0x87, 0x01, 0x82,
  0xd4, 0x25, 0xbd, 0x01, 0xbc, 0x35, 0x8a, 0x6d, 0xb7, 0x7c, 0x48, 0xaa,
  0x92, 0xd7, 0x57, 0x76, 0x6a, 0xb0, 0xc9, 0x46, 0xa6, 0xbe, 0xbf, 0x0f,
  0xf0, 0xea, 0x62, 0x57, 0x71, 0x42, 0xf6, 0x67, 0xa7, 0xa1, 0x50, 0x87,
  0x14, 0x8e, 0x32, 0xd0, 0x5e, 0xc9, 0x7b, 0x79, 0x7e, 0xfa, 0x17, 0xc7,
  0xad, 0xbd, 0xc3, 0x98, 0x79, 0x45, 0xfb, 0x7f, 0xf7, 0xe6, 0x9f, 0x77,
  0xb3, 0x44, 0xc3, 0xaf, 0x6b, 0x61, 0x6a, 0x04, 0x68, 0x24, 0x2d, 0x31,
  0xf1, 0x28, 0x2c, 0xf4, 0xf0, 0x07, 0xfe, 0xfd, 0x66, 0x98, 0x77, 0x37,
  0x7b, 0x80, 0x1f, 0xb2, 0x49, 0xe4, 0xa6, 0x24, 0x72, 0x42, 0xf4, 0xca,
  0x91, 0x80, 0xa1, 0xb2, 0x0a, 0xc9, 0xc0, 0x93, 0xa7, 0x22, 0x0b, 0x13,
  0x8a, 0xb2, 0x75, 0x4b, 0x66, 0xf9, 0x87, 0x3a, 0x51, 0x97, 0xc7, 0x1e,
  0x2b, 0x61, 0x81, 0x5c, 0xf0, 0xf8, 0x4c, 0xdb, 0x36, 0xc7, 0xba, 0x49,
  0xd9, 0x04, 0x6a, 0x95, 0xb0, 0x7f, 0xfc, 0xce, 0xca, 0x23, 0xad, 0xf9,
  0xaf, 0x8a, 0x72, 0x8e, 0xab, 0xb8, 0x8b, 0x7e, 0xf7, 0x39, 0xa6, 0x22,
  0x56, 0x03, 0x72, 0x06, 0xc3, 0x57, 0x1f, 0x32, 0xaa, 0xb5, 0xa6, 0x00,
  0x67, 0x88, 0x4b, 0x40, 0xe9, 0x5e, 0x4a, 0x6f, 0x76, 0xe8
};
static unsigned int test_device_cert_der_len = 982;

static unsigned char test_device_cert_key_der[] = {
  0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
  0xae, 0x03, 0x2c, 0xec, 0xa2, 0x79, 0xd1, 0x15, 0x20, 0x88, 0x4d, 0xcd,
  0xa2, 0x1b, 0x05, 0xe3, 0xbd, 0x55, 0xad, 0xc6, 0x1f, 0x64, 0xe8, 0xb5,
  0xc5, 0x0d, 0x67, 0xfc, 0x7e, 0xda, 0xfb, 0x70, 0xf6, 0xc9, 0x47, 0x87,
  0x3a, 0xaa, 0x88, 0x00, 0xf1, 0xa7, 0xf7, 0xe1, 0xf5, 0x2c, 0x54, 0x0e,
  0x33, 0xda, 0xbe, 0x9c, 0x66, 0x30, 0xd9, 0x40, 0xeb, 0x1d, 0xce, 0xe1,
  0x55, 0x15, 0x2b, 0x11, 0x47, 0x6c, 0x7e, 0x88, 0xc6, 0x24, 0xcf, 0x87,
  0x1b, 0xb5, 0x1f, 0x47, 0xb9, 0xef, 0xad, 0x29, 0xd3, 0x2e, 0x43, 0xee,
  0x39, 0xdd, 0x09, 0x54, 0xba, 0xfc, 0xed, 0xbc, 0x2e, 0x0e, 0x53, 0x15,
  0x37, 0xcb, 0xc5, 0xf5, 0xee, 0x70, 0x2a, 0xe8, 0x01, 0x6d, 0xb1, 0x39,
  0x94, 0x5a, 0xc2, 0x8a, 0x00, 0x04, 0xa9, 0xff, 0xea, 0x56, 0xf7, 0xd7,
  0xa8, 0x1b, 0xa4, 0x26, 0xcd, 0x28, 0xaf, 0xfa, 0x52, 0x85, 0x1c, 0x26,
  0x3e, 0x5e, 0x01, 0xf7, 0xe1, 0x66, 0xff, 0xac, 0xad, 0x9c, 0x98, 0x2f,
  0xe0, 0x7e, 0x9f, 0xf1, 0x33, 0x31, 0xc3, 0x7f, 0xe6, 0x58, 0x5d, 0xd8,
  0x5f, 0x7d, 0x2b, 0x5a, 0x55, 0xcf, 0xb1, 0x91, 0x53, 0x41, 0x04, 0xac,
  0x86, 0x5e, 0x01, 0x35, 0x2b, 0x74, 0x8d, 0x46, 0x4d, 0x48, 0xc0, 0x5f,
  0x83, 0x67, 0xb5, 0x6d, 0x52, 0x3f, 0x3e, 0xe6, 0xec, 0xf8, 0x2e, 0x10,
  0x28, 0xdb, 0x69, 0xa6, 0x9d, 0x4b, 0xde, 0x19, 0x2e, 0xd2, 0x5f, 0xc8,
  0xa9, 0x3b, 0x52, 0xe9, 0xb2, 0xcd, 0x6e, 0x19, 0x22, 0xf9, 0x99, 0xa6,
  0xcc, 0xf5, 0xd3, 0xec, 0xff, 0x0c, 0x77, 0x6f, 0x25, 0x92, 0x07, 0x4c,
  0x64, 0x7d, 0x34, 0x49, 0x6f, 0xff, 0x0a, 0xa8, 0x15, 0x64, 0x72, 0x2d,
  0x4f, 0x42, 0x05, 0xe8, 0x2b, 0x01, 0xf1, 0xe3, 0x65, 0x94, 0x23, 0xd9,
  0xdf, 0x5e, 0x3b, 0xb5, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
  0x01, 0x00, 0xa5, 0x22, 0x2c, 0x52, 0xd0, 0x09, 0x4c, 0x4a, 0x81, 0x59,
  0xf8, 0x83, 0xa9, 0x4f, 0x7d, 0xb2, 0x56, 0xad, 0xe5, 0x3f, 0xfb, 0xf0,
  0xf6, 0x09, 0xf1, 0x5b, 0x3c, 0x90, 0x58, 0x0e, 0x15, 0xc9, 0x68, 0xd9,
  0x30, 0x40, 0xfb, 0x82, 0x73, 0x98, 0x79, 0xbb, 0xcd, 0xb8, 0x27, 0xc3,
  0x8e, 0x6c, 0xff, 0xf6, 0x99, 0x26, 0xb0, 0xaf, 0xb0, 0xac, 0x33, 0xb3,
  0x50, 0xed, 0x73, 0xa1, 0xa8, 0x02, 0x38, 0xc6, 0x93, 0xf9, 0xd6, 0x17,
  0x7e, 0xbd, 0x97, 0xa4, 0xb5, 0x6f, 0x8a, 0xdb, 0x11, 0x78, 0x7c, 0x89,
  0x0e, 0x3c, 0x17, 0xbb, 0x54, 0x2c, 0x8d, 0x5a, 0x93, 0x7d, 0x1e, 0x33,
  0xc7, 0xd2, 0x7d, 0xe5, 0xaa, 0x12, 0x2d, 0xd9, 0x52, 0x4e, 0x63, 0x74,
  0xa6, 0x57, 0x9f, 0x1a, 0xd6, 0x3c, 0xc1, 0xb1, 0xab, 0x66, 0x4a, 0x0b,
  0x88, 0x1d, 0xa6, 0xd1, 0xbc, 0x60, 0x7a, 0x17, 0x1f, 0x8f, 0x9b, 0x35,
  0x57, 0xf8, 0xd0, 0x1c, 0xd3, 0xa6, 0x56, 0xc8, 0x03, 0x9c, 0x08, 0x3b,
  0x1b, 0x5b, 0xc2, 0x03, 0x3b, 0x3a, 0xa4, 0xe8, 0xed, 0x75, 0x66, 0xb0,
  0x85, 0x56, 0x40, 0xfe, 0xae, 0x97, 0x7e, 0xc0, 0x79, 0x49, 0x13, 0x8b,
  0x01, 0x0c, 0xae, 0x4c, 0x3d, 0x54, 0x47, 0xc5, 0x51, 0x40, 0x3d, 0xcc,
  0x4d, 0x17, 0xb3, 0x4e, 0x1d, 0x85, 0x1c, 0x41, 0x07, 0x03, 0x5e, 0xf9,
  0xfa, 0x17, 0x81, 0x24, 0x34, 0xaa, 0xbf, 0x67, 0x73, 0xb6, 0x9c, 0x67,
  0x36, 0xd9, 0xee, 0xf7, 0x86, 0x4c, 0x4d, 0x79, 0xca, 0xd7, 0xfd, 0x72,
  0xf9, 0xb3, 0x73, 0xc3, 0x57, 0xe5, 0x39, 0x72, 0x93, 0x56, 0xc2, 0xec,
  0xf8, 0x25, 0xe4, 0x8f, 0xba, 0xd0, 0x6f, 0x23, 0x8c, 0x39, 0x9e, 0x05,
  0x1a, 0x4e, 0xdc, 0x5e, 0xcd, 0x17, 0x59, 0x94, 0x37, 0x22, 0xb7, 0x39,
  0x50, 0x65, 0xdc, 0x91, 0x3c, 0xe1, 0x02, 0x81, 0x81, 0x00, 0xe4, 0xc6,
  0x42, 0xe5, 0xea, 0xe5, 0x32, 0xf3, 0x51, 0x36, 0x7b, 0x8c, 0x5b, 0x72,
  0x24, 0x1a, 0x4a, 0x44, 0x4f, 0x64, 0xe5, 0xa7, 0x74, 0xd9, 0xb2, 0x29,
  0x8a, 0x08, 0xcf, 0x9b, 0xd2, 0x9d, 0xc4, 0x20, 0x4c, 0xd3, 0x60, 0x4d,
  0xf7, 0xb7, 0xac, 0x92, 0x6b, 0x2b, 0x95, 0x73, 0x6e, 0x57, 0x00, 0x20,
  0x9d, 0xb2, 0xf6, 0xbd, 0x0b, 0xbb, 0xaa, 0x7e, 0x7e, 0x3e, 0x53, 0xfb,
  0x79, 0x7e, 0x45, 0xd5, 0x2e, 0xab, 0x5e, 0xff, 0x5c, 0x0a, 0x45, 0x2d,
  0x27, 0x19, 0xb0, 0x59, 0x0a, 0x39, 0x89, 0xf6, 0xae, 0xc6, 0xe2, 0xd1,
  0x07, 0x58, 0xbe, 0x95, 0x27, 0xaf, 0xf7, 0xa6, 0x2f, 0xaa, 0x37, 0x25,
  0x7c, 0x7b, 0xd3, 0xda, 0x13, 0x76, 0x0a, 0xb6, 0x6c, 0x99, 0x53, 0x5d,
  0xa5, 0x75, 0xfa, 0x10, 0x9b, 0x7f, 0xfe, 0xd7, 0xb4, 0x18, 0x95, 0xa8,
  0x65, 0x85, 0x07, 0xc5, 0xc4, 0xad, 0x02, 0x81, 0x81, 0x00, 0xc2, 0xb8,
  0x8e, 0xed, 0x9d, 0x4a, 0x1f, 0x9c, 0xda, 0x73, 0xf0, 0x2c, 0x35, 0x91,
  0xe4, 0x40, 0x78, 0xe1, 0x12, 0xf3, 0x08, 0xef, 0xdf, 0x97, 0xa0, 0xb0,
  0xdd, 0xea, 0xc2, 0xb9, 0x5b, 0xf8, 0xa1, 0xac, 0x32, 0xfd, 0xb8, 0xe9,
  0x0f, 0xed, 0xfd, 0xe0, 0xdc, 0x38, 0x90, 0x5e, 0xf5, 0x4c, 0x02, 0xc3,
  0x1a, 0x72, 0x18, 0xf7, 0xfe, 0xb7, 0xb8, 0x2a, 0xf8, 0x72, 0xbb, 0x99,
  0x56, 0xec, 0x85, 0x58, 0x31, 0x7e, 0x64, 0xdf, 0x02, 0x05, 0xe3, 0xb2,
  0xbb, 0xe2, 0x1b, 0xd6, 0x43, 0x73, 0xf8, 0x0f, 0xaf, 0x89, 0x57, 0x44,
  0x5f, 0x30, 0x1c, 0xe5, 0x78, 0xbf, 0x0b, 0xe7, 0x4b, 0xbe, 0x80, 0x2f,
  0x3d, 0x35, 0x44, 0xfc, 0x9e, 0x0d, 0x85, 0x5d, 0x94, 0x6e, 0xe9, 0x6a,
  0x72, 0xa7, 0x46, 0xd8, 0x64, 0x6c, 0xe9, 0x61, 0x92, 0xa0, 0xb6, 0xd1,
  0xee, 0xa6, 0xa6, 0xf4, 0x2c, 0x29, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xa7,
  0x7b, 0x1c, 0x64, 0x29, 0x29, 0xda, 0xca, 0x3e, 0xe3, 0xc1, 0x2a, 0x55,
  0x2f, 0xfd, 0x32, 0xb8, 0x4e, 0x99, 0xb6, 0x60, 0x4d, 0xfd, 0xba, 0x9a,
  0xe2, 0xcd, 0xa2, 0x63, 0xc2, 0x25, 0xa3, 0x42, 0x7e, 0x68, 0x4c, 0x9c,
  0x45, 0x09, 0x5d, 0xd5, 0x21, 0x9c, 0x01, 0x20, 0x6d, 0xf9, 0x75, 0xb8,
  0x4b, 0xcf, 0x8e, 0xd8, 0x29, 0xf3, 0xbf, 0xe6, 0xb3, 0x7a, 0x34, 0x87,
  0x58, 0xa1, 0x46, 0x33, 0xd9, 0xee, 0xa9, 0xcd, 0xac, 0xb8, 0xcf, 0x77,
  0xa0, 0x70, 0xc0, 0xb9, 0x0f, 0x41, 0xf0, 0x98, 0x43, 0xdb, 0xfa, 0x30,
  0x66, 0x44, 0xc5, 0xfa, 0xb2, 0xa4, 0x5a, 0x43, 0x79, 0x50, 0x48, 0xcb,
  0xe9, 0x49, 0x3f, 0x39, 0xee, 0x34, 0x40, 0xb1, 0x5d, 0x80, 0x96, 0x3c,
  0x54, 0xf4, 0x9c, 0xcb, 0x90, 0x7f, 0xba, 0x96, 0x4b, 0x39, 0x3e, 0xb5,
  0x03, 0xb5, 0xd1, 0x35, 0x72, 0xe1, 0x02, 0x81, 0x80, 0x60, 0x14, 0xd5,
  0x61, 0xe6, 0x24, 0xf7, 0x28, 0x5c, 0x9a, 0xac, 0xbe, 0x03, 0xc8, 0xf3,
  0x49, 0xe4, 0xdb, 0x9a, 0x90, 0x15, 0xae, 0xd7, 0x33, 0x68, 0x75, 0x1d,
  0x6b, 0x83, 0x9e, 0x17, 0x05, 0xbe, 0x30, 0xcc, 0x10, 0x6a, 0x37, 0x86,
  0x46, 0xb6, 0xe9, 0x47, 0x81, 0x19, 0xab, 0xe1, 0x7a, 0x1a, 0x3a, 0xcf,
  0x47, 0xd1, 0x8e, 0x3d, 0x3f, 0xc6, 0x3e, 0x5d, 0xcd, 0xaf, 0x47, 0xe0,
  0x9e, 0x60, 0xc5, 0xbd, 0xd6, 0x52, 0x4b, 0xc0, 0x21, 0xcb, 0xd3, 0x1b,
  0xe6, 0x5c, 0x3a, 0x03, 0x9a, 0xab, 0xa2, 0x81, 0xc9, 0x51, 0x28, 0x49,
  0x97, 0xe2, 0x0a, 0x50, 0xe4, 0x64, 0x29, 0x43, 0x34, 0xc2, 0xe7, 0x8c,
  0x5a, 0x46, 0xaa, 0x28, 0x0b, 0x1f, 0xed, 0xa7, 0x1a, 0x7b, 0x4e, 0xad,
  0x38, 0x61, 0x3a, 0xd1, 0x82, 0xf4, 0x3d, 0xd3, 0x2e, 0x3e, 0x47, 0xa4,
  0x6c, 0xd3, 0x20, 0xd4, 0xd1, 0x02, 0x81, 0x80, 0x68, 0x1a, 0x8d, 0x3c,
  0x18, 0x3f, 0x42, 0x5e, 0x38, 0x6d, 0x0a, 0x1e, 0x52, 0xd5, 0x8f, 0xd6,
  0x32, 0xff, 0x7c, 0x1c, 0xf3, 0x20, 0x8b, 0x92, 0xa5, 0x44, 0xff, 0x08,
  0x21, 0xa1, 0xce, 0x68, 0x8b, 0x03, 0xe0, 0x90, 0xeb, 0x01, 0x4e, 0x85,
  0xf9, 0xc5, 0xb7, 0x86, 0xee, 0xd0, 0x59, 0x10, 0x73, 0x98, 0x2a, 0xcb,
  0xf6, 0xfe, 0x0d, 0xba, 0x07, 0x91, 0x18, 0xf6, 0xbc, 0x93, 0x8a, 0x91,
  0xdd, 0x80, 0x16, 0x37, 0xdf, 0x75, 0x46, 0x87, 0x68, 0xee, 0xf4, 0x76,
  0x0c, 0xc5, 0x87, 0x38, 0xf5, 0xb6, 0xda, 0x8a, 0xee, 0x62, 0xc8, 0xc0,
  0xa2, 0x8d, 0xbf, 0xd5, 0xf8, 0xba, 0xb5, 0x74, 0xf0, 0x07, 0xa6, 0x1c,
  0xcf, 0x76, 0x61, 0xbe, 0xa4, 0x88, 0x4a, 0x95, 0xb0, 0xa3, 0x70, 0x73,
  0xa1, 0x6f, 0x73, 0xf0, 0xe8, 0x38, 0x8d, 0xe8, 0xd0, 0x7e, 0x2c, 0x0c,
  0xdc, 0x21, 0xfa, 0xc1
};

static unsigned int test_device_cert_key_der_len = 1192;

static UCHAR fake_handshake_data[] = "abcdefghijklmnopqrstuvwxyz1234567890";

static NX_SECURE_X509_CERT certificate;

CHAR server_crypto_metadata[16000]; 


/* certificate error */
void NX_Secure_TLS_SendCertificateVerifyTest_Test_1()
{

UINT status;
NX_PACKET *packet;
NX_SECURE_TLS_SESSION session = {0};
UCHAR header_buffer[6];
UCHAR header_data[6];
USHORT header_size;
UINT message_length;
USHORT message_type;
const NX_SECURE_TLS_CIPHERSUITE_INFO *ciphersuite;
USHORT priority;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_tls_session_reset(&session);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Initialize the server session. */
    status =  nx_secure_tls_session_create(&session,
                                           &nx_crypto_tls_ciphers,
                                           server_crypto_metadata,
                                           sizeof(server_crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup our packet reassembly buffer. */
    status = _nx_secure_tls_session_packet_buffer_set(&session, server_packet_buffer, sizeof(server_packet_buffer));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup TLS session as if we were in the middle of a handshake. */
    session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    status = _nx_secure_tls_ciphersuite_lookup(&session, TLS_RSA_WITH_AES_128_CBC_SHA256, &ciphersuite, &priority);
    EXPECT_EQ(NX_SUCCESS, status);
    // status = _nx_secure_tls_find_methods(&session, ciphersuite);
    // EXPECT_EQ(NX_SUCCESS, status);

    /* Initialize our certificate */
    memset(&certificate, 0, sizeof(certificate));
    status = _nx_secure_x509_certificate_initialize(&certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add certificate to session. */
    status = _nx_secure_tls_local_certificate_add(&session, &certificate);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Put some fake data into the handshake hash so we have something to actually encrypt. */
    status = _nx_secure_tls_handshake_hash_init(&session);
    EXPECT_EQ(NX_SUCCESS, status);
    status = _nx_secure_tls_handshake_hash_update(&session, fake_handshake_data, sizeof(fake_handshake_data));
    EXPECT_EQ(NX_SUCCESS, status);
        

    /* Allocate our packet so we can put data into it. */
    status =  nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);
    
    status = _nx_secure_tls_send_certificate_verify(&session, packet);
    EXPECT_EQ(NX_SUCCESS, status);

    USHORT tmp_size = certificate.nx_secure_x509_cipher_table_size;
    certificate.nx_secure_x509_cipher_table_size = 0;
    status = _nx_secure_tls_send_certificate_verify(&session, packet);
    EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CERT_SIG_ALGORITHM, status);

    certificate.nx_secure_x509_cipher_table_size = tmp_size;

    UINT tmp_type = certificate.nx_secure_x509_private_key_type;
    certificate.nx_secure_x509_private_key_type = NX_SECURE_X509_KEY_TYPE_USER_DEFINED_MASK;
    status = _nx_secure_tls_send_certificate_verify(&session, packet);
    //EXPECT_EQ(NX_SUCCESS, status);
    //EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);
    certificate.nx_secure_x509_private_key_type = tmp_type;

    UCHAR *tmp_data_end = packet->nx_packet_data_end;
    packet->nx_packet_data_end = packet->nx_packet_append_ptr + 1;
    status = _nx_secure_tls_send_certificate_verify(&session, packet);
    EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);
    packet->nx_packet_data_end = tmp_data_end;


    USHORT tmp_length = certificate.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length;
    certificate.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = 10;
    status = _nx_secure_tls_send_certificate_verify(&session, packet);
    certificate.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = tmp_length;
    EXPECT_EQ(NX_SECURE_TLS_INVALID_CERTIFICATE, status);

    
    ULONG tmp_meta_size = certificate.nx_secure_x509_public_cipher_metadata_size;
    certificate.nx_secure_x509_public_cipher_metadata_size = 0;
    status = _nx_secure_tls_send_certificate_verify(&session, packet);
    certificate.nx_secure_x509_public_cipher_metadata_size = tmp_meta_size;
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);
    nx_secure_tls_session_delete(&session);

    nx_packet_pool_delete(&pool_0);

}


extern NX_CRYPTO_METHOD crypto_method_none;
extern NX_CRYPTO_METHOD crypto_method_null;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_128;
extern NX_CRYPTO_METHOD crypto_method_aes_cbc_256;
extern NX_CRYPTO_METHOD crypto_method_aes_ccm_8;
extern NX_CRYPTO_METHOD crypto_method_aes_ccm_16;
extern NX_CRYPTO_METHOD crypto_method_aes_128_gcm_16;
extern NX_CRYPTO_METHOD crypto_method_aes_256_gcm_16;
extern NX_CRYPTO_METHOD crypto_method_ecdsa;
extern NX_CRYPTO_METHOD crypto_method_ecdh;
extern NX_CRYPTO_METHOD crypto_method_ecdhe;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha1;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha256;
extern NX_CRYPTO_METHOD crypto_method_hmac_sha384;
extern NX_CRYPTO_METHOD crypto_method_hmac_md5;
extern NX_CRYPTO_METHOD crypto_method_rsa;
extern NX_CRYPTO_METHOD crypto_method_pkcs1;
extern NX_CRYPTO_METHOD crypto_method_auth_psk;
extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;
extern NX_CRYPTO_METHOD crypto_method_md5;
extern NX_CRYPTO_METHOD crypto_method_sha1;
extern NX_CRYPTO_METHOD crypto_method_sha224;
extern NX_CRYPTO_METHOD crypto_method_sha256;
extern NX_CRYPTO_METHOD crypto_method_sha384;
extern NX_CRYPTO_METHOD crypto_method_sha512;
extern NX_CRYPTO_METHOD crypto_method_hkdf_sha1;
extern NX_CRYPTO_METHOD crypto_method_hkdf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_1;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha384;
extern NX_CRYPTO_METHOD crypto_method_hkdf;
extern NX_CRYPTO_METHOD crypto_method_hmac;

NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_256_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_RSA_WITH_AES_128_GCM_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    {TLS_PSK_WITH_AES_128_CBC_SHA,            &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_PSK_WITH_AES_256_CBC_SHA,            &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_PSK_WITH_AES_128_CBC_SHA256,         &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_PSK_WITH_AES_128_CCM_8,              &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_ccm_8,       16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif
#endif /* NX_SECURE_ENABLE_PSK_CIPHERSUITES */

    {TLS_RSA_WITH_NULL_SHA,                   &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_null,            0,       0,         &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_NULL_MD5,                   &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_null,            0,       0,         &crypto_method_hmac_md5,        16,        &crypto_method_tls_prf_sha256},
};

/* Lookup table for X.509 digital certificates - they need a public-key algorithm and a hash routine for verification. */
NX_SECURE_X509_CRYPTO _nx_crypto_x509_cipher_lookup_table[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &crypto_method_rsa,       &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_384,    &crypto_method_rsa,       &crypto_method_sha384},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_512,    &crypto_method_rsa,       &crypto_method_sha512},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_1,      &crypto_method_rsa,       &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_RSA_MD5,        &crypto_method_rsa,       &crypto_method_md5},
};


/* Declare the SHA256 hash method */
NX_CRYPTO_METHOD crypto_method_sha256_sha1 =
{
    NX_CRYPTO_HASH_SHA256,                         /* SHA256 algorithm                      */
    0,                                             /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    NX_CRYPTO_SHA256_ICV_LEN_IN_BITS,              /* Transmitted ICV size in bits          */
    NX_CRYPTO_SHA2_BLOCK_SIZE_IN_BYTES,            /* Block size in bytes                   */
    sizeof(NX_CRYPTO_SHA256),                      /* Metadata size in bytes                */
    _nx_crypto_method_sha256_init,                 /* SHA256 initialization routine         */
    _nx_crypto_method_sha256_cleanup,              /* SHA256 cleanup routine                */
    _nx_crypto_method_sha1_operation,              /* SHA256 operation                      */
};

/* Define the object we can pass into TLS. */
NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_test_3 =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table,
    sizeof(_nx_crypto_ciphersuite_lookup_table) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _nx_crypto_x509_cipher_lookup_table,
    sizeof(_nx_crypto_x509_cipher_lookup_table) / sizeof(NX_SECURE_X509_CRYPTO),
#endif

    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    &crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    &crypto_method_sha256_sha1,
    &crypto_method_tls_prf_sha256,
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif
};

void NX_Secure_TLS_SendCertificateVerifyTest_Test_2()
{

UINT status;
NX_PACKET *packet;
NX_SECURE_TLS_SESSION session = {0};
UCHAR header_buffer[6];
UCHAR header_data[6];
USHORT header_size;
UINT message_length;
USHORT message_type;
const NX_SECURE_TLS_CIPHERSUITE_INFO *ciphersuite;
USHORT priority;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_tls_session_reset(&session);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Initialize the server session. */
    status =  nx_secure_tls_session_create(&session,
                                           &nx_crypto_tls_ciphers_test_3,
                                           server_crypto_metadata,
                                           sizeof(server_crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup our packet reassembly buffer. */
    status = _nx_secure_tls_session_packet_buffer_set(&session, server_packet_buffer, sizeof(server_packet_buffer));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup TLS session as if we were in the middle of a handshake. */
    session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    status = _nx_secure_tls_ciphersuite_lookup(&session, TLS_RSA_WITH_AES_128_CBC_SHA256, &ciphersuite, &priority);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Initialize our certificate */
    memset(&certificate, 0, sizeof(certificate));
    status = _nx_secure_x509_certificate_initialize(&certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add certificate to session. */
    status = _nx_secure_tls_local_certificate_add(&session, &certificate);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Put some fake data into the handshake hash so we have something to actually encrypt. */
    status = _nx_secure_tls_handshake_hash_init(&session);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);
    status = _nx_secure_tls_handshake_hash_update(&session, fake_handshake_data, sizeof(fake_handshake_data));
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);      

    /* Allocate our packet so we can put data into it. */
    status =  nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_tls_send_certificate_verify(&session, packet);
    EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);

    // UINT tmp_type = certificate.nx_secure_x509_private_key_type;
    // certificate.nx_secure_x509_private_key_type = NX_SECURE_X509_KEY_TYPE_USER_DEFINED_MASK;
    // status = _nx_secure_tls_send_certificate_verify(&session, packet);
    // EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);
    // certificate.nx_secure_x509_private_key_type = tmp_type;

    nx_secure_tls_session_delete(&session);

    nx_packet_pool_delete(&pool_0);

}


NX_CRYPTO_METHOD crypto_method_rsa_test_4 =
{
    NX_CRYPTO_KEY_EXCHANGE_RSA,               /* RSA crypto algorithm                   */
    0,                                        /* Key size in bits                       */
    0,                                        /* IV size in bits                        */
    0,                                        /* ICV size in bits, not used.            */
    0,                                        /* Block size in bytes.                   */
    sizeof(NX_CRYPTO_RSA),                    /* Metadata size in bytes                 */
    _nx_crypto_method_rsa_init,               /* RSA initialization routine.            */
    _nx_crypto_method_rsa_cleanup,            /* RSA cleanup routine                    */
    _nx_crypto_method_rsa_operation           /* RSA operation                          */
};

/* Declare the SHA256 hash method */
NX_CRYPTO_METHOD crypto_method_sha256_test_4 =
{
    NX_CRYPTO_HASH_SHA256,                         /* SHA256 algorithm                      */
    0,                                             /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    NX_CRYPTO_SHA256_ICV_LEN_IN_BITS,              /* Transmitted ICV size in bits          */
    NX_CRYPTO_SHA2_BLOCK_SIZE_IN_BYTES,            /* Block size in bytes                   */
    sizeof(NX_CRYPTO_SHA256),                      /* Metadata size in bytes                */
    _nx_crypto_method_sha256_init,                 /* SHA256 initialization routine         */
    _nx_crypto_method_sha256_cleanup,              /* SHA256 cleanup routine                */
    _nx_crypto_method_sha256_operation,            /* SHA256 operation                      */
};

/* Lookup table for X.509 digital certificates - they need a public-key algorithm and a hash routine for verification. */
NX_SECURE_X509_CRYPTO _nx_crypto_x509_cipher_lookup_table_test_4[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &crypto_method_rsa_test_4,  &crypto_method_sha256_test_4},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_384,    &crypto_method_rsa,       &crypto_method_sha384},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_512,    &crypto_method_rsa,       &crypto_method_sha512},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_1,      &crypto_method_rsa,       &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_RSA_MD5,        &crypto_method_rsa,       &crypto_method_md5},
};

/* Define the object we can pass into TLS. */
NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_test_4 =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table,
    sizeof(_nx_crypto_ciphersuite_lookup_table) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _nx_crypto_x509_cipher_lookup_table_test_4,
    sizeof(_nx_crypto_x509_cipher_lookup_table_test_4) / sizeof(NX_SECURE_X509_CRYPTO),
#endif

    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    &crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    &crypto_method_sha256,
    &crypto_method_tls_prf_sha256,
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif
};

NX_CRYPTO_KEEP UINT  _nx_crypto_method_rsa_cleanup_test_4(VOID *crypto_metadata)
{

    return(NX_CRYPTO_NOT_SUCCESSFUL);
}

/* crypto init/cleanip/operation failure. */
void NX_Secure_TLS_SendCertificateVerifyTest_Test_3()
{

UINT status;
NX_PACKET *packet;
NX_SECURE_TLS_SESSION session = {0};
UCHAR header_buffer[6];
UCHAR header_data[6];
USHORT header_size;
UINT message_length;
USHORT message_type;
const NX_SECURE_TLS_CIPHERSUITE_INFO *ciphersuite;
USHORT priority;
UINT tmp_type;
UINT set_type = 0;

    for (int i = 0; i < 8; i++) {

        nx_system_initialize();

        status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
        EXPECT_EQ(NX_SUCCESS, status);

        status = _nx_secure_tls_session_reset(&session);
        EXPECT_EQ(NX_SUCCESS, status);

        switch (i) {
          case 0:
            crypto_method_rsa_test_4.nx_crypto_operation = _nx_crypto_method_sha256_operation;
            break;
          case 1:
            crypto_method_rsa_test_4.nx_crypto_init = _nx_crypto_method_sha256_init;
            break;
          case 2:
            crypto_method_rsa_test_4.nx_crypto_cleanup = _nx_crypto_method_rsa_cleanup_test_4;
            break;
          case 3:
            crypto_method_rsa_test_4.nx_crypto_operation = NX_NULL;
            break;
          case 4:
            crypto_method_rsa_test_4.nx_crypto_init = NX_NULL;
            break;
          case 5:
            crypto_method_rsa_test_4.nx_crypto_cleanup = NX_NULL;
            break;
          case 6:
            crypto_method_sha256_test_4.nx_crypto_operation = NX_NULL;
            break;
          case 7:
            set_type = 1;
            crypto_method_rsa_test_4.nx_crypto_operation = _nx_crypto_method_sha256_operation;
          default:
            break;
        }

        /* Initialize the server session. */
        status =  nx_secure_tls_session_create(&session,
                                               &nx_crypto_tls_ciphers_test_4,
                                               server_crypto_metadata,
                                               sizeof(server_crypto_metadata));
        EXPECT_EQ(NX_SUCCESS, status);

        /* Setup our packet reassembly buffer. */
        status = _nx_secure_tls_session_packet_buffer_set(&session, server_packet_buffer, sizeof(server_packet_buffer));
        EXPECT_EQ(NX_SUCCESS, status);

        /* Setup TLS session as if we were in the middle of a handshake. */
        session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
        status = _nx_secure_tls_ciphersuite_lookup(&session, TLS_RSA_WITH_AES_128_CBC_SHA256, &ciphersuite, &priority);
        EXPECT_EQ(NX_SUCCESS, status);

        /* Initialize our certificate */
        memset(&certificate, 0, sizeof(certificate));
        status = _nx_secure_x509_certificate_initialize(&certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
        EXPECT_EQ(NX_SUCCESS, status);

        if (set_type) {
            tmp_type = certificate.nx_secure_x509_private_key_type;
            certificate.nx_secure_x509_private_key_type = NX_SECURE_X509_KEY_TYPE_USER_DEFINED_MASK;
        }
        /* Add certificate to session. */
        status = _nx_secure_tls_local_certificate_add(&session, &certificate);
        EXPECT_EQ(NX_SUCCESS, status);

        /* Put some fake data into the handshake hash so we have something to actually encrypt. */
        status = _nx_secure_tls_handshake_hash_init(&session);
        EXPECT_EQ(NX_SUCCESS, status);
        status = _nx_secure_tls_handshake_hash_update(&session, fake_handshake_data, sizeof(fake_handshake_data));
        EXPECT_EQ(NX_SUCCESS, status);      

        /* Allocate our packet so we can put data into it. */
        status =  nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
        EXPECT_EQ(NX_SUCCESS, status);

        status = _nx_secure_tls_send_certificate_verify(&session, packet);

        switch (i) {
          case 0:
            EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
            crypto_method_rsa_test_4.nx_crypto_operation = _nx_crypto_method_rsa_operation;
            break;
          case 1:
            EXPECT_EQ(NX_SUCCESS, status);
            crypto_method_rsa_test_4.nx_crypto_init = _nx_crypto_method_rsa_init;
            break;
          case 2:
            EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);          
            crypto_method_rsa_test_4.nx_crypto_cleanup = _nx_crypto_method_rsa_cleanup;
            break;
          case 3:
            EXPECT_EQ(NX_SUCCESS, status);
            crypto_method_rsa_test_4.nx_crypto_operation = _nx_crypto_method_rsa_operation;
            break;
          case 4:
            //EXPECT_EQ(NX_SUCCESS, status);
            crypto_method_rsa_test_4.nx_crypto_init = _nx_crypto_method_rsa_init;
            break;
          case 5:
            EXPECT_EQ(NX_SUCCESS, status);          
            crypto_method_rsa_test_4.nx_crypto_cleanup = _nx_crypto_method_rsa_cleanup;
          case 6:
            EXPECT_EQ(NX_SUCCESS, status);          
            crypto_method_sha256_test_4.nx_crypto_operation = _nx_crypto_method_sha256_operation;
          case 7:
            //EXPECT_EQ(NX_SUCCESS, status);
            crypto_method_rsa_test_4.nx_crypto_operation = _nx_crypto_method_rsa_operation;
            certificate.nx_secure_x509_private_key_type = tmp_type;
            break;
          default:
            break;
        }

        nx_secure_tls_session_delete(&session);

        nx_packet_pool_delete(&pool_0);

    }

}

/* Cover
   hash_method = tls_session -> nx_secure_tls_crypto_table -> nx_secure_tls_handshake_hash_sha256_method;
   if (hash_method -> nx_crypto_operation != NX_NULL) */

/* crypto_method_sha256_null. */
NX_CRYPTO_METHOD crypto_method_sha256_null =
{
    NX_CRYPTO_HASH_SHA256,                         /* SHA256 algorithm                      */
    0,                                             /* Key size in bits                      */
    0,                                             /* IV size in bits, not used             */
    NX_CRYPTO_SHA256_ICV_LEN_IN_BITS,              /* Transmitted ICV size in bits          */
    NX_CRYPTO_SHA2_BLOCK_SIZE_IN_BYTES,            /* Block size in bytes                   */
    sizeof(NX_CRYPTO_SHA256),                      /* Metadata size in bytes                */
    _nx_crypto_method_sha256_init,                 /* SHA256 initialization routine         */
    _nx_crypto_method_sha256_cleanup,              /* SHA256 cleanup routine                */
    NX_NULL,                                       /* SHA256 operation                      */
};

NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_test =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table,
    sizeof(_nx_crypto_ciphersuite_lookup_table) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _nx_crypto_x509_cipher_lookup_table,
    sizeof(_nx_crypto_x509_cipher_lookup_table) / sizeof(NX_SECURE_X509_CRYPTO),
#endif

    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    &crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    &crypto_method_sha256_null,
    &crypto_method_tls_prf_sha256,
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif
};

/* Test for hash operation is null */
void NX_Secure_TLS_SendCertificateVerifyTest_Test_4()
{

UINT status;
NX_PACKET *packet;
NX_SECURE_TLS_SESSION session = {0};
UCHAR header_buffer[6];
UCHAR header_data[6];
USHORT header_size;
UINT message_length;
USHORT message_type;
const NX_SECURE_TLS_CIPHERSUITE_INFO *ciphersuite;
USHORT priority;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_tls_session_reset(&session);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Initialize the server session. */
    // memcpy(&nx_crypto_tls_ciphers_test, &nx_crypto_tls_ciphers, sizeof(nx_crypto_tls_ciphers));
    // nx_crypto_tls_ciphers_test.nx_secure_tls_handshake_hash_sha256_method->nx_crypto_operation = NX_NULL;
    status =  nx_secure_tls_session_create(&session,
                                           &nx_crypto_tls_ciphers_test,
                                           server_crypto_metadata,
                                           sizeof(server_crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup our packet reassembly buffer. */
    status = _nx_secure_tls_session_packet_buffer_set(&session, server_packet_buffer, sizeof(server_packet_buffer));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Setup TLS session as if we were in the middle of a handshake. */
    session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    status = _nx_secure_tls_ciphersuite_lookup(&session, TLS_RSA_WITH_AES_128_CBC_SHA256, &ciphersuite, &priority);
    EXPECT_EQ(NX_SUCCESS, status);
    // status = _nx_secure_tls_find_methods(&session, ciphersuite);
    // EXPECT_EQ(NX_SUCCESS, status);

    /* Initialize our certificate */
    memset(&certificate, 0, sizeof(certificate));
    status = _nx_secure_x509_certificate_initialize(&certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add certificate to session. */
    status = _nx_secure_tls_local_certificate_add(&session, &certificate);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Put some fake data into the handshake hash so we have something to actually encrypt. */
    status = _nx_secure_tls_handshake_hash_init(&session);
    EXPECT_EQ(NX_SUCCESS, status);
    status = _nx_secure_tls_handshake_hash_update(&session, fake_handshake_data, sizeof(fake_handshake_data));
    EXPECT_EQ(NX_NOT_SUCCESSFUL, status);      

    /* Allocate our packet so we can put data into it. */
    status =  nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    status = _nx_secure_tls_send_certificate_verify(&session, packet);
    EXPECT_EQ(NX_SUCCESS, status);

    nx_secure_tls_session_delete(&session);

    nx_packet_pool_delete(&pool_0);

}

#else
void NX_Secure_TLS_SendCertificateVerifyTest_Test_1()
{
    return;
}
void NX_Secure_TLS_SendCertificateVerifyTest_Test_2()
{
    return;
}

void NX_Secure_TLS_SendCertificateVerifyTest_Test_3()
{
    return;
}

void NX_Secure_TLS_SendCertificateVerifyTest_Test_4()
{
    return;
}


#endif

/* Test for ECC certificate */
#if defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && !defined(NX_SECURE_DISABLE_X509)

#define NX_CRYPTO_DIGITAL_SIGNATRUE_ECDSA        0x00050003
/* Declare the ECDSA crypto method */
NX_CRYPTO_METHOD crypto_method_ecdsa_test =
{
    NX_CRYPTO_DIGITAL_SIGNATRUE_ECDSA,           /* ECDSA crypto algorithm                 */
    0,                                           /* Key size in bits                       */
    0,                                           /* IV size in bits                        */
    0,                                           /* ICV size in bits, not used             */
    0,                                           /* Block size in bytes                    */
    sizeof(NX_CRYPTO_ECDSA),                     /* Metadata size in bytes                 */
    _nx_crypto_method_ecdsa_init,                /* ECDSA initialization routine           */
    _nx_crypto_method_ecdsa_cleanup,             /* ECDSA cleanup routine                  */
    _nx_crypto_method_ecdsa_operation            /* ECDSA operation                        */
};

NX_SECURE_X509_CRYPTO _nx_crypto_x509_cipher_lookup_table_ecc_test[] =
{
    /* OID identifier,                        public cipher,            hash method */
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_256,  &crypto_method_ecdsa_test,     &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_384,  &crypto_method_ecdsa,     &crypto_method_sha384},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_512,  &crypto_method_ecdsa,     &crypto_method_sha512},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_256,    &crypto_method_rsa,       &crypto_method_sha256},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_384,    &crypto_method_rsa,       &crypto_method_sha384},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_512,    &crypto_method_rsa,       &crypto_method_sha512},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_224,  &crypto_method_ecdsa,     &crypto_method_sha224},
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_1,    &crypto_method_ecdsa,     &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_RSA_SHA_1,      &crypto_method_rsa,       &crypto_method_sha1},
    {NX_SECURE_TLS_X509_TYPE_RSA_MD5,        &crypto_method_rsa,       &crypto_method_md5},
};

/* Ciphersuite table with ECC. */
static NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_ecc_test[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    {TLS_AES_128_GCM_SHA256,                  &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
    {TLS_AES_128_CCM_SHA256,                  &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_ccm_16,      96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
    {TLS_AES_128_CCM_8_SHA256,                &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_ccm_8,       96,      16,        &crypto_method_sha256,         32,         &crypto_method_hkdf},
#endif

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */

    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,   &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,    &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,      &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,    &crypto_method_ecdhe,     &crypto_method_ecdsa,     &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,      &crypto_method_ecdhe,     &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},

#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_RSA_WITH_AES_128_GCM_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */

    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_256_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},

};

/* Define the object we can pass into TLS. */
static const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc_test =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table_ecc_test,
    sizeof(_nx_crypto_ciphersuite_lookup_table_ecc_test) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _nx_crypto_x509_cipher_lookup_table_ecc_test,
    sizeof(_nx_crypto_x509_cipher_lookup_table_ecc_test) / sizeof(NX_SECURE_X509_CRYPTO),
#endif

    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    & crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    &crypto_method_sha256,
    &crypto_method_tls_prf_sha256,
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif


};


const USHORT nx_crypto_ecc_supported_groups_test[] =
{
    (USHORT)NX_CRYPTO_EC_SECP256R1,
    (USHORT)NX_CRYPTO_EC_SECP384R1,
    (USHORT)NX_CRYPTO_EC_SECP521R1,
};

extern NX_CRYPTO_METHOD crypto_method_ec_secp256;
extern NX_CRYPTO_METHOD crypto_method_ec_secp384;
extern NX_CRYPTO_METHOD crypto_method_ec_secp521;

const NX_CRYPTO_METHOD *nx_crypto_ecc_curves_test[] =
{
    &crypto_method_ec_secp256,
    &crypto_method_ec_secp384,
    &crypto_method_ec_secp521,
};

const UINT nx_crypto_ecc_supported_groups_size_test = sizeof(nx_crypto_ecc_supported_groups_test) / sizeof(USHORT);

NX_CRYPTO_KEEP UINT  _nx_crypto_init_fail(struct  NX_CRYPTO_METHOD_STRUCT *method,
                                                   UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                                   VOID  **handle,
                                                   VOID  *crypto_metadata,
                                                   ULONG crypto_metadata_size)
{
    return(NX_CRYPTO_PTR_ERROR);
}


void NX_Secure_TLS_SendCertificateVerifyTest_Test_ECC()
{

UINT status;
NX_PACKET *packet;
NX_SECURE_TLS_SESSION session = {0};
UCHAR header_buffer[6];
UCHAR header_data[6];
USHORT header_size;
UINT message_length;
USHORT message_type;
const NX_SECURE_TLS_CIPHERSUITE_INFO *ciphersuite;
USHORT priority;
USHORT tmp_count;
UINT tmp_type;

for (int i = 0; i < 10; i++) {
      nx_system_initialize();

      status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
      EXPECT_EQ(NX_SUCCESS, status);

      status = _nx_secure_tls_session_reset(&session);
      EXPECT_EQ(NX_SUCCESS, status);

      /* Initialize the server session. */
      status =  nx_secure_tls_session_create(&session,
                                             &nx_crypto_tls_ciphers_ecc_test,
                                             server_crypto_metadata,
                                             sizeof(server_crypto_metadata));
      EXPECT_EQ(NX_SUCCESS, status);

      status = nx_secure_tls_ecc_initialize(&session, nx_crypto_ecc_supported_groups_test,
                                            nx_crypto_ecc_supported_groups_size_test,
                                            nx_crypto_ecc_curves_test);
      EXPECT_EQ(NX_SUCCESS, status);

      switch (i) {
        case 1:
          tmp_count = session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count;
          session.nx_secure_tls_ecc.nx_secure_tls_ecc_supported_groups_count = 0;
          break;
        case 2:
          crypto_method_ecdsa_test.nx_crypto_init = NX_NULL;
          break;
        case 3:
          crypto_method_ecdsa_test.nx_crypto_init = _nx_crypto_init_fail;
          break;
        case 4:
          crypto_method_ecdsa_test.nx_crypto_operation = NX_NULL;
          break;
        case 5:
          crypto_method_ecdsa_test.nx_crypto_operation = _nx_crypto_method_sha256_operation;
          break;
        case 6:
          crypto_method_ecdsa_test.nx_crypto_cleanup = NX_NULL;
          break;
        case 7:
          crypto_method_ecdsa_test.nx_crypto_cleanup = _nx_crypto_method_rsa_cleanup_test_4;
          break;
        default:
          break;
      }
      /* Setup our packet reassembly buffer. */
      status = _nx_secure_tls_session_packet_buffer_set(&session, server_packet_buffer, sizeof(server_packet_buffer));
      EXPECT_EQ(NX_SUCCESS, status);

      /* Setup TLS session as if we were in the middle of a handshake. */
      session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
      // status = _nx_secure_tls_ciphersuite_lookup(&session, TLS_RSA_WITH_AES_128_CBC_SHA256, &ciphersuite, &priority);
      // EXPECT_EQ(NX_SUCCESS, status);
      // status = _nx_secure_tls_find_methods(&session, ciphersuite);
      // EXPECT_EQ(NX_SUCCESS, status);

      /* Initialize our certificate */
      memset(&certificate, 0, sizeof(certificate));
      //status = _nx_secure_x509_certificate_initialize(&certificate, test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, test_device_cert_key_der, test_device_cert_key_der_len, NX_SECURE_X509_KEY_TYPE_RSA_PKCS1_DER);
      status = nx_secure_x509_certificate_initialize(&certificate,
                                                     ECTestServer10_der, ECTestServer10_der_len,
                                                     NX_NULL, 0, ECTestServer7_256_key_der,
                                                     ECTestServer7_256_key_der_len, NX_SECURE_X509_KEY_TYPE_EC_DER);    

      EXPECT_EQ(NX_SUCCESS, status);

      switch (i) {
        case 0:
          tmp_type = certificate.nx_secure_x509_private_key_type;
          certificate.nx_secure_x509_private_key_type = NX_SECURE_X509_KEY_TYPE_HARDWARE;
          break;
        case 8:
          certificate.nx_secure_x509_private_key.ec_private_key.nx_secure_ec_private_key = NX_NULL;
          break;
        case 9:
          /* Cover branch at nx_secure_tls_send_certificate_verify.c line 729 */
          certificate.nx_secure_x509_public_algorithm = NX_SECURE_TLS_X509_TYPE_UNKNOWN;
          break;
        default:
          break;
      }

      /* Add certificate to session. */
      status = _nx_secure_tls_local_certificate_add(&session, &certificate);
      EXPECT_EQ(NX_SUCCESS, status);

      /* Put some fake data into the handshake hash so we have something to actually encrypt. */
      status = _nx_secure_tls_handshake_hash_init(&session);
      EXPECT_EQ(NX_SUCCESS, status);
      status = _nx_secure_tls_handshake_hash_update(&session, fake_handshake_data, sizeof(fake_handshake_data));
      EXPECT_EQ(NX_SUCCESS, status);      

      /* Allocate our packet so we can put data into it. */
      status =  nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
      EXPECT_EQ(NX_SUCCESS, status);

      status = _nx_secure_tls_send_certificate_verify(&session, packet);

      switch (i) {
        case 0:
          //EXPECT_EQ(NX_SUCCESS, status);
          break;
        case 1:
          //EXPECT_EQ(NX_CRYTPO_MISSING_ECC_CURVE, status);
          break;
        case 2:
          //EXPECT_EQ(NX_SUCCESS, status);
          crypto_method_ecdsa_test.nx_crypto_init = _nx_crypto_method_ecdsa_init;
        case 3:
          //EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);
          crypto_method_ecdsa_test.nx_crypto_init = _nx_crypto_method_ecdsa_init;
          break;
        case 4:
          //EXPECT_EQ(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE, status);
          crypto_method_ecdsa_test.nx_crypto_operation = _nx_crypto_method_ecdsa_operation;
          break;
        case 5:
          //EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
          crypto_method_ecdsa_test.nx_crypto_operation = _nx_crypto_method_ecdsa_operation;
          break;
        case 6:
          //EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
          crypto_method_ecdsa_test.nx_crypto_cleanup = _nx_crypto_method_ecdsa_cleanup;
          break;
        case 7:
          //EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
          crypto_method_ecdsa_test.nx_crypto_cleanup = _nx_crypto_method_ecdsa_cleanup;
          break;
        case 8:
          //EXPECT_EQ(NX_CRYPTO_PTR_ERROR, status);
          break;  
        default:
          break;
      }
      nx_secure_tls_session_delete(&session);

      nx_packet_pool_delete(&pool_0);

  }

}


NX_SECURE_TLS_CIPHERSUITE_INFO _nx_crypto_ciphersuite_lookup_table_test[] =
{
    /* Ciphersuite,                           public cipher,            public_auth,              session cipher & cipher mode,   iv size, key size,  hash method,                    hash size, TLS PRF */
    {TLS_RSA_WITH_AES_256_CBC_SHA256,         &crypto_method_rsa_test_4,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_256_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_AES_128_CBC_SHA,            &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_RSA_WITH_AES_128_GCM_SHA256,         &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_aes_128_gcm_16,  16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif /* NX_SECURE_ENABLE_AEAD_CIPHER */

#ifdef NX_SECURE_ENABLE_PSK_CIPHERSUITES
    {TLS_PSK_WITH_AES_128_CBC_SHA,            &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_PSK_WITH_AES_256_CBC_SHA,            &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_256,     16,      32,        &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_PSK_WITH_AES_128_CBC_SHA256,         &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_cbc_128,     16,      16,        &crypto_method_hmac_sha256,     32,        &crypto_method_tls_prf_sha256},
#ifdef NX_SECURE_ENABLE_AEAD_CIPHER
    {TLS_PSK_WITH_AES_128_CCM_8,              &crypto_method_null,      &crypto_method_auth_psk,  &crypto_method_aes_ccm_8,       16,      16,        &crypto_method_null,            0,         &crypto_method_tls_prf_sha256},
#endif
#endif /* NX_SECURE_ENABLE_PSK_CIPHERSUITES */

    {TLS_RSA_WITH_NULL_SHA,                   &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_null,            0,       0,         &crypto_method_hmac_sha1,       20,        &crypto_method_tls_prf_sha256},
    {TLS_RSA_WITH_NULL_MD5,                   &crypto_method_rsa,       &crypto_method_rsa,       &crypto_method_null,            0,       0,         &crypto_method_hmac_md5,        16,        &crypto_method_tls_prf_sha256},
};

/* Define the object we can pass into TLS. */
NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_test_5 =
{
    /* Ciphersuite lookup table and size. */
    _nx_crypto_ciphersuite_lookup_table_test,
    sizeof(_nx_crypto_ciphersuite_lookup_table_test) / sizeof(NX_SECURE_TLS_CIPHERSUITE_INFO),

#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    _nx_crypto_x509_cipher_lookup_table_test_4,
    sizeof(_nx_crypto_x509_cipher_lookup_table_test_4) / sizeof(NX_SECURE_X509_CRYPTO),
#endif

    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    &crypto_method_md5,
    &crypto_method_sha1,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    &crypto_method_sha256,
    &crypto_method_tls_prf_sha256,
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif
};

void NX_Secure_TLS_SendClientKeyExchangeTest()
{

UINT status;
NX_PACKET *packet;
NX_SECURE_TLS_SESSION session = {0};
UCHAR header_buffer[6];
UCHAR header_data[6];
USHORT header_size;
UINT message_length;
USHORT message_type;
const NX_SECURE_TLS_CIPHERSUITE_INFO *ciphersuite;
USHORT priority;
UCHAR tmp_count;
UINT tmp_type;
VOID *tmp_ptr;

  memset(&session, 0, sizeof(NX_SECURE_TLS_SESSION));

  for (int i = 0; i < 7; i++) {
      nx_system_initialize();

      status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);
      EXPECT_EQ(NX_SUCCESS, status);

      status = _nx_secure_tls_session_reset(&session);
      EXPECT_EQ(NX_SUCCESS, status);

      /* Initialize the server session. */
      status =  nx_secure_tls_session_create(&session,
                                             &nx_crypto_tls_ciphers_ecc_test,
                                             server_crypto_metadata,
                                             sizeof(server_crypto_metadata));
      EXPECT_EQ(NX_SUCCESS, status);

      status = nx_secure_tls_ecc_initialize(&session, nx_crypto_ecc_supported_groups_test,
                                            nx_crypto_ecc_supported_groups_size_test,
                                            nx_crypto_ecc_curves_test);
      EXPECT_EQ(NX_SUCCESS, status);

      switch (i) {
        case 4:
          crypto_method_rsa_test_4.nx_crypto_init = _nx_crypto_init_fail;
          break;
        case 5:
          crypto_method_rsa_test_4.nx_crypto_init = _nx_crypto_method_rsa_init;
          crypto_method_rsa_test_4.nx_crypto_operation = _nx_crypto_method_sha256_operation;
          break;
        case 6:
          crypto_method_rsa_test_4.nx_crypto_operation = _nx_crypto_method_rsa_operation;
          crypto_method_rsa_test_4.nx_crypto_cleanup = _nx_crypto_method_rsa_cleanup_test_4;
          break;
        default:
          break;
      }

      /* Setup our packet reassembly buffer. */
      status = _nx_secure_tls_session_packet_buffer_set(&session, server_packet_buffer, sizeof(server_packet_buffer));
      EXPECT_EQ(NX_SUCCESS, status);

      /* Setup TLS session as if we were in the middle of a handshake. */
      session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
      status = _nx_secure_tls_ciphersuite_lookup(&session, TLS_RSA_WITH_AES_128_CBC_SHA256, &ciphersuite, &priority);

      /* Initialize our certificate */
      memset(&certificate, 0, sizeof(certificate));
      status = nx_secure_x509_certificate_initialize(&certificate,
                                                     ECTestServer10_der, ECTestServer10_der_len,
                                                     NX_NULL, 0, ECTestServer7_256_key_der,
                                                     ECTestServer7_256_key_der_len, NX_SECURE_X509_KEY_TYPE_EC_DER);    

      EXPECT_EQ(NX_SUCCESS, status);

      /* Add certificate to session. */
      status = _nx_secure_tls_local_certificate_add(&session, &certificate);
      EXPECT_EQ(NX_SUCCESS, status);

      /* Allocate our packet so we can put data into it. */
      status =  nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
      EXPECT_EQ(NX_SUCCESS, status);
      
      switch (i) {
        case 0: {
          /* cover nx_secure_tls_send_client_key_exchange.c: 124 */
          packet->nx_packet_data_end = packet->nx_packet_append_ptr;
          session.nx_secure_tls_session_ciphersuite = _nx_crypto_ciphersuite_lookup_table_ecc_test;
          break;
        }
        case 1: {
          /* cover nx_secure_tls_send_client_key_exchange.c: 124 */
          session.nx_secure_tls_key_material.nx_secure_tls_new_key_material_data[0] = 255;
          session.nx_secure_tls_session_ciphersuite = _nx_crypto_ciphersuite_lookup_table_ecc_test;
          break;
        }

        case 2: {
          /* cover nx_secure_tls_send_client_key_exchange.c: 221 */
          packet->nx_packet_data_end = packet->nx_packet_append_ptr;
          session.nx_secure_tls_session_ciphersuite = _nx_crypto_ciphersuite_lookup_table;
          session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates =
                  session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates;
          break;
        }
        case 3: {
          /* cover nx_secure_tls_send_client_key_exchange.c: 221 */
          session.nx_secure_tls_session_ciphersuite = _nx_crypto_ciphersuite_lookup_table;
          session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates =
                  session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates;
          session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates
            -> nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = 1;
          break;
        }

        default: {
          /* cover nx_secure_tls_send_client_key_exchange.c: 257, 286, 301 */
          session.nx_secure_tls_session_ciphersuite = _nx_crypto_ciphersuite_lookup_table_test;
          session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates =
                  session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_local_certificates;
          break;
        }
      }

      status = _nx_secure_tls_send_client_key_exchange(&session, packet);

      nx_secure_tls_session_delete(&session);

      nx_packet_pool_delete(&pool_0);

  }

}

#else
void NX_Secure_TLS_SendCertificateVerifyTest_Test_ECC()
{
  return;
}

void NX_Secure_TLS_SendClientKeyExchangeTest()
{
  return;
}

#endif //defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE)