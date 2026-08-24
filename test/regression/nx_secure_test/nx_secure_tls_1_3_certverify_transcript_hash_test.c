/***************************************************************************/
/* Copyright (c) 2024 Microsoft Corporation                                */
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* Regression test for the TLS 1.3 CertificateVerify transcript-hash length.

   Per RFC 8446 4.4.3 the transcript hash embedded in the CertificateVerify
   content is sized by the negotiated ciphersuite's hash, not by the signature
   scheme's hash. A spy hash method stands in for the signature scheme's hash
   and captures the exact number of bytes the assembled content ends up with,
   for both the send and the process side. Two ciphersuite configurations pin
   the length down to that one source:

     1. Ciphersuite SHA-256, signature scheme SHA-384. This is the reported
        failure: an ECDSA P-384 certificate (ecdsa_secp384r1_sha384) with
        TLS_AES_128_GCM_SHA256, the only suite currently enabled. Expect 32
        transcript bytes; keying the length to the signature scheme yields 48.

     2. Ciphersuite SHA-384, signature scheme SHA-384. Expect 48 transcript
        bytes, which a hardcoded 32 would not produce.

   Configuration 2 is synthetic and cannot be run end to end today, so a passing test is not
   evidence that SHA-384 ciphersuites work. No such TLS 1.3 suite is enabled
   (crypto_libraries/src/nx_crypto_generic_ciphersuites.c:199), and NX_SECURE_TLS_MAX_HASH_SIZE
   is 32, so a 48-byte transcript has nowhere to be stored: _nx_secure_tls_1_3_transcript_hash_save
   would overrun its row of nx_secure_tls_transcript_hashes long before CertificateVerify is
   reached. Enabling such a suite means growing that constant first, which is load-bearing for
   the key schedule as well. This case covers the length derivation, nothing more. */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"
#include "test_ca_cert.c"

extern VOID    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_TLS_SERVER_DISABLED) && \
    defined(NX_SECURE_ENABLE_ECC_CIPHERSUITE) && !defined(NX_SECURE_DISABLE_X509) && \
    (NX_SECURE_TLS_TLS_1_3_ENABLED)

#define THREAD_STACK_SIZE           1024
#define METADATA_SIZE               16000
#define NX_PACKET_POOL_SIZE         ((1536 + sizeof(NX_PACKET)) * 8)

static TX_THREAD                thread_0;
static ULONG                    thread_0_stack[THREAD_STACK_SIZE / sizeof(ULONG)];
static UCHAR                    tls_session_metadata[METADATA_SIZE];
static NX_PACKET_POOL            pool_0;
static ULONG                    packet_pool_area[NX_PACKET_POOL_SIZE / sizeof(ULONG) + 64 / sizeof(ULONG)];

extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers_ecc;

/* The content hashed for CertificateVerify is 64 octets of 0x20, then the 33-byte context
   string plus its 0-byte separator, then the transcript hash. Only the last part varies. */
#define CONTENT_PREFIX_LENGTH       (64u + 34u)

static ULONG spy_captured_length;
static UINT  spy_call_count;

/* Stand-in for the signature scheme's hash (SHA-384, 48-byte ICV). The caller drives hashing
   through three separate nx_crypto_operation calls -- HASH_INITIALIZE, HASH_UPDATE,
   HASH_CALCULATE -- checking the status after each and bailing out immediately on failure.
   Let HASH_INITIALIZE succeed so HASH_UPDATE is reached, capture the length of the content
   HASH_UPDATE is asked to hash, then fail deliberately so the caller returns right there:
   this test observes how many transcript-hash bytes were assembled, it does not complete a
   signature. */
static UINT spy_hash_operation(UINT op, VOID *handler, struct NX_CRYPTO_METHOD_STRUCT *method,
                                UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                UCHAR *input, ULONG input_length_in_byte,
                                UCHAR *iv_ptr, UCHAR *output, ULONG output_length_in_byte,
                                VOID *crypto_metadata, ULONG crypto_metadata_size,
                                VOID *packet_ptr,
                                VOID (*nx_crypto_hw_process_callback)(VOID *packet_ptr, UINT status))
{
    if (op == NX_CRYPTO_HASH_INITIALIZE)
    {
        return(NX_CRYPTO_SUCCESS);
    }
    if (op == NX_CRYPTO_HASH_UPDATE)
    {
        spy_captured_length = input_length_in_byte;
        spy_call_count++;
    }
    return(NX_CRYPTO_NOT_SUCCESSFUL);
}

static NX_CRYPTO_METHOD spy_hash_method_sha384 =
{
    NX_CRYPTO_HASH_SHA384,     /* Algorithm identifier -- nominal, never dispatched on.  */
    0,                         /* Key size in bits, not used.                            */
    0,                         /* IV size in bits, not used.                             */
    384,                       /* ICV size in bits: stands in for SHA-384 (48 bytes).     */
    0,                         /* Block size in bytes, not used.                         */
    0,                         /* Metadata size in bytes, not used by the spy.           */
    NX_NULL,                  /* No init routine -- skips straight to the operations.    */
    NX_NULL,                  /* No cleanup routine.                                     */
    spy_hash_operation         /* Captures the assembled content length.                 */
};

/* Ciphersuite hash for configuration 2. Only its ICV size is read -- the code under test takes
   the transcript length from it and never invokes it. */
static NX_CRYPTO_METHOD ciphersuite_hash_sha384 =
{
    NX_CRYPTO_HASH_SHA384, 0, 0, 384, 0, 0, NX_NULL, NX_NULL, NX_NULL
};

/* Placeholder public-key method for the ECDSA_SHA_384 cipher-table row. Never invoked: the spy
   hash fails before either function reaches the signing/verification step. */
static NX_CRYPTO_METHOD dummy_public_cipher_method = {0};

static NX_SECURE_X509_CRYPTO mismatched_hash_cipher_table[] =
{
    /* OID identifier,                        public cipher,                hash method */
    {NX_SECURE_TLS_X509_TYPE_ECDSA_SHA_384,  &dummy_public_cipher_method,  &spy_hash_method_sha384},
};

/* Copy of TLS_AES_128_GCM_SHA256 with a SHA-384 hash, for configuration 2. See the header
   comment for why this configuration is synthetic. */
static NX_SECURE_TLS_CIPHERSUITE_INFO sha384_ciphersuite;

/* Runs _nx_secure_tls_send_certificate_verify and asserts the transcript-hash length that
   reached the signature scheme's hash. */
static VOID check_send_side(NX_SECURE_TLS_SESSION *tls_session, ULONG expected_transcript_length)
{
UINT       status;
NX_PACKET *packet;

    status = nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_WAIT_FOREVER);
    EXPECT_EQ(NX_SUCCESS, status);

    spy_captured_length = 0;
    spy_call_count = 0;
    status = _nx_secure_tls_send_certificate_verify(tls_session, packet);
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    EXPECT_EQ(1, spy_call_count);
    EXPECT_EQ(CONTENT_PREFIX_LENGTH + expected_transcript_length, spy_captured_length);

    nx_packet_release(packet);
}

/* Same for _nx_secure_tls_process_certificate_verify. */
static VOID check_process_side(NX_SECURE_TLS_SESSION *tls_session, ULONG expected_transcript_length)
{
UINT  status;
UCHAR verify_buffer[8];

    /* Wire SignatureScheme ecdsa_secp384r1_sha384 (0x0503). Nothing past these two bytes is
       read: the spy fails before the signature itself is parsed. */
    memset(verify_buffer, 0, sizeof(verify_buffer));
    verify_buffer[0] = NX_SECURE_TLS_HASH_ALGORITHM_SHA384;
    verify_buffer[1] = NX_SECURE_TLS_SIGNATURE_ALGORITHM_ECDSA;

    spy_captured_length = 0;
    spy_call_count = 0;
    status = _nx_secure_tls_process_certificate_verify(tls_session, verify_buffer, sizeof(verify_buffer));
    EXPECT_EQ(NX_CRYPTO_NOT_SUCCESSFUL, status);
    EXPECT_EQ(1, spy_call_count);
    EXPECT_EQ(CONTENT_PREFIX_LENGTH + expected_transcript_length, spy_captured_length);
}

static VOID ntest_0_entry(ULONG thread_input)
{
UINT   status;
NX_SECURE_TLS_SESSION tls_session;
NX_SECURE_X509_CERTIFICATE_STORE store;
NX_SECURE_X509_CERT local_certificate;
NX_SECURE_X509_CERT remote_certificate;
const NX_SECURE_TLS_CIPHERSUITE_INFO *sha256_ciphersuite;
USHORT priority;

    printf("NetX Secure Test:   TLS 1.3 CertificateVerify Transcript Hash Length Test..");

    nx_system_initialize();

    status = nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,
                                   (ULONG *)(((int)packet_pool_area + 64) & ~63), NX_PACKET_POOL_SIZE);
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_secure_tls_session_create(&tls_session, &nx_crypto_tls_ciphers_ecc,
                                          tls_session_metadata, sizeof(tls_session_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    tls_session.nx_secure_tls_1_3 = 1;

    /* Configuration 1's ciphersuite: TLS_AES_128_GCM_SHA256, hash SHA-256 (32-byte ICV). */
    status = _nx_secure_tls_ciphersuite_lookup(&tls_session, TLS_AES_128_GCM_SHA256,
                                               &sha256_ciphersuite, &priority);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Configuration 2's ciphersuite: the same entry with a SHA-384 hash (48-byte ICV). */
    sha384_ciphersuite = *sha256_ciphersuite;
    sha384_ciphersuite.nx_secure_tls_hash = &ciphersuite_hash_sha384;

    /* Fill the certificate transcript-hash slot, and the slot that follows it in
       nx_secure_tls_transcript_hashes, with known bytes. A 48-byte read from the 32-byte
       certificate slot -- what happens whenever the length is larger than the ciphersuite's
       hash -- then lands in initialized memory, so the outcome is an assertion failure on the
       captured length rather than a report from a memory sanitizer. */
    memset(tls_session.nx_secure_tls_key_material.nx_secure_tls_transcript_hashes[NX_SECURE_TLS_TRANSCRIPT_IDX_CERTIFICATE],
           0x11, NX_SECURE_TLS_MAX_HASH_SIZE);
    memset(tls_session.nx_secure_tls_key_material.nx_secure_tls_transcript_hashes[NX_SECURE_TLS_TRANSCRIPT_IDX_CLIENT_FINISHED],
           0xAA, NX_SECURE_TLS_MAX_HASH_SIZE);

    /* ---- Send side: _nx_secure_tls_send_certificate_verify (TLS 1.3 client). ---- */

    memset(&local_certificate, 0, sizeof(local_certificate));
    memset(&store, 0, sizeof(store));
    status = nx_secure_x509_certificate_initialize(&local_certificate, test_ca_cert_der, test_ca_cert_der_len,
                                                    NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = _nx_secure_x509_store_certificate_add(&local_certificate, &store, NX_SECURE_X509_CERT_LOCATION_LOCAL);
    EXPECT_EQ(NX_SUCCESS, status);
    /* No private key was provided above (the spy fails before any real signing), so
       nx_secure_x509_certificate_initialize left this false. _nx_secure_x509_local_device_
       certificate_get(..., NX_NULL, ...) only matches identity certificates -- force it. */
    local_certificate.nx_secure_x509_certificate_is_identity_cert = NX_CRYPTO_TRUE;
    local_certificate.nx_secure_x509_cipher_table = mismatched_hash_cipher_table;
    local_certificate.nx_secure_x509_cipher_table_size = 1;
    tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store = store;

    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;
    tls_session.nx_secure_tls_signature_algorithm = NX_SECURE_TLS_SIGNATURE_ECDSA_SHA384;

    tls_session.nx_secure_tls_session_ciphersuite = sha256_ciphersuite;
    check_send_side(&tls_session, 32);

    tls_session.nx_secure_tls_session_ciphersuite = &sha384_ciphersuite;
    check_send_side(&tls_session, 48);

    /* ---- Process side: _nx_secure_tls_process_certificate_verify (TLS 1.3 server). ---- */

    memset(&remote_certificate, 0, sizeof(remote_certificate));
    memset(&store, 0, sizeof(store));
    status = nx_secure_x509_certificate_initialize(&remote_certificate, test_ca_cert_der, test_ca_cert_der_len,
                                                    NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);
    status = _nx_secure_x509_store_certificate_add(&remote_certificate, &store, NX_SECURE_X509_CERT_LOCATION_REMOTE);
    EXPECT_EQ(NX_SUCCESS, status);
    remote_certificate.nx_secure_x509_cipher_table = mismatched_hash_cipher_table;
    remote_certificate.nx_secure_x509_cipher_table_size = 1;
    tls_session.nx_secure_tls_credentials.nx_secure_tls_certificate_store = store;

    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;

    tls_session.nx_secure_tls_session_ciphersuite = sha256_ciphersuite;
    check_process_side(&tls_session, 32);

    tls_session.nx_secure_tls_session_ciphersuite = &sha384_ciphersuite;
    check_process_side(&tls_session, 48);

    nx_secure_tls_session_delete(&tls_session);
    nx_packet_pool_delete(&pool_0);

    printf("SUCCESS!\n");
    test_control_return(0);
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_certverify_transcript_hash_test_application_define(void *first_unused_memory)
#endif
{
    tx_thread_create(&thread_0, "thread 0", ntest_0_entry, 0,
                     thread_0_stack, sizeof(thread_0_stack),
                     7, 7, TX_NO_TIME_SLICE, TX_AUTO_START);
}

#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
VOID    nx_secure_tls_1_3_certverify_transcript_hash_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Secure Test:   TLS 1.3 CertificateVerify Transcript Hash Length Test..N/A\n");
    test_control_return(3);
}
#endif
