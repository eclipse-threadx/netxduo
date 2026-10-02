/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* This test covers the per-certificate extensions length checking in the TLS 1.3
   branch of _nx_secure_tls_process_remote_certificate().

   Each entry in a TLS 1.3 certificate list is followed by a two-byte extensions
   length. It was read from the wire, added to the read cursor and subtracted from
   the remaining list length, none of it checked, so a value larger than the list
   has room for wrapped an unsigned length and the loop continued with a cursor
   nothing had bounded.

   The parser is driven directly, which is how
   nx_secure_tls_certificate_coverage_test.c and several other tests in this suite
   reach it. That exercises the parsing, not the path that delivers a message to
   it: this test does not establish that a zero-length Certificate message is
   deliverable through the record layer, only that the parser rejects one.  */

#include   "tx_api.h"
#include   "nx_api.h"
#include   "nx_tcp.h"
#include   "nx_secure_tls_api.h"
#include   "tls_test_utility.h"

extern void    test_control_return(UINT status);

#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_DISABLE_X509) && (NX_SECURE_TLS_TLS_1_3_ENABLED)

/* A structurally valid certificate, so that the cases exercising the
   per-certificate extensions length get past X.509 parsing and actually reach
   that code. The cases exercising the context length fail before parsing and do
   not need it. */
#include "test_device_cert.c"

#define     DEMO_STACK_SIZE     4096

/* NX_SECURE_TLS_MINIMUM_MESSAGE_BUFFER_SIZE is the floor the error-checking
   wrapper enforces, so the packet buffer cannot be made arbitrarily small here. */
#define     PACKET_BUFFER_SIZE  NX_SECURE_TLS_MINIMUM_MESSAGE_BUFFER_SIZE

/* Larger than the packet buffer on purpose. The only bound at the copy inside
   the parser is the capacity of this buffer, so making it the larger of the two
   is what turned a wrapped length into a read past the end of the other.  */
#define     CERT_BUFFER_SIZE    (PACKET_BUFFER_SIZE * 2)

static TX_THREAD               ntest_0;
static NX_SECURE_TLS_SESSION   client_tls_session;
static NX_SECURE_X509_CERT     remote_certificate;

static UCHAR                   client_packet_buffer[PACKET_BUFFER_SIZE];
static UCHAR                   remote_cert_buffer[CERT_BUFFER_SIZE];
static CHAR                    client_crypto_metadata[16000];

static ULONG                   ntest_0_stack[DEMO_STACK_SIZE / sizeof(ULONG)];

extern NX_SECURE_TLS_CRYPTO    nx_crypto_tls_ciphers;

static void    ntest_0_entry(ULONG thread_input);

/* The parser is reached directly, as elsewhere in this suite. */
extern UINT _nx_secure_tls_process_remote_certificate(NX_SECURE_TLS_SESSION *tls_session,
                                                      UCHAR *packet_buffer, UINT message_length,
                                                      UINT data_length);

/* Offset into the packet buffer at which the message begins, standing in for
   bytes of the record already consumed. */
#define     DATA_LENGTH         64


/* Define what the initial system looks like.  */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_1_3_certificate_extensions_length_test_application_define(void *first_unused_memory)
#endif
{
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,
                     ntest_0_stack, sizeof(ntest_0_stack),
                     16, 16, 4, TX_AUTO_START);
}

/* Bring the session back to a known state before each case. */
static void session_setup(void)
{
UINT status;

    status = nx_secure_tls_session_create(&client_tls_session,
                                         &nx_crypto_tls_ciphers,
                                         client_crypto_metadata,
                                         sizeof(client_crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_secure_tls_session_packet_buffer_set(&client_tls_session, client_packet_buffer,
                                                    sizeof(client_packet_buffer));
    EXPECT_EQ(NX_SUCCESS, status);

    /* The documented client setup, and what makes the copy inside the parser the
       destination rather than the packet buffer itself. */
    status = nx_secure_tls_remote_certificate_allocate(&client_tls_session, &remote_certificate,
                                                      remote_cert_buffer, sizeof(remote_cert_buffer));
    EXPECT_EQ(NX_SUCCESS, status);

    client_tls_session.nx_secure_tls_1_3 = NX_TRUE;
}

static void session_teardown(void)
{
    nx_secure_tls_session_delete(&client_tls_session);
}

/* Build a Certificate message body: a context of context_length bytes, the test
   certificate, and an extensions length declaring declared_extensions with
   extensions_present bytes actually supplied. Returns the message length a
   handshake header would declare for it. */
static UINT certificate_message_build(UCHAR *message, UINT context_length,
                                      UINT declared_extensions, UINT extensions_present)
{
UINT index = 0;
UINT list_length;
UINT cert_length = (UINT)test_device_cert_der_len;

    message[index++] = (UCHAR)context_length;
    while (index <= context_length)
    {
        message[index++] = 0xC0;
    }

    list_length = 3 + cert_length + 2 + extensions_present;
    message[index++] = (UCHAR)(list_length >> 16);
    message[index++] = (UCHAR)(list_length >> 8);
    message[index++] = (UCHAR)(list_length);

    message[index++] = (UCHAR)(cert_length >> 16);
    message[index++] = (UCHAR)(cert_length >> 8);
    message[index++] = (UCHAR)(cert_length);

    memcpy(&message[index], test_device_cert_der, cert_length);
    index += cert_length;

    message[index++] = (UCHAR)(declared_extensions >> 8);
    message[index++] = (UCHAR)(declared_extensions);

    memset(&message[index], 0xEE, extensions_present);
    index += extensions_present;

    return index;
}

static void    ntest_0_entry(ULONG thread_input)
{
UINT   status;
UCHAR *message;
UINT   message_length;

    printf("NetX Secure Test:   TLS 1.3 Certificate Extensions Length Test............");

    message = &client_packet_buffer[DATA_LENGTH];

    /* An extensions length larger than the certificate list has room for. The
       parser must not subtract it from the remaining length, which would wrap and
       leave every later bounds test unable to fail, nor advance its read cursor
       by it.  */
    session_setup();
    memset(client_packet_buffer, 0x41, sizeof(client_packet_buffer));
    message_length = certificate_message_build(message, 0, 1000, 0);
    status = _nx_secure_tls_process_remote_certificate(&client_tls_session, message,
                                                      message_length, DATA_LENGTH);
    EXPECT_EQ(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH, status);
    session_teardown();

    /* Well-formed messages must still get past the length checking. These assert
       that the status is no longer a length complaint rather than asserting
       success, because a real certificate goes on to chain verification that this
       test does not set up.

       The first carries no extensions. The second carries eight bytes that are
       actually present, which sits exactly on the bound the check applies, so it
       covers that bound being inclusive rather than off by one.  */
    session_setup();
    memset(client_packet_buffer, 0x41, sizeof(client_packet_buffer));
    message_length = certificate_message_build(message, 0, 0, 0);
    status = _nx_secure_tls_process_remote_certificate(&client_tls_session, message,
                                                      message_length, DATA_LENGTH);
    EXPECT_TRUE(status != NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH);
    session_teardown();

    session_setup();
    memset(client_packet_buffer, 0x41, sizeof(client_packet_buffer));
    message_length = certificate_message_build(message, 0, 8, 8);
    status = _nx_secure_tls_process_remote_certificate(&client_tls_session, message,
                                                      message_length, DATA_LENGTH);
    EXPECT_TRUE(status != NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH);
    session_teardown();

    printf("SUCCESS!\n");
    test_control_return(0);
}

#else

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_1_3_certificate_extensions_length_test_application_define(void *first_unused_memory)
#endif
{
    printf("NetX Secure Test:   TLS 1.3 Certificate Extensions Length Test............N/A\n");
    test_control_return(3);
}

#endif
