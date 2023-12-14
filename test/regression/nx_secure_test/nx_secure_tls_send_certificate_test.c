/* This tests nx_secure_tls_send_certificate. */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

extern VOID    test_control_return(UINT status);

#ifndef NX_SECURE_DISABLE_X509

UCHAR packet_buffer[100];

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_send_certificate_test_application_define(void *first_unused_memory)
#endif
{
UINT   status;
NX_SECURE_TLS_SESSION tls_session;
NX_SECURE_X509_CERT certificate;
NX_PACKET send_packet;

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Send Certificate Test....................");

	memset(&tls_session, 0, sizeof(tls_session));
	tls_session.nx_secure_tls_credentials.nx_secure_tls_active_certificate = &certificate;

	memset(&send_packet, 0, sizeof(send_packet));
	send_packet.nx_packet_data_end = send_packet.nx_packet_append_ptr + 1;

    status = _nx_secure_tls_send_certificate(&tls_session, &send_packet, TX_WAIT_FOREVER);
	EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

    status = _nx_secure_tls_send_certificate_request(&tls_session, &send_packet);
	EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

	send_packet.nx_packet_append_ptr = packet_buffer;
	send_packet.nx_packet_data_end = send_packet.nx_packet_append_ptr + 100;
	tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    status = _nx_secure_tls_send_certificate_request(&tls_session, &send_packet);
	EXPECT_EQ(NX_SUCCESS, status);

	tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_3;
    status = _nx_secure_tls_send_certificate_request(&tls_session, &send_packet);
	EXPECT_EQ(NX_SUCCESS, status);
	tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;

	/* Coverage test for _nx_secure_tls_send_finished */
	send_packet.nx_packet_data_end = send_packet.nx_packet_append_ptr + 10;
	tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
	status = _nx_secure_tls_send_finished(&tls_session, &send_packet);
	EXPECT_EQ(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL, status);

	send_packet.nx_packet_data_end = send_packet.nx_packet_append_ptr + 50;
	tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_SERVER;
	status = _nx_secure_tls_send_finished(&tls_session, &send_packet);
	EXPECT_EQ(NX_SECURE_TLS_UNKNOWN_CIPHERSUITE, status);

	printf("SUCCESS!\n");
	test_control_return(0);
}
#else
#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_send_certificate_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Send Certificate Test....................N/A\n");
    test_control_return(3);
}
#endif
