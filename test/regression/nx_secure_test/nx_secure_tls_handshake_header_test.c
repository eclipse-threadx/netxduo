#include <stdio.h>

#include "nx_secure_tls.h"

#include "tls_test_utility.h"

extern void    test_control_return(UINT status);


void NX_Secure_TLS_ProcessServerHandshakeHeader();

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_handshake_header_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Handshake header Test..........................");

    NX_Secure_TLS_ProcessServerHandshakeHeader();

    printf("SUCCESS!\n");
    test_control_return(0);

}


TEST(NX_Secure_TLS, ProcessServerHandshakeHeader)
{
struct {
    UCHAR message_type;
    USHORT expected_state;
} test_data[] =
{
    { NX_SECURE_TLS_CLIENT_HELLO,        NX_SECURE_TLS_SERVER_STATE_SEND_HELLO          },
    { NX_SECURE_TLS_CERTIFICATE_MSG,     NX_SECURE_TLS_SERVER_STATE_CLIENT_CERTIFICATE  },
    { NX_SECURE_TLS_CERTIFICATE_VERIFY,  NX_SECURE_TLS_SERVER_STATE_CERTIFICATE_VERIFY  },
    { NX_SECURE_TLS_CLIENT_KEY_EXCHANGE, NX_SECURE_TLS_SERVER_STATE_KEY_EXCHANGE        },
    { NX_SECURE_TLS_FINISHED,            NX_SECURE_TLS_SERVER_STATE_HANDSHAKE_FINISHED  },
    { NX_SECURE_TLS_HELLO_REQUEST,       NX_SECURE_TLS_SERVER_STATE_ALERT_SENT          },
    { NX_SECURE_TLS_SERVER_HELLO,        NX_SECURE_TLS_SERVER_STATE_ALERT_SENT          },
    { NX_SECURE_TLS_SERVER_KEY_EXCHANGE, NX_SECURE_TLS_SERVER_STATE_ALERT_SENT          },
    { NX_SECURE_TLS_CERTIFICATE_REQUEST, NX_SECURE_TLS_SERVER_STATE_ALERT_SENT          },
    { NX_SECURE_TLS_SERVER_HELLO_DONE,   NX_SECURE_TLS_SERVER_STATE_ALERT_SENT          },
};

UINT status;
UCHAR header_buffer[6];
UINT header_size;
UINT message_length;
USHORT message_type;

    for(unsigned int i = 0; i < sizeof(test_data) / sizeof(test_data[0]); ++i)
    {
        // Build our test header to pass into the function.
        header_buffer[0] = test_data[i].message_type;
        header_buffer[1] = 0x0; // Message length (dummy value for test)
        header_buffer[2] = 0x5;
        header_buffer[3] = 0xA;
        header_buffer[4] = 0x3; // TLS 1.2
        header_buffer[5] = 0x3;

        status = _nx_secure_tls_process_handshake_header(header_buffer, &message_type, &header_size, &message_length);
        EXPECT_EQ(test_data[i].message_type, message_type);
        EXPECT_EQ(NX_SECURE_TLS_SUCCESS, status);
        EXPECT_EQ(4, header_size);
        EXPECT_EQ(0x050A, message_length);
    }
}

