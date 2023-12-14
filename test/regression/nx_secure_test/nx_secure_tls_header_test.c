#include <stdio.h>

#include "nx_secure_tls_api.h"

#include "tls_test_utility.h"

extern void    test_control_return(UINT status);

static NX_SECURE_TLS_SESSION session;

void NX_Secure_TLS_ProcessHeader();

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_header_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Record header Test.............................");

    NX_Secure_TLS_ProcessHeader();

    printf("SUCCESS!\n");
    test_control_return(0);

}


static struct {
  UINT message_type;
  UINT length;
  UINT protocol_version;
  UINT status;
} test_data[] =
        {
                { NX_SECURE_TLS_CHANGE_CIPHER_SPEC, 0x1234, 0x0303, NX_SUCCESS },
                { NX_SECURE_TLS_ALERT, 0x5a5a, 0x0302, NX_SUCCESS },
                { NX_SECURE_TLS_HANDSHAKE, 0x1111, 0x0303, NX_SUCCESS },
                { NX_SECURE_TLS_APPLICATION_DATA, 0x0012, 0x0303, NX_SUCCESS },
        };


static NX_PACKET_POOL    pool_0;

#define NX_PACKET_POOL_SIZE ((1536 + sizeof(NX_PACKET)) * 32)

static ULONG             packet_pool_area[NX_PACKET_POOL_SIZE/sizeof(ULONG) + 64 / sizeof(ULONG)];

UCHAR crypto_metadata[16000];
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

TEST(NX_Secure_TLS, ProcessHeader)
{

UINT status;
NX_PACKET *packet;
UCHAR header_buffer[6];
UCHAR header_data[6];
USHORT header_size;
UINT message_length;
USHORT message_type;

    nx_system_initialize();

    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", 1536,  (ULONG*)(((int)packet_pool_area + 64) & ~63) , NX_PACKET_POOL_SIZE);

    nx_secure_tls_session_create(&session, &nx_crypto_tls_ciphers, crypto_metadata, sizeof(crypto_metadata));
    nx_secure_tls_session_reset(&session);
    for(unsigned int i = 0; i < sizeof(test_data) / sizeof(test_data[0]); ++i)
    {

        nx_packet_allocate(&pool_0, &packet, NX_TCP_PACKET, NX_NO_WAIT);

        // Build our test header to pass into the function.
        header_buffer[0] = test_data[i].message_type;
        header_buffer[1] = (UCHAR)(test_data[i].protocol_version >> 8);
        header_buffer[2] = (UCHAR)test_data[i].protocol_version;
        header_buffer[3] = (UCHAR)(test_data[i].length >> 8);
        header_buffer[4] = (UCHAR)test_data[i].length;
        header_size = 5;

        nx_packet_data_append(packet, header_buffer, 5, &pool_0, NX_NO_WAIT);

        /* Need to set the protocol version in our TLS session or the processing will fail. */
        session.nx_secure_tls_protocol_version = test_data[i].protocol_version;
        
        status = _nx_secure_tls_process_header(&session, packet, 0, &message_type, &message_length,
                                              header_data, &header_size);
        EXPECT_EQ(test_data[i].status, status);
        EXPECT_EQ(test_data[i].message_type, message_type);
        EXPECT_EQ(test_data[i].length, message_length);

        nx_packet_release(packet);
    }
}

