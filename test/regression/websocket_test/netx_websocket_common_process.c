/* This file contains common process functions. */
#include    "tx_api.h"
#include    "nx_api.h"

#if !defined(NX_DISABLE_IPV4) && defined(__PRODUCT_NETXDUO__) && !defined(NX_DISABLE_PACKET_CHAIN)
#include    "nx_websocket_client.h"

#define TEST_CONNECT_GUID         "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define TEST_CONNECT_GUID_SIZE    (sizeof(TEST_CONNECT_GUID) - 1)
#define TEST_CONNECT_DIGEST_SIZE  20 /* The length of SHA-1 hash is 20 bytes */
#define TEST_CONNECT_KEY_SIZE     32 /* Make it larger than the minimum length (28 bytes )for the encoded key */

static UCHAR   connect_key[TEST_CONNECT_KEY_SIZE];
static UINT    connect_key_size;

UINT  _server_connect_response_process(NX_PACKET *packet_ptr)
{
UCHAR  *buffer_ptr;
UINT    offset = 0;
UCHAR  *field_name;
UINT    field_name_length;
UCHAR  *field_value;
UINT    field_value_length;
NX_SHA1 SH;
UCHAR   digest[TEST_CONNECT_DIGEST_SIZE];

    buffer_ptr = packet_ptr -> nx_packet_prepend_ptr;

    /* Skip over the first Command line (GET /xxx HTTP/1.1\r\n).  */
    while(((buffer_ptr + 1) < packet_ptr -> nx_packet_append_ptr) &&
          (*buffer_ptr != '\r') && (*(buffer_ptr + 1) != '\n'))
    {
        buffer_ptr++;
        offset++;
    }

    /* Skip over the CR,LF. */
    buffer_ptr += 2;
    offset += 2;

    /* Skip over the first Host line (Host: xxx\r\n).  */
    while(((buffer_ptr + 1) < packet_ptr -> nx_packet_append_ptr) &&
          (*buffer_ptr != '\r') && (*(buffer_ptr + 1) != '\n'))
    {
        buffer_ptr++;
        offset++;
    }

    /* Skip over the CR,LF. */
    buffer_ptr += 2;
    offset += 2;

    /* Loop until we find the "cr,lf,cr,lf" token.  */
    while (((buffer_ptr + 1) < packet_ptr -> nx_packet_append_ptr) && (*buffer_ptr != 0))
    {

        /* Check for the <cr,lf,cr,lf> token.  This signals a blank line, which also 
           specifies the start of the content.  */
        if ((*buffer_ptr == '\r') &&
            (*(buffer_ptr + 1) ==  '\n'))
        {

            /* Adjust the offset.  */
            offset = offset + 2;
            break;
        }

        /* We haven't seen the <cr,lf,cr,lf> so we are still processing header data.
           Extract the field name and it's value.  */
        field_name = buffer_ptr;
        field_name_length = 0;

        /* Look for the ':' that separates the field name from its value. */
        while(*buffer_ptr != ':')
        {
            buffer_ptr++;
            field_name_length++;
        }
        offset += field_name_length;

        /* Skip ':'.  */
        buffer_ptr++;
        offset++;

        /* Now skip over white space. */
        while ((buffer_ptr < packet_ptr -> nx_packet_append_ptr) && (*buffer_ptr == ' '))
        {
            buffer_ptr++;
            offset++;
        }

        /* Now get the field value. */
        field_value = buffer_ptr;
        field_value_length = 0;

        /* Loop until we see a <CR, LF>. */
        while(((buffer_ptr + 1) < packet_ptr -> nx_packet_append_ptr) && (*buffer_ptr != '\r') && (*(buffer_ptr+1) != '\n'))
        {
            buffer_ptr++;
            field_value_length++;
        }
        offset += field_value_length;

        /* Skip over the CR,LF. */
        buffer_ptr += 2;
        offset += 2;

        /* Check the upgrade.  */
        if (_nx_websocket_client_name_compare((UCHAR *)field_name, field_name_length, (UCHAR *)"Upgrade", sizeof("Upgrade") - 1) == NX_SUCCESS)
        {
            if (_nx_websocket_client_name_compare((UCHAR *)field_value, field_value_length, (UCHAR *)"websocket", sizeof("websocket") - 1))
            {
                return(NX_WEBSOCKET_INVALID_PACKET);
            }
        }
        else if (_nx_websocket_client_name_compare((UCHAR *)field_name, field_name_length, (UCHAR *)"Connection", sizeof("Connection") - 1) == NX_SUCCESS)
        {
            if (_nx_websocket_client_name_compare((UCHAR *)field_value, field_value_length, (UCHAR *)"Upgrade", sizeof("Upgrade") - 1))
            {
                return(NX_WEBSOCKET_INVALID_PACKET);
            }
        }
        else if (_nx_websocket_client_name_compare((UCHAR *)field_name, field_name_length, (UCHAR *)"Sec-WebSocket-Key", sizeof("Sec-WebSocket-Key") - 1) == NX_SUCCESS)
        {

            /* Calculate the SHA-1 hash of the concatenation of the client key and the Globally Unique Identifier (GUID)
               Referenced in RFC 6455, Section 1.3, Page 6 */
            _nx_sha1_initialize(&SH);
            _nx_sha1_update(&SH, field_value, field_value_length);
            _nx_sha1_update(&SH, (UCHAR*)TEST_CONNECT_GUID, TEST_CONNECT_GUID_SIZE);
            _nx_sha1_digest_calculate(&SH, digest);

            /* Encode the hash and compare it with the field value from the server.  */
            _nx_utility_base64_encode(digest, TEST_CONNECT_DIGEST_SIZE, connect_key, TEST_CONNECT_KEY_SIZE, &connect_key_size);
        }
    }

    /* Check if the all fields are processed.  */
    if (offset != packet_ptr -> nx_packet_length)
    {
        return(NX_WEBSOCKET_INVALID_PACKET);
    }

    return(NX_SUCCESS);
}

#endif

void SET_ERROR_COUNTER(ULONG *error_counter, CHAR *filename, int line_number)
{
    *error_counter = (*error_counter) + 1;

    printf("Error: File %s:%d\n", filename, line_number);
}

