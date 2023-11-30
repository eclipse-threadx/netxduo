
#define HTTP_MAX_BINARY_MD5              16
#define HTTP_MAX_ASCII_MD5               32
#define HTTP_SERVER_NONCE_SIZE           32
#define HTTP_MAX_RESOURCE                64

VOID http_hex_ascii_convert(CHAR *source, UINT source_length, CHAR *destination)
{

UINT    i,j;
CHAR    digit;


    /* Setup destination index.  */
    j =  0;

    /* Loop to process the entire source string.  */
    for (i = 0; i < source_length; i++)
    {

        /* Pickup the first nibble.  */
        digit =  (source[i] >> 4) & 0xF;

        /* Convert to ASCII and store.  */
        if (digit <= 9)
            destination[j++] =  (CHAR)(digit + '0');
        else
            destination[j++] =  (CHAR)(digit + 'a' - 10);

        /* Pickup the second nibble.  */
        digit =  source[i] & 0xF;

        /* Convert to ASCII and store.  */
        if (digit <= 9)
            destination[j++] =  (CHAR)(digit + '0');
        else
            destination[j++] =  (CHAR)(digit + 'a' - 10);
    }

    /* Finally, place a NULL in the destination string.  */
    destination[j] =  (CHAR) NX_NULL;
}

UINT http_nonce_retrieve(NX_PACKET *packet_ptr, CHAR *nonce)
{
UINT    length;
UINT    found;
CHAR    *buffer_ptr;

    found = NX_FALSE;
    length = 0;
    nonce[0] = NX_NULL;

    buffer_ptr = (CHAR *) packet_ptr -> nx_packet_prepend_ptr;

    while (((buffer_ptr + 6) < (CHAR *) packet_ptr -> nx_packet_append_ptr) && (*buffer_ptr != (CHAR) 0))
    {

        /* Check for the uri token.  */
        if (((*(buffer_ptr) ==  'n') || (*(buffer_ptr) ==  'N')) &&
            ((*(buffer_ptr+1) ==  'o') || (*(buffer_ptr+1) ==  'O')) &&
            ((*(buffer_ptr+2) ==  'n') || (*(buffer_ptr+2) ==  'N')) &&
            ((*(buffer_ptr+3) ==  'c') || (*(buffer_ptr+3) ==  'C')) &&
            ((*(buffer_ptr+4) ==  'e') || (*(buffer_ptr+4) ==  'E')) &&
            (*(buffer_ptr+5) == '='))
        {

            /* Move the pointer up to the actual authorization string.  */
            buffer_ptr =  buffer_ptr + 6;
            found = NX_TRUE;

            break;
        }

        /* Move the pointer up to the next character.  */
        buffer_ptr++;
    }

    if (found == NX_FALSE)
    {
        return(NX_NOT_FOUND);
    }

    /* Now remove any extra blanks and quotes.  */
    while ((buffer_ptr < (CHAR *) packet_ptr -> nx_packet_append_ptr) && ((*buffer_ptr == ' ') || (*buffer_ptr == (CHAR) 0x22)))
    {

        /* Move the pointer up one character.  */
        buffer_ptr++;
    }

    /* Now pickup the nonce string.  */
    length =  0;
    while ((buffer_ptr < (CHAR *) packet_ptr -> nx_packet_append_ptr) && (*buffer_ptr != (CHAR) 0) && (*buffer_ptr != ' ') && (*buffer_ptr != (CHAR) 13) && (length < HTTP_SERVER_NONCE_SIZE))
    {

        /* Determine if the ending quote is present.  */
        if (*buffer_ptr == (CHAR) 0x22)
        {

            break;
        }

        /* Copy a character of the authorization string into the destination.  */
        nonce[length++] =  *buffer_ptr++;
    }

    nonce[length] = NX_NULL;
    return(NX_SUCCESS);
}

VOID http_digest_response_calculate(NX_MD5 *md5data, CHAR *username, CHAR *realm, CHAR *password, CHAR *nonce, CHAR *method, CHAR *uri, CHAR *nc, CHAR *cnonce, CHAR *result)
{

CHAR    md5_binary[HTTP_MAX_BINARY_MD5];
CHAR    ha1_string[HTTP_MAX_ASCII_MD5 + 1];
CHAR    ha2_string[HTTP_MAX_ASCII_MD5 + 1];
UINT    username_length;
UINT    password_length;
UINT    realm_length;
UINT    method_length;
UINT    uri_length;
UINT    nc_length;
UINT    cnonce_length;

    /* Get string length.  */
    username_length = strlen(username);
    password_length = strlen(password);
    realm_length = strlen(realm);
    method_length = strlen(method);
    uri_length = strlen(uri);
    nc_length = strlen(nc);
    cnonce_length = strlen(cnonce);


    /* Calculate the H(A1) portion of the digest.  */
    _nx_md5_initialize(md5data);
    _nx_md5_update(md5data, (unsigned char *) username, username_length);
    _nx_md5_update(md5data, (unsigned char *) ":", 1);
    _nx_md5_update(md5data, (unsigned char *) realm, realm_length);
    _nx_md5_update(md5data, (unsigned char *) ":", 1);
    _nx_md5_update(md5data, (unsigned char *) password, password_length);
    _nx_md5_digest_calculate(md5data, (unsigned char *) md5_binary);

    /* Convert this H(A1) portion to ASCII Hex representation.  */
    http_hex_ascii_convert(md5_binary, HTTP_MAX_BINARY_MD5, ha1_string);

    /* Make the H(A2) portion of the digest.  */
    _nx_md5_initialize(md5data);
    _nx_md5_update(md5data, (unsigned char *) method, method_length);
    _nx_md5_update(md5data, (unsigned char *) ":", 1);
    _nx_md5_update(md5data, (unsigned char *) uri, uri_length);
    _nx_md5_digest_calculate(md5data, (unsigned char *) md5_binary);

    /* Convert this H(A2) portion to ASCII Hex representation.  */
    http_hex_ascii_convert(md5_binary, HTTP_MAX_BINARY_MD5, ha2_string);

    /* Now make the final MD5 digest.  */
    _nx_md5_initialize(md5data);
    _nx_md5_update(md5data, (unsigned char *) ha1_string, sizeof(ha1_string) - 1);
    _nx_md5_update(md5data, (unsigned char *) ":", 1);
    _nx_md5_update(md5data, (unsigned char *) nonce, HTTP_SERVER_NONCE_SIZE);

    /* Start of Internet Explorer bug work-around.  */
    _nx_md5_update(md5data, (unsigned char *) ":", 1);
    _nx_md5_update(md5data, (unsigned char *) nc, nc_length);
    _nx_md5_update(md5data, (unsigned char *) ":", 1);
    _nx_md5_update(md5data, (unsigned char *) cnonce, cnonce_length);
    _nx_md5_update(md5data, (unsigned char *) ":auth", 5);
    /* End of Internet Explorer bug work-around.  */

    _nx_md5_update(md5data, (unsigned char *) ":", 1);
    _nx_md5_update(md5data, (unsigned char *) ha2_string, sizeof(ha2_string) - 1);
    _nx_md5_digest_calculate(md5data, (unsigned char *) md5_binary);

    /* Finally, convert the response back to an ASCII string and place in
       the destination.  */
    http_hex_ascii_convert(md5_binary, HTTP_MAX_BINARY_MD5, result);
}