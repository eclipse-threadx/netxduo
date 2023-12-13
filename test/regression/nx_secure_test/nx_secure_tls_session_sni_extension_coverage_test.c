#include <stdio.h>

#include "nx_secure_tls_api.h"
#include "nx_crypto.h"
#include "tls_test_utility.h"

extern void    test_control_return(UINT status);

static NX_SECURE_TLS_SESSION session;
static NX_CRYPTO_METHOD fake_crypto_method;


void NX_Secure_TLS_session_sni_extension_parse();

/* Test cases all taken from RFC 4231. Relevant section numbers included in comments. */

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_session_sni_extension_test_application_define(void *first_unused_memory)
#endif
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   TLS Hash Session sni extension  Test...............");

    NX_Secure_TLS_session_sni_extension_parse();

    printf("SUCCESS!\n");
    test_control_return(0);

}
UCHAR extension_data[200];
static NX_SECURE_X509_DNS_NAME  dns_name;

TEST(NX_Secure_TLS, session_sni_extension_parse)
{
UINT status;
USHORT list_length;
UCHAR name_type;
NX_SECURE_TLS_HELLO_EXTENSION sni_extension;

 
    sni_extension.nx_secure_tls_extension_data = extension_data;
    

    
    sni_extension.nx_secure_tls_extension_id = NX_SECURE_TLS_EXTENSION_SERVER_NAME_INDICATION;


    /* Cover line 121-123: name_type is not NX_SECURE_TLS_SNI_NAME_TYPE_DNS
                           list_length > extension_data_length
                           dns name length > list length */

    list_length = 5;
    sni_extension.nx_secure_tls_extension_data_length = list_length - 1;
    extension_data[0] = 0; 
    extension_data[1] = list_length;
    extension_data[2] = (NX_SECURE_TLS_SNI_NAME_TYPE_DNS + 1);
    extension_data[3] = 0;
    extension_data[4] = list_length + 1;
    status = _nx_secure_tls_session_sni_extension_parse(NX_NULL, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SNI_EXTENSION_INVALID, status);


    list_length = 5;
    sni_extension.nx_secure_tls_extension_data_length = list_length + 1;
    extension_data[0] = 0; 
    extension_data[1] = list_length;
    extension_data[2] = (NX_SECURE_TLS_SNI_NAME_TYPE_DNS + 1);
    extension_data[3] = 0;
    extension_data[4] = list_length + 1;
    status = _nx_secure_tls_session_sni_extension_parse(NX_NULL, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SNI_EXTENSION_INVALID, status);

    list_length = 5;
    sni_extension.nx_secure_tls_extension_data_length = list_length + 1;
    extension_data[0] = 0; 
    extension_data[1] = list_length;
    extension_data[2] = (NX_SECURE_TLS_SNI_NAME_TYPE_DNS + 1);
    extension_data[3] = 0;
    extension_data[4] = list_length - 1;
    status = _nx_secure_tls_session_sni_extension_parse(NX_NULL, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SNI_EXTENSION_INVALID, status);

    list_length = 5;
    sni_extension.nx_secure_tls_extension_data_length = list_length + 1;
    extension_data[0] = 0; 
    extension_data[1] = list_length;
    extension_data[2] = (NX_SECURE_TLS_SNI_NAME_TYPE_DNS);
    extension_data[3] = 0;
    extension_data[4] = list_length + 1;
    status = _nx_secure_tls_session_sni_extension_parse(NX_NULL, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SNI_EXTENSION_INVALID, status);


    list_length = 5;
    sni_extension.nx_secure_tls_extension_data_length = list_length + 1;
    extension_data[0] = 0; 
    extension_data[1] = list_length;
    extension_data[2] = (NX_SECURE_TLS_SNI_NAME_TYPE_DNS);
    extension_data[3] = 0;
    extension_data[4] = list_length - 1;
    status = _nx_secure_tls_session_sni_extension_parse(NX_NULL, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SUCCESS, status);

    list_length = 5;
    sni_extension.nx_secure_tls_extension_data_length = list_length - 1;
    extension_data[0] = 0; 
    extension_data[1] = list_length;
    extension_data[2] = (NX_SECURE_TLS_SNI_NAME_TYPE_DNS + 1);
    extension_data[3] = 0;
    extension_data[4] = list_length - 1;
    status = _nx_secure_tls_session_sni_extension_parse(NX_NULL, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SNI_EXTENSION_INVALID, status);

    list_length = 5;
    sni_extension.nx_secure_tls_extension_data_length = list_length - 1;
    extension_data[0] = 0; 
    extension_data[1] = list_length;
    extension_data[2] = (NX_SECURE_TLS_SNI_NAME_TYPE_DNS);
    extension_data[3] = 0;
    extension_data[4] = list_length + 1;
    status = _nx_secure_tls_session_sni_extension_parse(NX_NULL, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SECURE_TLS_SNI_EXTENSION_INVALID, status);

    /* Cover line 129  */
    list_length = 110;
    sni_extension.nx_secure_tls_extension_data_length = list_length + 1;    
    extension_data[1] = list_length;
    extension_data[2] = NX_SECURE_TLS_SNI_NAME_TYPE_DNS;
    extension_data[3] = 0;
    extension_data[4] = NX_SECURE_X509_DNS_NAME_MAX + 1;
    status = _nx_secure_tls_session_sni_extension_parse(NX_NULL, &sni_extension, 1, &dns_name);
    EXPECT_EQ(NX_SUCCESS, status);    

}

