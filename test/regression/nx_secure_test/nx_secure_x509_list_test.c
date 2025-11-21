#include <stdio.h>


#include "tls_test_utility.h"
#include "nx_secure_x509.h"


/* Test basic X509 parsing with an example certificates. */
#include "google_cert.c"
#include "test_ca_cert.c"
#include "test_device_cert.c"

#define     DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */
static TX_THREAD               thread_0;

/* Define thread prototypes.  */
static void    thread_0_entry(ULONG thread_input);

void NX_SECURE_X509_ListTest();
void NX_SECURE_X509_ListTestNULLs();

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_x509_list_test_application_define(void *first_unused_memory)
#endif
{

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     first_unused_memory, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
}

static void    thread_0_entry(ULONG thread_input)
{

    /* Print out test information banner.  */
    printf("NetX Secure Test:   X509 list Test  ...................................");

    NX_SECURE_X509_ListTest();
    
    NX_SECURE_X509_ListTestNULLs();

    printf("SUCCESS!\n");
    test_control_return(0);

}

#define NUM_TEST_CERTS 3
NX_SECURE_X509_CERT certificate_array[NUM_TEST_CERTS];

TEST(NX_SECURE_X509, ListTest)
{
UINT status;
NX_SECURE_X509_CERT *list_head;
UINT i;
NX_SECURE_X509_DISTINGUISHED_NAME cert_name;
NX_SECURE_X509_DISTINGUISHED_NAME cert_name_g;
NX_SECURE_X509_DISTINGUISHED_NAME cert_name_ca;
NX_SECURE_X509_CERT *certificate;


    /* Initialize our certificate structures with some data. */
    for(i = 0; i < NUM_TEST_CERTS; ++i)
    {
        memset(&certificate_array[i], 0, sizeof(NX_SECURE_X509_CERT));
    }

    /* Initialize the list head. */
    list_head = NX_NULL;

    status = nx_secure_x509_certificate_initialize(&certificate_array[0], google_cert_der, google_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(0, status);

    status = nx_secure_x509_certificate_initialize(&certificate_array[1], test_ca_cert_der, test_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(0, status);

    status = nx_secure_x509_certificate_initialize(&certificate_array[2], test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(0, status);

    /* Add our certificates to the list. */
    for(i = 0; i < NUM_TEST_CERTS; ++i)
    {
        status = _nx_secure_x509_certificate_list_add(&list_head, &certificate_array[i], 0);

        EXPECT_EQ(0, status);
    }

    /* Try adding a certificate twice. */
    status = _nx_secure_x509_certificate_list_add(&list_head, &certificate_array[0], 0);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Setup an example certificate name to search for - use strict name comparison.*/
    cert_name.nx_secure_x509_common_name = (const UCHAR*)"www.example.com";
    cert_name.nx_secure_x509_common_name_length = strlen("www.example.com");

    cert_name.nx_secure_x509_organization = (const UCHAR*)"Express Logic";
    cert_name.nx_secure_x509_organization_length = strlen("Express Logic");

    cert_name.nx_secure_x509_org_unit = (const UCHAR*)"NetX Secure";
    cert_name.nx_secure_x509_org_unit_length= strlen("NetX Secure");

    cert_name.nx_secure_x509_state = (const UCHAR*)"CA";
    cert_name.nx_secure_x509_state_length = strlen("CA");

    cert_name.nx_secure_x509_country = (const UCHAR*)"US";
    cert_name.nx_secure_x509_country_length = strlen("US");

    cert_name.nx_secure_x509_serial_number = NX_NULL;
    cert_name.nx_secure_x509_serial_number_length = 0;

    cert_name.nx_secure_x509_distinguished_name_qualifier = NX_NULL;
    cert_name.nx_secure_x509_distinguished_name_qualifier_length = 0;

    /* Search for certificate in the list. */
    status = _nx_secure_x509_certificate_list_find(&list_head, &cert_name, 0, &certificate);

    EXPECT_EQ(0, status);

    /* Remove our certificate from the list. */
    status = _nx_secure_x509_certificate_list_remove(&list_head, &cert_name, NX_NULL);
    EXPECT_EQ(0, status);

    /* Search for certificate in the list after removing it. */
    status = _nx_secure_x509_certificate_list_find(&list_head, &cert_name, 0, &certificate);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);

    /* Setup an example certificate name to search for - use common name comparison.*/
    cert_name_g.nx_secure_x509_common_name = (const UCHAR*)"www.google.com";
    cert_name_g.nx_secure_x509_common_name_length = strlen("www.google.com");
    cert_name_ca.nx_secure_x509_common_name = (const UCHAR*)"NetX Secure Test CA";
    cert_name_ca.nx_secure_x509_common_name_length = strlen("NetX Secure Test CA");

    status = _nx_secure_x509_certificate_list_find(&list_head, &cert_name_g, 0, &certificate);
    EXPECT_EQ(0, status);

    status = _nx_secure_x509_certificate_list_find(&list_head, &cert_name_ca, 0, &certificate);
    EXPECT_EQ(0, status);

    /* Remove google certificate from the list. */
    status = _nx_secure_x509_certificate_list_remove(&list_head, &cert_name_g, NX_NULL);
    EXPECT_EQ(0, status);

    status = _nx_secure_x509_certificate_list_find(&list_head, &cert_name_g, 0, &certificate);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);

    status = _nx_secure_x509_certificate_list_find(&list_head, &cert_name_ca, 0, &certificate);
    EXPECT_EQ(0, status);

    status = _nx_secure_x509_certificate_list_remove(&list_head, &cert_name_g, NX_NULL);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);

    /* Remove CA certificate from the list. */
    status = _nx_secure_x509_certificate_list_remove(&list_head, &cert_name_ca, NX_NULL);
    EXPECT_EQ(0, status);

    status = _nx_secure_x509_certificate_list_find(&list_head, &cert_name_ca, 0, &certificate);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);

}



TEST(NX_SECURE_X509, ListTestNULLs)
{
UINT status;
NX_SECURE_X509_DISTINGUISHED_NAME cert_name;
NX_SECURE_X509_CERT *certificate;

    /* Test NULLS. */
    status = _nx_secure_x509_certificate_list_find(NX_NULL, &cert_name, 0, &certificate);

    EXPECT_EQ(NX_PTR_ERROR, status);
    EXPECT_TRUE((certificate == NX_NULL));

    status = _nx_secure_x509_certificate_list_remove(NX_NULL, &cert_name, NX_NULL);

    EXPECT_EQ(NX_PTR_ERROR, status);

}

