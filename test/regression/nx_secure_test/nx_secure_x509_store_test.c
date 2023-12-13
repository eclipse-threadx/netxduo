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

void NX_SECURE_X509_StoreTest();
void NX_SECURE_X509_StoreTestNULLs();
void NX_SECURE_TLS_StoreTest();

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_x509_store_test_application_define(void *first_unused_memory)
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
    printf("NetX Secure Test:   X509 store test....................................");

    NX_SECURE_X509_StoreTest();
    
    NX_SECURE_X509_StoreTestNULLs();

#ifndef NX_SECURE_DISABLE_X509
    NX_SECURE_TLS_StoreTest();
#endif

    printf("SUCCESS!\n");
    test_control_return(0);

}

#define NUM_TEST_CERTS 3
NX_SECURE_X509_CERT certificate_array[NUM_TEST_CERTS];

TEST(NX_SECURE_X509, StoreTest)
{
UINT status;
NX_SECURE_X509_CERTIFICATE_STORE store;
/*NX_SECURE_X509_CERT *list_head;*/
UINT i;
NX_SECURE_X509_DISTINGUISHED_NAME cert_name;
NX_SECURE_X509_CERT *certificate;
UINT location;


    memset(&store, 0, sizeof(NX_SECURE_X509_CERTIFICATE_STORE));

    /* Initialize our certificate structures with some data. */
    for(i = 0; i < NUM_TEST_CERTS; ++i)
    {
        memset(&certificate_array[i], 0, sizeof(NX_SECURE_X509_CERT));
    }

    /* Initialize the list head. */
    /*list_head = NX_NULL;*/

    status = nx_secure_x509_certificate_initialize(&certificate_array[0], google_cert_der, google_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(0, status);

    status = nx_secure_x509_certificate_initialize(&certificate_array[1], test_ca_cert_der, test_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(0, status);

    status = nx_secure_x509_certificate_initialize(&certificate_array[2], test_device_cert_der, test_device_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);


    /* Add our certificates to the store. */
    status = _nx_secure_x509_store_certificate_add(&certificate_array[0], &store, NX_SECURE_X509_CERT_LOCATION_REMOTE);

    EXPECT_EQ(0, status);

    status = _nx_secure_x509_store_certificate_add(&certificate_array[1], &store, NX_SECURE_X509_CERT_LOCATION_TRUSTED);

    EXPECT_EQ(0, status);

    status = _nx_secure_x509_store_certificate_add(&certificate_array[2], &store, NX_SECURE_X509_CERT_LOCATION_LOCAL);

    EXPECT_EQ(0, status);

    /* Try adding a certificate twice in the same location. */
    status = _nx_secure_x509_store_certificate_add(&certificate_array[1], &store, NX_SECURE_X509_CERT_LOCATION_TRUSTED);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Try adding a certificate twice but in a new location (should be OK). */
    status = _nx_secure_x509_store_certificate_add(&certificate_array[1], &store, NX_SECURE_X509_CERT_LOCATION_LOCAL);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Try adding an invalid certitifcate location. */
    status = _nx_secure_x509_store_certificate_add(&certificate_array[1], &store, NX_SECURE_X509_CERT_LOCATION_NONE);
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

    /* Search for certificate in the store. */
    status = _nx_secure_x509_store_certificate_find(&store, &cert_name, 0, &certificate, &location);
    EXPECT_EQ(0, status);
    EXPECT_EQ(NX_SECURE_X509_CERT_LOCATION_LOCAL, location);

    /* Set up bogus name and search again. */
    cert_name.nx_secure_x509_common_name = (const UCHAR*)"www.abogusexample.com";
    cert_name.nx_secure_x509_common_name_length = strlen("www.abogusexample.com");
    status = _nx_secure_x509_store_certificate_find(&store, &cert_name, 0, &certificate, &location);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);
    EXPECT_EQ(NX_SECURE_X509_CERT_LOCATION_NONE, location);


    /* Remove our certificate from the store after resetting the name. */
    cert_name.nx_secure_x509_common_name = (const UCHAR*)"www.example.com";
    cert_name.nx_secure_x509_common_name_length = strlen("www.example.com");
    status = _nx_secure_x509_store_certificate_remove(&store, &cert_name, NX_SECURE_X509_CERT_LOCATION_LOCAL, 0);
    EXPECT_EQ(0, status);

    /* Search for certificate in the list after removing it. */
    status = _nx_secure_x509_store_certificate_find(&store, &cert_name, 0, &certificate, &location);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);
    EXPECT_EQ(NX_SECURE_X509_CERT_LOCATION_NONE, location);

}



TEST(NX_SECURE_X509, StoreTestNULLs)
{
UINT status;
NX_SECURE_X509_CERTIFICATE_STORE store;
NX_SECURE_X509_DISTINGUISHED_NAME cert_name;
NX_SECURE_X509_CERT *certificate=NX_NULL;
UINT location;

    memset(&store, 0, sizeof(NX_SECURE_X509_CERTIFICATE_STORE));
    memset(&cert_name, 0, sizeof(NX_SECURE_X509_DISTINGUISHED_NAME));

    /* Test NULLS. */
    status =_nx_secure_x509_store_certificate_add(NX_NULL, &store, NX_SECURE_X509_CERT_LOCATION_LOCAL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status =_nx_secure_x509_store_certificate_add(certificate, NX_NULL, NX_SECURE_X509_CERT_LOCATION_LOCAL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = _nx_secure_x509_store_certificate_find(NX_NULL, &cert_name, 0, &certificate, &location);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = _nx_secure_x509_store_certificate_find(&store, NX_NULL, 0, &certificate, &location);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = _nx_secure_x509_store_certificate_find(&store, &cert_name, 0, NX_NULL, &location);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = _nx_secure_x509_store_certificate_find(&store, &cert_name, 0, &certificate, NX_NULL);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = _nx_secure_x509_store_certificate_remove(NX_NULL, &cert_name, NX_SECURE_X509_CERT_LOCATION_LOCAL, 0);
    EXPECT_EQ(NX_PTR_ERROR, status);

    status = _nx_secure_x509_store_certificate_remove(&store, &cert_name, NX_SECURE_X509_CERT_LOCATION_NONE, 0);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    status = _nx_secure_x509_store_certificate_remove(&store, NX_NULL, NX_SECURE_X509_CERT_LOCATION_LOCAL, 0);
    EXPECT_EQ(NX_SECURE_X509_CERTIFICATE_NOT_FOUND, status);


}


static NX_SECURE_TLS_SESSION   tls_session;
static CHAR crypto_metadata[16000];
static NX_SECURE_X509_CERT local_certificate;
static NX_SECURE_X509_CERT trusted_certificate;

/*  Cryptographic routines. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

TEST(NX_SECURE_TLS, StoreTest)
{
UINT status;
NX_SECURE_X509_CERT *cert_ptr;

    nx_secure_tls_initialize();

    /* Create a TLS session.  */
    status =  nx_secure_tls_session_create(&tls_session,
                                           &nx_crypto_tls_ciphers,
                                           crypto_metadata,
                                           sizeof(crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);

    status = nx_secure_x509_certificate_initialize(&local_certificate, google_cert_der, google_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add our certificates to the local store. */
    status = nx_secure_tls_local_certificate_add(&tls_session, &local_certificate);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Try adding a certificate twice in the same location. */
    status = nx_secure_tls_local_certificate_add(&tls_session, &local_certificate);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Try finding the certificate by common name. */
    status = nx_secure_tls_local_certificate_find(&tls_session, &cert_ptr, "www.google.com", strlen("www.google.com"));
    EXPECT_EQ(NX_SUCCESS, status);
    EXPECT_TRUE(((VOID*)&local_certificate == (VOID*)cert_ptr));

    /* Try finding a non-existent certificate with a bogus name. */
    status = nx_secure_tls_local_certificate_find(&tls_session, &cert_ptr, "www.bogus.com", strlen("www.bogus.com"));
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    /* Remove non-existent certificate from the local store. */
    status = nx_secure_tls_local_certificate_remove(&tls_session, "n", strlen("n"));
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

    /* Remove actual certificate from the local store. */
    status = nx_secure_tls_local_certificate_remove(&tls_session, "www.google.com", strlen("www.google.com"));
    EXPECT_EQ(NX_SUCCESS, status);

    /* Try finding the certificate by common name after removing it. */
    status = nx_secure_tls_local_certificate_find(&tls_session, &cert_ptr, "www.google.com", strlen("www.google.com"));
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);
    EXPECT_TRUE(((VOID*)NX_NULL == (VOID*)cert_ptr));


    status = nx_secure_x509_certificate_initialize(&trusted_certificate, test_ca_cert_der, test_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Add our certificates to the trusted store. */
    status = nx_secure_tls_trusted_certificate_add(&tls_session, &trusted_certificate);
    EXPECT_EQ(NX_SUCCESS, status);

    /* Try adding a certificate twice in the same location. */
    status = nx_secure_tls_trusted_certificate_add(&tls_session, &trusted_certificate);
    EXPECT_EQ(NX_INVALID_PARAMETERS, status);

    /* Remove non-existent certificate from the trusted store. */
    status = nx_secure_tls_trusted_certificate_remove(&tls_session, "notca", strlen("notca"));
    EXPECT_EQ(NX_SECURE_TLS_CERTIFICATE_NOT_FOUND, status);

}
