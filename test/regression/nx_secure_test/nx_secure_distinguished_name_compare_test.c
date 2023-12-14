
#include <stdio.h>
#include "nx_secure_tls.h"

#include "tls_test_utility.h"

#include "nx_secure_x509.h"


/* Test data. */
static NX_SECURE_X509_DISTINGUISHED_NAME test_data[] =
{
        /* Generic distinguished name. */
        {
           "US",                              /* const UCHAR *nx_secure_x509_country;                              */
            2,                                /* USHORT       nx_secure_x509_country_length;                       */
                                              /*                                                                   */
           "Organization",                    /* const UCHAR *nx_secure_x509_organization;                         */
           sizeof("Organization"),            /* USHORT       nx_secure_x509_organization_length;                  */
                                              /*                                                                   */
           "Org unit",                        /* const UCHAR *nx_secure_x509_org_unit;                             */
           sizeof("Org unit"),                /* USHORT       nx_secure_x509_org_unit_length;                      */
                                              /*                                                                   */
           "Qualifier",                       /* const UCHAR *nx_secure_x509_distinguished_name_qualifier;         */
           sizeof("Qualifier"),               /* USHORT       nx_secure_x509_distinguished_name_qualifier_length;  */
                                              /*                                                                   */
           "California",                      /* const UCHAR *nx_secure_x509_state;                                */
           sizeof("California"),              /* USHORT       nx_secure_x509_state_length;                         */
                                              /*                                                                   */
           "Common Name",                     /* const UCHAR *nx_secure_x509_common_name;                          */
           sizeof("Common Name"),             /* USHORT       nx_secure_x509_common_name_length;                   */
                                              /*                                                                   */
           "1234",                            /* const UCHAR *nx_secure_x509_serial_number;                        */
           sizeof("1234"),                    /* USHORT       nx_secure_x509_serial_number_length;                 */
        },

        /* Permutation - change common name to proper subset of generic entry. */
        {
           "US",                              /* const UCHAR *nx_secure_x509_country;                              */
            2,                                /* USHORT       nx_secure_x509_country_length;                       */
                                              /*                                                                   */
           "Organization",                    /* const UCHAR *nx_secure_x509_organization;                         */
           sizeof("Organization"),            /* USHORT       nx_secure_x509_organization_length;                  */
                                              /*                                                                   */
           "Org unit",                        /* const UCHAR *nx_secure_x509_org_unit;                             */
           sizeof("Org unit"),                /* USHORT       nx_secure_x509_org_unit_length;                      */
                                              /*                                                                   */
           "Qualifier",                       /* const UCHAR *nx_secure_x509_distinguished_name_qualifier;         */
           sizeof("Qualifier"),               /* USHORT       nx_secure_x509_distinguished_name_qualifier_length;  */
                                              /*                                                                   */
           "California",                      /* const UCHAR *nx_secure_x509_state;                                */
           sizeof("California"),              /* USHORT       nx_secure_x509_state_length;                         */
                                              /*                                                                   */
           "Common",                          /* const UCHAR *nx_secure_x509_common_name;                          */
           sizeof("Common"),                  /* USHORT       nx_secure_x509_common_name_length;                   */
                                              /*                                                                   */
           "1234",                            /* const UCHAR *nx_secure_x509_serial_number;                        */
           sizeof("1234"),                    /* USHORT       nx_secure_x509_serial_number_length;                 */
        },

        /* Permutation - change common name to proper superset of generic entry. */
        {
           "US",                              /* const UCHAR *nx_secure_x509_country;                              */
            2,                                /* USHORT       nx_secure_x509_country_length;                       */
                                              /*                                                                   */
           "Organization",                    /* const UCHAR *nx_secure_x509_organization;                         */
           sizeof("Organization"),            /* USHORT       nx_secure_x509_organization_length;                  */
                                              /*                                                                   */
           "Org unit",                        /* const UCHAR *nx_secure_x509_org_unit;                             */
           sizeof("Org unit"),                /* USHORT       nx_secure_x509_org_unit_length;                      */
                                              /*                                                                   */
           "Qualifier",                       /* const UCHAR *nx_secure_x509_distinguished_name_qualifier;         */
           sizeof("Qualifier"),               /* USHORT       nx_secure_x509_distinguished_name_qualifier_length;  */
                                              /*                                                                   */
           "California",                      /* const UCHAR *nx_secure_x509_state;                                */
           sizeof("California"),              /* USHORT       nx_secure_x509_state_length;                         */
                                              /*                                                                   */
           "Common Name Extended",            /* const UCHAR *nx_secure_x509_common_name;                          */
           sizeof("Common Name Extended"),    /* USHORT       nx_secure_x509_common_name_length;                   */
                                              /*                                                                   */
           "1234",                            /* const UCHAR *nx_secure_x509_serial_number;                        */
           sizeof("1234"),                    /* USHORT       nx_secure_x509_serial_number_length;                 */
        },

        /* Permutation - omit all fields other than common name, which matches above.                              */
        /* Should NOT compare equal if strict comparison is on, but should compare equal otherwise!                */
        {
           "",                                /* const UCHAR *nx_secure_x509_country;                              */
            0,                                /* USHORT       nx_secure_x509_country_length;                       */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_organization;                         */
           0,                                 /* USHORT       nx_secure_x509_organization_length;                  */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_org_unit;                             */
           0,                                 /* USHORT       nx_secure_x509_org_unit_length;                      */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_distinguished_name_qualifier;         */
           0,                                 /* USHORT       nx_secure_x509_distinguished_name_qualifier_length;  */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_state;                                */
           0,                                 /* USHORT       nx_secure_x509_state_length;                         */
                                              /*                                                                   */
           "Common Name",                     /* const UCHAR *nx_secure_x509_common_name;                          */
           sizeof("Common Name"),             /* USHORT       nx_secure_x509_common_name_length;                   */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_serial_number;                        */
           0,                                 /* USHORT       nx_secure_x509_serial_number_length;                 */
        },

        /* Permutation - completely empty certificate.                                                             */
        /* Should compare equal only to itself.                                                                    */
        {
           "",                                /* const UCHAR *nx_secure_x509_country;                              */
            0,                                /* USHORT       nx_secure_x509_country_length;                       */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_organization;                         */
           0,                                 /* USHORT       nx_secure_x509_organization_length;                  */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_org_unit;                             */
           0,                                 /* USHORT       nx_secure_x509_org_unit_length;                      */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_distinguished_name_qualifier;         */
           0,                                 /* USHORT       nx_secure_x509_distinguished_name_qualifier_length;  */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_state;                                */
           0,                                 /* USHORT       nx_secure_x509_state_length;                         */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_common_name;                          */
           0,                                 /* USHORT       nx_secure_x509_common_name_length;                   */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_serial_number;                        */
           0,                                 /* USHORT       nx_secure_x509_serial_number_length;                 */
        },

        /* Permutation - change state field but leave all else the same.  */
        /* Should NOT compare equal if strict comparison is on, but should compare equal otherwise!                */
        {
           "US",                              /* const UCHAR *nx_secure_x509_country;                              */
            2,                                /* USHORT       nx_secure_x509_country_length;                       */
                                              /*                                                                   */
           "Organization",                    /* const UCHAR *nx_secure_x509_organization;                         */
           sizeof("Organization"),            /* USHORT       nx_secure_x509_organization_length;                  */
                                              /*                                                                   */
           "Org unit",                        /* const UCHAR *nx_secure_x509_org_unit;                             */
           sizeof("Org unit"),                /* USHORT       nx_secure_x509_org_unit_length;                      */
                                              /*                                                                   */
           "Qualifier",                       /* const UCHAR *nx_secure_x509_distinguished_name_qualifier;         */
           sizeof("Qualifier"),               /* USHORT       nx_secure_x509_distinguished_name_qualifier_length;  */
                                              /*                                                                   */
           "Nevada",                          /* const UCHAR *nx_secure_x509_state;                                */
           sizeof("Nevada"),                  /* USHORT       nx_secure_x509_state_length;                         */
                                              /*                                                                   */
           "Common Name",                     /* const UCHAR *nx_secure_x509_common_name;                          */
           sizeof("Common Name"),             /* USHORT       nx_secure_x509_common_name_length;                   */
                                              /*                                                                   */
           "1234",                            /* const UCHAR *nx_secure_x509_serial_number;                        */
           sizeof("1234"),                    /* USHORT       nx_secure_x509_serial_number_length;                 */
        },

        /* Permutation - change common name field to new value with same length as base case but leave all else    */
        /* the same.  */
        /* Should NOT compare equal! */
        {
           "US",                              /* const UCHAR *nx_secure_x509_country;                              */
            2,                                /* USHORT       nx_secure_x509_country_length;                       */
                                              /*                                                                   */
           "Organization",                    /* const UCHAR *nx_secure_x509_organization;                         */
           sizeof("Organization"),            /* USHORT       nx_secure_x509_organization_length;                  */
                                              /*                                                                   */
           "Org unit",                        /* const UCHAR *nx_secure_x509_org_unit;                             */
           sizeof("Org unit"),                /* USHORT       nx_secure_x509_org_unit_length;                      */
                                              /*                                                                   */
           "Qualifier",                       /* const UCHAR *nx_secure_x509_distinguished_name_qualifier;         */
           sizeof("Qualifier"),               /* USHORT       nx_secure_x509_distinguished_name_qualifier_length;  */
                                              /*                                                                   */
           "California",                      /* const UCHAR *nx_secure_x509_state;                                */
           sizeof("California"),              /* USHORT       nx_secure_x509_state_length;                         */
                                              /*                                                                   */
           "Fishy Name1",                     /* const UCHAR *nx_secure_x509_common_name;                          */
           sizeof("Fishy Name1"),             /* USHORT       nx_secure_x509_common_name_length;                   */
                                              /*                                                                   */
           "1234",                            /* const UCHAR *nx_secure_x509_serial_number;                        */
           sizeof("1234"),                    /* USHORT       nx_secure_x509_serial_number_length;                 */
        },


        /* Permutation - No common name, but other fields.  */
        /* Should NOT compare equal! */
        {
           "US",                              /* const UCHAR *nx_secure_x509_country;                              */
            0,                                /* USHORT       nx_secure_x509_country_length;                       */
                                              /*                                                                   */
           "Organization",                    /* const UCHAR *nx_secure_x509_organization;                         */
           sizeof("Organization"),            /* USHORT       nx_secure_x509_organization_length;                  */
                                              /*                                                                   */
           "Org unit",                        /* const UCHAR *nx_secure_x509_org_unit;                             */
           sizeof("Org unit"),                /* USHORT       nx_secure_x509_org_unit_length;                      */
                                              /*                                                                   */
           "Qualifier",                       /* const UCHAR *nx_secure_x509_distinguished_name_qualifier;         */
           sizeof("Qualifier"),               /* USHORT       nx_secure_x509_distinguished_name_qualifier_length;  */
                                              /*                                                                   */
           "California",                      /* const UCHAR *nx_secure_x509_state;                                */
           sizeof("California"),              /* USHORT       nx_secure_x509_state_length;                         */
                                              /*                                                                   */
           "",                                /* const UCHAR *nx_secure_x509_common_name;                          */
           0,                                 /* USHORT       nx_secure_x509_common_name_length;                   */
                                              /*                                                                   */
           "1234",                            /* const UCHAR *nx_secure_x509_serial_number;                        */
           sizeof("1234"),                    /* USHORT       nx_secure_x509_serial_number_length;                 */
        },

};

static UINT test_data_size = sizeof(test_data) / sizeof(NX_SECURE_X509_DISTINGUISHED_NAME);

static TX_THREAD thread_0;

static VOID thread_0_entry(ULONG thread_input);

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_distingushed_name_compare_test_application_define(void *first_unused_memory)
#endif
{
    tx_thread_create(&thread_0, "Thread 0", thread_0_entry, 0,
                     first_unused_memory, 4096,
                     16, 16, 4, TX_AUTO_START);
}

static VOID thread_0_entry(ULONG thread_input)
{
UINT i, j;
INT compare_result;
UINT error_count = 0;

    /* Print out test information banner.  */                                     
    printf("NetX Secure Test:   X590 Name Compare Test.............................");

    /* First, compare each entry to itself - should all compare equal. */
    for (i = 0; i < test_data_size ; i++)
    {
        compare_result = _nx_secure_x509_distinguished_name_compare(&test_data[i], &test_data[i], NX_SECURE_X509_NAME_ALL_FIELDS);
        EXPECT_EQ(0, compare_result);
    }

    /* Now compare all the entries with each other. Should all compare unequal if strict
       name comparison is on. */
    for(i = 0; i < test_data_size; ++i)
    {
        for(j = i + 1; j < test_data_size; ++j)
        {
            /* Compare entry i to entry j. */
            compare_result = compare_result = _nx_secure_x509_distinguished_name_compare(&test_data[i], &test_data[j], NX_SECURE_X509_NAME_ALL_FIELDS);
            if(compare_result == 0)
            {
                printf("\nError in distinguished name compare. First name index: %d, Second name index: %d\n", i, j);
                error_count++;
            }

            /* Compare entry j to entry i. Reversed to make sure order doesn't matter. */
            compare_result = compare_result = _nx_secure_x509_distinguished_name_compare(&test_data[j], &test_data[i], NX_SECURE_X509_NAME_ALL_FIELDS);

            if(compare_result == 0)
            {
                printf("\nError in distinguished name compare. First name index: %d, Second name index: %d\n", j, i);
                error_count++;
            }
        }
    }

    /* See if we got errors. */
    if(error_count > 0)
    {
        printf("ERROR\n");
        test_control_return(1);
    }
    else
    {
        printf("SUCCESS!\n");
        test_control_return(0);
    }
}
